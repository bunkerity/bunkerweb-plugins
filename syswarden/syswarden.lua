local cjson = require("cjson.safe")
local class = require("middleclass")
local ipmatcher = require("resty.ipmatcher")
local plugin = require("bunkerweb.plugin")
local syswarden_helpers = require("syswarden.syswarden_helpers")
local utils = require("bunkerweb.utils")

local syswarden = class("syswarden", plugin)

local ngx = ngx
local INFO = ngx.INFO
local ERR = ngx.ERR
local HTTP_OK = ngx.HTTP_OK
local get_deny_status = utils.get_deny_status
local get_phase = ngx.get_phase
local has_variable = utils.has_variable
local ipmatcher_new = ipmatcher.new
local cache_key = syswarden_helpers.cache_key
local classify_cache = syswarden_helpers.classify_cache
local decide = syswarden_helpers.decide
local lists_empty = syswarden_helpers.lists_empty
local list_sizes = syswarden_helpers.list_sizes
local decode = cjson.decode
local tostring = tostring
local ipairs = ipairs
local insert = table.insert
local open = io.open

-- Where syswarden-blocklist-download.py and syswarden-telemetry-poll.py leave their
-- output. The scheduler ships this directory to every BunkerWeb instance, which is how
-- a job running in the scheduler container reaches the Lua code in another one.
local CACHE_DIR = "/var/cache/bunkerweb/syswarden/"

-- Read one cached list file into a table of lines. A missing file is not an error:
-- it means the download job has not run yet, and the caller fails open on it.
local function read_list(name)
	local list = {}
	local file = open(CACHE_DIR .. name, "r")
	if not file then
		return list
	end
	for line in file:lines() do
		if line ~= "" then
			insert(list, line)
		end
	end
	file:close()
	return list
end

function syswarden:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "syswarden", ctx)
	-- Decode the lists only in the request phases that consume them (access/preread),
	-- so init/log/api don't pay for a datastore read they never use.
	if get_phase() ~= "init" and self.is_request and self:is_needed() then
		local lists, err = self.datastore:get("plugin_syswarden_lists", true)
		if not lists then
			self.logger:log(ERR, "can't get SysWarden lists from datastore : " .. tostring(err))
			lists = {}
		end
		-- Both settings are multisite: a service that only asks for the blocklist must not
		-- get the whitelist's allow, so the list it did not enable is empty for it. The
		-- tables themselves are read-only and shared with the worker LRU on purpose.
		self.lists = {
			blocklist = self.variables["USE_SYSWARDEN_BLOCKLIST"] == "yes" and (lists.blocklist or {}) or {},
			whitelist = self.variables["USE_SYSWARDEN_WHITELIST"] == "yes" and (lists.whitelist or {}) or {},
		}
	end
end

function syswarden:is_needed()
	-- Loading case
	if self.is_loading then
		return false
	end
	-- Request phases: the deny path is per-service, so it follows the multisite settings
	if self.is_request and (self.ctx.bw.server_name ~= "_") then
		return self.variables["USE_SYSWARDEN_BLOCKLIST"] == "yes" or self.variables["USE_SYSWARDEN_WHITELIST"] == "yes"
	end
	-- Other cases : the integration is enabled at all
	local is_needed, err = has_variable("USE_SYSWARDEN", "yes")
	if is_needed == nil then
		self.logger:log(ERR, "can't check USE_SYSWARDEN variable : " .. err)
	end
	return is_needed
end

function syswarden:init()
	-- Check if init is needed
	if not self:is_needed() then
		return self:ret(true, "init not needed")
	end
	-- Load what syswarden-blocklist-download.py cached. Both lists are global: one
	-- download serves every vhost, the per-service gate lives in access()/preread().
	local lists = {
		blocklist = read_list("blocklist.list"),
		whitelist = read_list("whitelist.list"),
	}
	local ok, err = self.datastore:set("plugin_syswarden_lists", lists, nil, true)
	if not ok then
		return self:ret(false, "can't store SysWarden lists into datastore : " .. err)
	end
	local blocked, allowed = list_sizes(lists)
	self.logger:log(
		INFO,
		"successfully loaded " .. tostring(blocked) .. " blocklist and " .. tostring(allowed) .. " whitelist entries"
	)
	return self:ret(true, "success")
end

function syswarden:init_worker()
	-- Check if init_worker is needed
	if self.is_loading then
		return self:ret(true, "init_worker not needed")
	end
	local is_needed, err = has_variable("USE_SYSWARDEN", "yes")
	if is_needed == nil then
		return self:ret(false, "can't check USE_SYSWARDEN variable : " .. err)
	end
	if not is_needed then
		return self:ret(true, "syswarden is not used")
	end
	-- Warm the matcher once per worker so the first request doesn't pay for building it.
	local lists = self.datastore:get("plugin_syswarden_lists", true)
	if lists then
		for _, kind in ipairs({ "blocklist", "whitelist" }) do
			local list = lists[kind]
			if list and #list > 0 then
				local matcher, merr = ipmatcher_new(list)
				if not matcher then
					self.logger:log(ERR, "can't build the " .. kind .. " matcher : " .. tostring(merr))
				end
			end
		end
	end
	return self:ret(true, "success")
end

-- Compute (and cache) the verdict for an address: "whitelisted", "blocked" or
-- "no-match". Returns nil, err on failure so callers can fail open.
function syswarden:peer_verdict(addr)
	local ok, cached = self:is_in_cache(addr)
	if not ok then
		self.logger:log(ERR, "error while checking cache : " .. cached)
	elseif classify_cache(cached) ~= "miss" then
		return cached
	end
	local verdict, err = decide(self.lists, addr, ipmatcher_new)
	if verdict == nil then
		return nil, err
	end
	local cache_ok, cache_err = self:add_to_cache(addr, verdict)
	if not cache_ok then
		self.logger:log(ERR, "error while adding element to cache : " .. cache_err)
	end
	return verdict
end

-- Shared by access() and preread(): both deny the same way, on the same verdict.
function syswarden:check(addr)
	if not self:is_needed() then
		return self:ret(true, "syswarden not activated")
	end
	-- Fail open while the lists are not loaded: an empty blocklist means the download
	-- job hasn't run yet (or the peer is down), never "deny everything".
	if lists_empty(self.lists) then
		return self:ret(true, "SysWarden lists not loaded yet, allowing")
	end
	local verdict, err = self:peer_verdict(addr)
	if verdict == nil then
		-- Fail open: never deny because of an internal error.
		self.logger:log(ERR, "error while checking " .. tostring(addr) .. " : " .. tostring(err))
		return self:ret(true, "SysWarden check error (fail open)")
	end
	if verdict == "whitelisted" then
		return self:ret(true, addr .. " is in the SysWarden whitelist")
	end
	if verdict == "blocked" then
		self:set_metric("counters", "failed_syswarden", 1)
		return self:ret(true, addr .. " is in the SysWarden blocklist", get_deny_status())
	end
	return self:ret(true, addr .. " is not in the SysWarden blocklist")
end

function syswarden:access()
	return self:check(self.ctx.bw.remote_addr)
end

function syswarden:preread()
	return self:check(self.ctx.bw.remote_addr)
end

function syswarden:is_in_cache(ele)
	local ok, data = self.cachestore_local:get(cache_key(self.ctx.bw.server_name, ele))
	if not ok then
		return false, data
	end
	return true, data
end

function syswarden:add_to_cache(ele, value)
	-- One hour: the blocklist itself refreshes hourly, so a longer TTL would keep
	-- denying an address the peer has already released.
	local ok, err = self.cachestore_local:set(cache_key(self.ctx.bw.server_name, ele), value, 3600)
	if not ok then
		return false, err
	end
	return true
end

function syswarden:api()
	if self.ctx.bw.uri == "/syswarden/ping" and self.ctx.bw.request_method == "POST" then
		local check, err = has_variable("USE_SYSWARDEN", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_SYSWARDEN (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "SysWarden plugin not enabled")
		end
		-- Report peer reachability from the cached telemetry rather than calling the HA
		-- API here: the ping then costs no extra entry in the peer's IP allowlist, and a
		-- slow or dead peer can't stall the web UI.
		local file = open(CACHE_DIR .. "telemetry.json", "r")
		if not file then
			return self:ret(true, "SysWarden telemetry not available yet", HTTP_OK)
		end
		local raw = file:read("*a")
		file:close()
		local telemetry = decode(raw or "")
		if type(telemetry) ~= "table" or type(telemetry.peers) ~= "table" then
			return self:ret(true, "SysWarden telemetry is not readable yet", HTTP_OK)
		end
		local total, reachable = 0, 0
		for _, peer in ipairs(telemetry.peers) do
			total = total + 1
			if peer.reachable then
				reachable = reachable + 1
			end
		end
		return self:ret(
			true,
			"syswarden is up (" .. tostring(reachable) .. "/" .. tostring(total) .. " peer(s) reachable)",
			HTTP_OK
		)
	end
	return self:ret(false, "success")
end

return syswarden
