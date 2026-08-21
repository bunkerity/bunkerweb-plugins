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
local decide = syswarden_helpers.decide
local list_sizes = syswarden_helpers.list_sizes
local matchers_empty = syswarden_helpers.matchers_empty
local request_enabled = syswarden_helpers.request_enabled
local decode = cjson.decode
local tostring = tostring
local ipairs = ipairs
local insert = table.insert
local open = io.open

-- Where syswarden-blocklist-download.py and syswarden-telemetry-poll.py leave their
-- output. The scheduler ships this directory to every BunkerWeb instance, which is how
-- a job running in the scheduler container reaches the Lua code in another one.
local CACHE_DIR = "/var/cache/bunkerweb/syswarden/"

-- Per-worker compiled state. Reloads create new workers, so a changed downloaded list is
-- visible immediately without a stale per-address verdict cache.
local worker_matchers = {}
local worker_matcher_errors = {}
local worker_built = false

-- Compile the cached lists into matchers for the worker running this Lua VM.
--
-- BunkerWeb runs init_worker() **once per instance, not once per worker**: the phase is
-- gated behind a shared "misc_ready" flag taken under a lock, so the first worker to grab
-- it runs every plugin's init_worker() and all the others skip it. Building the matchers
-- there alone left every other worker with an empty table, and since nginx hands a new
-- connection to whichever worker wins the accept race, a blocked address was denied or
-- allowed depending on which worker answered. Hence the lazy build below, on the first
-- request each worker serves.
local function build_matchers(datastore, logger)
	local lists = datastore:get("plugin_syswarden_lists", true)
	if not lists then
		-- init() has not stored anything yet. Stay unbuilt and retry on the next request
		-- rather than caching an empty verdict for the worker's whole lifetime.
		return
	end
	worker_matchers = {}
	worker_matcher_errors = {}
	worker_built = true
	for _, kind in ipairs({ "blocklist", "whitelist" }) do
		local list = lists[kind]
		if list and #list > 0 then
			local matcher, merr = ipmatcher_new(list)
			if not matcher then
				worker_matcher_errors[kind] = merr
				logger:log(ERR, "can't build the " .. kind .. " matcher : " .. tostring(merr))
			else
				worker_matchers[kind] = matcher
			end
		end
	end
end

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
	-- Request instances only select the per-service matchers: the expensive constructors
	-- run once per worker, and these tables are read-only for the worker lifetime after that.
	if get_phase() ~= "init" and self.is_request and self:is_needed() then
		if not worker_built then
			build_matchers(self.datastore, self.logger)
		end
		self.matchers = {
			blocklist = self.variables["USE_SYSWARDEN_BLOCKLIST"] == "yes" and worker_matchers.blocklist or nil,
			whitelist = self.variables["USE_SYSWARDEN_WHITELIST"] == "yes" and worker_matchers.whitelist or nil,
		}
		self.matcher_errors = {
			blocklist = self.variables["USE_SYSWARDEN_BLOCKLIST"] == "yes" and worker_matcher_errors.blocklist or nil,
			whitelist = self.variables["USE_SYSWARDEN_WHITELIST"] == "yes" and worker_matcher_errors.whitelist or nil,
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
		return request_enabled(
			self.variables["USE_SYSWARDEN"],
			self.variables["USE_SYSWARDEN_BLOCKLIST"],
			self.variables["USE_SYSWARDEN_WHITELIST"]
		)
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
	-- Warms the one worker this phase actually runs in; every other worker builds its own
	-- matchers on its first request. Compiling once per worker matters because a
	-- high-cardinality request stream must never rebuild a list.
	build_matchers(self.datastore, self.logger)
	return self:ret(true, "success")
end

-- Compute the verdict for an address through the worker's precompiled matchers.
-- Returns nil, err on failure so callers can fail open.
function syswarden:peer_verdict(addr)
	return decide(self.matchers, self.matcher_errors, addr)
end

-- Shared by access() and preread(): both deny the same way, on the same verdict.
function syswarden:check(addr)
	if not self:is_needed() then
		return self:ret(true, "syswarden not activated")
	end
	-- Fail open while the lists are not loaded: an empty blocklist means the download
	-- job hasn't run yet (or the peer is down), never "deny everything".
	if
		matchers_empty(self.matchers)
		and not (self.matcher_errors and (self.matcher_errors.blocklist or self.matcher_errors.whitelist))
	then
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
