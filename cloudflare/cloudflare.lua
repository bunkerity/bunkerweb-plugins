local class = require("middleclass")
local cloudflare_helpers = require("cloudflare.cloudflare_helpers")
local ipmatcher = require("resty.ipmatcher")
local plugin = require("bunkerweb.plugin")
local ssl = require("ngx.ssl")
local utils = require("bunkerweb.utils")

local cloudflare = class("cloudflare", plugin)

local ngx = ngx
local var = ngx.var
local ngx_req = ngx.req
local INFO = ngx.INFO
local WARN = ngx.WARN
local ERR = ngx.ERR
local HTTP_OK = ngx.HTTP_OK
local get_deny_status = utils.get_deny_status
local get_phase = ngx.get_phase
local parse_pem_cert = ssl.parse_pem_cert
local parse_pem_priv_key = ssl.parse_pem_priv_key
local ssl_server_name = ssl.server_name
local get_variable = utils.get_variable
local get_multiple_variables = utils.get_multiple_variables
local has_variable = utils.has_variable
local has_not_variable = utils.has_not_variable
local read_files = utils.read_files
local ipmatcher_new = ipmatcher.new
local match_trusted = cloudflare_helpers.match_trusted
local classify_cache = cloudflare_helpers.classify_cache
local parse_additional = cloudflare_helpers.parse_additional
local cache_key = cloudflare_helpers.cache_key
local trusted_list_empty = cloudflare_helpers.trusted_list_empty
local clear_header = ngx_req.clear_header
local tostring = tostring
local ipairs = ipairs
local insert = table.insert
local open = io.open

-- Client-supplied request headers that an upstream might trust as coming from
-- Cloudflare. Stripped when the connection is NOT from a trusted Cloudflare IP
-- (CLOUDFLARE_STRIP_SPOOFED_HEADERS) so a direct-to-origin attacker can't spoof them.
local CF_HEADERS = {
	"CF-Connecting-IP",
	"CF-Connecting-IPv6",
	"True-Client-IP",
	"CF-IPCountry",
	"CF-RAY",
	"CF-Visitor",
	"CF-Worker",
}

-- Strip client-supplied Cloudflare headers (defence-in-depth when the peer is not a
-- trusted Cloudflare IP). Module-local: it needs no instance state.
local function strip_cf_headers()
	for _, header in ipairs(CF_HEADERS) do
		clear_header(header)
	end
end

function cloudflare:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "cloudflare", ctx)
	-- Decode trusted_ips — only in request phases that actually consume it (access/preread).
	-- self.is_request gates out init/ssl_certificate/etc., avoiding a per-handshake build.
	if get_phase() ~= "init" and self.is_request and self:is_needed() then
		local trusted_ips, err = self.datastore:get("plugin_cloudflare_trusted_ips", true)
		if not trusted_ips then
			self.logger:log(ERR, err)
			trusted_ips = {}
		end
		-- Build a FRESH per-request table. self.datastore:get(key, true) returns the
		-- worker-LRU table by reference, so the read-only ipv4/ipv6 lists may be shared,
		-- but "additional" (from the multisite CLOUDFLARE_ADDITIONAL_TRUSTED_FROM setting)
		-- MUST be rebuilt each request — mutating the shared table would leak memory and
		-- bleed one service's additional IPs into every other service.
		self.trusted_ips = {
			ipv4 = trusted_ips.ipv4 or {},
			ipv6 = trusted_ips.ipv6 or {},
			additional = parse_additional(self.variables["CLOUDFLARE_ADDITIONAL_TRUSTED_FROM"]),
		}
	end
end

function cloudflare:is_needed()
	-- Loading case
	if self.is_loading then
		return false
	end
	-- Request phases
	if self.is_request and (self.ctx.bw.server_name ~= "_") then
		return self.variables["USE_CLOUDFLARE"] == "yes"
	end
	-- Other cases : at least one service uses it
	local is_needed, err = has_variable("USE_CLOUDFLARE", "yes")
	if is_needed == nil then
		self.logger:log(ERR, "can't check USE_CLOUDFLARE variable : " .. err)
	end
	return is_needed
end

function cloudflare:set()
	-- Check if set is needed
	if not self:is_needed() then
		return self:ret(true, "set not needed")
	end
	local https_configured = "no"
	-- Only advertise HTTPS as configured once an origin certificate is actually
	-- loaded for this server, otherwise BunkerWeb may enable a TLS vhost with no
	-- usable certificate until the daily cert job catches up.
	if self.variables["CLOUDFLARE_API_TOKEN"] ~= "" and self.variables["CLOUDFLARE_MANAGE_ORIGIN_CERTS"] == "yes" then
		local data = self.internalstore:get("plugin_cloudflare_" .. self.ctx.bw.server_name, true)
		if data then
			https_configured = "yes"
			self.ctx.bw.https_configured = "yes"
		end
	end
	return self:ret(true, "set https_configured to " .. https_configured)
end

function cloudflare:init()
	-- Check if init is needed
	if not self:is_needed() then
		return self:ret(true, "init not needed")
	end
	-- Read trusted_ips downloaded by cf-trusted-ips-download.py. "additional" comes
	-- from the CLOUDFLARE_ADDITIONAL_TRUSTED_FROM setting (parsed per-request), no job
	-- writes an additional.list, so only ipv4/ipv6 are read from disk here.
	local trusted_ips = {
		["ipv4"] = {},
		["ipv6"] = {},
		["additional"] = {},
	}
	local i = 0
	for _, kind in ipairs({ "ipv4", "ipv6" }) do
		local f = open("/var/cache/bunkerweb/cloudflare/" .. kind .. ".list", "r")
		if f then
			for line in f:lines() do
				insert(trusted_ips[kind], line)
				i = i + 1
			end
			f:close()
		end
	end
	-- Load them into datastore
	local ok, err = self.datastore:set("plugin_cloudflare_trusted_ips", trusted_ips, nil, true)
	if not ok then
		return self:ret(false, "can't store cloudflare trusted IPs list into datastore : " .. err)
	end
	self.logger:log(INFO, "successfully loaded " .. tostring(i) .. " IP/network")

	local ret_ok, ret_err = true, "success"
	if
		has_variable("USE_CLOUDFLARE", "yes")
		and has_not_variable("CLOUDFLARE_API_TOKEN", "")
		and has_variable("CLOUDFLARE_MANAGE_ORIGIN_CERTS", "yes")
	then
		local multisite
		multisite, err = get_variable("MULTISITE", false)
		if not multisite then
			return self:ret(false, "can't get MULTISITE variable : " .. err)
		end
		if multisite == "yes" then
			local vars
			vars, err = get_multiple_variables({
				"SERVER_NAME",
				"USE_CLOUDFLARE",
				"CLOUDFLARE_API_TOKEN",
				"CLOUDFLARE_MANAGE_ORIGIN_CERTS",
			})
			if not vars then
				return self:ret(false, "can't get SERVER_NAME variable : " .. err)
			end
			for server_name, multisite_vars in pairs(vars) do
				if
					multisite_vars["USE_CLOUDFLARE"] == "yes"
					and multisite_vars["CLOUDFLARE_API_TOKEN"] ~= ""
					and multisite_vars["CLOUDFLARE_MANAGE_ORIGIN_CERTS"] == "yes"
					and server_name ~= "global"
				then
					local check, data = read_files({
						"/var/cache/bunkerweb/cloudflare/" .. server_name .. "/origin_cert.pem",
						"/var/cache/bunkerweb/cloudflare/" .. server_name .. "/private.key",
					})
					if not check then
						self.logger:log(ERR, "error while reading files : " .. data)
						ret_ok = false
						ret_err = "error reading files"
					else
						check, err = self:load_data(data, multisite_vars["SERVER_NAME"])
						if not check then
							self.logger:log(ERR, "error while loading data : " .. err)
							ret_ok = false
							ret_err = "error loading data"
						end
					end
				end
			end
		else
			local server_name
			server_name, err = get_variable("SERVER_NAME", false)
			if not server_name then
				return self:ret(false, "can't get SERVER_NAME variable : " .. err)
			end
			local check, data = read_files({
				"/var/cache/bunkerweb/cloudflare/" .. server_name:match("%S+") .. "/origin_cert.pem",
				"/var/cache/bunkerweb/cloudflare/" .. server_name:match("%S+") .. "/private.key",
			})
			if not check then
				self.logger:log(ERR, "error while reading files : " .. data)
				ret_ok = false
				ret_err = "error reading files"
			else
				check, err = self:load_data(data, server_name)
				if not check then
					self.logger:log(ERR, "error while loading data : " .. err)
					ret_ok = false
					ret_err = "error loading data"
				end
			end
		end
	else
		ret_err = "cloudflare is not used"
	end
	return self:ret(ret_ok, ret_err)
end

function cloudflare:ssl_certificate()
	local server_name, err = ssl_server_name()
	if not server_name then
		-- No SNI is normal (ngx.ssl.server_name() returns nil, nil); don't nil-concat.
		if err then
			return self:ret(false, "can't get server_name : " .. err)
		end
		return self:ret(true, "no SNI provided")
	end
	local data
	data, err = self.internalstore:get("plugin_cloudflare_" .. server_name, true)
	if not data and err ~= "not found" then
		return self:ret(
			false,
			"error while getting plugin_cloudflare_" .. server_name .. " from internalstore : " .. err
		)
	elseif data then
		return self:ret(true, "certificate/key data found", data)
	end
	return self:ret(true, "cloudflare is not used")
end

function cloudflare:load_data(data, server_name)
	-- Load certificate
	local cert_chain, err = parse_pem_cert(data[1])
	if not cert_chain then
		return false, "error while parsing pem cert : " .. err
	end
	-- Load key
	local priv_key
	priv_key, err = parse_pem_priv_key(data[2])
	if not priv_key then
		return false, "error while parsing pem priv key : " .. err
	end
	-- Cache parsed cert/key in the internalstore (worker-local, like the letsencrypt
	-- core plugin) so private keys never reach the API-exposed datastore.
	for key in server_name:gmatch("%S+") do
		local ok
		ok, err = self.internalstore:set("plugin_cloudflare_" .. key, { cert_chain, priv_key }, nil, true)
		if not ok then
			return false, "error while setting data into internalstore : " .. err
		end
	end
	return true
end

-- Compute (and cache) the trust verdict for an address: "ipv4"/"ipv6"/"additional"
-- when trusted, "ko" when not. Returns nil, err on failure (callers fail open).
function cloudflare:peer_trust(addr)
	local ok, cached = self:is_in_cache(addr)
	if not ok then
		self.logger:log(ERR, "error while checking cache : " .. cached)
	elseif classify_cache(cached) ~= "miss" then
		return cached
	end
	if not self.trusted_ips then
		return nil, "trusted_ips is nil"
	end
	local trusted, kind_or_err = match_trusted(self.trusted_ips, addr, ipmatcher_new)
	if trusted == nil then
		return nil, kind_or_err
	end
	local verdict = kind_or_err -- "ipv4"/"ipv6"/"additional" or "ko"
	local err
	ok, err = self:add_to_cache(addr, verdict)
	if not ok then
		self.logger:log(ERR, "error while adding element to cache : " .. err)
	end
	return verdict
end

function cloudflare:access()
	-- Check if access is needed
	if not self:is_needed() then
		return self:ret(true, "cloudflare not activated")
	end

	-- Authenticated Origin Pulls (mTLS) — HTTP only. The connection only verifies when it
	-- came through Cloudflare's network presenting its origin-pull client certificate.
	-- Skipped when the core mTLS plugin owns the handshake (USE_MTLS=yes) — otherwise
	-- $ssl_client_verify reflects *its* CA, not Cloudflare's, which would mis-judge here
	-- (matches the gating in confs/server-http/cloudflare-ssl.conf). USE_MTLS is the core
	-- mTLS plugin's own setting, so it's NOT in self.variables — read it request-scoped.
	if
		self.variables["CLOUDFLARE_AUTHENTICATED_ORIGIN_PULLS"] == "yes"
		and (get_variable("USE_MTLS", true, self.ctx)) ~= "yes"
	then
		local verify = var.ssl_client_verify
		-- An empty/nil verify means ssl_verify_client wasn't emitted (the origin-pull CA
		-- hasn't been downloaded yet by cf-aop-ca-download.py): fail OPEN so we never deny
		-- everyone while not ready. "NONE"/"FAILED:*" means the CA IS wired and the peer
		-- presented no / an invalid client cert — that is a genuine non-Cloudflare origin.
		if verify == nil or verify == "" then
			self.logger:log(
				WARN,
				"Authenticated Origin Pulls enabled but the origin-pull CA isn't loaded yet, not enforcing"
			)
		elseif verify ~= "SUCCESS" then
			self:set_metric("counters", "failed_cloudflare_aop", 1)
			if self.variables["CLOUDFLARE_AOP_MODE"] == "enforce" then
				return self:ret(
					true,
					"connection did not present a valid Cloudflare client certificate (ssl_client_verify="
						.. verify
						.. ")",
					get_deny_status()
				)
			end
			self.logger:log(
				WARN,
				"Authenticated Origin Pulls: ssl_client_verify=" .. verify .. " (log mode, request allowed)"
			)
		end
	end

	-- Trust verdict is needed for the deny feature and/or header stripping.
	local deny = self.variables["CLOUDFLARE_DENY_NON_TRUSTED_IPS"] == "yes"
	local strip = self.variables["CLOUDFLARE_STRIP_SPOOFED_HEADERS"] == "yes"
	if not deny and not strip then
		return self:ret(true, "cloudflare trust check not needed")
	end

	-- Fail open until the trusted ranges have loaded, so we never deny everyone (or
	-- cache a bogus "ko" for a legitimate IP) during the brief window before the
	-- cf-trusted-ips-download.py job has populated the list.
	if trusted_list_empty(self.trusted_ips) then
		return self:ret(true, "cloudflare trusted IP list not loaded yet, allowing")
	end

	local realip_remote_addr = var.realip_remote_addr
	local verdict, err = self:peer_trust(realip_remote_addr)
	if verdict == nil then
		-- Fail open: never deny because of an internal error.
		self.logger:log(
			ERR,
			"error while checking if " .. tostring(realip_remote_addr) .. " is trusted : " .. tostring(err)
		)
		return self:ret(true, "trust check error (fail open)")
	end

	local trusted = verdict ~= "ko"
	if strip and not trusted then
		strip_cf_headers()
	end
	if deny and not trusted then
		self:set_metric("counters", "failed_cloudflare_trust", 1)
		return self:ret(true, realip_remote_addr .. " is not trusted", get_deny_status())
	end
	if trusted then
		return self:ret(true, realip_remote_addr .. " is trusted (type : " .. verdict .. ")")
	end
	return self:ret(true, "cloudflare access checks passed")
end

function cloudflare:preread()
	-- Check if access is needed
	if not self:is_needed() then
		return self:ret(true, "cloudflare not activated")
	end
	-- Stream only enforces the IP trust check (no headers / no mTLS in preread).
	if self.variables["CLOUDFLARE_DENY_NON_TRUSTED_IPS"] ~= "yes" then
		return self:ret(true, "cloudflare trust check not needed")
	end
	-- Fail open until the trusted ranges have loaded (see access()).
	if trusted_list_empty(self.trusted_ips) then
		return self:ret(true, "cloudflare trusted IP list not loaded yet, allowing")
	end
	local realip_remote_addr = var.realip_remote_addr
	local verdict, err = self:peer_trust(realip_remote_addr)
	if verdict == nil then
		self.logger:log(
			ERR,
			"error while checking if " .. tostring(realip_remote_addr) .. " is trusted : " .. tostring(err)
		)
		return self:ret(true, "trust check error (fail open)")
	end
	if verdict == "ko" then
		self:set_metric("counters", "failed_cloudflare_trust", 1)
		return self:ret(true, realip_remote_addr .. " is not trusted", get_deny_status())
	end
	return self:ret(true, realip_remote_addr .. " is trusted (type : " .. verdict .. ")")
end

function cloudflare:is_in_cache(ele)
	local ok, data = self.cachestore_local:get(cache_key(self.ctx.bw.server_name, ele))
	if not ok then
		return false, data
	end
	return true, data
end

function cloudflare:add_to_cache(ele, value)
	local ok, err = self.cachestore_local:set(cache_key(self.ctx.bw.server_name, ele), value, 86400)
	if not ok then
		return false, err
	end
	return true
end

function cloudflare:api()
	if self.ctx.bw.uri == "/cloudflare/ping" and self.ctx.bw.request_method == "POST" then
		local check, err = has_variable("USE_CLOUDFLARE", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_CLOUDFLARE (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "Cloudflare plugin not enabled")
		end
		-- Report how many trusted Cloudflare ranges are loaded (proves the download
		-- job ran and the lists made it into the datastore).
		local data = self.datastore:get("plugin_cloudflare_trusted_ips", true)
		local n4 = (data and data.ipv4) and #data.ipv4 or 0
		local n6 = (data and data.ipv6) and #data.ipv6 or 0
		return self:ret(
			true,
			"cloudflare is up (trusted ranges: " .. tostring(n4) .. " IPv4, " .. tostring(n6) .. " IPv6)",
			HTTP_OK
		)
	end
	return self:ret(false, "success")
end

return cloudflare
