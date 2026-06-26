local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local sentinelone_helpers = require("sentinelone.sentinelone_helpers")
local sha1 = require("resty.sha1")
local str = require("resty.string")
local upload = require("resty.upload")
local utils = require("bunkerweb.utils")

local sentinelone = class("sentinelone", plugin)

local ngx = ngx
local ngx_req = ngx.req
local NOTICE = ngx.NOTICE
local ERR = ngx.ERR
local WARN = ngx.WARN
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_OK = ngx.HTTP_OK
local to_hex = str.to_hex
local http_new = http.new
local has_variable = utils.has_variable
local get_deny_status = utils.get_deny_status
local tostring = tostring
local decode = cjson.decode
local encode = cjson.encode
local open = io.open

local read_all = function(form)
	while true do
		local typ = form:read()
		if not typ then
			return
		end
		if typ == "eof" then
			return
		end
	end
end

-- Read the full request body for the HTTP/2 / HTTP/3 buffered path in a way that
-- never crashes the worker. Returns (body, nil) on success or (nil, reason) when
-- the body can't be read - the caller then allows the upload through unscanned and
-- logged, the same best-effort stance as other un-scannable uploads. Mirrors
-- BunkerWeb core's crowdsec bouncer get_body(): ngx.req.read_body() reads the body
-- on every HTTP version (it does not require Content-Length), but it can raise a
-- Lua error on a read failure, so it is pcall'd rather than guarded - that both
-- maximizes what we can scan (e.g. streamed HTTP/2 uploads) and prevents a 500.
-- When the body spilled to a temp file (larger than client_body_buffer_size)
-- get_body_data() returns nil and we read the file (blocking, but it is already on
-- local disk).
local read_request_body = function()
	local ok, err = pcall(ngx_req.read_body)
	if not ok then
		return nil, "read_body() failed : " .. tostring(err)
	end
	local body = ngx_req.get_body_data()
	if not body then
		local path = ngx_req.get_body_file()
		if path then
			local handle = open(path, "rb")
			if handle then
				body = handle:read("*a")
				handle:close()
			end
		end
	end
	return body
end

function sentinelone:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "sentinelone", ctx)
end

function sentinelone:init_worker()
	-- Check if worker is needed
	local init_needed, err = has_variable("USE_SENTINELONE", "yes")
	if init_needed == nil then
		return self:ret(false, "can't check USE_SENTINELONE variable : " .. err)
	end
	if not init_needed or self.is_loading then
		return self:ret(true, "init_worker not needed")
	end
	-- Without an API URL and token there is nothing to validate; skip quietly so a
	-- not-yet-configured plugin does not spam connectivity errors at startup.
	if self.variables["SENTINELONE_API_URL"] == "" or self.variables["SENTINELONE_API_TOKEN"] == "" then
		return self:ret(true, "SentinelOne not configured, skipping connectivity check")
	end
	-- Validate URL + token + reachability against a cheap, always-on endpoint.
	local ok, data = self:request("/system/info")
	if not ok then
		return self:ret(false, "connectivity with the SentinelOne API failed : " .. tostring(data))
	end
	self.logger:log(NOTICE, "connectivity with the SentinelOne API is successful")
	return self:ret(true, "success")
end

function sentinelone:access()
	-- Check if enabled
	if
		self.variables["USE_SENTINELONE"] ~= "yes"
		or (self.variables["SENTINELONE_SCAN_IP"] ~= "yes" and self.variables["SENTINELONE_SCAN_FILE"] ~= "yes")
	then
		return self:ret(true, "sentinelone plugin not enabled")
	end

	-- Config guard : without an API URL and token there is nothing to query, so skip
	-- (allow) rather than failing every request. SentinelOne has no public default.
	if self.variables["SENTINELONE_API_URL"] == "" or self.variables["SENTINELONE_API_TOKEN"] == "" then
		self.logger:log(WARN, "SENTINELONE_API_URL or SENTINELONE_API_TOKEN is not set; skipping SentinelOne checks")
		return self:ret(true, "sentinelone not configured")
	end

	-- IP check
	if self.variables["SENTINELONE_SCAN_IP"] == "yes" and self.ctx.bw.ip_is_global then
		local ok, report = self:check_ip()
		if not ok then
			return self:ret(false, "error while checking if IP is malicious : " .. report)
		end
		if report and report ~= "clean" then
			return self:ret(
				true,
				"IP " .. self.ctx.bw.remote_addr .. " is malicious : " .. report,
				get_deny_status(),
				nil,
				{
					id = "ip",
					report = report,
				}
			)
		end
	end

	-- File check
	if self.variables["SENTINELONE_SCAN_FILE"] == "yes" then
		-- Check if we have downloads
		if
			not self.ctx.bw.http_content_type
			or (
				not self.ctx.bw.http_content_type:match("boundary")
				or not self.ctx.bw.http_content_type:match("multipart/form%-data")
			)
		then
			return self:ret(true, "no file upload detected")
		end
		-- Perform the check
		local ok, detected, checksum = self:check_file()
		if not ok then
			return self:ret(false, "error while checking if file is malicious : " .. detected)
		end
		-- Malicious case
		if detected and detected ~= "clean" then
			return self:ret(
				true,
				"file with checksum " .. checksum .. " is detected : " .. detected,
				get_deny_status(),
				nil,
				{
					id = "file",
					checksum = checksum,
					detected = detected,
				}
			)
		end
	end
	return self:ret(true, "no ip/file detected")
end

function sentinelone:check_ip()
	-- Check cache
	local ok, report = self:is_in_cache("ip_" .. self.ctx.bw.remote_addr)
	if not ok then
		return false, report
	end
	if report then
		return true, report
	end
	-- Ask the SentinelOne threat-intelligence IOC database. IPv6 addresses carry a
	-- ":" which IPv4 dotted-quads never do, so it is a reliable type discriminator.
	local ioc_type = self.ctx.bw.remote_addr:find(":", 1, true) and "ipv6" or "ipv4"
	local found, response
	ok, found, response =
		self:request("/threat-intelligence/iocs", { type = ioc_type, value = self.ctx.bw.remote_addr })
	if not ok then
		return false, response
	end
	local result = "clean"
	if found and sentinelone_helpers.is_malicious(response) then
		result = "listed as a SentinelOne IOC"
	end
	-- Add to cache
	local err
	ok, err = self:add_to_cache("ip_" .. self.ctx.bw.remote_addr, result)
	if not ok then
		return false, err
	end
	return true, result
end

function sentinelone:check_file()
	-- resty.upload reads the raw request socket, which is unavailable on HTTP/2 /
	-- HTTP/3 (ngx.req.socket() raises "http v2 not supported yet"). Use the
	-- buffered fallback there so the upload is still scanned instead of 500ing.
	if sentinelone_helpers.is_http2_plus(self.ctx.bw.http_version, ngx.var.server_protocol) then
		return self:check_file_buffered()
	end
	-- Loop on files
	local ok_new, form, new_err = pcall(upload.new, upload, 4096, 512, true)
	if not ok_new then
		-- Belt-and-suspenders: any unexpected raw-socket error still degrades to
		-- the buffered path rather than bubbling up as a 500 (form holds the raised message).
		self.logger:log(WARN, "resty.upload raised an error (" .. tostring(form) .. "); falling back to buffered scan")
		return self:check_file_buffered()
	end
	if not form then
		self.logger:log(WARN, "resty.upload unavailable (" .. tostring(new_err) .. "); falling back to buffered scan")
		return self:check_file_buffered()
	end
	local err
	local sha = sha1:new()
	local processing = nil
	while true do
		-- Read part
		local typ, res
		typ, res, err = form:read()
		if not typ then
			return false, "form:read() failed : " .. err
		end
		-- Header case : check if we have a filename
		if typ == "header" then
			local found = false
			for _, header in ipairs(res) do
				-- Match the filename parameter in any RFC 7578 / 2183 form: quoted
				-- (filename="x"), unquoted (filename=x) and RFC 5987 extended
				-- (filename*=...). %f[%a] anchors on a parameter boundary so form
				-- fields like name="myfilename" don't match. Same matcher as the
				-- buffered path (sentinelone_helpers.parse_multipart) and ClamAV.
				if header:find("%f[%a]filename%*?%s*=") then
					found = true
					break
				end
			end
			if found then
				processing = true
			end
			-- Body case : update checksum
		elseif typ == "body" and processing then
			sha:update(res)
			-- Part end case : get final checksum and SentinelOne result
		elseif typ == "part_end" and processing then
			processing = nil
			-- Compute checksum
			local checksum = to_hex(sha:final())
			sha:reset()
			local ok, verdict = self:check_checksum(checksum)
			if not ok then
				read_all(form)
				return false, verdict
			end
			-- Stop here if one file is detected
			if verdict ~= "clean" then
				read_all(form)
				return true, verdict, checksum
			end
			-- End of body case : no file detected
		elseif typ == "eof" then
			return true
		end
	end
	-- luacheck: ignore 511
	return false, "malformed content"
end

-- Resolve a file checksum to a verdict ("clean" or a detection summary). Shared by
-- the streaming and buffered paths. Returns (ok, verdict|error).
function sentinelone:check_checksum(checksum)
	local ok, cached = self:is_in_cache("file_" .. checksum)
	if not ok then
		-- Fail-open on a cache-backend error, mirroring the streaming path.
		self.logger:log(ERR, "can't check if file with checksum " .. checksum .. " is in cache : " .. cached)
		return true, "clean"
	end
	if cached then
		return true, cached
	end
	-- Look the SHA1 up in SentinelOne's hash reputation.
	local found, response
	ok, found, response = self:request("/hashes/" .. checksum .. "/reputation")
	if not ok then
		return false, found
	end
	local result = "clean"
	if found then
		result = self:get_result(response)
	end
	local err
	ok, err = self:add_to_cache("file_" .. checksum, result)
	if not ok then
		return false, err
	end
	return true, result
end

-- HTTP/2 / HTTP/3 fallback for check_file(): buffer the body (memory or the nginx
-- temp file for large uploads) and parse the multipart parts ourselves, since
-- resty.upload cannot read the raw request socket on these protocols.
function sentinelone:check_file_buffered()
	local body, err = read_request_body()
	if not body then
		-- Can't read the body (e.g. chunked HTTP/2 upload) -> nothing we can scan;
		-- allow it through, best-effort.
		if err then
			self.logger:log(WARN, "can't read request body to scan upload (" .. err .. "); upload not scanned")
		end
		return true
	end
	local boundary = sentinelone_helpers.get_boundary(self.ctx.bw.http_content_type)
	if not boundary then
		return true
	end
	local parts = sentinelone_helpers.parse_multipart(body, boundary)
	for _, part in ipairs(parts) do
		local sha = sha1:new()
		sha:update(part.content)
		local checksum = to_hex(sha:final())
		local ok, verdict = self:check_checksum(checksum)
		if not ok then
			return false, verdict
		end
		if verdict ~= "clean" then
			return true, verdict, checksum
		end
	end
	return true
end

function sentinelone:get_result(response)
	-- Threshold evaluation lives in sentinelone/sentinelone_helpers.lua so it can be
	-- unit-tested with busted outside OpenResty (see spec/sentinelone_helpers_spec.lua).
	return sentinelone_helpers.evaluate(response.rank, tonumber(self.variables["SENTINELONE_FILE_RANK"]))
end

function sentinelone:is_in_cache(key)
	local ok, data = self.cachestore:get("plugin_sentinelone_" .. key)
	if not ok then
		return false, data
	end
	return true, data
end

function sentinelone:add_to_cache(key, value)
	local ok, err = self.cachestore:set("plugin_sentinelone_" .. key, value, 86400)
	if not ok then
		return false, err
	end
	return true
end

-- Perform a GET against the SentinelOne API. `query` is an optional table of query
-- arguments (lua-resty-http URL-encodes it). Returns:
--   (false, err)            on any transport / non-2xx / malformed-JSON error
--   (true, false)           on a 404 (unknown hash / nothing found) -> treat as clean
--   (true, true, data.data) on a 200 (data.data is an object for hash reputation,
--                           an array for the IOC endpoint; the caller interprets it)
function sentinelone:request(path, query)
	-- Get object
	local httpc, err = http_new()
	if not httpc then
		return false, err
	end
	-- Set timeouts for connect, send, and read
	local timeout = tonumber(self.variables["SENTINELONE_TIMEOUT"]) or 1000
	httpc:set_timeouts(timeout, timeout, timeout)
	-- Build the base URL (per-tenant, no public default)
	local base_url = self.variables["SENTINELONE_API_URL"]
	if base_url == nil or base_url == "" then
		return false, "SENTINELONE_API_URL is not configured"
	end
	-- Strip trailing slash(es) so base_url .. "/hashes/..." never doubles the slash.
	while base_url:sub(-1) == "/" do
		base_url = base_url:sub(1, -2)
	end
	local res
	res, err = httpc:request_uri(base_url .. path, {
		headers = {
			["Authorization"] = "ApiToken " .. (self.variables["SENTINELONE_API_TOKEN"] or ""),
		},
		query = query,
	})
	if not res then
		return false, err
	end
	-- Check status
	if res.status == 404 then
		return true, false
	end
	if res.status ~= 200 then
		err = "received status " .. tostring(res.status) .. " from the SentinelOne API"
		local ok, data = pcall(decode, res.body)
		if ok then
			err = err .. " with data " .. encode(data)
		end
		return false, err
	end
	-- Get result
	local ok, data = pcall(decode, res.body)
	if not ok then
		return false, data
	end
	-- All three endpoints wrap the payload in a "data" field that is a table (an
	-- object for hash reputation / system info, an array for the IOC endpoint).
	-- Require a table so a missing field or a JSON null (cjson's truthy sentinel)
	-- fails open cleanly here instead of erroring later when the caller indexes it.
	if type(data.data) ~= "table" then
		return false, "malformed json response"
	end
	return true, true, data.data
end

function sentinelone:api()
	if self.ctx.bw.uri == "/sentinelone/ping" and self.ctx.bw.request_method == "POST" then
		-- Check SentinelOne connection
		local check, err = has_variable("USE_SENTINELONE", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_SENTINELONE (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "SentinelOne plugin not enabled")
		end

		-- Probe the always-on system/info endpoint to confirm URL + token + reachability.
		local ok, found, response = self:request("/system/info")
		if not ok then
			return self:ret(true, "error while contacting the SentinelOne API : " .. found, HTTP_INTERNAL_SERVER_ERROR)
		end
		if not found then
			return self:ret(
				true,
				"unexpected response from the SentinelOne API (system/info not found)",
				HTTP_INTERNAL_SERVER_ERROR
			)
		end
		return self:ret(true, "successfully contacted the SentinelOne API, response: " .. encode(response), HTTP_OK)
	end
	return self:ret(false, "success")
end

return sentinelone
