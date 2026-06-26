local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local sha256 = require("resty.sha256")
local str = require("resty.string")
local upload = require("resty.upload")
local utils = require("bunkerweb.utils")
local virustotal_helpers = require("virustotal.virustotal_helpers")

local virustotal = class("virustotal", plugin)

local ngx = ngx
local ngx_req = ngx.req
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

function virustotal:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "virustotal", ctx)
end

-- Todo : find a "ping" endpoint on VT API
-- function virustotal:init_worker()
-- end

function virustotal:access()
	-- Check if enabled
	if
		self.variables["USE_VIRUSTOTAL"] ~= "yes"
		or (self.variables["VIRUSTOTAL_SCAN_IP"] ~= "yes" and self.variables["VIRUSTOTAL_SCAN_FILE"] ~= "yes")
	then
		return self:ret(true, "virustotal plugin not enabled")
	end

	-- IP check
	if self.variables["VIRUSTOTAL_SCAN_IP"] == "yes" and self.ctx.bw.ip_is_global then
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
	if self.variables["VIRUSTOTAL_SCAN_FILE"] == "yes" then
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
				"file with checksum " .. checksum .. "is detected : " .. detected,
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

function virustotal:check_ip()
	-- Check cache
	local ok, report = self:is_in_cache("ip_" .. self.ctx.bw.remote_addr)
	if not ok then
		return false, report
	end
	if report then
		return true, report
	end
	-- Ask VT API
	local found, response
	ok, found, response = self:request("/ip_addresses/" .. self.ctx.bw.remote_addr)
	if not ok then
		return false, response
	end
	local result = "clean"
	if found then
		result = self:get_result(response, "IP")
	end
	-- Add to cache
	local err
	ok, err = self:add_to_cache("ip_" .. self.ctx.bw.remote_addr, result)
	if not ok then
		return false, err
	end
	return true, result
end

function virustotal:check_file()
	-- resty.upload reads the raw request socket, which is unavailable on HTTP/2 /
	-- HTTP/3 (ngx.req.socket() raises "http v2 not supported yet"). Use the
	-- buffered fallback there so the upload is still scanned instead of 500ing.
	if virustotal_helpers.is_http2_plus(self.ctx.bw.http_version, ngx.var.server_protocol) then
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
	local sha = sha256:new()
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
				-- buffered path (virustotal_helpers.parse_multipart) and ClamAV.
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
			-- Part end case : get final checksum and VT result
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
function virustotal:check_checksum(checksum)
	local ok, cached = self:is_in_cache("file_" .. checksum)
	if not ok then
		-- Fail-open on a cache-backend error, mirroring the streaming path.
		self.logger:log(ERR, "can't check if file with checksum " .. checksum .. " is in cache : " .. cached)
		return true, "clean"
	end
	if cached then
		return true, cached
	end
	-- Check if the file is already known to VirusTotal.
	local found, response
	ok, found, response = self:request("/files/" .. checksum)
	if not ok then
		return false, found
	end
	local result = "clean"
	if found then
		result = self:get_result(response, "FILE")
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
function virustotal:check_file_buffered()
	local body, err = read_request_body()
	if not body then
		-- Can't read the body (e.g. chunked HTTP/2 upload) -> nothing we can scan;
		-- allow it through, best-effort.
		if err then
			self.logger:log(WARN, "can't read request body to scan upload (" .. err .. "); upload not scanned")
		end
		return true
	end
	local boundary = virustotal_helpers.get_boundary(self.ctx.bw.http_content_type)
	if not boundary then
		return true
	end
	local parts = virustotal_helpers.parse_multipart(body, boundary)
	for _, part in ipairs(parts) do
		local sha = sha256:new()
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

function virustotal:get_result(response, type)
	-- Threshold evaluation lives in virustotal/virustotal_helpers.lua so it can be
	-- unit-tested with busted outside OpenResty (see spec/virustotal_helpers_spec.lua).
	return virustotal_helpers.evaluate(
		response["suspicious"],
		response["malicious"],
		tonumber(self.variables["VIRUSTOTAL_" .. type .. "_SUSPICIOUS"]),
		tonumber(self.variables["VIRUSTOTAL_" .. type .. "_MALICIOUS"])
	)
end

function virustotal:is_in_cache(key)
	local ok, data = self.cachestore:get("plugin_virustotal_" .. key)
	if not ok then
		return false, data
	end
	return true, data
end

function virustotal:add_to_cache(key, value)
	local ok, err = self.cachestore:set("plugin_virustotal_" .. key, value, 86400)
	if not ok then
		return false, err
	end
	return true
end

function virustotal:request(url)
	-- Get object
	local httpc, err = http_new()
	if not httpc then
		return false, err
	end
	-- Set timeouts for connect, send, and read
	local timeout = tonumber(self.variables["VIRUSTOTAL_TIMEOUT"]) or 1000
	httpc:set_timeouts(timeout, timeout, timeout)
	-- Send request
	local base_url = self.variables["VIRUSTOTAL_API_URL"]
	if base_url == nil or base_url == "" then
		base_url = "https://www.virustotal.com/api/v3"
	end
	-- Strip trailing slash(es) so base_url .. "/files/..." never doubles the slash.
	while base_url:sub(-1) == "/" do
		base_url = base_url:sub(1, -2)
	end
	local res
	res, err = httpc:request_uri(base_url .. url, {
		headers = {
			["x-apikey"] = self.variables["VIRUSTOTAL_API_KEY"],
		},
	})
	if not res then
		return false, err
	end
	-- Check status
	if res.status == 404 then
		return true, false
	end
	if res.status ~= 200 then
		err = "received status " .. tostring(res.status) .. " from VT API"
		local ok, data = pcall(decode, res.body)
		if ok then
			err = err .. " with data " .. data
		end
		return false, err
	end
	-- Get result
	local ok, data = pcall(decode, res.body)
	if not ok then
		return false, data
	end
	if not data.data or not data.data.attributes or not data.data.attributes.last_analysis_stats then
		return false, "malformed json response"
	end
	return true, true, data.data.attributes.last_analysis_stats
end

function virustotal:api()
	if self.ctx.bw.uri == "/virustotal/ping" and self.ctx.bw.request_method == "POST" then
		-- Check virustotal connection
		local check, err = has_variable("USE_VIRUSTOTAL", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_VIRUSTOTAL (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "Virustotal plugin not enabled")
		end

		-- Send test data to virustotal virustotal
		local ok, found, response =
			self:request("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") -- sha256 of eicar test file
		if not ok then
			return self:ret(true, "error while sending test data to virustotal : " .. found, HTTP_INTERNAL_SERVER_ERROR)
		end
		if not found then
			return self:ret(
				true,
				"error while sending test data to virustotal : file not found on virustotal but it should be",
				HTTP_INTERNAL_SERVER_ERROR
			)
		end
		return self:ret(true, "test data sent to virustotal, response: " .. encode(response), HTTP_OK)
	end
	return self:ret(false, "success")
end

return virustotal
