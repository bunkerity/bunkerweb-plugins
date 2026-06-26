local clamav_helpers = require("clamav.clamav_helpers")
local class = require("middleclass")
local plugin = require("bunkerweb.plugin")
local sha512 = require("resty.sha512")
local str = require("resty.string")
local upload = require("resty.upload")
local utils = require("bunkerweb.utils")

local clamav = class("clamav", plugin)

local ngx = ngx
local ngx_req = ngx.req
local NOTICE = ngx.NOTICE
local ERR = ngx.ERR
local WARN = ngx.WARN
local socket = ngx.socket
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_OK = ngx.HTTP_OK
local to_hex = str.to_hex
local has_variable = utils.has_variable
local get_deny_status = utils.get_deny_status
local tonumber = tonumber
local tostring = tostring
local open = io.open
-- The big-endian INSTREAM length prefix lives in clamav/clamav_helpers.lua so it
-- can be unit-tested with busted outside OpenResty (see spec/clamav_helpers_spec.lua).
local stream_size = clamav_helpers.stream_size

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

function clamav:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "clamav", ctx)
end

function clamav:init_worker()
	-- Check if worker is needed
	local init_needed, err = has_variable("USE_CLAMAV", "yes")
	if init_needed == nil then
		return self:ret(false, "can't check USE_CLAMAV variable : " .. err)
	end
	if not init_needed or self.is_loading then
		return self:ret(true, "init_worker not needed")
	end
	-- Send PING to ClamAV
	local ok, data = self:command("PING")
	if not ok then
		return self:ret(false, "connectivity with ClamAV failed : " .. data)
	end
	if data ~= "PONG" then
		return self:ret(false, "wrong data received from ClamAV : " .. data)
	end
	self.logger:log(
		NOTICE,
		"connectivity with "
			.. self.variables["CLAMAV_HOST"]
			.. ":"
			.. self.variables["CLAMAV_PORT"]
			.. " is successful"
	)
	return self:ret(true, "success")
end

function clamav:access()
	-- Check if ClamAV is activated
	if self.variables["USE_CLAMAV"] ~= "yes" then
		return self:ret(true, "ClamAV plugin not enabled")
	end

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

	-- Check files
	local ok, detected, checksum = self:scan()
	if not ok then
		return self:ret(false, "error while scanning file(s) : " .. detected)
	end
	if detected then
		return self:ret(
			true,
			"file with checksum " .. checksum .. "is detected : " .. detected,
			get_deny_status(),
			nil,
			{
				id = "detected",
				checksum = checksum,
				signature = detected,
			}
		)
	end
	return self:ret(true, "no file detected")
end

function clamav:command(cmd)
	-- Get socket
	local clamav_socket, err = self:socket()
	if not clamav_socket then
		return false, err
	end
	-- Send command
	local bytes
	bytes, err = clamav_socket:send("n" .. cmd .. "\n")
	if not bytes then
		clamav_socket:close()
		return false, err
	end
	-- Receive response
	local data
	data, err = clamav_socket:receive("*l")
	if not data then
		clamav_socket:close()
		return false, err
	end
	clamav_socket:close()
	return true, data
end

function clamav:socket()
	-- Init socket
	local tcp_socket = socket.tcp()
	tcp_socket:settimeout(tonumber(self.variables["CLAMAV_TIMEOUT"]))
	local ok, err = tcp_socket:connect(self.variables["CLAMAV_HOST"], tonumber(self.variables["CLAMAV_PORT"]))
	if not ok then
		return false, err
	end
	return tcp_socket
end

function clamav:scan()
	-- resty.upload reads the raw request socket, which is unavailable on HTTP/2 /
	-- HTTP/3 (ngx.req.socket() raises "http v2 not supported yet"). Use the
	-- buffered fallback there so the upload is still scanned instead of 500ing.
	if clamav_helpers.is_http2_plus(self.ctx.bw.http_version, ngx.var.server_protocol) then
		return self:scan_buffered()
	end
	-- Loop on files
	local ok_new, form, new_err = pcall(upload.new, upload, 4096, 512, true)
	if not ok_new then
		-- Belt-and-suspenders: any unexpected raw-socket error still degrades to
		-- the buffered path rather than bubbling up as a 500 (form holds the raised message).
		self.logger:log(WARN, "resty.upload raised an error (" .. tostring(form) .. "); falling back to buffered scan")
		return self:scan_buffered()
	end
	if not form then
		self.logger:log(WARN, "resty.upload unavailable (" .. tostring(new_err) .. "); falling back to buffered scan")
		return self:scan_buffered()
	end
	local sha = sha512:new()
	local scan_socket = nil
	while true do
		-- Read part
		local typ, res, err = form:read()
		if not typ then
			if scan_socket then
				scan_socket:close()
			end
			return false, "form:read() failed : " .. err
		end

		local bytes

		-- Header case : check if we have a filename
		if typ == "header" then
			local found = false
			for _, header in ipairs(res) do
				-- Match the filename parameter in any RFC 7578 / 2183 form :
				-- quoted (filename="x"), unquoted (filename=x) and RFC 5987 extended (filename*=...).
				-- %f[%a] anchors on a parameter boundary so form fields like name="myfilename" don't match.
				if header:find("%f[%a]filename%*?%s*=") then
					found = true
					break
				end
			end
			if found then
				if scan_socket then
					scan_socket:close()
				end
				scan_socket, err = self:socket()
				if not scan_socket then
					read_all(form)
					return false, "socket failed : " .. err
				end
				bytes, err = scan_socket:send("nINSTREAM\n")
				if not bytes then
					scan_socket:close()
					read_all(form)
					return false, "socket:send() failed : " .. err
				end
			end
			-- Body case : update checksum and send to clamav
		elseif typ == "body" and scan_socket then
			sha:update(res)
			bytes, err = scan_socket:send(stream_size(#res) .. res)
			if not bytes then
				scan_socket:close()
				read_all(form)
				return false, "socket:send() failed : " .. err
			end
			-- Part end case : get final checksum and clamav result
		elseif typ == "part_end" and scan_socket then
			local checksum = to_hex(sha:final())
			sha:reset()
			-- Check if file is in cache
			local ok, cached = self:is_in_cache(checksum)
			if not ok then
				self.logger:log(
					ngx.ERR,
					"can't check if file with checksum " .. checksum .. " is in cache : " .. cached
				)
			elseif cached then
				scan_socket:close()
				scan_socket = nil
				if cached ~= "clean" then
					read_all(form)
					return true, cached, checksum
				end
			else
				-- End the INSTREAM
				bytes, err = scan_socket:send(stream_size(0))
				if not bytes then
					scan_socket:close()
					read_all(form)
					return false, "socket:send() failed : " .. err
				end
				-- Read result
				local data
				data, err = scan_socket:receive("*l")
				if not data then
					scan_socket:close()
					read_all(form)
					return false, err
				end
				scan_socket:close()
				scan_socket = nil
				local detected, unscannable = clamav_helpers.parse_instream_result(data)
				if unscannable then
					self.logger:log(
						ERR,
						"can't scan file with checksum "
							.. checksum
							.. " because size exceeded StreamMaxLength in clamd.conf"
					)
				else
					ok, err = self:add_to_cache(checksum, detected)
					if not ok then
						self.logger:log(ERR, "can't cache result : " .. err)
					end
					if detected ~= "clean" then
						read_all(form)
						return true, detected, checksum
					end
				end
			end
			-- End of body case : no file detected
		elseif typ == "eof" then
			if scan_socket then
				scan_socket:close()
			end
			return true
		end
	end
	-- luacheck: ignore 511
	return false, "malformed content"
end

-- HTTP/2 / HTTP/3 fallback for scan(): the raw request socket is unavailable so
-- resty.upload can't stream. Buffer the whole body (in memory, or the nginx temp
-- file for large uploads), parse the multipart parts ourselves and scan each file
-- with the same INSTREAM logic as the streaming path.
function clamav:scan_buffered()
	local body, err = read_request_body()
	if not body then
		-- Can't read the body (e.g. chunked HTTP/2 upload) -> nothing we can scan;
		-- allow it through, best-effort, like the existing un-scannable-file behavior.
		if err then
			self.logger:log(WARN, "can't read request body to scan upload (" .. err .. "); upload not scanned")
		end
		return true
	end
	local boundary = clamav_helpers.get_boundary(self.ctx.bw.http_content_type)
	if not boundary then
		return true
	end
	local parts = clamav_helpers.parse_multipart(body, boundary)
	for _, part in ipairs(parts) do
		local ok, detected, checksum = self:scan_buffer(part.content)
		if not ok then
			return false, detected
		end
		if detected and detected ~= "clean" then
			return true, detected, checksum
		end
	end
	return true
end

-- Scan a single in-memory file body with ClamAV INSTREAM. Shared per-file unit of
-- the buffered path; mirrors the streaming loop's hashing, caching and verdict
-- handling (fail-open on a cache-backend error, skip on StreamMaxLength).
function clamav:scan_buffer(content)
	local sha = sha512:new()
	sha:update(content)
	local checksum = to_hex(sha:final())
	-- Check the cache first (fail-open on cache error, like the streaming path).
	local ok, cached = self:is_in_cache(checksum)
	if not ok then
		self.logger:log(ERR, "can't check if file with checksum " .. checksum .. " is in cache : " .. cached)
		return true, "clean", checksum
	end
	if cached then
		return true, cached, checksum
	end
	-- Stream the buffered file to ClamAV.
	local scan_socket, err = self:socket()
	if not scan_socket then
		return false, "socket failed : " .. err
	end
	local bytes
	bytes, err = scan_socket:send("nINSTREAM\n")
	if not bytes then
		scan_socket:close()
		return false, "socket:send() failed : " .. err
	end
	local len = #content
	local i = 1
	while i <= len do
		local chunk = content:sub(i, i + 4095)
		bytes, err = scan_socket:send(stream_size(#chunk) .. chunk)
		if not bytes then
			scan_socket:close()
			return false, "socket:send() failed : " .. err
		end
		i = i + 4096
	end
	-- End the INSTREAM and read the verdict.
	bytes, err = scan_socket:send(stream_size(0))
	if not bytes then
		scan_socket:close()
		return false, "socket:send() failed : " .. err
	end
	local data
	data, err = scan_socket:receive("*l")
	if not data then
		scan_socket:close()
		return false, err
	end
	scan_socket:close()
	local detected, unscannable = clamav_helpers.parse_instream_result(data)
	if unscannable then
		self.logger:log(
			ERR,
			"can't scan file with checksum " .. checksum .. " because size exceeded StreamMaxLength in clamd.conf"
		)
		return true, "clean", checksum
	end
	ok, err = self:add_to_cache(checksum, detected)
	if not ok then
		self.logger:log(ERR, "can't cache result : " .. err)
	end
	return true, detected, checksum
end

function clamav:is_in_cache(checksum)
	local ok, data = self.cachestore:get("plugin_clamav_" .. checksum)
	if not ok then
		return false, data
	end
	return true, data
end

function clamav:add_to_cache(checksum, value)
	local ok, err = self.cachestore:set("plugin_clamav_" .. checksum, value, 86400)
	if not ok then
		return false, err
	end
	return true
end

function clamav:api()
	if self.ctx.bw.uri == "/clamav/ping" and self.ctx.bw.request_method == "POST" then
		-- Check clamav connection
		local check, err = has_variable("USE_CLAMAV", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_CLAMAV (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "Clamav plugin not enabled")
		end

		-- Send PING to ClamAV
		local ok, data = self:command("PING")
		if not ok then
			return self:ret(true, "connectivity with ClamAV failed : " .. data, HTTP_INTERNAL_SERVER_ERROR)
		end
		if data ~= "PONG" then
			return self:ret(true, "wrong data received from ClamAV : " .. data, HTTP_INTERNAL_SERVER_ERROR)
		end
		return self:ret(true, "connectivity with ClamAV is successful", HTTP_OK)
	end
	return self:ret(false, "success")
end

return clamav
