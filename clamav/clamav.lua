local class = require("middleclass")
local plugin = require("bunkerweb.plugin")
local sha512 = require("resty.sha512")
local str = require("resty.string")
local upload = require("resty.upload")
local utils = require("bunkerweb.utils")

local clamav = class("clamav", plugin)

local stream_size = function(size)
	local floor = math.floor
	return ("%c%c%c%c")
		:format(
			size % 0x100,
			floor(size / 0x100) % 0x100,
			floor(size / 0x10000) % 0x100,
			floor(size / 0x1000000) % 0x100
		)
		:reverse()
end

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

function clamav:initialize()
	-- Call parent initialize
	plugin.initialize(self, "clamav")
end

function clamav:init_worker()
	-- Check if worker is needed
	local init_needed, err = utils.has_variable("USE_CLAMAV", "yes")
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
		ngx.NOTICE,
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
			utils.get_deny_status(self.ctx)
		)
	end
	return self:ret(true, "no file detected")
end

function clamav:command(cmd)
	-- Get socket
	local socket, err = self:socket()
	if not socket then
		return false, err
	end
	-- Send command
	local bytes
	bytes, err = socket:send("n" .. cmd .. "\n")
	if not bytes then
		socket:close()
		return false, err
	end
	-- Receive response
	-- luacheck: ignore partial
	local data, partial
	data, err, partial = socket:receive("*l")
	if not data then
		socket:close()
		return false, err
	end
	socket:close()
	return true, data
end

function clamav:socket()
	-- Init socket
	local socket = ngx.socket.tcp()
	socket:settimeout(tonumber(self.variables["CLAMAV_TIMEOUT"]))
	local ok, err = socket:connect(self.variables["CLAMAV_HOST"], tonumber(self.variables["CLAMAV_PORT"]))
	if not ok then
		return false, err
	end
	return socket
end

function clamav:scan()
	-- Loop on files
	local form = upload:new(4096, 512, true)
	if not form then
		return false, "failed to create upload form"
	end
	local sha = sha512:new()
	local socket
	while true do
		-- Read part
		local typ, res, err = form:read()
		if not typ then
			if socket then
				socket:close()
			end
			return false, "form:read() failed : " .. err
		end

		local bytes

		-- Header case : check if we have a filename
		if typ == "header" then
			local found = false
			-- luacheck: ignore 213
			for i, header in ipairs(res) do
				if header:find('^.*filename="(.*)".*$') then
					found = true
					break
				end
			end
			if found then
				if socket then
					socket:close()
				end
				socket, err = self:socket()
				if not socket then
					read_all(form)
					return false, "socket failed : " .. err
				end
				bytes, err = socket:send("nINSTREAM\n")
				if not bytes then
					socket:close()
					read_all(form)
					return false, "socket:send() failed : " .. err
				end
			end
			-- Body case : update checksum and send to clamav
		elseif typ == "body" and socket then
			sha:update(res)
			bytes, err = socket:send(stream_size(#res) .. res)
			if not bytes then
				socket:close()
				read_all(form)
				return false, "socket:send() failed : " .. err
			end
			-- Part end case : get final checksum and clamav result
		elseif typ == "part_end" and socket then
			local checksum = str.to_hex(sha:final())
			sha:reset()
			-- Check if file is in cache
			local ok, cached = self:is_in_cache(checksum)
			if not ok then
				self.logger:log(
					ngx.ERR,
					"can't check if file with checksum " .. checksum .. " is in cache : " .. cached
				)
			elseif cached then
				socket:close()
				socket = nil
				if cached ~= "clean" then
					read_all(form)
					return true, cached, checksum
				end
			else
				-- End the INSTREAM
				bytes, err = socket:send(stream_size(0))
				if not bytes then
					socket:close()
					read_all(form)
					return false, "socket:send() failed : " .. err
				end
				-- Read result
				-- luacheck: ignore partial
				local data, partial
				data, err, partial = socket:receive("*l")
				if not data then
					socket:close()
					read_all(form)
					return false, err
				end
				socket:close()
				socket = nil
				if data:match("^.*INSTREAM size limit exceeded.*$") then
					self.logger:log(
						ngx.ERR,
						"can't scan file with checksum "
							.. checksum
							.. " because size exceeded StreamMaxLength in clamd.conf"
					)
				else
					-- luacheck: ignore iend
					local istart
					istart, iend, data = data:find("^stream: (.*) FOUND$")
					local detected = "clean"
					if istart then
						detected = data
					end
					ok, err = self:add_to_cache(checksum, detected)
					if not ok then
						self.logger:log(ngx.ERR, "can't cache result : " .. err)
					end
					if detected ~= "clean" then
						read_all(form)
						return true, detected, checksum
					end
				end
			end
			-- End of body case : no file detected
		elseif typ == "eof" then
			if socket then
				socket:close()
			end
			return true
		end
	end
	-- luacheck: ignore 511
	return false, "malformed content"
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

return clamav
