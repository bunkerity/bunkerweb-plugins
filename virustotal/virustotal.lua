local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local sha256 = require("resty.sha256")
local str = require("resty.string")
local upload = require("resty.upload")
local utils = require("bunkerweb.utils")

local virustotal = class("virustotal", plugin)

local ngx = ngx
local ERR = ngx.ERR
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_OK = ngx.HTTP_OK
local to_hex = str.to_hex
local http_new = http.new
local has_variable = utils.has_variable
local get_deny_status = utils.get_deny_status
local tostring = tostring
local decode = cjson.decode
local encode = cjson.encode

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
	-- Loop on files
	local form, err = upload:new(4096, 512, true)
	if not form then
		return false, err
	end
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
				if header:find('^.*filename="(.*)".*$') then
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
			-- Part end case : get final checksum and clamav result
		elseif typ == "part_end" and processing then
			processing = nil
			-- Compute checksum
			local checksum = to_hex(sha:final())
			sha:reset()
			-- Check if file is in cache
			local ok, cached = self:is_in_cache("file_" .. checksum)
			if not ok then
				self.logger:log(ERR, "can't check if file with checksum " .. checksum .. " is in cache : " .. cached)
			elseif cached then
				if cached ~= "clean" then
					read_all(form)
					return true, cached, checksum
				end
			else
				-- Check if file is already present on VT
				local found, response
				ok, found, response = self:request("/files/" .. checksum)
				if not ok then
					read_all(form)
					return false, found
				end
				local result = "clean"
				if found then
					result = self:get_result(response, "FILE")
				end
				-- Add to cache
				ok, err = self:add_to_cache("file_" .. checksum, result)
				if not ok then
					read_all(form)
					return false, err
				end
				-- Stop here if one file is detected
				if result ~= "clean" then
					read_all(form)
					return true, result, checksum
				end
			end
			-- End of body case : no file detected
		elseif typ == "eof" then
			return true
		end
	end
	-- luacheck: ignore 511
	return false, "malformed content"
end

function virustotal:get_result(response, type)
	local result = "clean"
	if
		response["suspicious"] > tonumber(self.variables["VIRUSTOTAL_" .. type .. "_SUSPICIOUS"])
		or response["malicious"] > tonumber(self.variables["VIRUSTOTAL_" .. type .. "_MALICIOUS"])
	then
		result = tostring(response["suspicious"])
			.. " suspicious and "
			.. tostring(response["malicious"])
			.. " malicious"
	end
	return result
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
	-- Send request
	local res
	res, err = httpc:request_uri("https://www.virustotal.com/api/v3" .. url, {
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
