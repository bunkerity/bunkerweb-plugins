local class      = require "middleclass"
local plugin     = require "bunkerweb.plugin"
local utils      = require "bunkerweb.utils"
local cjson		 = require "cjson"
local upload	 = require "resty.upload"
local http		 = require "resty.http"
local sha256	 = require "resty.sha256"
local str		 = require "resty.string"

local virustotal    = class("virustotal", plugin)

function virustotal:initialize()
	-- Call parent initialize
	plugin.initialize(self, "virustotal")
end

-- Todo : find a "ping" endpoint on VT API
-- function virustotal:init_worker()
-- end

function virustotal:access()
	-- Check if enabled
	if self.variables["USE_VIRUSTOTAL"] ~= "yes" or (self.variables["VIRUSTOTAL_SCAN_IP"] ~= "yes" and self.variables["VIRUSTOTAL_SCAN_FILE"] ~= "yes") then
		return self:ret(true, "virustotal plugin not enabled")
	end

	-- IP check
	if self.variables["VIRUSTOTAL_SCAN_IP"] == "yes" and self.ctx.bw.ip_is_global then
		local ok, report = self:check_ip()
		if not ok then
			return self:ret(false, "error while checking if IP is malicious : " .. report)
		end
		if report and report ~= "clean" then
			return self:ret(true, "IP " .. self.ctx.bw.remote_addr .. " is malicious : " .. report, utils.get_deny_status(self.ctx))
		end
	end

	-- File check
	if self.variables["VIRUSTOTAL_SCAN_FILE"] == "yes" then
		-- Check if we have downloads
		if not self.ctx.bw.http_content_type or (not self.ctx.bw.http_content_type:match("boundary") or not self.ctx.bw.http_content_type:match("multipart/form%-data")) then
			return self:ret(true, "no file upload detected")
		end
		-- Perform the check
		local ok, detected, checksum = self:check_file()
		if not ok then
			return self:ret(false, "error while checking if file is malicious : " .. detected)
		end
		-- Malicious case
		if detected and detected ~= "clean" then
			return self:ret(true, "file with checksum " .. checksum .. "is detected : " .. detected, utils.get_deny_status(self.ctx))
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
	local ok, found, response = self:request("/ip_addresses/" .. self.ctx.bw.remote_addr)
	if not ok then
		return false, response
	end
	local result = "clean"
	if found then
		result = self:get_result(response, "IP")
	end
	-- Add to cache
	local ok, err = self:add_to_cache("ip_" .. ngx.ctx.bw.remote_addr, result)
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
		local typ, res, err = form:read()
		if not typ then
			return false, "form:read() failed : " .. err
		end
		-- Header case : check if we have a filename
		if typ == "header" then
			local found = false
			for i, header in ipairs(res) do
				if header:find("^.*filename=\"(.*)\".*$") then
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
			local checksum = str.to_hex(sha:final())
			sha:reset()
			-- Check if file is in cache
			local ok, cached = self:is_in_cache("file_" .. checksum)
			if not ok then
				self.logger:log(ngx.ERR, "can't check if file with checksum " .. checksum .. " is in cache : " .. cached)
			elseif cached then
				if cached ~= "clean" then
					self:read_all(form)
					return true, cached, checksum
				end
			else
				-- Check if file is already present on VT
				local ok, found, response = self:request("/files/" .. checksum)
				if not ok then
					self:read_all(form)
					return false, found
				end
				local result = "clean"
				if found then
					result = self:get_result(response, "FILE")
				end
				-- Add to cache
				local ok, err = self:add_to_cache("file_" .. checksum, result)
				if not ok then
					self:read_all(form)
					return false, err
				end
				-- Stop here if one file is detected
				if result ~= "clean" then
					self:read_all(form)
					return true, result, checksum
				end
			end
		-- End of body case : no file detected
		elseif typ == "eof" then
			return true
		end
	end
	return false, "malformed content"
end

function virustotal:get_result(response, type)
	local result = "clean"
	if response["suspicious"] > tonumber(self.variables["VIRUSTOTAL_" .. type .. "_SUSPICIOUS"]) or response["malicious"] > tonumber(self.variables["VIRUSTOTAL_" .. type .. "_MALICIOUS"]) then
		result = tostring(response["suspicious"]) .. " suspicious and " .. tostring(response["malicious"]) .. " malicious"
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
	local httpc, err = http.new()
	if not httpc then
		return false, err
	end
	-- Send request
	local res, err = httpc:request_uri("https://www.virustotal.com/api/v3" .. url,
		{
			headers = {
				["x-apikey"] = self.variables["VIRUSTOTAL_API_KEY"]
			}
		}
	)
	if not res then
		return false, err
	end
	-- Check status
	if res.status == 404 then
		return true, false
	end
	if res.status ~= 200 then
		local err = "received status " .. tostring(res.status) .. " from VT API"
		local ok, data = pcall(cjson.decode, res.body)
		if ok then
			err = err .. " with data " .. data
		end
		return false, err
	end
	-- Get result
	local ok, data = pcall(cjson.decode, res.body)
	if not ok then
		return false, data
	end
	if not data.data or not data.data.attributes or not data.data.attributes.last_analysis_stats then
		return false, "malformed json response"
	end
	return true, true, data.data.attributes.last_analysis_stats
end

function virustotal:read_all(form)
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

return virustotal