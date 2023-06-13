local class      = require "middleclass"
local plugin     = require "bunkerweb.plugin"
local utils      = require "bunkerweb.utils"
local cjson		 = require "cjson"
local upload	 = require "resty.upload"
local sha512	 = require "resty.sha512"
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
		if report then
			return self:ret(true, "IP " .. self.ctx.bw.remote_addr .. " is malicious : " .. report, utils.get_deny_status())
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
		if detected then
			return self:ret(true, "file with checksum " .. checksum .. "is detected : " .. detected, utils.get_deny_status())
		end
	end
	return self:ret(true, "no ip/file detected")
end

function virustotal:check_ip()
	-- Check cache
	local ok, detected = self:is_in_cache("ip_" .. self.ctx.bw.remote_addr)
	if not ok then
		return false, detected
	elseif detected then
		if detected ~= "clean" then
	end
	-- Send request
	local ok, 
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



function virustotal:init_worker()
	-- Check if worker is needed
	local init_needed, err = utils.has_variable("USE_VIRUSTOTAL", "yes")
	if init_needed == nil then
		return self:ret(false, "can't check USE_VIRUSTOTAL variable : " .. err)
	end
	if not init_needed or self.is_loading then
		return self:ret(true, "init_worker not needed")
	end
	-- Send ping to VirusTotal API
	local ok, err, status, data = self:request("GET", "/ping")
	if not ok then
		return self:ret(false, "error from request : " .. err)
	end
	if not data.success then
		return self:ret(false, "received status code " .. tostring(status) .. " from VirusTotal API : " .. data.error)
	end
	self.logger:log(ngx.NOTICE, "connectivity with " .. self.variables["VIRUSTOTAL_API"] .. " successful")
	return self:ret(true, "success")
end

function virustotal:access()
	-- Check if enabled
	if self.variables["USE_VIRUSTOTAL"] ~= "yes" or (self.variables["VIRUSTOTAL_SCAN_IP"] ~= "yes" and self.variables["VIRUSTOTAL_SCAN_FILE"] ~= "yes") then
		return self:ret(true, "virustotal plugin not enabled")
	end

	-- IP check
	if self.variables["VIRUSTOTAL_SCAN_IP"] == "yes" then
		local ok, err, status, data = self:request("POST", "/check_ip", "ip")
		if not ok then
			return self:ret(false, "error from request : " .. err)
		end
		if not data.success then
			return self:ret(false, "error from API : " .. data.error)
		end
		if data.detected then
			self:ret(true, "ip " .. self.ctx.bw.remote_addr .. " is detected", utils.get_deny_status(self.ctx))
		end
	end

	-- File check
	if self.variables["VIRUSTOTAL_SCAN_FILE"] == "yes" then
		-- Check if we have downloads
		if not self.ctx.bw.http_content_type or (not self.ctx.bw.http_content_type:match("boundary") or not self.ctx.bw.http_content_type:match("multipart/form%-data")) then
			return self:ret(true, "no file upload detected")
		end
		local ok, err, status, data = self:request("POST", "/check", "file")
		if not ok then
			return self:ret(false, "error from request : " .. err)
		end
		if not data.success then
			return self:ret(false, "error from API : " .. data.error)
		end
		if data.detected then
			return self:ret(true, "file with hash " .. data.hash .. " is detected", utils.get_deny_status(self.ctx))
		end
	end

	return self:ret(true, "no ip/file detected")

end

function virustotal:request(method, url, type)
	local api = self.variables["VIRUSTOTAL_API"]
	local httpc, err = http.new()
	if not httpc then
		return false, "can't instantiate http object : " .. err, nil, nil
	end
	local res = nil
	local err_http = "unknown error"
	if method == "GET" then
		res, err_http = httpc:request_uri(api .. url, {
			method = method,
		})
	else
		local headers = {}
		if type == "ip" then
			headers["Content-Type"] = "application/json"
			res, err_http = httpc:request_uri(api .. url, {
				method = method,
				headers = headers,
				body = cjson.encode({
					ip = self.ctx.bw.remote_addr
				})
			})
		elseif type == "file" then
			local body, err = httpc:get_client_body_reader()
			if not body then
				ngx.req.read_body()
				body = ngx.req.get_body_data()
				if not body then
					local body_file = ngx.req.get_body_file()
					if not body_file then
						return false, "can't access client body", nil, nil
					end
					local f, err = io.open(body_file, "rb")
					if not f then
						return false, "can't read body from file " .. body_file .. " : " .. err, nil, nil
					end
					body = function()
						return f:read(4096)
					end
				end
			end
			headers = ngx.req.get_headers()
			res, err_http = httpc:request_uri(api .. url, {
				method = method,
				headers = headers,
				body = body
			})
		end
	end
	httpc:close()
	if not res then
		return false, "error while sending request : " .. err_http, nil, nil
	end
	local ok, ret = pcall(cjson.decode, res.body)
	if not ok then
		return false, "error while decoding json : " .. ret, nil, nil
	end
	return true, "success", res.status, ret
end

return virustotal