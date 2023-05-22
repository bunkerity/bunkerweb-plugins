local class      = require "middleclass"
local plugin     = require "bunkerweb.plugin"
local utils      = require "bunkerweb.utils"
local cjson		 = require "cjson"
local http		 = require "resty.http"

local virustotal    = class("virustotal", plugin)

function virustotal:initialize()
	-- Call parent initialize
	plugin.initialize(self, "virustotal")
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
			self:ret(true, "ip " .. ngx.ctx.bw.remote_addr .. " is detected", utils.get_deny_status())
		end
	end

	-- File check
	if self.variables["VIRUSTOTAL_SCAN_FILE"] == "yes" then
		-- Check if we have downloads
		if not ngx.ctx.bw.http_content_type or (not ngx.ctx.bw.http_content_type:match("boundary") or not ngx.ctx.bw.http_content_type:match("multipart/form%-data")) then
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
			return self:ret(true, "file with hash " .. data.hash .. " is detected", utils.get_deny_status())
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
					ip = ngx.ctx.bw.remote_addr
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