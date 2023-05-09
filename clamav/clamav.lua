local class      = require "middleclass"
local plugin     = require "bunkerweb.plugin"
local utils      = require "bunkerweb.utils"
local cachestore = require "bunkerweb.cachestore"

local clamav     = class("clamav", plugin)

function clamav:initialize()
	-- Call parent initialize
	plugin.initialize(self, "clamav")
	-- Instantiate cachestore
	local use_redis, err = utils.get_variable("USE_REDIS", false)
	if not use_redis then
		self.logger:log(ngx.ERR, err)
	end
	self.use_redis = use_redis == "yes"
	self.cachestore = cachestore:new(self.use_redis)
end

function clamav:access()
	-- Check if ClamAV is activated
	if self.variables["USE_CLAMAV"] ~= "yes" then
		return self:ret(true, "ClamAV plugin not enabled")
	end

	-- Check if we have downloads
	if not ngx.var.http_content_type or (not ngx.var.http_content_type:match("boundary") or not ngx.var.http_content_type:match("multipart/form%-data")) then
		return self:ret(true, "No file upload detected")
	end

	-- Forward request to ClamAV API helper
	local ok, err, status, data = self:request("POST", "/check")
	if not ok then
		return self:ret(true, "Error from request : " .. err)
	end
	if not data.success then
		return self:ret(false, "Received status code " .. tostring(status) .. " from ClamAV API : " .. data.error)
	end
	if data.detected then
		return self:ret(true, "File with hash " .. data.hash .. " is detected",
			utils.get_deny_status())
	end

	return self:ret(true, "File is not detected")
end

function clamav:request(method, url)
	local api = self.variables["CLAMAV_API"]
	local httpc, err = http.new()
	if not httpc then
		return self:ret(false, "Can't instantiate http object : " .. err)
	end
	local res = nil
	local err_http = "unknown error"
	if method == "GET" then
		res, err_http = httpc:request_uri(api .. url, {
			method = method,
		})
	else
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
		res, err_http = httpc:request_uri(self.api .. url, {
			method = method,
			headers = ngx.req.get_headers(),
			body = body
		})
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

return clamav
