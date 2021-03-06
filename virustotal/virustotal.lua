local _M        = {}
_M.__index      = _M

local utils     = require "utils"
local datastore = require "datastore"
local logger    = require "logger"
local cjson		= require "cjson"
local http		= require "resty.http"

function _M.new()
	local self = setmetatable({}, _M)
	local value, err = utils.get_variable("VIRUSTOTAL_API", false)
	if not value then
		logger.log(ngx.ERR, "VIRUSTOTAL", "error while getting VIRUSTOTAL_API setting : " .. err)
		return nil, "error while getting VIRUSTOTAL_API setting : " .. err
	end
	self.api = value
	return self, nil
end

function _M:access()
	-- Check if VT is activated
	local check, err = utils.get_variable("USE_VIRUSTOTAL")
	if check == nil then
		return false, "error while getting variable USE_VIRUSTOTAL (" .. err .. ")", nil, nil
	end
	if check ~= "yes" then
		return true, "VirusTotal plugin not enabled", nil, nil
	end

	-- Check if we have downloads
	if not ngx.var.http_content_type or (not ngx.var.http_content_type:match("boundary") or not ngx.var.http_content_type:match("multipart/form%-data")) then
		return true, "no file upload detected", nil, nil
	end

	-- Forward request to VT API helper
	local ok, err, status, data = self:request("POST", "/check")
		if not ok then
			return false, "error from request : " .. err, nil, nil
		end
	if not data.success then
		return false, "error from VirusTotal API : " .. data.error, nil, nil
	end
	if data.detected then
		return true, "file with hash " .. data.hash .. " is detected", true, ngx.HTTP_FORBIDDEN
	end

	return true, "success", nil, nil

end

function _M:request(method, url)
	local httpc, err = http.new()
	if not httpc then
		return false, "can't instantiate http object : " .. err, nil, nil
	end
	local res = nil
	local err_http = "unknown error"
	if method == "GET" then
		res, err_http = httpc:request_uri(self.api .. url, {
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
				body = function ()
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

return _M
