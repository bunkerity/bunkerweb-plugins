local _M        = {}
_M.__index      = _M

local utils     = require "utils"
local datastore = require "datastore"
local logger    = require "logger"
local cjson		= require "cjson"
local http		= require "resty.http"

function _M.new()
	local self = setmetatable({}, _M)
	local value, err = utils.get_variable("CLAMAV_API", false)
	if not value then
		logger.log(ngx.ERR, "CLAMAV", "error while getting CLAMAV_API setting : " .. err)
		return nil, "error while getting CLAMAV_API setting : " .. err
	end
	self.api = value
	return self, nil
end

function _M:init()
--	local check, err = utils.has_variable("USE_CLAMAV", "yes")
--	if check == nil then
--		return false, "error while checking variable USE_CLAMAV (" .. err .. ")"
--	end
--	if not check then
--		return true, "ClamAV plugin not enabled"
--	end
--	local ok, err, status, ret = self:request("GET", "/api/v1/version")
--	if not ok then
--		return false, "error while getting version from ClamAV API (" .. err .. ")"
--	end
--	if status ~= 200 then
--		return false, "received status code " .. tostring(status) .. " from ClamAV API : " .. ret.data.error
--	end
	return true, "success"
end

function _M:access()
	local check, err = utils.get_variable("USE_CLAMAV")
	if check == nil then
		return false, "error while getting variable USE_CLAMAV (" .. err .. ")", nil, nil
	end
	if check ~= "yes" then
		return true, "ClamAV plugin not enabled", nil, nil
	end
	if not ngx.var.http_content_type:match("boundary") or not ngx.var.http_content_type:match("multipart/form%-data") then
		return true, "no file upload detected", nil, nil
	end
	local ok, err, status, ret = self:request("POST", "/api/v1/scan")
	if not ok then
		return false, "error while sending request to ClamAV API (" .. err ..")", nil, nil
	end
	if not ret.success then
		return false, "received status code " .. tostring(status) .. " from ClamAV API : " .. ret.data.error, nil, nil
	end
	for i, result in ipairs(ret.data.result) do
		if result["is_infected"] then
			return true, "ClamAV detected infected file : " .. result.viruses[1], true, ngx.HTTP_FORBIDDEN
		end
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
		if not reader then
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
				f:close()
				body = io.lines(body_file)
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
