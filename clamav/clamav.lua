local _M        = {}
_M.__index      = _M

local utils     = require "utils"
local datastore = require "datastore"
local logger    = require "logger"
local upload	= require "resty.upload"

function _M.new()
	local self = setmetatable({}, _M)
	local value, err = utils:get_variable("CLAMAV_API", false)
	if not value then
		logger.log(ngx.ERR, "CLAMAV", "error while getting CLAMAV_API setting : " .. err)
		return nil, "error while getting CLAMAV_API setting : " .. err
	end
	self.remote_api = value
	return self, nil
end

function _M:init()
	
	logger.log(ngx.NOTICE, "MYPLUGIN", "init called")
	return true, "success"
end

function _M:access()
	logger.log(ngx.NOTICE, "MYPLUGIN", "access called")
	return true, "success", nil, nil
end

function _M:log()
	logger.log(ngx.NOTICE, "MYPLUGIN", "log called")
	return true, "success"
end

return _M
