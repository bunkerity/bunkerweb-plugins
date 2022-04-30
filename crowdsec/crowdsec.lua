local _M        = {}
_M.__index      = _M

local utils     = require "utils"
local datastore = require "datastore"
local logger    = require "logger"
local cjson		= require "cjson"
local http		= require "resty.http"
local cs		= require "crowdsec.bouncer"

function _M.new()
	local self = setmetatable({}, _M)
	local value, err = utils.get_variable("CROWDSEC_API", false)
	if not value then
		logger.log(ngx.ERR, "CROWDSEC", "error while getting CROWDSEC_API setting : " .. err)
		return nil, "error while getting CROWDSEC_API setting : " .. err
	end
	self.api = value
	return self, nil
end

function _M:init()
	-- Check if CS is activated
	local check, err = utils.has_variable("USE_CROWDSEC", "yes")
	if check == nil then
		return false, "error while checking variable USE_CROWDSEC (" .. err .. ")"
	end
	if not check then
		return true, "CrowdSec plugin not enabled"
	end
	-- Init bouncer
	local ok, err = cs.init("/opt/bunkerweb/plugins/cache/crowdsec/bouncer.conf", "crowdsec-bunkerweb-bouncer/v0.1")
	if ok == nil then
		return false, "error while initializing bouncer : " .. err
	end
	return true, "success"
end

function _M:access()
	-- Check if CS is activated
	local check, err = utils.get_variable("USE_CROWDSEC")
	if check == nil then
		return false, "error while getting variable USE_CROWDSEC (" .. err .. ")", nil, nil
	end
	if check ~= "yes" then
		return true, "CrowdSec plugin not enabled", nil, nil
	end

	-- Do the check
	local ok, err, allowed = cs.allowed()
	if not ok then
		return false, "error while executing CrowdSec bouncer : " .. err, nil, nil
	end
	if not allowed then
		return true, "CrowSec bouncer banned IP : " .. reason, true, ngx.HTTP_FORBIDDEN
	end

	return true, "success", nil, nil

end

return _M
