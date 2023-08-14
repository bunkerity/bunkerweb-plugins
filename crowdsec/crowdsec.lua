local class      = require "middleclass"
local plugin     = require "bunkerweb.plugin"
local utils      = require "bunkerweb.utils"
local cachestore = require "bunkerweb.cachestore"
local cjson      = require "cjson"
local cs         = require "crowdsec.lib.bouncer"

local crowdsec   = class("crowdsec", plugin)

function crowdsec:initialize()
	-- Call parent initialize
	plugin.initialize(self, "crowdsec")
end

function crowdsec:init()
	-- Check if init is needed
	local init_needed, err = utils.has_variable("USE_CROWDSEC", "yes")
	if init_needed == nil then
		return self:ret(false, "can't check USE_CROWDSEC variable : " .. err)
	end
	if not init_needed or self.is_loading then
		return self:ret(true, "init not needed")
	end
	-- Init CS
	local ok, err = cs.init("/var/cache/bunkerweb/crowdsec/crowdsec.conf", "crowdsec-bunkerweb-bouncer/v1.0")
	if not ok then
		self.logger:log(ngx.ERR, "error while initializing bouncer : " .. err)
	end
end

function crowdsec:access()
	-- Check if CS is activated
	if self.variables["USE_CROWDSEC"] ~= "yes" then
		return self:ret(true, "CrowdSec plugin not enabled")
	end
	-- Do the check
	local ok, err, allowed = cs.allowed()
	if not ok then
		return self:ret(false, "Error while executing CrowdSec bouncer : " .. err)
	end
	if not allowed then
		return self:ret(true, "CrowSec bouncer denied request", utils.get_deny_status(self.ctx))
	end

	return self:ret(true, "Not denied by CrowdSec bouncer")
end

return crowdsec
