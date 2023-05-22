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
	local value = self.variables["CROWDSEC_API"]
	if value then
		self.api = value
		-- Check if CS is activated
		if self.variables["USE_CROWDSEC"] == "yes" then
			-- Init bouncer
			local ok, err = cs.init("/var/cache/bunkerweb/crowdsec/crowdsec.conf", "crowdsec-bunkerweb-bouncer/v0.1")
			if ok == nil then
				self.logger:log(ngx.ERR, "Error while initializing bouncer : " .. err)
			end
		end
	else
		self.api = nil
		self.logger:log(ngx.ERR, "Error while getting CROWDSEC_API setting : " .. err)
	end
end

function crowdsec:access()
	-- Check if CS is activated
	if self.variables["USE_CROWDSEC"] ~= "yes" then
		return self:ret(true, "CrowdSec plugin not enabled")
	end
	if self.api == nil then
		return self:ret(false, "CrowdSec API not set")
	end

	-- Do the check
	local ok, err, allowed = cs.allowed()
	if not ok then
		return self:ret(false, "Error while executing CrowdSec bouncer : " .. err)
	end
	if not allowed then
		return self:ret(true, "CrowSec bouncer denied request", utils.get_deny_status())
	end

	return self:ret(true, "Not denied by CrowdSec bouncer")
end

return crowdsec
