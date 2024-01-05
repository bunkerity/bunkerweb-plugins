local class = require("middleclass")
local cs = require("crowdsec.lib.bouncer")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local crowdsec = class("crowdsec", plugin)

local ngx = ngx
local ERR = ngx.ERR
local has_variable = utils.has_variable
local get_deny_status = utils.get_deny_status
local cs_init = cs.init
local cs_allow = cs.Allow

function crowdsec:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "crowdsec", ctx)
end

function crowdsec:init()
	-- Check if init is needed
	local init_needed, err = has_variable("USE_CROWDSEC", "yes")
	if init_needed == nil then
		return self:ret(false, "can't check USE_CROWDSEC variable : " .. err)
	end
	if not init_needed or self.is_loading then
		return self:ret(true, "init not needed")
	end
	-- Init CS
	local ok
	ok, err = cs_init("/var/cache/bunkerweb/crowdsec/crowdsec.conf", "crowdsec-bunkerweb-bouncer/v1.1")
	if not ok then
		self.logger:log(ERR, "error while initializing bouncer : " .. err)
	end
end

function crowdsec:access()
	-- Check if CS is activated
	if self.variables["USE_CROWDSEC"] ~= "yes" then
		return self:ret(true, "CrowdSec plugin not enabled")
	end
	-- Do the check
	local ok, err, banned = cs_allow(self.ctx.bw.remote_addr)
	if not ok then
		return self:ret(false, "Error while executing CrowdSec bouncer : " .. err)
	end
	if banned then
		return self:ret(true, "CrowSec bouncer denied request", get_deny_status())
	end

	return self:ret(true, "Not denied by CrowdSec bouncer")
end

return crowdsec
