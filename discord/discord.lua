local _M        = {}
_M.__index      = _M

local utils     = require "utils"
local logger    = require "logger"
local cjson		= require "cjson"
local http		= require "resty.http"

function _M.new()
	local self = setmetatable({}, _M)
	local value, err = utils.get_variable("DISCORD_WEBHOOK_URL", false)
	if not value then
		logger.log(ngx.ERR, "DISCORD", "error while getting DISCORD_WEBHOOK_URL setting : " .. err)
		return nil, "error while getting DISCORD_WEBHOOK_URL setting : " .. err
	end
	self.webhook = value
	return self, nil
end


function _M:log()
	-- Check if discord is activated
	local check, err = utils.get_variable("USE_DISCORD")
	if check == nil then
		return false, "error while getting variable USE_DISCORD (" .. err .. ")"
	end
	if check ~= "yes" then
		return true, "Discord plugin not enabled"
	end

	-- Check if request is denied
	local reason = utils.get_reason()
	if reason == nil then
		return true, "request not denied"
	end
	
	-- Send request in a timer because cosocket is not allowed in log()
	local function send(premature, obj, ip, reason)
		local httpc, err = http.new()
		if not httpc then
			logger.log(ngx.ERR, "DISCORD", "can't instantiate http object : " .. err)
		end
		local data = {}
		data.content = "Banned IP " .. ip .. " (reason = " .. reason .. ")"
		local res, err_http = httpc:request_uri(self.webhook, {
			method = "POST",
			headers = {
				["Content-Type"] = "application/json",
				["User-Agent"] = "BunkerWeb/" .. utils.get_version()
			},
			body = cjson.encode(data)
		})	
		httpc:close()
		if not res then
			logger.log(ngx.ERR, "DISCORD", "error while sending request : " .. err)
		end
		if res.status < 200 or res.status > 299 then
			logger.log(ngx.ERR, "DISCORD", "request returned status " .. tostring(res.status))
		end
		logger.log(ngx.INFO, "DISCORD", "request sent to webhook")
	end
	local hdr, err = ngx.timer.at(0, send, self, ngx.var.remote_addr, reason)
	if not hdr then
		return false, "can't create report timer : " .. err
	end
	-- Done
	return true, "created report timer"
end

return _M
