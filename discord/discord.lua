local _M     = {}
_M.__index   = _M

local utils  = require "utils"
local logger = require "logger"
local cjson  = require "cjson"
local http   = require "resty.http"

function _M.new()
	local self = setmetatable({}, _M)
	local value, err = utils.get_variable("DISCORD_WEBHOOK_URL", false)
	if not value then
		logger.log(ngx.ERR, "DISCORD", "error while getting DISCORD_WEBHOOK_URL setting : " .. err)
		return self, "error while getting DISCORD_WEBHOOK_URL setting : " .. err
	end
	self.webhook = value
	local value, err = utils.get_variable("DISCORD_RETRY_IF_LIMITED", false)
	if not value then
		logger.log(ngx.ERR, "DISCORD", "error while getting DISCORD_RETRY_IF_LIMITED setting : " .. err)
		return self, "error while getting DISCORD_RETRY_IF_LIMITED setting : " .. err
	end
	self.retry = value
	return self, nil
end

function _M:log(bypass_use_discord)
	if not bypass_use_discord then
		-- Check if discord is activated
		local check, err = utils.get_variable("USE_DISCORD")
		if check == nil then
			return false, "error while getting variable USE_DISCORD (" .. err .. ")"
		end
		if check ~= "yes" then
			return true, "Discord plugin not enabled"
		end
	end

	-- Check if request is denied
	local reason = utils.get_reason()
	if reason == nil then
		return true, "request not denied"
	end

	-- Send request in a timer because cosocket is not allowed in log()
	local function send(premature, obj, data)
		local httpc, err = http.new()
		if not httpc then
			logger.log(ngx.ERR, "DISCORD", "can't instantiate http object : " .. err)
		end
		local res, err_http = httpc:request_uri(obj.webhook, {
			method = "POST",
			headers = {
				["Content-Type"] = "application/json",
			},
			body = cjson.encode(data)
		})
		httpc:close()
		if not res then
			logger.log(ngx.ERR, "DISCORD", "error while sending request : " .. err)
		end
		if obj.retry == "yes" and res.status == 429 and res.headers["Retry-After"] then
			logger.log(ngx.WARN, "DISCORD",
				"Discord API is rate-limiting us, retrying in " .. res.headers["Retry-After"] .. "s")
			local hdr, err = ngx.timer.at(res.headers["Retry-After"], send, obj, data)
			if not hdr then
				logger.log(ngx.ERR, "DISCORD", "can't create report timer : " .. err)
				return
			end
			return
		end
		if res.status < 200 or res.status > 299 then
			logger.log(ngx.ERR, "DISCORD", "request returned status " .. tostring(res.status))
			return
		end
		logger.log(ngx.INFO, "DISCORD", "request sent to webhook")
	end
	local data = {}
	data.content = "```Denied request for IP " ..
			ngx.var.remote_addr .. " (reason = " .. reason .. ").\n\nRequest data :\n\n" .. ngx.var.request .. "\n"
	local headers, err = ngx.req.get_headers()
	if not headers then
		data.content = data.content .. "error while getting headers : " .. err
	else
		for header, value in pairs(headers) do
			data.content = data.content .. header .. ": " .. value .. "\n"
		end
	end
	data.content = data.content .. "```"
	local hdr, err = ngx.timer.at(0, send, self, data)
	if not hdr then
		return false, "can't create report timer : " .. err
	end
	-- Done
	return true, "created report timer"
end

function _M:log_default()
	-- Check if discord is activated
	local check, err = utils.has_variable("USE_DISCORD", "yes")
	if check == nil then
		return false, "error while checking variable USE_DISCORD (" .. err .. ")"
	end
	if not check then
		return true, "Discord plugin not enabled"
	end
	-- Check if default server is disabled
	local check, err = utils.get_variable("DISABLE_DEFAULT_SERVER", false)
	if check == nil then
		return false, "error while getting variable DISABLE_DEFAULT_SERVER (" .. err .. ")"
	end
	if check ~= "yes" then
		return true, "default server not disabled"
	end
	-- Call log method
	return self:log(true)
end

return _M
