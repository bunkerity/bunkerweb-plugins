local class   = require "middleclass"
local plugin  = require "bunkerweb.plugin"
local utils   = require "bunkerweb.utils"
local cjson   = require "cjson"
local http    = require "resty.http"

local webhook = class("webhook", plugin)

function webhook:initialize()
	-- Call parent initialize
	plugin.initialize(self, "webhook")
end

function webhook:log(bypass_use_webhook)
	-- Check if webhook is enabled
	if not bypass_use_webhook then
		if self.variables["USE_WEBHOOK"] ~= "yes" then
			return self:ret(true, "webhook plugin not enabled")
		end
	end
	-- Check if request is denied
	local reason = utils.get_reason(self.ctx)
	if reason == nil then
		return self:ret(true, "request not denied")
	end
	-- Compute data
	local data = {}
	data.content = "```Denied request for IP " ..
			self.ctx.bw.remote_addr .. " (reason = " .. reason .. ").\n\nRequest data :\n\n" .. ngx.var.request .. "\n"
	local headers, err = ngx.req.get_headers()
	if not headers then
		data.content = data.content .. "error while getting headers : " .. err
	else
		for header, value in pairs(headers) do
			data.content = data.content .. header .. ": " .. value .. "\n"
		end
	end
	data.content = data.content .. "```"
	-- Send request
	local hdr, err = ngx.timer.at(0, self.send, self, data)
	if not hdr then
		return self:ret(true, "can't create report timer : " .. err)
	end
end

function webhook.send(premature, self, data)
	local httpc, err = http.new()
	if not httpc then
		self.logger:log(ngx.ERR, "can't instantiate http object : " .. err)
	end
	local res, err_http = httpc:request_uri(self.variables["WEBHOOK_URL"], {
		method = "POST",
		headers = {
			["Content-Type"] = "application/json",
		},
		body = cjson.encode(data)
	})
	httpc:close()
	if not res then
		self.logger:log(ngx.ERR, "error while sending request : " .. err_http)
	end
	if self.variables["WEBHOOK_RETRY_IF_LIMITED"] == "yes" and res.status == 429 and res.headers["Retry-After"] then
		self.logger:log(ngx.WARN,
			"HTTP endpoint is rate-limiting us, retrying in " .. res.headers["Retry-After"] .. "s")
		local hdr, err = ngx.timer.at(res.headers["Retry-After"], self.send, self, data)
		if not hdr then
			self.logger:log(ngx.ERR, "can't create report timer : " .. err)
			return
		end
		return
	end
	if res.status < 200 or res.status > 299 then
		self.logger:log(ngx.ERR, "request returned status " .. tostring(res.status))
		return
	end
	self.logger:log(ngx.INFO, "request sent to webhook")
end

function webhook:log_default()
	-- Check if webhook is activated
	local check, err = utils.has_variable("USE_WEBHOOK", "yes")
	if check == nil then
		return self:ret(false, "error while checking variable USE_WEBHOOK (" .. err .. ")")
	end
	if not check then
		return self:ret(true, "webhook plugin not enabled")
	end
	-- Check if default server is disabled
	local check, err = utils.get_variable("DISABLE_DEFAULT_SERVER", false)
	if check == nil then
		return self:ret(false, "error while getting variable DISABLE_DEFAULT_SERVER (" .. err .. ")")
	end
	if check ~= "yes" then
		return self:ret(true, "default server not disabled")
	end
	-- Call log method
	return self:log(true)
end

return webhook
