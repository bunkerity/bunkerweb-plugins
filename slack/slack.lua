local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local slack = class("slack", plugin)

local ngx = ngx
local ngx_req = ngx.req
local ERR = ngx.ERR
local WARN = ngx.WARN
local INFO = ngx.INFO
local ngx_timer = ngx.timer
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_TOO_MANY_REQUESTS = ngx.HTTP_TOO_MANY_REQUESTS
local HTTP_OK = ngx.HTTP_OK
local http_new = http.new
local has_variable = utils.has_variable
local get_variable = utils.get_variable
local get_reason = utils.get_reason
local tostring = tostring
local encode = cjson.encode

function slack:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "slack", ctx)
end

function slack:log(bypass_use_slack)
	-- Check if slack is enabled
	if not bypass_use_slack then
		if self.variables["USE_SLACK"] ~= "yes" then
			return self:ret(true, "slack plugin not enabled")
		end
	end
	-- Check if request is denied
	local reason, reason_data = get_reason(self.ctx)
	if reason == nil then
		return self:ret(true, "request not denied")
	end
	-- Compute data
	local data = {}
	data.text = "```Denied request for IP "
		.. self.ctx.bw.remote_addr
		.. " (reason = "
		.. reason
		.. " / reason data = "
		.. encode(reason_data or {})
		.. ").\n\nRequest data :\n\n"
		.. ngx.var.request
		.. "\n"
	local headers, err = ngx_req.get_headers()
	if not headers then
		data.text = data.text .. "error while getting headers : " .. err
	else
		for header, value in pairs(headers) do
			data.text = data.text .. header .. ": " .. value .. "\n"
		end
	end
	data.text = data.text .. "```"
	-- Send request
	local hdr
	hdr, err = ngx_timer.at(0, self.send, self, data)
	if not hdr then
		return self:ret(true, "can't create report timer : " .. err)
	end
end

-- luacheck: ignore 212
function slack.send(premature, self, data)
	local httpc, err = http_new()
	if not httpc then
		self.logger:log(ERR, "can't instantiate http object : " .. err)
	end
	local res, err_http = httpc:request_uri(self.variables["SLACK_WEBHOOK_URL"], {
		method = "POST",
		headers = {
			["Content-Type"] = "application/json",
		},
		body = encode(data),
	})
	httpc:close()
	if not res then
		self.logger:log(ERR, "error while sending request : " .. err_http)
	end
	if self.variables["SLACK_RETRY_IF_LIMITED"] == "yes" and res.status == 429 and res.headers["Retry-After"] then
		self.logger:log(WARN, "slack API is rate-limiting us, retrying in " .. res.headers["Retry-After"] .. "s")
		local hdr
		hdr, err = ngx_timer.at(res.headers["Retry-After"], self.send, self, data)
		if not hdr then
			self.logger:log(ERR, "can't create report timer : " .. err)
			return
		end
		return
	end
	if res.status < 200 or res.status > 299 then
		self.logger:log(ERR, "request returned status " .. tostring(res.status))
		return
	end
	self.logger:log(INFO, "request sent to webhook")
end

function slack:log_default()
	-- Check if slack is activated
	local check, err = has_variable("USE_SLACK", "yes")
	if check == nil then
		return self:ret(false, "error while checking variable USE_slack (" .. err .. ")")
	end
	if not check then
		return self:ret(true, "slack plugin not enabled")
	end
	-- Check if default server is disabled
	check, err = get_variable("DISABLE_DEFAULT_SERVER", false)
	if check == nil then
		return self:ret(false, "error while getting variable DISABLE_DEFAULT_SERVER (" .. err .. ")")
	end
	if check ~= "yes" then
		return self:ret(true, "default server not disabled")
	end
	-- Call log method
	return self:log(true)
end

function slack:api()
	if self.ctx.bw.uri == "/slack/ping" and self.ctx.bw.request_method == "POST" then
		-- Check slack connection
		local check, err = has_variable("USE_SLACK", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_SLACK (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "Slack plugin not enabled")
		end

		-- Send test data to slack webhook
		local data = {
			text = "```Test message from bunkerweb```",
		}
		-- Send request
		local httpc
		httpc, err = http_new()
		if not httpc then
			self.logger:log(ERR, "can't instantiate http object : " .. err)
		end
		local res, err_http = httpc:request_uri(self.variables["SLACK_WEBHOOK_URL"], {
			method = "POST",
			headers = {
				["Content-Type"] = "application/json",
			},
			body = encode(data),
		})
		httpc:close()
		if not res then
			self.logger:log(ERR, "error while sending request : " .. err_http)
		end
		if self.variables["SLACK_RETRY_IF_LIMITED"] == "yes" and res.status == 429 and res.headers["Retry-After"] then
			return self:ret(
				true,
				"slack API is rate-limiting us, retry in " .. res.headers["Retry-After"] .. "s",
				HTTP_TOO_MANY_REQUESTS
			)
		end
		if res.status < 200 or res.status > 299 then
			return self:ret(true, "request returned status " .. tostring(res.status), HTTP_INTERNAL_SERVER_ERROR)
		end
		return self:ret(true, "request sent to webhook", HTTP_OK)
	end
	return self:ret(false, "success")
end

return slack
