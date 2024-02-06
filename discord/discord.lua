local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local discord = class("discord", plugin)

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
local len = string.len
local sub = string.sub
local format = string.format
local encode = cjson.encode
local floor = math.floor
local date = os.date

function discord:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "discord", ctx)
end

function discord:log(bypass_use_discord)
	-- Check if discord is enabled
	if not bypass_use_discord then
		if self.variables["USE_DISCORD"] ~= "yes" then
			return self:ret(true, "discord plugin not enabled")
		end
	end
	-- Check if request is denied
	local reason, reason_data = get_reason(self.ctx)
	if reason == nil then
		return self:ret(true, "request not denied")
	end
	-- Compute data
	local timestamp = ngx_req.start_time()
	local formattedTimestamp = date("!%Y-%m-%dT%H:%M:%S", timestamp)
	local milliseconds = floor((timestamp - floor(timestamp)) * 1000)
	local formatField = function(inputString)
		if len(inputString) <= 1021 then
			return inputString
		else
			return sub(inputString, 1, 1021) .. "..."
		end
	end

	local data = {
		username = "BunkerWeb",
		embeds = {
			{
				title = "Denied request for IP " .. self.ctx.bw.remote_addr,
				timestamp = formattedTimestamp .. "." .. format("%03d", milliseconds) .. "Z",
				color = 0x125678,
				provider = {
					name = "BunkerWeb",
					url = "https://github.com/bunkerity/bunkerweb",
				},
				author = {
					name = "BunkerWeb's Discord plugin",
					url = "https://github.com/bunkerity/bunkerweb",
					icon_url = "https://raw.githubusercontent.com/bunkerity/bunkerweb-plugins/main/logo.png",
				},
				fields = {
					{
						name = "Request data",
						value = formatField(ngx.var.request),
						inline = false,
					},
					{
						name = "Reason",
						value = formatField(reason),
						inline = false,
					},
					{
						name = "Reason data",
						value = formatField(encode(reason_data or {})),
						inline = false,
					},
				},
			},
		},
	}
	local headers, err = ngx_req.get_headers()
	if not headers then
		data.embeds[1].description = "**error while getting headers : " .. err .. "**"
	else
		local count = 0
		for _ in pairs(headers) do
			count = count + 1
		end
		if count > 23 then
			data.embeds[1].description = "Headers :\n```"
			for header, value in pairs(headers) do
				data.embeds[1].description = data.embeds[1].description .. header .. ": " .. value .. "\n"
			end
			data.embeds[1].description = data.embeds[1].description .. "```"
		else
			for header, value in pairs(headers) do
				table.insert(data.embeds[1].fields, {
					name = header,
					value = formatField(value),
					inline = true,
				})
			end
		end
	end
	-- Send request
	local hdr
	hdr, err = ngx_timer.at(0, self.send, self, data)
	if not hdr then
		return self:ret(true, "can't create report timer : " .. err)
	end
end

-- luacheck: ignore 212
function discord.send(premature, self, data)
	local httpc, err = http_new()
	if not httpc then
		self.logger:log(ERR, "can't instantiate http object : " .. err)
	end
	local res, err_http = httpc:request_uri(self.variables["DISCORD_WEBHOOK_URL"], {
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
	if self.variables["DISCORD_RETRY_IF_LIMITED"] == "yes" and res.status == 429 and res.headers["Retry-After"] then
		self.logger:log(WARN, "Discord API is rate-limiting us, retrying in " .. res.headers["Retry-After"] .. "s")
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

function discord:log_default()
	-- Check if discord is activated
	local check, err = has_variable("USE_DISCORD", "yes")
	if check == nil then
		return self:ret(false, "error while checking variable USE_DISCORD (" .. err .. ")")
	end
	if not check then
		return self:ret(true, "Discord plugin not enabled")
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

function discord:api()
	if self.ctx.bw.uri == "/discord/ping" and self.ctx.bw.request_method == "POST" then
		-- Check discord connection
		local check, err = has_variable("USE_DISCORD", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_DISCORD (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "Discord plugin not enabled")
		end

		-- Send test data to discord webhook
		local data = {
			username = "BunkerWeb",
			embeds = {
				{
					title = "Test message",
					description = "This is a test message sent by BunkerWeb's Discord plugin",
					color = 0x125678,
					provider = {
						name = "BunkerWeb",
						url = "https://github.com/bunkerity/bunkerweb",
					},
					author = {
						name = "BunkerWeb's Discord plugin",
						url = "https://github.com/bunkerity/bunkerweb",
						icon_url = "https://raw.githubusercontent.com/bunkerity/bunkerweb-plugins/main/logo.png",
					},
				},
			},
		}
		-- Send request
		local httpc
		httpc, err = http_new()
		if not httpc then
			self.logger:log(ERR, "can't instantiate http object : " .. err)
		end
		local res, err_http = httpc:request_uri(self.variables["DISCORD_WEBHOOK_URL"], {
			method = "POST",
			headers = {
				["Content-Type"] = "application/json",
			},
			body = encode(data),
		})
		httpc:close()
		if not res then
			return self:ret(true, "error while sending request : " .. err_http, HTTP_INTERNAL_SERVER_ERROR)
		end
		if self.variables["DISCORD_RETRY_IF_LIMITED"] == "yes" and res.status == 429 and res.headers["Retry-After"] then
			return self:ret(
				true,
				"Discord API is rate-limiting us, retry in " .. res.headers["Retry-After"] .. "s",
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

return discord
