local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")
local matrix_utils = require("matrix.utils")

local matrix = class("matrix", plugin)

local ngx = ngx
local ngx_req = ngx.req
local ERR = ngx.ERR
local INFO = ngx.INFO
local ngx_timer = ngx.timer
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_OK = ngx.HTTP_OK
local http_new = http.new
local has_variable = utils.has_variable
local get_variable = utils.get_variable
local get_reason = utils.get_reason
local get_country = utils.get_country
local get_asn = utils.get_asn
local get_asn_org = matrix_utils.get_asn_org
local tostring = tostring
local encode = cjson.encode

function matrix:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "matrix", ctx)
end

function matrix:log(bypass_use_matrix)
	-- Check if matrix is enabled
	if not bypass_use_matrix then
		if self.variables["USE_MATRIX"] ~= "yes" then
			return self:ret(true, "matrix plugin not enabled")
		end
	end
	-- Check if request is denied
	local reason, reason_data = get_reason(self.ctx)
	if reason == nil then
		return self:ret(true, "request not denied")
	end
	-- Compute data
	local request_host = ngx.var.host or "unknown host"
	local remote_addr = self.ctx.bw.remote_addr
	local request_method = self.ctx.bw.request_method
	local country, err = get_country(self.ctx.bw.remote_addr)
	if not country then
		elf.logger:log(ERR, "can't get Country of IP " .. remote_addr .. " : " .. err)
		country = "Country unknown"
	else
		country = tostring(country)
	end
	local asn, err = get_asn(remote_addr)
	if not asn then
		self.logger:log(ERR, "can't get ASN of IP " .. remote_addr .. " : " .. err)
		asn = "ASN unknown"
	else
		asn = "ASN " .. tostring(asn)
	end
	local asn_org, err = get_asn_org(remote_addr)
	if not asn_org then
		self.logger:log(ERR, "can't get Organization of IP " .. remote_addr .. " : " .. err)
		asn_org = "AS Organization unknown"
	else
		asn_org = tostring(asn_org)
	end
	local data = {}
	data["formatted_body"] = "<p>Denied " .. request_method .. " from <b>" .. remote_addr .. "</b> (" .. country .. " • \"<i>" .. asn_org .. "</i>\" • " .. asn .. ") to " .. request_host .. self.ctx.bw.uri .. "<br>"
	data["formatted_body"] = data["formatted_body"] .. "Reason <b>" .. reason .. "</b> (" .. encode(reason_data or {}) .. ").</p>"
	data["body"] = "Denied " .. request_method .. " from " .. remote_addr .. " (" .. country .. " • \"" .. asn_org .. "\" • " .. asn .. ") to " .. request_host .. self.ctx.bw.uri .. "\n"
	data["body"] = data["body"] .. "Reason " .. reason .. " (" .. encode(reason_data or {}) .. ")."
	-- Add headers if enabled
	if self.variables["MATRIX_INCLUDE_HEADERS"] == "yes" then
		local headers, err = ngx_req.get_headers()
		if not headers then
			data["formatted_body"] = data["formatted_body"] .. "error while getting headers: " .. err
			data["body"] = data["body"] .. "\n error while getting headers: " .. err
		else
            data["formatted_body"] = data["formatted_body"] .. "<table><tr><th>Header</th><th>Value</th></tr>"
			data["body"] = data["body"] .. "\n\n"
			for header, value in pairs(headers) do
				data["formatted_body"] = data["formatted_body"] .. "<tr><td>" .. header .. "</td><td>" .. value .. "</td></tr>"
				data["body"] = data["body"] .. header .. ": " .. value .. "\n"
			end
			data["formatted_body"] = data["formatted_body"] .. "</table>"
		end
	end
	-- Anonymize IP if enabled
	if self.variables["MATRIX_ANONYMIZE_IP"] == "yes" then
		remote_addr = string.gsub(remote_addr, "%d+%.%d+$", "xxx.xxx")
		data = string.gsub(data, self.ctx.bw.remote_addr, remote_addr)
	end
	-- Send request
	local hdr, err = ngx_timer.at(0, self.send, self, data)
	if not hdr then
		return self:ret(true, "can't create report timer: " .. err)
	end
	return self:ret(true, "scheduled timer")
end

-- luacheck: ignore 212
function matrix.send(premature, self, data)
	local httpc, err = http_new()
	if not httpc then
		self.logger:log(ERR, "can't instantiate http object : " .. err)
	end
	-- Prapare data
	local base_url = self.variables["MATRIX_BASE_URL"]
	local access_token = self.variables["MATRIX_ACCESS_TOKEN"]
	local room_id = self.variables["MATRIX_ROOM_ID"]
	local txn_id = tostring(os.time())
	local url = string.format("%s/_matrix/client/r0/rooms/%s/send/m.room.message/%s", base_url, room_id, txn_id)
	local message_data = {
		msgtype = "m.text",
		body = data["body"],
		format = "org.matrix.custom.html",
		formatted_body = data["formatted_body"]
	}
	local post_data = cjson.encode(message_data)
	-- Send request
	local res, err_http = httpc:request_uri(url, {
		method = "PUT",
		body = post_data,
		headers = {
			["Content-Type"] = "application/json",
			["Authorization"] = "Bearer " .. access_token  -- Access Token im Header
		}
	})
	httpc:close()
	if not res then
		self.logger:log(ERR, "error while sending request : " .. err_http)
	end
	if res.status < 200 or res.status > 299 then
		self.logger:log(ERR, "request returned status " .. tostring(res.status))
		return
	end
	self.logger:log(INFO, "request sent to matrix")
end

function matrix:log_default()
	-- Check if matrix is activated
	local check, err = has_variable("USE_MATRIX", "yes")
	if check == nil then
		return self:ret(false, "error while checking variable USE_MATRIX (" .. err .. ")")
	end
	if not check then
		return self:ret(true, "matrix plugin not enabled")
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

function matrix:api()
	if self.ctx.bw.uri == "/matrix/ping" and self.ctx.bw.request_method == "POST" then
		-- Check matrix connection
		local check, err = has_variable("USE_MATRIX", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_MATRIX (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "matrix plugin not enabled")
		end
		-- Prepare data
		local base_url = self.variables["MATRIX_BASE_URL"]
		local access_token = self.variables["MATRIX_ACCESS_TOKEN"]
		local room_id = self.variables["MATRIX_ROOM_ID"]
		local txn_id = tostring(os.time())
		local url = string.format("%s/_matrix/client/r0/rooms/%s/send/m.room.message/%s", base_url, room_id, txn_id)
		local message_data = {
				msgtype = "m.text",
				body = "Test message from bunkerweb."
			}
		-- Send request
		local httpc
		httpc, err = http_new()
		if not httpc then
			self.logger:log(ERR, "can't instantiate http object : " .. err)
		end
		local res, err_http = httpc:request_uri(url, {
			method = "PUT",
			headers = {
                ["Content-Type"] = "application/json",
                ["Authorization"] = "Bearer " .. access_token 
            },
			body = encode(message_data),
		})
		httpc:close()
		if not res then
			self.logger:log(ERR, "error while sending request : " .. err_http)
		end
		if res.status < 200 or res.status > 299 then
			return self:ret(true, "request returned status " .. tostring(res.status), HTTP_INTERNAL_SERVER_ERROR)
		end
		return self:ret(true, "request sent to matrix", HTTP_OK)
	end
	return self:ret(false, "success")
end

return matrix