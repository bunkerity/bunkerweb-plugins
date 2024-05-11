local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local coraza = class("coraza", plugin)

local ngx = ngx
local ngx_req = ngx.req
local ERR = ngx.ERR
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_OK = ngx.HTTP_OK
local http_new = http.new
local has_variable = utils.has_variable
local get_deny_status = utils.get_deny_status
local rand = utils.rand
local tostring = tostring
local decode = cjson.decode
local open = io.open
local coroutine_create = coroutine.create
local coroutine_yield = coroutine.yield
local coroutine_resume = coroutine.resume

function coraza:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "coraza", ctx)
end

function coraza:init_worker()
	-- Check if needed
	if not self:is_needed() then
		return self:ret(true, "coraza not activated")
	end
	-- Send ping request
	local ok, data = self:ping()
	if not ok then
		return self:ret(false, "error while sending ping request to " .. self.variables["CORAZA_API"] .. " : " .. data)
	end
	return self:ret(true, "ping request to " .. self.variables["CORAZA_API"] .. " is successful")
end

function coraza:access()
	-- Check if needed
	if not self:is_needed() then
		return self:ret(true, "coraza not activated")
	end
	-- Process phases 1 (headers) and 2 (body)

	local ok, deny, data = self:process_request()
	if not ok then
		return self:ret(false, "error while processing request : " .. deny)
	end
	if deny then
		return self:ret(true, "coraza denied request : " .. data, get_deny_status(), nil, { id = "raw", data = data })
	end

	return self:ret(true, "coraza accepted request")
end

function coraza:ping()
	-- Get http object
	local httpc, err = http_new()
	if not httpc then
		return false, err
	end
	httpc:set_timeout(1000)
	-- Send ping
	local res
	res, err = httpc:request_uri(self.variables["CORAZA_API"] .. "/ping", { keepalive = false })
	if not res then
		return false, err
	end
	-- Check status
	if res.status ~= 200 then
		err = "received status " .. tostring(res.status) .. " from Coraza API"
		local ok, data = pcall(decode, res.body)
		if ok then
			err = err .. " with data " .. data
		end
		return false, err
	end
	-- Get pong
	local ok, data = pcall(decode, res.body)
	if not ok then
		return false, data
	end
	if data.pong == nil then
		return false, "malformed json response"
	end
	return true
end

function coraza:process_request()
	-- Instantiate lua-resty-http obj
	local httpc, err = http_new()
	if not httpc then
		return false, err
	end
	-- Variables to pass to coraza
	local data = {
		["X-Coraza-Version"] = self.ctx.bw.http_version,
		["X-Coraza-Method"] = self.ctx.bw.request_method,
		["X-Coraza-Ip"] = self.ctx.bw.remote_addr,
		["X-Coraza-Id"] = rand(16),
		["X-Coraza-Uri"] = self.ctx.bw.request_uri,
	}
	-- Compute headers
	local headers
	headers, err = ngx_req.get_headers()
	if err == "truncated" then
		return true, true, "too many headers"
	end
	for header, value in pairs(headers) do
		data["X-Coraza-Header-" .. header] = value
	end
	-- Body setup
	ngx_req.read_body()
	local body = ngx_req.get_body_data()
	if not body then
		local file = ngx_req.get_body_file()
		if file then
			local handle
			-- luacheck: ignore err
			handle, err = open(file)
			if handle then
				data["Content-Length"] = tostring(handle:seek("end"))
				handle:close()
			end
			local fbody = function()
				handle, err = open(file)
				if not handle then
					return nil, err
				end
				local cbody = function()
					while true do
						local chunk = handle:read(8192)
						if not chunk then
							break
						end
						coroutine_yield(chunk)
					end
					handle:close()
				end
				local co = coroutine_create(cbody)
				return function(...)
					local ok, ret = coroutine_resume(co, ...)
					if ok then
						return ret
					end
					return nil, ret
				end
			end
			body = fbody()
		end
	end
	local res, err = httpc:request_uri(self.variables["CORAZA_API"] .. "/request", {
		method = "POST",
		headers = data,
		body = body,
	})
	if not res then
		return false, err
	end
	-- Check status
	if res.status ~= 200 then
		local err = "received status " .. tostring(res.status) .. " from Coraza API"
		local ok
		ok, data = pcall(decode, res.body)
		if ok then
			err = err .. " with data " .. data
		end
		return false, err
	end
	-- Get result
	local ok
	ok, data = pcall(decode, res.body)
	if not ok then
		return false, data
	end
	if data.deny == nil or not data.msg then
		return false, "malformed json response"
	end
	return true, data.deny, data.msg
end

function coraza:is_needed()
	-- Loading case
	if self.is_loading then
		return false
	end
	-- Request phases (no default)
	if self.is_request and (self.ctx.bw.server_name ~= "_") then
		return self.variables["USE_CORAZA"] == "yes" and not ngx_req.is_internal()
	end
	-- Other cases : at least one service uses it
	local is_needed, err = has_variable("USE_CORAZA", "yes")
	if is_needed == nil then
		self.logger:log(ERR, "can't check USE_CORAZA variable : " .. err)
	end
	return is_needed
end

function coraza:api()
	if self.ctx.bw.uri == "/coraza/ping" and self.ctx.bw.request_method == "POST" then
		-- Check coraza connection
		local check, err = has_variable("USE_CORAZA", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_CORAZA (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "Coraza plugin not enabled")
		end

		-- Send ping request
		local ok, data = self:ping()
		if not ok then
			return self:ret(
				true,
				"error while sending ping request to " .. self.variables["CORAZA_API"] .. " : " .. data,
				HTTP_INTERNAL_SERVER_ERROR
			)
		end
		return self:ret(true, "ping request is successful", HTTP_OK)
	end
	return self:ret(false, "success")
end

return coraza
