local cjson = require("cjson")
local class = require("middleclass")
local helpers = require("openappsec/openappsec_helpers")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local openappsec = class("openappsec", plugin)

local ngx = ngx
local ngx_req = ngx.req
local ngx_re_find = ngx.re.find
local ngx_now = ngx.now
local ERR = ngx.ERR
local NOTICE = ngx.NOTICE
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_SERVICE_UNAVAILABLE = ngx.HTTP_SERVICE_UNAVAILABLE
local HTTP_OK = ngx.HTTP_OK
local http_new = http.new
local has_variable = utils.has_variable
local get_deny_status = utils.get_deny_status
local json_decode = cjson.decode
local json_encode = cjson.encode
local tostring = tostring
local open = io.open
local coroutine_create = coroutine.create
local coroutine_yield = coroutine.yield
local coroutine_resume = coroutine.resume
local upper = string.upper
local lower = string.lower
local tonumber = tonumber
local floor = math.floor
local CANARY_KEY = "plugin_openappsec_canary"

-- Per-worker: judge URL -> epoch until which the judge is skipped after an error. Plain
-- per-VM state on purpose: each worker discovers the outage on its own first failed
-- request, which is the cheapest correct behaviour and needs no shared dict.
local cooldown_until = {}
local last_probe

function openappsec:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "openappsec", ctx)
end

function openappsec:init_worker()
	-- Check if needed
	if not self:is_needed() then
		return self:ret(true, "open-appsec not activated")
	end
	-- Send ping request
	local ok, data = self:ping()
	if not ok then
		return self:ret(
			false,
			"error while sending ping request to " .. self.variables["OPENAPPSEC_API"] .. " : " .. data
		)
	end
	return self:ret(true, "ping request to " .. self.variables["OPENAPPSEC_API"] .. " is successful")
end

function openappsec:timer()
	if self.is_loading then
		return self:ret(true, "open-appsec canary skipped while loading")
	end
	local is_needed, err = has_variable("USE_OPENAPPSEC", "yes")
	if is_needed == nil then
		return self:ret(false, "can't check USE_OPENAPPSEC variable : " .. err)
	end
	if not is_needed then
		return self:ret(true, "open-appsec not activated")
	end
	if ngx.worker.id() ~= 0 then
		return self:ret(true, "open-appsec canary runs in worker 0")
	end

	local interval = tonumber(self.variables["OPENAPPSEC_CANARY_INTERVAL"]) or 60
	if interval <= 0 then
		return self:ret(true, "open-appsec canary disabled")
	end
	local ttl = helpers.canary_ttl(interval)

	local now = ngx_now()
	if last_probe and now - last_probe < interval then
		return self:ret(true, "open-appsec canary in cooldown")
	end
	last_probe = now

	local httpc, request_err = http_new()
	local res
	if httpc then
		local read_timeout = tonumber(self.variables["OPENAPPSEC_READ_TIMEOUT"]) or 5000
		httpc:set_timeouts(tonumber(self.variables["OPENAPPSEC_CONNECT_TIMEOUT"]) or 1000, read_timeout, read_timeout)
		res, request_err = httpc:request_uri(self.variables["OPENAPPSEC_API"] .. "/?id=/etc/passwd", {
			method = "GET",
			headers = {
				["Host"] = "canary.openappsec.bunkerweb.invalid",
				["X-Forwarded-For"] = "127.0.0.1",
				["X-Forwarded-Proto"] = "http",
				["User-Agent"] = "bunkerweb-openappsec-canary",
			},
			keepalive = false,
		})
	end

	local state, reason = helpers.canary_state(res, request_err)
	local record = {
		state = state,
		reason = reason,
		checked_at = ngx.time(),
		latency_ms = floor((ngx_now() - now) * 1000),
		status = res and res.status or cjson.null,
		judge = self.variables["OPENAPPSEC_API"],
	}

	local previous_state
	local previous = self.datastore:get(CANARY_KEY)
	if previous then
		local ok, decoded = pcall(json_decode, previous)
		if ok and type(decoded) == "table" then
			previous_state = decoded.state
		end
	end
	local stored, store_err = self.datastore:set(CANARY_KEY, json_encode(record), ttl)
	if not stored then
		self.logger:log(ERR, "can't persist open-appsec canary state : " .. tostring(store_err))
	end
	self.logger:log(
		NOTICE,
		"open-appsec canary state=" .. state .. " (previous=" .. (previous_state or "unknown") .. ")"
	)
	if state ~= "enforcing" then
		self.logger:log(ERR, "open-appsec canary " .. state .. " : " .. reason)
	end
	return self:ret(true, "open-appsec canary " .. state)
end

function openappsec:access()
	-- Check if needed
	if not self:is_needed() then
		return self:ret(true, "open-appsec not activated")
	end

	local vars = self.variables
	local request_id = ngx.var.request_id
	local fail_mode = vars["OPENAPPSEC_FAIL_MODE"]
	-- Exclusions never reach the judge and are counted apart.
	local excluded, why = helpers.is_excluded(
		self.ctx.bw.uri,
		self.ctx.bw.request_method,
		helpers.parse_list(vars["OPENAPPSEC_EXCLUDED_URIS"]),
		helpers.parse_list(vars["OPENAPPSEC_EXCLUDED_METHODS"], upper),
		ngx_re_find
	)
	if excluded then
		self:set_metric("counters", "skipped", 1)
		return self:ret(true, "open-appsec skipped request : " .. why)
	end
	if vars["OPENAPPSEC_CANARY_FAIL"] == "yes" then
		local canary = self.datastore:get(CANARY_KEY)
		if canary then
			local ok, data = pcall(json_decode, canary)
			if ok and type(data) == "table" and data.state == "not_enforcing" then
				local reason = "canary reports judge not enforcing"
				self:set_metric("counters", "errors", 1)
				if fail_mode == "closed" then
					return self:ret(
						true,
						"error while calling open-appsec, failing closed : " .. reason,
						HTTP_INTERNAL_SERVER_ERROR
					)
				end
				self.logger:log(ERR, "open-appsec " .. reason .. ", failing open")
				return self:ret(true, "open-appsec unreachable, failing open : " .. reason)
			end
		end
	end

	local api = vars["OPENAPPSEC_API"]
	local verdict, reason, res
	if helpers.in_cooldown(cooldown_until[api], ngx_now()) then
		verdict, reason = "error", "judge in cooldown after a previous error"
	else
		verdict, reason, res = self:process_request()
		if verdict == "error" then
			local cooldown = tonumber(vars["OPENAPPSEC_ERROR_COOLDOWN"]) or 0
			if cooldown > 0 then
				cooldown_until[api] = ngx_now() + cooldown
			end
		end
	end
	if verdict == "accept" then
		self:set_metric("counters", "accepted", 1)
		return self:ret(true, "open-appsec accepted request")
	end
	if verdict == "deny" then
		-- Everything the report and the plugin page can show about this block. The event id
		-- is open-appsec's own (eventReferenceId in the agent's logs), so the operator can
		-- find the matched indicators, confidence and incident type on the agent side.
		local event_id = helpers.event_id(res)
		local status = res and res.status or nil
		local deny_reason = "open-appsec denied request [" .. (request_id or "-") .. "] : " .. reason
		self:set_metric("counters", "denied", 1)
		self:set_metric("tables", "denies", {
			date = self.ctx.bw.start_time,
			ip = self.ctx.bw.remote_addr,
			server_name = self.ctx.bw.server_name,
			method = self.ctx.bw.request_method or "-",
			url = self.ctx.bw.request_uri or "-",
			judge_status = status,
			event_id = event_id or "-",
			request_id = request_id or "-",
		})
		return self:ret(true, deny_reason, get_deny_status(), nil, {
			id = "openappsec",
			judge_status = status,
			event_id = event_id,
			judge = self.variables["OPENAPPSEC_API"],
			reason = reason,
			request_id = request_id,
		})
	end
	self:set_metric("counters", "errors", 1)
	if fail_mode == "closed" then
		-- A plain self:ret(false, ...) only logs: BunkerWeb's access phase carries on to
		-- the upstream when a plugin reports a failure without a status. Failing closed
		-- means answering, so hand back an explicit 500.
		return self:ret(
			true,
			"error while calling open-appsec, failing closed : " .. reason,
			HTTP_INTERNAL_SERVER_ERROR
		)
	end
	self.logger:log(ERR, "error while calling open-appsec : " .. reason)
	return self:ret(true, "open-appsec unreachable, failing open : " .. reason)
end

function openappsec:ping()
	-- Get http object
	local httpc, err = http_new()
	if not httpc then
		return false, err
	end
	httpc:set_timeout(1000)
	-- Send ping
	local res
	-- A plain GET / goes through the whole chain (judge nginx, attachment, echo upstream),
	-- unlike a dedicated ping location, which would also be a replayable path that skips
	-- inspection: the client's own URI is replayed verbatim to the judge.
	res, err = httpc:request_uri(self.variables["OPENAPPSEC_API"] .. "/", {
		method = "GET",
		keepalive = false,
	})
	if not res then
		return false, err
	end
	-- Check status
	if res.status ~= 200 then
		return false, "received status " .. tostring(res.status) .. " from open-appsec API"
	end
	return true
end

function openappsec:process_request()
	-- Instantiate lua-resty-http obj
	local httpc, err = http_new()
	if not httpc then
		return helpers.verdict(nil, err)
	end
	local read_timeout = tonumber(self.variables["OPENAPPSEC_READ_TIMEOUT"]) or 5000
	httpc:set_timeouts(tonumber(self.variables["OPENAPPSEC_CONNECT_TIMEOUT"]) or 1000, read_timeout, read_timeout)

	-- Compute headers
	local headers
	headers, err = ngx_req.get_headers()
	if err == "truncated" then
		return "deny", "too many headers"
	end
	headers = headers or {}
	helpers.strip_headers(headers, helpers.parse_list(self.variables["OPENAPPSEC_STRIP_HEADERS"], lower))
	headers["content-length"] = nil
	headers["Content-Length"] = nil
	headers["transfer-encoding"] = nil
	headers["Transfer-Encoding"] = nil
	headers["connection"] = nil
	headers["Connection"] = nil
	headers["expect"] = nil
	headers["Expect"] = nil
	helpers.strip_headers(headers, { "x-request-id" })
	headers["X-Request-ID"] = ngx.var.request_id
	-- Remaining hop-by-hop headers: never meaningful on the replay, only smuggling surface.
	headers["keep-alive"] = nil
	headers["Keep-Alive"] = nil
	headers["te"] = nil -- codespell:ignore
	headers["TE"] = nil -- codespell:ignore
	headers["upgrade"] = nil
	headers["Upgrade"] = nil
	headers["proxy-connection"] = nil
	headers["Proxy-Connection"] = nil
	headers["host"] = nil
	headers["Host"] = self.ctx.bw.http_host or ngx.var.host
	headers["x-forwarded-for"] = nil
	headers["X-Forwarded-For"] = self.ctx.bw.remote_addr
	headers["x-forwarded-proto"] = nil
	headers["X-Forwarded-Proto"] = ngx.var.scheme

	-- Body setup
	local body
	local inspect_body, skip_reason = helpers.body_policy(
		tonumber(ngx.var.content_length),
		self.variables["OPENAPPSEC_INSPECT_BODY"] == "yes",
		tonumber(self.variables["OPENAPPSEC_MAX_BODY_SIZE"]) or 0
	)
	if inspect_body then
		local body_ok, body_err = pcall(ngx_req.read_body)
		if not body_ok then
			return helpers.verdict(nil, body_err)
		end
		body = ngx_req.get_body_data()
		if not body then
			local file = ngx_req.get_body_file()
			if file then
				local handle
				-- luacheck: ignore err
				handle, err = open(file)
				if not handle then
					-- An unreadable body file would replay a body with no framing at all; treat it
					-- like a dead judge and let OPENAPPSEC_FAIL_MODE decide.
					return helpers.verdict(nil, "can't open request body file : " .. tostring(err))
				end
				headers["Content-Length"] = tostring(handle:seek("end"))
				handle:close()
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
	else
		self.logger:log(NOTICE, "replaying without body : " .. skip_reason)
	end

	local res
	res, err = httpc:request_uri(self.variables["OPENAPPSEC_API"] .. self.ctx.bw.request_uri, {
		method = self.ctx.bw.request_method,
		headers = headers,
		body = body or "",
	})
	local verdict, reason = helpers.verdict(res, err)
	return verdict, reason, res
end

function openappsec:is_needed()
	-- Loading case
	if self.is_loading then
		return false
	end
	-- Request phases (no default)
	if self.is_request and (self.ctx.bw.server_name ~= "_") then
		return self.variables["USE_OPENAPPSEC"] == "yes" and not ngx_req.is_internal()
	end
	-- Other cases : at least one service uses it
	local is_needed, err = has_variable("USE_OPENAPPSEC", "yes")
	if is_needed == nil then
		self.logger:log(ERR, "can't check USE_OPENAPPSEC variable : " .. err)
	end
	return is_needed
end

function openappsec:api()
	if self.ctx.bw.uri == "/openappsec/canary" and self.ctx.bw.request_method == "GET" then
		local data = { state = "unknown" }
		local stored = self.datastore:get(CANARY_KEY)
		if stored then
			local ok, decoded = pcall(json_decode, stored)
			if ok and type(decoded) == "table" then
				data = decoded
			end
		end
		return self:ret(true, data, HTTP_OK)
	end
	if self.ctx.bw.uri == "/openappsec/ping" and self.ctx.bw.request_method == "POST" then
		-- Check open-appsec connection
		local check, err = has_variable("USE_OPENAPPSEC", "yes")
		if check == nil then
			return self:ret(
				true,
				"error while checking variable USE_OPENAPPSEC (" .. err .. ")",
				HTTP_INTERNAL_SERVER_ERROR
			)
		end
		if not check then
			return self:ret(true, "open-appsec plugin not enabled", HTTP_SERVICE_UNAVAILABLE)
		end

		-- Send ping request
		local ok, data = self:ping()
		if not ok then
			return self:ret(
				true,
				"error while sending ping request to " .. self.variables["OPENAPPSEC_API"] .. " : " .. data,
				HTTP_INTERNAL_SERVER_ERROR
			)
		end
		return self:ret(true, "ping request is successful", HTTP_OK)
	end
	return self:ret(false, "success")
end

return openappsec
