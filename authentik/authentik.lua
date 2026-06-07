local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local authentik = class("authentik", plugin)

local ngx = ngx
local ngx_req = ngx.req
local ERR = ngx.ERR
local WARN = ngx.WARN
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_MOVED_TEMPORARILY = ngx.HTTP_MOVED_TEMPORARILY
local http_new = http.new
local has_variable = utils.has_variable
local tostring = tostring
local tonumber = tonumber
local sub = string.sub
local len = string.len

local function starts_with(s, prefix)
	if not s or not prefix or prefix == "" then
		return false
	end
	return sub(s, 1, len(prefix)) == prefix
end

local function rstrip_slash(s)
	if not s or s == "" then
		return s
	end
	while sub(s, -1) == "/" do
		s = sub(s, 1, -2)
	end
	return s
end

function authentik:initialize(ctx)
	plugin.initialize(self, "authentik", ctx)
end

function authentik:is_needed()
	if self.is_loading then
		return false
	end
	if self.is_request and (self.ctx.bw.server_name ~= "_") then
		return self.variables["USE_AUTHENTIK"] == "yes" and not ngx_req.is_internal()
	end
	local is_needed, err = has_variable("USE_AUTHENTIK", "yes")
	if is_needed == nil then
		self.logger:log(ERR, "can't check USE_AUTHENTIK variable : " .. err)
	end
	return is_needed
end

function authentik:access()
	if not self:is_needed() then
		return self:ret(true, "authentik not activated")
	end

	local outpost_path = rstrip_slash(self.variables["AUTHENTIK_OUTPOST_PATH"])
	if outpost_path == nil or outpost_path == "" then
		outpost_path = "/outpost.goauthentik.io"
	end

	-- Outpost endpoints (start, callback, sign_out, ...) handle their own flow,
	-- and the /auth/nginx subrequest must not loop into us. Pass through.
	local uri = self.ctx.bw.uri or ngx.var.uri or ""
	if starts_with(uri, outpost_path) then
		return self:ret(true, "outpost endpoint, no auth check")
	end

	local upstream = rstrip_slash(self.variables["AUTHENTIK_URL"])
	if upstream == nil or upstream == "" then
		self.logger:log(WARN, "USE_AUTHENTIK is yes but AUTHENTIK_URL is empty, denying request")
		return self:ret(true, "AUTHENTIK_URL not configured", HTTP_INTERNAL_SERVER_ERROR)
	end

	local scheme = ngx.var.scheme
	local host = ngx.var.http_host or ngx.var.host
	local request_uri = ngx.var.request_uri or uri
	local original_url = scheme .. "://" .. host .. request_uri

	local headers, err = ngx_req.get_headers()
	if err == "truncated" then
		self.logger:log(WARN, "too many request headers, auth check may be incomplete")
		headers = headers or {}
	end

	local fwd_headers = {
		["Host"] = host,
		["X-Original-URL"] = original_url,
		["X-Original-URI"] = request_uri,
		["X-Forwarded-For"] = self.ctx.bw.remote_addr,
		["X-Forwarded-Host"] = host,
		["X-Forwarded-Proto"] = scheme,
	}
	for _, h in ipairs({ "cookie", "user-agent", "accept", "accept-language", "authorization" }) do
		if headers[h] then
			fwd_headers[h] = headers[h]
		end
	end

	local httpc
	httpc, err = http_new()
	if not httpc then
		return self:ret(true, "failed to create http client : " .. err, HTTP_INTERNAL_SERVER_ERROR)
	end
	httpc:set_timeout(tonumber(self.variables["AUTHENTIK_TIMEOUT"]) or 5000)

	local ssl_verify = self.variables["AUTHENTIK_SSL_VERIFY"] ~= "no"
	local auth_url = upstream .. "/outpost.goauthentik.io/auth/nginx"

	local res
	res, err = httpc:request_uri(auth_url, {
		method = "GET",
		headers = fwd_headers,
		ssl_verify = ssl_verify,
		keepalive = true,
	})
	if not res then
		return self:ret(true, "auth subrequest failed : " .. tostring(err), HTTP_INTERNAL_SERVER_ERROR)
	end

	-- Forward any Set-Cookie from Authentik back to the client so the session
	-- cookie / refresh lands on the protected domain.
	local set_cookie = res.headers["Set-Cookie"]
	if set_cookie then
		ngx.header["Set-Cookie"] = set_cookie
	end

	if res.status == 200 then
		return self:ret(true, "authentik authorized request")
	end

	if res.status == 401 or res.status == 403 then
		local redirect = outpost_path .. "/start?rd=" .. ngx.escape_uri(original_url)
		ngx.header["Location"] = redirect
		return self:ret(true, "authentik signin redirect", HTTP_MOVED_TEMPORARILY)
	end

	return self:ret(
		true,
		"unexpected status from authentik outpost : " .. tostring(res.status),
		HTTP_INTERNAL_SERVER_ERROR
	)
end

return authentik
