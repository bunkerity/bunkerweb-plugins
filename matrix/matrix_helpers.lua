-- Pure helpers extracted from matrix.lua so they can be unit-tested with busted
-- outside the OpenResty runtime. No ngx/resty dependencies — see
-- spec/matrix_helpers_spec.lua.
local gsub = string.gsub
local find = string.find
local match = string.match
local lower = string.lower
local concat = table.concat
local tostring = tostring
local type = type

local _M = {}

-- Request headers that carry credentials/secrets. Their values are never
-- forwarded to the third-party notification service. Keys are lowercase so the
-- lookup is case-insensitive (HTTP header names are case-insensitive).
local SENSITIVE_HEADERS = {
	["authorization"] = true,
	["proxy-authorization"] = true,
	["cookie"] = true,
	["set-cookie"] = true,
	["x-api-key"] = true,
	["x-csrf-token"] = true,
	["x-xsrf-token"] = true,
	["x-auth-token"] = true,
	["x-access-token"] = true,
	["x-session-token"] = true,
	["x-amz-security-token"] = true,
}

-- Repeated headers are returned by ngx.req.get_headers() as an array table.
-- Flatten to a single string so downstream concatenation never fails on a table.
function _M.flatten_header_value(value)
	if type(value) == "table" then
		return concat(value, ", ")
	end
	return tostring(value)
end

-- Return a notification-safe value for a header: "[REDACTED]" for sensitive
-- headers, otherwise the flattened value. Caller is responsible for any further
-- escaping (e.g. html_escape) required by the destination format.
function _M.redact_header(name, value)
	if SENSITIVE_HEADERS[lower(name)] then
		return "[REDACTED]"
	end
	return _M.flatten_header_value(value)
end

-- Escape characters that are significant in the org.matrix.custom.html body so that
-- attacker-controlled values (URI, Host, header names/values) can't break the markup.
function _M.html_escape(str)
	return (gsub(tostring(str), "[&<>]", { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;" }))
end

-- Escape Lua pattern magic characters so a literal string can be used as a gsub pattern.
function _M.escape_pattern(str)
	return (gsub(str, "([%(%)%.%%%+%-%*%?%[%]%^%$])", "%%%1"))
end

-- Mask an IP for notifications. Handles both IPv4 and IPv6.
function _M.anonymize_ip(ip)
	if find(ip, ":", 1, true) then
		-- IPv6: keep the first three hextets, mask the remainder
		local prefix = match(ip, "^(%x*:%x*:%x*):")
		return prefix and (prefix .. ":xxxx") or "xxxx::xxxx"
	end
	-- IPv4: mask the last two octets
	return (gsub(ip, "%d+%.%d+$", "xxx.xxx"))
end

return _M
