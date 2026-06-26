-- Pure helpers extracted from discord.lua so they can be unit-tested with busted
-- outside the OpenResty runtime. No ngx/resty dependencies — see
-- spec/discord_helpers_spec.lua.
local len = string.len
local sub = string.sub
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

-- Discord embed field values are capped at 1024 characters. Truncate to 1021 and
-- append "..." so the value always fits, leaving shorter strings untouched.
function _M.format_field(input_string)
	if len(input_string) <= 1021 then
		return input_string
	end
	return sub(input_string, 1, 1021) .. "..."
end

-- Repeated headers are returned by ngx.req.get_headers() as an array table.
-- Flatten to a single string so downstream concatenation never fails on a table.
function _M.flatten_header_value(value)
	if type(value) == "table" then
		return concat(value, ", ")
	end
	return tostring(value)
end

-- Return a notification-safe value for a header: "[REDACTED]" for sensitive
-- headers, otherwise the flattened value.
function _M.redact_header(name, value)
	if SENSITIVE_HEADERS[lower(name)] then
		return "[REDACTED]"
	end
	return _M.flatten_header_value(value)
end

return _M
