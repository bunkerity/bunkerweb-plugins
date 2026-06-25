-- Pure helpers extracted from matrix.lua so they can be unit-tested with busted
-- outside the OpenResty runtime. No ngx/resty dependencies — see
-- spec/matrix_helpers_spec.lua.
local gsub = string.gsub
local find = string.find
local match = string.match
local tostring = tostring

local _M = {}

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
