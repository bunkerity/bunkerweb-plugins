-- Pure string helpers extracted from authentik.lua so they can be unit-tested
-- with busted outside the OpenResty runtime. No ngx/resty dependencies — see
-- spec/authentik_helpers_spec.lua.
local sub = string.sub
local len = string.len
local gmatch = string.gmatch

local _M = {}

function _M.starts_with(s, prefix)
	if not s or not prefix or prefix == "" then
		return false
	end
	return sub(s, 1, len(prefix)) == prefix
end

function _M.rstrip_slash(s)
	if not s or s == "" then
		return s
	end
	while sub(s, -1) == "/" do
		s = sub(s, 1, -2)
	end
	return s
end

-- Split a space/comma separated header list into an array of names.
function _M.split_headers(s)
	local t = {}
	if not s then
		return t
	end
	for name in gmatch(s, "[^%s,]+") do
		t[#t + 1] = name
	end
	return t
end

return _M
