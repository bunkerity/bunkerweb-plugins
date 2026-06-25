-- Pure helpers extracted from discord.lua so they can be unit-tested with busted
-- outside the OpenResty runtime. No ngx/resty dependencies — see
-- spec/discord_helpers_spec.lua.
local len = string.len
local sub = string.sub

local _M = {}

-- Discord embed field values are capped at 1024 characters. Truncate to 1021 and
-- append "..." so the value always fits, leaving shorter strings untouched.
function _M.format_field(input_string)
	if len(input_string) <= 1021 then
		return input_string
	end
	return sub(input_string, 1, 1021) .. "..."
end

return _M
