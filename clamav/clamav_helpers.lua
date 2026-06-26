-- Pure helpers extracted from clamav.lua so they can be unit-tested with busted
-- outside the OpenResty runtime. No ngx/resty dependencies — see
-- spec/clamav_helpers_spec.lua.
local floor = math.floor

local _M = {}

-- Encode a chunk length as the 4-byte big-endian (network byte order) prefix the
-- ClamAV INSTREAM protocol expects before each chunk. The bytes are built
-- little-endian then reversed, so byte 1 is the most-significant.
function _M.stream_size(size)
	return ("%c%c%c%c")
		:format(
			size % 0x100,
			floor(size / 0x100) % 0x100,
			floor(size / 0x10000) % 0x100,
			floor(size / 0x1000000) % 0x100
		)
		:reverse()
end

return _M
