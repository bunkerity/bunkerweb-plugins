-- Minimal stand-in for resty.ipmatcher used by the busted specs. The real matcher
-- needs OpenResty; the helper under test only relies on the (new -> :match) contract,
-- so an exact-membership fake is enough to exercise the ordering / sentinel logic.
local _M = {}

local matcher = {}
matcher.__index = matcher

function matcher:match(addr)
	for _, ip in ipairs(self.list) do
		if ip == addr then
			return true
		end
	end
	return false
end

-- Normal factory: build a matcher over an exact-match list.
function _M.new(list)
	return setmetatable({ list = list }, matcher)
end

-- Factory that fails to build (drives the (nil, err) construction-error path).
function _M.new_err()
	return nil, "construction boom"
end

-- Factory that succeeds once then fails, so the SECOND matcher decide() builds (the
-- blocklist one, after the whitelist) is the one that errors. Without this the blocklist
-- error branch is never reached: a matcher error there would fall through as "no-match",
-- which the caller caches as an allow for the whole TTL.
function _M.new_second_err(list)
	_M._built = (_M._built or 0) + 1
	if _M._built >= 2 then
		return nil, "blocklist boom"
	end
	return setmetatable({ list = list }, matcher)
end

-- Reset the counter used by new_second_err between examples.
function _M.reset()
	_M._built = 0
end

-- Factory whose :match errors (drives the (nil, err) match-error path).
function _M.new_match_err(list)
	return setmetatable({ list = list }, {
		__index = {
			match = function()
				return nil, "match boom"
			end,
		},
	})
end

return _M
