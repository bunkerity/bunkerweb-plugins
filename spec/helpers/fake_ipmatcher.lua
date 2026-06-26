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
