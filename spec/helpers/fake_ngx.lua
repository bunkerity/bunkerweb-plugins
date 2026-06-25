-- Skeleton fake ngx/resty harness for FUTURE whole-plugin busted specs
-- (Strategy 2). Not wired up yet: today we unit-test the pure helper module
-- directly (spec/authentik_helpers_spec.lua). Flesh this out when adding
-- coverage for hook methods that touch the OpenResty runtime (sockets, http,
-- ngx.req, ...). Kept minimal on purpose so it does not pretend to cover more
-- than it does.
local _M = {}

-- Install a minimal global `ngx` table good enough to `require` a plugin file
-- without erroring at load time. Returns the installed table.
function _M.install()
	_G.ngx = _G.ngx
		or {
			ERR = 1,
			WARN = 2,
			INFO = 3,
			HTTP_INTERNAL_SERVER_ERROR = 500,
			HTTP_MOVED_TEMPORARILY = 302,
			req = {
				get_headers = function()
					return {}
				end,
				set_header = function() end,
				clear_header = function() end,
				is_internal = function()
					return false
				end,
			},
			log = function() end,
			var = {},
			escape_uri = function(s)
				return s
			end,
		}
	return _G.ngx
end

return _M
