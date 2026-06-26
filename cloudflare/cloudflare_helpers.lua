-- Pure helpers extracted from cloudflare.lua so they can be unit-tested with
-- busted outside the OpenResty runtime. No ngx/resty dependencies (the IP matcher
-- is injected) — see spec/cloudflare_helpers_spec.lua.

local _M = {}

-- Split a space-separated string of IPs/networks into a list. Tolerates nil/empty
-- (the setting may be absent in the phase where initialize() runs).
function _M.parse_additional(str)
	local list = {}
	for data in (str or ""):gmatch("%S+") do
		list[#list + 1] = data
	end
	return list
end

-- Build the per-server cache key. A separator between server_name and the element
-- (an IP) prevents "example.com" .. "1.2.3.4" colliding with "example.com1" .. "2.3.4".
function _M.cache_key(server_name, ele)
	return "plugin_cloudflare_" .. tostring(server_name) .. "_" .. tostring(ele)
end

-- Map a cached trust verdict to an action. The cache stores the *string* result of
-- match_trusted ("ipv4"/"ipv6"/"additional" when trusted, "ko" when not, nil on a
-- miss). Returning a boolean here is what silently disabled the deny feature before
-- (a cached "ko" took the allow branch), hence this is unit-tested.
function _M.classify_cache(cached)
	if cached == nil then
		return "miss"
	end
	if cached == "ko" then
		return "deny"
	end
	return "allow"
end

-- True when no trusted ranges are loaded yet (all categories empty/absent). The deny
-- feature must fail OPEN in this state instead of denying everyone: the Cloudflare
-- ranges are public and load within seconds of startup, so an empty list means
-- "not ready", not "deny all" — and it avoids caching a bogus "ko" for legitimate IPs.
function _M.trusted_list_empty(trusted_ips)
	if not trusted_ips then
		return true
	end
	for _, kind in ipairs({ "ipv4", "ipv6", "additional" }) do
		local list = trusted_ips[kind]
		if list and #list > 0 then
			return false
		end
	end
	return true
end

-- Decide whether addr is a trusted Cloudflare/additional IP. Checks ipv4, then ipv6,
-- then additional, returning (true, "<kind>") on the first match, (false, "ko") when
-- nothing matches, or (nil, err) if a matcher can't be built / errors. new_matcher is
-- injected (resty.ipmatcher.new in production, a fake in tests).
function _M.match_trusted(trusted_ips, addr, new_matcher)
	for _, kind in ipairs({ "ipv4", "ipv6", "additional" }) do
		local matcher, err = new_matcher(trusted_ips[kind] or {})
		if not matcher then
			return nil, err
		end
		local matched, merr = matcher:match(addr)
		if merr then
			return nil, merr
		end
		if matched then
			return true, kind
		end
	end
	return false, "ko"
end

return _M
