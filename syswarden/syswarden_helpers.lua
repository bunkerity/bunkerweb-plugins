-- Pure helpers extracted from syswarden.lua so they can be unit-tested with busted
-- outside the OpenResty runtime. No ngx/resty dependencies (the IP matcher is
-- injected) — see spec/syswarden_helpers_spec.lua.

local _M = {}

-- Build the per-server cache key. The separator between server_name and the element
-- keeps "example.com" .. "1.2.3.4" from colliding with "example.com1" .. ".2.3.4".
function _M.cache_key(server_name, ele)
	return "plugin_syswarden_" .. tostring(server_name) .. "_" .. tostring(ele)
end

-- Map a cached verdict to an action. The cache stores the *string* verdict
-- ("whitelisted"/"blocked"/"no-match"), so a boolean here would silently turn a
-- cached "blocked" into an allow — the exact bug that once disabled the equivalent
-- Cloudflare feature.
function _M.classify_cache(cached)
	if cached == nil then
		return "miss"
	end
	if cached == "blocked" then
		return "deny"
	end
	return "allow"
end

-- True when neither list holds an entry. The deny path must fail OPEN in this state:
-- an empty blocklist means the download job has not run yet (or the peer is down),
-- not "deny nobody's traffic is known good". It also avoids caching a verdict built
-- from a list that is not loaded.
function _M.lists_empty(lists)
	if not lists then
		return true
	end
	for _, kind in ipairs({ "blocklist", "whitelist" }) do
		local list = lists[kind]
		if list and #list > 0 then
			return false
		end
	end
	return true
end

-- Match addr against one list. Returns (true), (false) or (nil, err) when the matcher
-- can't be built or errors. new_matcher is injected (resty.ipmatcher.new in
-- production, a fake in tests).
function _M.match_any(list, addr, new_matcher)
	local matcher, err = new_matcher(list or {})
	if not matcher then
		return nil, err
	end
	local matched, merr = matcher:match(addr)
	if merr then
		return nil, merr
	end
	return matched and true or false
end

-- Decide what to do with addr. The whitelist is consulted FIRST: an address present in
-- both lists is allowed, because SysWarden's whitelist is the operator's explicit
-- override and a blocklist hit is a policy default.
--
-- Returns "whitelisted", "blocked" or "no-match", or (nil, err) so the caller can fail
-- open on an internal error instead of denying.
function _M.decide(lists, addr, new_matcher)
	lists = lists or {}
	local matched, err = _M.match_any(lists.whitelist, addr, new_matcher)
	if matched == nil then
		return nil, err
	end
	if matched then
		return "whitelisted"
	end
	matched, err = _M.match_any(lists.blocklist, addr, new_matcher)
	if matched == nil then
		return nil, err
	end
	if matched then
		return "blocked"
	end
	return "no-match"
end

-- Count entries per list, for the api() ping and the logs. Absent lists count as 0.
function _M.list_sizes(lists)
	lists = lists or {}
	return #(lists.blocklist or {}), #(lists.whitelist or {})
end

return _M
