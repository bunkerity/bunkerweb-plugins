-- Pure helpers extracted from syswarden.lua so they can be unit-tested with busted
-- outside the OpenResty runtime. No ngx/resty dependencies (the IP matcher is
-- injected) — see spec/syswarden_helpers_spec.lua.

local _M = {}

function _M.request_enabled(master, blocklist, whitelist)
	return master == "yes" and (blocklist == "yes" or whitelist == "yes")
end

-- True until init_worker has retained at least one compiled matcher.
function _M.matchers_empty(matchers)
	if not matchers then
		return true
	end
	for _, kind in ipairs({ "blocklist", "whitelist" }) do
		if matchers[kind] then
			return false
		end
	end
	return true
end

-- Match through an object compiled once in init_worker. A construction error is retained
-- beside it so requests fail open without rebuilding the full list.
function _M.match_any(matcher, addr, construction_error)
	if construction_error then
		return nil, construction_error
	end
	if not matcher then
		return false
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
function _M.decide(matchers, errors, addr)
	matchers = matchers or {}
	errors = errors or {}
	local matched, err = _M.match_any(matchers.whitelist, addr, errors.whitelist)
	if matched == nil then
		return nil, err
	end
	if matched then
		return "whitelisted"
	end
	matched, err = _M.match_any(matchers.blocklist, addr, errors.blocklist)
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
