local helpers = {}

-- Turn the judge's HTTP answer into a verdict. Only "200 + marker" is an accept: the
-- marker proves the reply came through the judge nginx conf shipped with the plugin (a
-- stock agent-unified default site, or a wrong OPENAPPSEC_API, answers 200 without it).
-- A 5xx is the judge's own failure (echo upstream gone, bad conf), not a WAF verdict,
-- so it is reported as an error and follows OPENAPPSEC_FAIL_MODE like a dead judge.
function helpers.verdict(res, err)
	if not res then
		return "error", tostring(err)
	end
	if res.status >= 500 then
		return "error", "judge returned status " .. tostring(res.status)
	end

	local headers = res.headers or {}
	local marker = headers["x-openappsec-judge"] or headers["X-Openappsec-Judge"]
	if type(marker) == "table" then
		marker = marker[1]
	end
	if res.status == 200 then
		if marker == "pass" then
			return "accept", "status 200"
		end
		return "deny", "status 200 without judge marker"
	end

	return "deny", "status " .. tostring(res.status)
end

function helpers.canary_state(res, err)
	local verdict, reason = helpers.verdict(res, err)
	if verdict == "deny" then
		return "enforcing", reason
	end
	if verdict == "accept" then
		return "not_enforcing", reason
	end
	return "down", reason
end

function helpers.canary_ttl(interval)
	return math.max((tonumber(interval) or 60) * 3, 30)
end

-- The judge's 403 carries open-appsec's event id (X-Event-ID), the same value the agent
-- logs as eventReferenceId: stored in the BunkerWeb report so a block can be traced to the
-- agent's own event (matched indicators, confidence, incident type).
function helpers.event_id(res)
	local headers = res and res.headers or {}
	local id = headers["x-event-id"] or headers["X-Event-ID"]
	if type(id) == "table" then
		id = id[1]
	end
	if type(id) == "string" and id ~= "" then
		return id
	end
	return nil
end

-- Space/comma separated setting value -> list. `transform` normalises each entry (upper for
-- methods, lower for header names); regexes are kept verbatim.
function helpers.parse_list(value, transform)
	local list = {}
	for item in tostring(value or ""):gmatch("[^%s,]+") do
		list[#list + 1] = transform and transform(item) or item
	end
	return list
end

-- `re_find(subject, pattern)` is injected (ngx.re.find in production, a plain matcher in
-- busted) so the exclusion logic stays testable outside OpenResty.
function helpers.is_excluded(uri, method, uri_patterns, methods, re_find)
	for _, m in ipairs(methods or {}) do
		if m == (method or ""):upper() then
			return true, "method " .. m
		end
	end
	for _, pattern in ipairs(uri_patterns or {}) do
		if re_find(uri or "", pattern) then
			return true, "uri matches " .. pattern
		end
	end
	return false
end

-- Remove the named headers (case-insensitive) from a headers table in place.
function helpers.strip_headers(headers, names)
	for _, name in ipairs(names or {}) do
		local lower = name:lower()
		for key in pairs(headers) do
			if type(key) == "string" and key:lower() == lower then
				headers[key] = nil
			end
		end
	end
	return headers
end

-- Whether the body should be replayed: (true) or (false, reason).
function helpers.body_policy(content_length, inspect_body, max_size)
	if not inspect_body then
		return false, "OPENAPPSEC_INSPECT_BODY is no"
	end
	if max_size and max_size > 0 and content_length and content_length > max_size then
		return false, "body of " .. content_length .. " bytes exceeds OPENAPPSEC_MAX_BODY_SIZE (" .. max_size .. ")"
	end
	return true
end

function helpers.in_cooldown(until_ts, now)
	return until_ts ~= nil and now < until_ts
end

return helpers
