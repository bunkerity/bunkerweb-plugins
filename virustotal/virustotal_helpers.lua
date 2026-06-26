-- Pure helpers extracted from virustotal.lua so they can be unit-tested with
-- busted outside the OpenResty runtime. No ngx/resty dependencies — see
-- spec/virustotal_helpers_spec.lua.
local tostring = tostring

local _M = {}

-- Decide whether a VirusTotal last_analysis_stats result is malicious. Returns the
-- string "clean" when both counts are within their thresholds, otherwise a human
-- readable "<s> suspicious and <m> malicious" summary. Thresholds use a strict ">"
-- so a count equal to its threshold is still considered clean.
function _M.evaluate(suspicious, malicious, susp_threshold, mal_threshold)
	if suspicious > susp_threshold or malicious > mal_threshold then
		return tostring(suspicious) .. " suspicious and " .. tostring(malicious) .. " malicious"
	end
	return "clean"
end

return _M
