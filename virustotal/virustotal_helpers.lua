-- Pure helpers extracted from virustotal.lua so they can be unit-tested with
-- busted outside the OpenResty runtime. No ngx/resty dependencies — see
-- spec/virustotal_helpers_spec.lua.
local tostring = tostring
local tonumber = tonumber
local type = type

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

-- Return true when the request uses HTTP/2 or HTTP/3, where resty.upload cannot
-- read the raw downstream socket (ngx.req.socket() raises "http v2 not supported
-- yet"). Accepts ngx.req.http_version() (a number like 1.1/2.0/3.0) and/or
-- ngx.var.server_protocol ("HTTP/1.1"/"HTTP/2.0"/"HTTP/3.0"); either may be nil.
function _M.is_http2_plus(http_version, server_protocol)
	local v = tonumber(http_version)
	if v and v >= 2 then
		return true
	end
	if type(server_protocol) == "string" and server_protocol:find("^HTTP/[23]") then
		return true
	end
	return false
end

-- Extract the multipart boundary token (without the leading "--") from a
-- Content-Type header value. Handles both the quoted (boundary="...") and the
-- bare-token (boundary=...) forms. Returns nil when absent.
function _M.get_boundary(content_type)
	if type(content_type) ~= "string" then
		return nil
	end
	return content_type:match(';%s*boundary="([^"]+)"') or content_type:match(';%s*boundary=([^",;]+)')
end

-- Parse a buffered multipart/form-data body into a list of file parts. Returns an
-- array of { filename = <string|nil>, content = <string> }, one entry per part
-- whose Content-Disposition header carries a filename; non-file fields are skipped.
-- Returns {} for nil/empty/garbage input or a missing boundary. The content bytes
-- are exactly what resty.upload yields as "body" chunks, so SHA checksums match the
-- streaming HTTP/1.x path. Used by the HTTP/2/3 fallback path where the raw request
-- socket (and thus resty.upload) is unavailable.
--
-- Delimiters are anchored on CRLF ("\r\n--boundary"), per RFC 7578 and exactly as
-- lua-resty-upload frames parts. This is security-critical: a bare "--boundary" not
-- preceded by CRLF must NOT be treated as a delimiter, otherwise an attacker could
-- embed it inside file content to split a part and hide bytes from the scanner on
-- the HTTP/2/3 path that the HTTP/1.x path would scan. The body is virtually
-- prefixed with CRLF so the opening boundary (at offset 0) matches the same search.
function _M.parse_multipart(body, boundary)
	local parts = {}
	if type(body) ~= "string" or type(boundary) ~= "string" or boundary == "" then
		return parts
	end
	local data = "\r\n" .. body
	local delim = "\r\n--" .. boundary
	local dlen = #delim
	-- Locate the opening delimiter; anything before it is the (usually empty) preamble.
	local _, e = data:find(delim, 1, true)
	if not e then
		return parts
	end
	local pos = e + 1
	while true do
		-- "--" right after a delimiter marks the closing delimiter "--boundary--".
		if data:sub(pos, pos + 1) == "--" then
			break
		end
		-- The part runs from here (just past the boundary line's CRLF) to the next delimiter.
		local ns = data:find(delim, pos, true)
		if not ns then
			break
		end
		local seg = data:sub(pos, ns - 1)
		-- Strip the line break that terminated the boundary line (the line break
		-- before the next delimiter belongs to that delimiter, so it is not in seg).
		if seg:sub(1, 2) == "\r\n" then
			seg = seg:sub(3)
		elseif seg:sub(1, 1) == "\n" then
			seg = seg:sub(2)
		end
		-- Split headers from content at the first blank line.
		local _, he = seg:find("\r\n\r\n", 1, true)
		if not he then
			_, he = seg:find("\n\n", 1, true)
		end
		if he then
			local headers = seg:sub(1, he)
			local content = seg:sub(he + 1)
			-- Only parts with a Content-Disposition filename are scanned. The
			-- %f[%a] frontier rejects fields like name="myfilename" and the
			-- trailing "=" rejects name="filename"; covers quoted, unquoted and
			-- RFC 5987 filename*= forms (the same matcher used on the streaming path).
			if headers:find("%f[%a]filename%*?%s*=") then
				local filename = headers:match('filename="([^"]*)"') or headers:match("filename=([^;\r\n]+)")
				parts[#parts + 1] = { filename = filename, content = content }
			end
		end
		pos = ns + dlen
	end
	return parts
end

return _M
