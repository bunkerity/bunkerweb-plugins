-- luacheck: std min+busted
local helpers = require("sentinelone/sentinelone_helpers")

describe("sentinelone helpers", function()
	describe("evaluate", function()
		it("returns clean when the rank is below the threshold", function()
			assert.equals("clean", helpers.evaluate(0, 7))
			assert.equals("clean", helpers.evaluate(6, 7))
		end)
		it("flags a rank exactly equal to its threshold (>=)", function()
			assert.equals("rank 7 >= threshold 7", helpers.evaluate(7, 7))
			assert.equals("rank 3 >= threshold 3", helpers.evaluate(3, 3))
		end)
		it("flags a rank above its threshold", function()
			assert.equals("rank 10 >= threshold 7", helpers.evaluate(10, 7))
		end)
		it("treats a nil / non-numeric rank as clean", function()
			assert.equals("clean", helpers.evaluate(nil, 7))
			assert.equals("clean", helpers.evaluate("not a number", 7))
		end)
		it("accepts string inputs", function()
			assert.equals("rank 8 >= threshold 7", helpers.evaluate("8", "7"))
		end)
	end)

	describe("is_malicious", function()
		it("is true when the IOC array is non-empty", function()
			assert.is_true(helpers.is_malicious({ { uuid = "x" } }))
			assert.is_true(helpers.is_malicious({ { uuid = "a" }, { uuid = "b" } }))
		end)
		it("is false for an empty array", function()
			assert.is_false(helpers.is_malicious({}))
		end)
		it("is false for nil / non-table input", function()
			assert.is_false(helpers.is_malicious(nil))
			assert.is_false(helpers.is_malicious("listed"))
		end)
	end)

	describe("is_http2_plus", function()
		it("is false for HTTP/1.x", function()
			assert.is_false(helpers.is_http2_plus(1.1, "HTTP/1.1"))
			assert.is_false(helpers.is_http2_plus(1.0, "HTTP/1.0"))
		end)
		it("is true for HTTP/2 and HTTP/3 by version number", function()
			assert.is_true(helpers.is_http2_plus(2.0, "HTTP/2.0"))
			assert.is_true(helpers.is_http2_plus(3.0, "HTTP/3.0"))
		end)
		it("falls back to server_protocol when the version is nil", function()
			assert.is_true(helpers.is_http2_plus(nil, "HTTP/2.0"))
			assert.is_true(helpers.is_http2_plus(nil, "HTTP/3.0"))
			assert.is_false(helpers.is_http2_plus(nil, "HTTP/1.1"))
			assert.is_false(helpers.is_http2_plus(nil, nil))
		end)
		it("accepts a string http_version", function()
			assert.is_true(helpers.is_http2_plus("2.0", nil))
		end)
	end)

	describe("multipart helpers", function()
		local CRLF = "\r\n"
		-- Build a multipart body from raw part strings (each part already contains
		-- its headers, a blank line, then its content).
		local function body_of(boundary, ...)
			local out = {}
			for _, raw in ipairs({ ... }) do
				out[#out + 1] = "--" .. boundary .. CRLF .. raw .. CRLF
			end
			out[#out + 1] = "--" .. boundary .. "--" .. CRLF
			return table.concat(out)
		end
		local function file_part(disposition, content)
			return disposition .. CRLF .. "Content-Type: application/octet-stream" .. CRLF .. CRLF .. content
		end

		describe("get_boundary", function()
			it("reads a quoted boundary", function()
				assert.equals("abc123", helpers.get_boundary('multipart/form-data; boundary="abc123"'))
			end)
			it("reads a bare-token boundary", function()
				assert.equals("abc123", helpers.get_boundary("multipart/form-data; boundary=abc123"))
			end)
			it("returns nil when absent", function()
				assert.is_nil(helpers.get_boundary("application/json"))
				assert.is_nil(helpers.get_boundary(nil))
			end)
		end)

		describe("parse_multipart", function()
			it("extracts a quoted filename and exact content", function()
				local b = body_of(
					"X",
					file_part('Content-Disposition: form-data; name="file"; filename="hello.txt"', "EICAR-BODY")
				)
				local parts = helpers.parse_multipart(b, "X")
				assert.equals(1, #parts)
				assert.equals("hello.txt", parts[1].filename)
				assert.equals("EICAR-BODY", parts[1].content)
			end)
			it("extracts an unquoted filename", function()
				local b =
					body_of("X", file_part("Content-Disposition: form-data; name=file; filename=plain.txt", "data"))
				local parts = helpers.parse_multipart(b, "X")
				assert.equals(1, #parts)
				assert.equals("plain.txt", parts[1].filename)
				assert.equals("data", parts[1].content)
			end)
			it("captures an RFC 5987 filename*= part (filename left nil)", function()
				local b = body_of(
					"X",
					file_part("Content-Disposition: form-data; name=file; filename*=UTF-8''na%C3%AFve.txt", "body5987")
				)
				local parts = helpers.parse_multipart(b, "X")
				assert.equals(1, #parts)
				assert.is_nil(parts[1].filename)
				assert.equals("body5987", parts[1].content)
			end)
			it("returns every file part when several are present", function()
				local b = body_of(
					"X",
					file_part('Content-Disposition: form-data; name="a"; filename="a.txt"', "AAA"),
					file_part('Content-Disposition: form-data; name="b"; filename="b.bin"', "BBB")
				)
				local parts = helpers.parse_multipart(b, "X")
				assert.equals(2, #parts)
				assert.equals("a.txt", parts[1].filename)
				assert.equals("AAA", parts[1].content)
				assert.equals("b.bin", parts[2].filename)
				assert.equals("BBB", parts[2].content)
			end)
			it("skips form fields that have no filename", function()
				local field = 'Content-Disposition: form-data; name="field1"' .. CRLF .. CRLF .. "just a value"
				local b = body_of(
					"X",
					field,
					file_part('Content-Disposition: form-data; name="file"; filename="f.txt"', "FILE")
				)
				local parts = helpers.parse_multipart(b, "X")
				assert.equals(1, #parts)
				assert.equals("f.txt", parts[1].filename)
				assert.equals("FILE", parts[1].content)
			end)
			it('does not treat name="myfilename" as a file part', function()
				local field = 'Content-Disposition: form-data; name="myfilename"' .. CRLF .. CRLF .. "value"
				local parts = helpers.parse_multipart(body_of("X", field), "X")
				assert.equals(0, #parts)
			end)
			it("preserves binary content with embedded CRLF and NUL bytes", function()
				local content = "line1" .. CRLF .. "line2" .. string.char(0) .. "end"
				local b = body_of("X", file_part('Content-Disposition: form-data; name="f"; filename="b.bin"', content))
				local parts = helpers.parse_multipart(b, "X")
				assert.equals(1, #parts)
				assert.equals(content, parts[1].content)
			end)
			it("ignores a preamble before the first boundary", function()
				local b = "This is a preamble"
					.. CRLF
					.. body_of("X", file_part('Content-Disposition: form-data; name="f"; filename="p.txt"', "PRE"))
				local parts = helpers.parse_multipart(b, "X")
				assert.equals(1, #parts)
				assert.equals("PRE", parts[1].content)
			end)
			it("does not split on a bare --boundary that is not CRLF-anchored (no scan bypass)", function()
				-- An attacker embeds raw "--X" inside file content. RFC delimiters are
				-- CRLF-anchored, so this must stay part of the single scanned file, not
				-- split into a second filename-less part that would be skipped.
				local content = "harmless prefix --X still the same file --X tail"
				local b = body_of("X", file_part('Content-Disposition: form-data; name="f"; filename="m.bin"', content))
				local parts = helpers.parse_multipart(b, "X")
				assert.equals(1, #parts)
				assert.equals(content, parts[1].content)
			end)
			it("returns an empty list for nil/empty/garbage input", function()
				assert.same({}, helpers.parse_multipart(nil, "X"))
				assert.same({}, helpers.parse_multipart("whatever", nil))
				assert.same({}, helpers.parse_multipart("whatever", ""))
				assert.same({}, helpers.parse_multipart("no boundary here", "X"))
			end)
		end)
	end)
end)
