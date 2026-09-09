-- luacheck: std min+busted
local helpers = require("clamav/clamav_helpers")

describe("clamav helpers", function()
	describe("stream_size", function()
		-- The ClamAV INSTREAM protocol prefixes each chunk with its length as a
		-- 4-byte unsigned integer in network byte order (big-endian, MSB first).
		local function bytes(s)
			local out = {}
			for i = 1, #s do
				out[i] = string.byte(s, i)
			end
			return out
		end

		it("encodes zero as four zero bytes", function()
			assert.same({ 0, 0, 0, 0 }, bytes(helpers.stream_size(0)))
		end)
		it("encodes a one-byte value big-endian", function()
			assert.same({ 0, 0, 0, 1 }, bytes(helpers.stream_size(1)))
			assert.same({ 0, 0, 0, 255 }, bytes(helpers.stream_size(255)))
		end)
		it("carries into the second byte", function()
			assert.same({ 0, 0, 1, 0 }, bytes(helpers.stream_size(256)))
		end)
		it("carries into the third byte", function()
			assert.same({ 0, 1, 0, 0 }, bytes(helpers.stream_size(65536)))
		end)
		it("encodes a value spanning all four bytes", function()
			-- 0x01020304 -> {1, 2, 3, 4}
			assert.same({ 1, 2, 3, 4 }, bytes(helpers.stream_size(0x01020304)))
		end)
		it("always returns exactly four bytes", function()
			assert.equals(4, #helpers.stream_size(0))
			assert.equals(4, #helpers.stream_size(0xFFFFFFFF))
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

	describe("parse_instream_result", function()
		it("extracts a detected signature", function()
			local verdict, unscannable = helpers.parse_instream_result("stream: Eicar-Test-Signature FOUND")
			assert.equals("Eicar-Test-Signature", verdict)
			assert.is_false(unscannable)
		end)
		it("treats an OK line as clean", function()
			local verdict, unscannable = helpers.parse_instream_result("stream: OK")
			assert.equals("clean", verdict)
			assert.is_false(unscannable)
		end)
		it("flags a size-limit notice as unscannable", function()
			local verdict, unscannable = helpers.parse_instream_result("INSTREAM size limit exceeded")
			assert.equals("clean", verdict)
			assert.is_true(unscannable)
		end)
		it("handles a nil line", function()
			local verdict, unscannable = helpers.parse_instream_result(nil)
			assert.equals("clean", verdict)
			assert.is_false(unscannable)
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
