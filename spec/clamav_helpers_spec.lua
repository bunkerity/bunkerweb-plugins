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
end)
