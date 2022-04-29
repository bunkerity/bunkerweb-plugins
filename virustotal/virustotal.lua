local _M        = {}
_M.__index      = _M

local utils     = require "utils"
local datastore = require "datastore"
local logger    = require "logger"
local cjson		= require "cjson"
local http		= require "resty.http"
local upload	= require "resty.upload"
local sha256	= require "resty.sha256"

function _M.new()
	local self = setmetatable({}, _M)
	local value, err = utils.get_variable("VIRUSTOTAL_API", false)
	if not value then
		logger.log(ngx.ERR, "VIRUSTOTAL", "error while getting VIRUSTOTAL_API setting : " .. err)
		return nil, "error while getting VIRUSTOTAL_API setting : " .. err
	end
	self.api = value
	return self, nil
end

function _M:access()
	-- Check if VT is activated
	local check, err = utils.get_variable("USE_VIRUSTOTAL")
	if check == nil then
		return false, "error while getting variable USE_VIRUSTOTAL (" .. err .. ")", nil, nil
	end
	if check ~= "yes" then
		return true, "VirusTotal plugin not enabled", nil, nil
	end

	-- Check if we have downloads
	if not ngx.var.http_content_type:match("boundary") or not ngx.var.http_content_type:match("multipart/form%-data") then
		return true, "no file upload detected", nil, nil
	end

	-- Loop on files
	local form = upload:new(4096, 512, true)
	local process_file = false
	local hash = sha256:new()
	local all_cached = true
	while true do
		-- Read the part
		local typ, res, err = form:read()
		if not typ then
			return false, "upload read failed : " .. err, nil, nil
		end
		-- Check if header has filename pattern
		if typ == "header" and not process_file then
			local found_filename = false
			for i, data in ipairs(res) do
				if data:match("filename=") then
					process_file = true
				end
			end
		-- If we are reading a file
		elseif typ == "body" and process_file then
			hash:update(res)
		-- If it's the end of the file
		elseif typ == "part_end" and process_file then
			local final_hash = hash:final()
			-- Check if hash is already in cache
			local cached, err = self:is_in_cache(final_hash)
			if cached == nil then
				logger.log(ngx.ERR, "VIRUSTOTAL", "can't check the hashes cache : " .. err)
			elseif not cached then
				all_cached = false
			elseif cached ~= "clean" then
				return true, "file with hash " .. final_hash .. " is detected (from cache)", true, ngx.HTTP_FORBIDDEN
			end
			hash:reset()
			process_file = false
		-- End of parsing
		elseif typ == "eof" then
			break
		end 
	end

	-- Send files to VirusTotal API if needed
	if not all_cached then
		local ok, err, status, data = self:request("POST", "/check")
		if not ok then
			return false, "error from request : " .. err, nil, nil
		end
		if not data.success then
			return false, "error from VirusTotal API : " .. data.error, nil, nil
		end
		local is_infected = false
		for hash, infected in pairs(data.results) do
			if infected then
				is_infected = true
				logger.log(ngx.WARN, "VIRUSTOTAL", "file with hash " .. hash .. " is detected (not cached)")
				local ok, err = self:add_to_cache(hash, "infected")
				if not ok then
					logger.log(ngx.ERR, "VIRUSTOTAL", "can't add file hash to cache : " .. err)
				end
			else
				logger.log(ngx.INFO, "VIRUSTOTAL", "file with hash " .. hash .. " is not detected (not cached)")
				local ok, err = self:add_to_cache(hash, "clean")
				if not ok then
					logger.log(ngx.ERR, "VIRUSTOTAL", "can't add file hash to cache : " .. err)
				end
			end
		end
		if is_infected then
			return true, "at least one file is infected", true, ngx.HTTP_FORBIDDEN
		end
	end

	return true, "success", nil, nil
end

function _M:request(method, url)
	local httpc, err = http.new()
	if not httpc then
		return false, "can't instantiate http object : " .. err, nil, nil
	end
	local res = nil
	local err_http = "unknown error"
	if method == "GET" then
		res, err_http = httpc:request_uri(self.api .. url, {
			method = method,
		})
	else
		local body, err = httpc:get_client_body_reader()
		if not reader then
			ngx.req.read_body()
			body = ngx.req.get_body_data()
			if not body then
				local body_file = ngx.req.get_body_file()
				if not body_file then
					return false, "can't access client body", nil, nil
				end
				local f, err = io.open(body_file, "rb")
				if not f then
					return false, "can't read body from file " .. body_file .. " : " .. err, nil, nil
				end
				f:close()
				body = io.lines(body_file)
			end
		end
		res, err_http = httpc:request_uri(self.api .. url, {
			method = method,
			headers = ngx.req.get_headers(),
			body = body
		})
	end
	httpc:close()
	if not res then
		return false, "error while sending request : " .. err_http, nil, nil
	end
	local ok, ret = pcall(cjson.decode, res.body)
	if not ok then
		return false, "error while decoding json : " .. ret, nil, nil
	end
	return true, "success", res.status, ret
end

function _M:is_in_cache(ele) 
	local ret, err = datastore:get("plugin_virustotal_cache_" .. ele)
	if not ret then
		if err ~= "not found" then
			logger.log(ngx.ERR, "VIRUSTOTAL", "Error while accessing cache : " .. err)
		end
		return false, err
	end
	return ret, "success"
end

function _M:add_to_cache(ele, kind)
	local ok, err = datastore:set("plugin_virustotal_cache_" .. ele, kind, 86400)
	if not ok then
		logger.log(ngx.ERR, "VIRUSTOTAL", "Error while adding element to cache : " .. err)
		return false, err
	end
	return true, "success"
end

return _M
