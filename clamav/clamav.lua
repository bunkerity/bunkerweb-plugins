-- ClamAV plugin for BunkerWeb with improved multipart parsing and HTTP/2 support
local class = require("middleclass")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local clamav = class("clamav", plugin)

local ngx = ngx
local ERR = ngx.ERR
local NOTICE = ngx.NOTICE
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN
local HTTP_OK = ngx.HTTP_OK
local has_variable = utils.has_variable
local get_deny_status = utils.get_deny_status

local bit = require("bit")

function clamav:initialize(ctx)
  plugin.initialize(self, "clamav", ctx)
end

function clamav:socket()
  local sock = ngx.socket.tcp()
  sock:settimeout(tonumber(self.variables["CLAMAV_TIMEOUT"] or 5000))
  local ok, err = sock:connect(self.variables["CLAMAV_HOST"], tonumber(self.variables["CLAMAV_PORT"]))
  if not ok then
    return nil, err
  end
  return sock
end

function clamav:ping()
  local sock, err = self:socket()
  if not sock then
    return false, err
  end
  local ok = sock:send("nPING\n")
  if not ok then
    sock:close()
    return false, "send failed"
  end
  local res = sock:receive("*l")
  sock:close()
  return res == "PONG", res
end

-- Improved boundary extraction function with better quote handling
function clamav:extract_boundary(content_type)
  if not content_type then
    return nil
  end
  
  -- Handle both boundary=value and boundary="value" formats
  local boundary = content_type:match('boundary=([^;%s]+)')
  if not boundary then
    boundary = content_type:match('boundary="([^"]+)"')
  end
  
  if boundary then
    -- Remove quotes if present
    boundary = boundary:gsub('^"', ''):gsub('"$', '')
    return "--" .. boundary
  end
  
  return nil
end

-- Enhanced multipart parsing function with proper HTTP/2 support
function clamav:parse_multipart(body, boundary)
  if not body or not boundary then
    return {}
  end
  
  local parts = {}
  
  -- Split body by boundary markers
  local sections = {}
  local current_pos = 1
  
  -- Find first boundary
  local first_boundary_pos = body:find(boundary, 1, true)
  if not first_boundary_pos then
    return {}
  end
  
  current_pos = first_boundary_pos + #boundary
  
  while true do
    -- Find next boundary
    local next_boundary_pos = body:find(boundary, current_pos, true)
    if not next_boundary_pos then
      -- Last section
      local section = body:sub(current_pos)
      if section and #section > 10 then -- Minimum length check
        table.insert(sections, section)
      end
      break
    end
    
    -- Extract section from current position to next boundary
    local section = body:sub(current_pos, next_boundary_pos - 1)
    if section and #section > 10 then -- Minimum length check
      table.insert(sections, section)
    end
    
    current_pos = next_boundary_pos + #boundary
    
    -- Check for end boundary (ends with --)
    if body:sub(current_pos, current_pos + 1) == "--" then
      break
    end
  end
  
  -- Parse each section into headers and data
  for i, section in ipairs(sections) do
    if section and #section > 0 then
      -- Remove leading whitespace and newlines
      section = section:gsub("^%s*\r?\n", "")
      
      -- Separate headers and body (\r\n\r\n or \n\n)
      local header_end = section:find("\r\n\r\n", 1, true)
      local separator_len = 4
      if not header_end then
        header_end = section:find("\n\n", 1, true)
        separator_len = 2
      end
      
      if header_end then
        local headers = section:sub(1, header_end - 1)
        local data = section:sub(header_end + separator_len)
        
        -- Remove trailing \r\n
        data = data:gsub("\r\n$", ""):gsub("\n$", "")
        
        -- Extract filename from Content-Disposition header
        local filename = self:extract_filename(headers)
        if filename and #data > 0 then
          table.insert(parts, {
            headers = headers,
            data = data,
            filename = filename
          })
        end
      end
    end
  end
  
  return parts
end

-- Improved filename extraction function
function clamav:extract_filename(headers)
  if not headers then
    return nil
  end
  
  -- Extract filename from Content-Disposition header
  local content_disposition = headers:match("Content%-Disposition:%s*([^\r\n]+)")
  if not content_disposition then
    return nil
  end
  
  -- Handle both filename="value" and filename=value formats
  local filename = content_disposition:match('filename="([^"]+)"')
  if not filename then
    filename = content_disposition:match('filename=([^;%s\r\n]+)')
  end
  
  return filename
end

function clamav:api()
  if self.ctx.bw.uri == "/clamav/ping" and self.ctx.bw.request_method == "POST" then
    local enabled, err = has_variable("USE_CLAMAV", "yes")
    if not enabled then
      return self:ret(true, "ClamAV plugin not enabled")
    end
    local ok, res = self:ping()
    if not ok then
      return self:ret(true, "ClamAV ping failed: " .. tostring(res), HTTP_INTERNAL_SERVER_ERROR)
    end
    return self:ret(true, "ClamAV ping successful", HTTP_OK)
  end
  return self:ret(false, "success")
end

function clamav:access()
  -- Check if ClamAV plugin is enabled
  if self.variables["USE_CLAMAV"] ~= "yes" then
    return self:ret(true, "ClamAV plugin not enabled")
  end

  -- Only process POST requests
  if ngx.req.get_method() ~= "POST" then
    return self:ret(true, "Not a POST request")
  end

  -- Check for multipart/form-data content type
  local content_type = ngx.var.content_type or ngx.req.get_headers()["content-type"]
  if not content_type or not content_type:find("multipart/form-data", 1, true) then
    return self:ret(true, "Not a multipart/form-data request")
  end

  -- Extract boundary from content type
  local boundary = self:extract_boundary(content_type)
  if not boundary then
    self.logger:log(ERR, "[clamav] No boundary found in Content-Type")
    return self:ret(true, "Invalid multipart/form-data")
  end

  -- Read request body
  ngx.req.read_body()
  local body = ngx.req.get_body_data()
  if not body then
    local file_path = ngx.req.get_body_file()
    if file_path then
      local f = io.open(file_path, "rb")
      if f then
        body = f:read("*a")
        f:close()
      end
    end
  end

  if not body then
    self.logger:log(ERR, "[clamav] Failed to read request body")
    return self:ret(true, "Empty request body")
  end

  -- Parse multipart data to extract file parts
  local parts = self:parse_multipart(body, boundary)

  -- Scan each file part with ClamAV
  for i, part in ipairs(parts) do
    if #part.data > 0 then
      local sock, err = self:socket()
      if not sock then
        self.logger:log(ERR, "[clamav] Socket error: " .. tostring(err))
        return self:ret(false, "Socket error: " .. err)
      end

      -- Initiate INSTREAM command
      local ok = sock:send("nINSTREAM\n")
      if not ok then
        self.logger:log(ERR, "[clamav] Failed to initiate INSTREAM")
        sock:close()
        return self:ret(false, "Failed to initiate INSTREAM")
      end

      -- Send file size as 4-byte big-endian integer
      local len = #part.data
      local prefix = string.char(
        bit.rshift(len, 24),
        bit.band(bit.rshift(len, 16), 0xFF),
        bit.band(bit.rshift(len, 8), 0xFF),
        bit.band(len, 0xFF)
      )
      
      local sent = sock:send(prefix .. part.data)
      if not sent then
        self.logger:log(ERR, "[clamav] Failed to send file data")
        sock:close()
        return self:ret(false, "Failed to send file data")
      end

      -- Send stream termination marker
      sock:send(string.char(0, 0, 0, 0))
      local result = sock:receive("*l")
      sock:close()

      if not result then
        self.logger:log(ERR, "[clamav] No response from ClamAV")
        return self:ret(false, "No response from ClamAV")
      else
        self.logger:log(ERR, "[clamav] ClamAV result for " .. part.filename .. ": " .. tostring(result))
      end

      -- Check if malware was detected
      if result and result:find("FOUND") then
        return self:ret(true, "Malware detected in " .. part.filename .. ": " .. result, get_deny_status(), nil, {
          id = "clamav",
          result = result,
          filename = part.filename
        })
      end
    end
  end

  if #parts == 0 then
    return self:ret(true, "No files found in multipart data")
  end

  return self:ret(true, "No malware detected")
end

return clamav