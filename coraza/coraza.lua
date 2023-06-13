local class  = require "middleclass"
local plugin = require "bunkerweb.plugin"
local utils  = require "bunkerweb.utils"
local http   = require "resty.http"
local cjson  = require "cjson"
local coraza = class("coraza", plugin)

function coraza:initialize()
    -- Call parent initialize
    plugin.initialize(self, "coraza")
end

function coraza:init_worker()
    -- Check if needed
    if not self:is_needed() then
        return self:ret(true, "coraza not activated")
    end
    -- Send ping request
    local ok, data = self:ping()
    if not ok then
        return self:ret(false, "error while sending ping request to " .. self.variables["CORAZA_API"] .. " : " .. data)
    end
    return self:ret(true, "ping request to " .. self.variables["CORAZA_API"] .. " is successful")
end

function coraza:access()
    -- Check if needed
    if not self.is_needed then
        return self:ret(true, "coraza not activated")
    end
    -- Generate transaction ID
    self.ctx.bw.coraza_txid = utils.rand(16)
    -- Process phases 1 (headers) and 2 (body)
    local ok, deny, data = self:process_request()
    if not ok then
        return self:ret(false, "error while processing request : " .. deny)
    end
    if deny then
        return self:ret(true, "coraza denied request : " .. data, utils.get_deny_status(self.ctx))
    end
    return self:ret(true, "coraza accepted request")
end

function coraza:ping()
    -- Get http object
    local httpc, err = http.new()
    if not httpc then
        return false, err
    end
    httpc:set_timeout(1000)
    -- Send ping
    local res, err = httpc:request_uri(self.variables["CORAZA_API"] .. "/ping", { keepalive = false })
    if not res then
        return false, err
    end
    -- Check status
    if res.status ~= 200 then
        local err = "received status " .. tostring(res.status) .. " from Coraza API"
        local ok, data = pcall(cjson.decode, res.body)
        if ok then
            err = err .. " with data " .. data
        end
        return false, err
    end
    -- Get pong
    local ok, data = pcall(cjson.decode, res.body)
    if not ok then
        return false, data
    end
    if data.pong == nil then
        return false, "malformed json response"
    end
    return true
end

function coraza:process_request()
    -- -- Get http object
    -- local httpc, err = http.new()
    -- if not httpc then
    --     return false, err
    -- end
    -- httpc:set_timeout(2500)
    -- -- Get request headers
    -- local headers, err = ngx.req.get_headers(nil, true)
    -- if err == "truncated" then
    --     return true, true, "too many headers"
    -- end
    -- if not headers then
    --     return false, err
    -- end
    -- -- Compute API headers
    -- -- local headers = {
    -- --     ["X-Coraza-ID"] = self.ctx.bw.coraza_txid,
    -- --     ["X-Coraza-IP"] = self.ctx.bw.remote_addr,
    -- --     ["X-Coraza-URI"] = self.ctx.bw.request_uri,
    -- --     ["X-Coraza-METHOD"] = self.ctx.bw.request_method,
    -- --     ["X-Coraza-VERSION"] = "HTTP/" .. tostring(self.ctx.bw.http_version),
    -- --     ["X-Coraza-HEADERS"] = cjson.encode(headers)
    -- -- }
    -- -- Compute body reader
    -- local body = false
    -- if ngx.var.http_transfer_encoding then
    --     body = "chunked"
    --     headers["Transfer-Encoding"] = ngx.var.http_transfer_encoding
    -- elseif self.ctx.bw.http_content_length then
    --     body = "length"
    --     headers["Content-Length"] = self.ctx.bw.http_content_length
    -- end
    -- local downstream_reader = nil
    -- if body then
    --     -- local client_body_reader, err = httpc:get_client_body_reader()
    --     -- if err then
    --     --     return false, err
    --     -- end
    --     local sock, err = ngx.req.socket(true)
    --     if not sock then
    --         return false, err
    --     end
    --     local obj
    --     ngx.req.init_body()
    --     downstream_reader = function()
    --         local data, err, partial = sock:receive(8192)
    --         if data then
    --             ngx.req.append_body(data)
    --         end
    --         return data
    --     end
    --     -- 
    --     -- downstream_reader = function()
    --     --     local chunk = client_body_reader(8192)
    --     --     if chunk then
    --     --         ngx.req.append_body(chunk)
    --     --     end
    --     --     return chunk
    --     -- end
    -- end
    -- -- Send request
    -- local res, err = httpc:request_uri(self.variables["CORAZA_API"] .. "/request",
    --     {
    --         method = "POST",
    --         body = downstream_reader,
    --         headers = headers,
    --         keepalive = false
    --     }
    -- )
    -- if not res then
    --     httpc:close()
    --     return false, err
    -- end
    -- Send subrequest
    local res = ngx.location.capture("/bw/coraza" .. self.ctx.bw.request_uri, {
        method = self.ctx.bw.request_method,
        always_forward_body = true
    })
    -- Check status
    if res.status ~= 200 then
        local err = "received status " .. tostring(res.status) .. " from Coraza API"
        local ok, data = pcall(cjson.decode, res.body)
        if ok then
            err = err .. " with data " .. data
        end
        --httpc:close()
        return false, err
    end
    -- Get result
    local ok, data = pcall(cjson.decode, res.body)
    if not ok then
        --httpc:close()
        return false, data
    end
    if data.deny == nil or not data.msg then
        --httpc:close()
        return false, "malformed json response"
    end
    --httpc:close()
    return true, data.deny, data.msg
end

function coraza:is_needed()
    -- Loading case
    if self.is_loading then
        return false
    end
    -- Request phases (no default)
    if self.is_request and (self.ctx.bw.server_name ~= "_") then
        return self.variables["USE_CORAZA"] == "yes"
    end
    -- Other cases : at least one service uses it
    local is_needed, err = utils.has_variable("USE_CORAZA", "yes")
    if is_needed == nil then
        self.logger:log(ngx.ERR, "can't check USE_CORAZA variable : " .. err)
    end
    return is_needed
end

return coraza
