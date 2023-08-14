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
    -- Process phases 1 (headers) and 2 (body)

    local ok, deny, data = self:process_request()
    if not ok then
        return self:ret(false, "error while processing request : " .. deny )
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
    -- Instantiate lua-resty-http obj
    local httpc, err = http.new()
    if not httpc then
        return false, err
    end
    -- Variables to pass to coraza
    local data = {
        ["X-Coraza-Version"] = ngx.req.http_version(),
        ["X-Coraza-Method"] = self.ctx.bw.request_method,
        ["X-Coraza-Ip"] = self.ctx.bw.remote_addr,
        ["X-Coraza-Id"] =  utils.rand(16),
        ["X-Coraza-Uri"] = self.ctx.bw.request_uri
    }
    -- Compute headers
    local headers, err = ngx.req.get_headers()
    if err == "truncated" then
        return true, true, "too many headers"
    end 
    for header, value in pairs(headers) do
        data["X-Coraza-Header-" .. header] = value
    end
    -- Body setup
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local handle, err = io.open(file)
            if handle then
                data["Content-Length"] = tostring(handle:seek("end"))
                handle:close()
            end
            body = function()
                local handle, err = io.open(file)
                if not handle then
                    return nil, err
                end
                local cbody = function()
                    while true do
                        local chunk = handle:read(8192)
                        if not chunk then
                            break
                        end
                        coroutine.yield(chunk)
                    end
                    handle:close()
                end
                local co = coroutine.create(cbody)
                return function(...)
                    local ok, ret = coroutine.resume(co, ...)
                    if ok then
                        return ret
                    end
                    return nil, ret
                end
            end
        end
    end
    local res, err = httpc:request_uri(
        self.variables["CORAZA_API"] .. "/request",
        {
            method = "POST",
            headers = data,
            body = body()
        }
    )
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
    -- Get result
    local ok, data = pcall(cjson.decode, res.body)
    if not ok then
        return false, data
    end
    if data.deny == nil or not data.msg then
        return false, "malformed json response"
    end
    return true, data.deny, data.msg
end

function coraza:is_needed()
    -- Loading case
    if self.is_loading then
        return false
    end
    -- Request phases (no default)
    if self.is_request and (self.ctx.bw.server_name ~= "_") then
        return self.variables["USE_CORAZA"] == "yes" and not ngx.req.is_internal()
    end
    -- Other cases : at least one service uses it
    local is_needed, err = utils.has_variable("USE_CORAZA", "yes")
    if is_needed == nil then
        self.logger:log(ngx.ERR, "can't check USE_CORAZA variable : " .. err)
    end
    return is_needed
end

return coraza
