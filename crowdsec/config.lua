local config = {}

function config.file_exists(file)
    local f = io.open(file, "rb")
    if f then 
        f:close() 
    end
    return f ~= nil
end

  function split(s, delimiter)
    result = {};
    for match in (s..delimiter):gmatch("(.-)"..delimiter.."(.-)") do
        table.insert(result, match);
    end
    return result;
end

local function has_value (tab, val)
    for index, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

local function starts_with(str, start)
    return str:sub(1, #start) == start
end

local function trim(s)
    return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end


function config.loadConfig(file)
    if not config.file_exists(file) then
        return nil, "File ".. file .." doesn't exist"
    end
    local conf = {}
    local valid_params = {'ENABLED','API_URL', 'API_KEY', 'BOUNCING_ON_TYPE', 'MODE', 'SECRET_KEY', 'SITE_KEY', 'BAN_TEMPLATE_PATH' ,'CAPTCHA_TEMPLATE_PATH', 'REDIRECT_LOCATION', 'RET_CODE', 'EXCLUDE_LOCATION', 'FALLBACK_REMEDIATION'}
    local valid_int_params = {'CACHE_EXPIRATION', 'CACHE_SIZE', 'REQUEST_TIMEOUT', 'UPDATE_FREQUENCY', 'CAPTCHA_EXPIRATION'}
    local valid_bouncing_on_type_values = {'ban', 'captcha', 'all'}
    local valid_truefalse_values = {'false', 'true'}
    local default_values = {
        ['ENABLED'] = "true",
        ['REQUEST_TIMEOUT'] = 0.2,
        ['BOUNCING_ON_TYPE'] = "ban",
        ['MODE'] = "stream",
        ['UPDATE_FREQUENCY'] = 10,
        ['CAPTCHA_EXPIRATION'] = 3600,
        ['REDIRECT_LOCATION'] = "",
        ['EXCLUDE_LOCATION'] = {},
        ['RET_CODE'] = 0
    }
    for line in io.lines(file) do
        local isOk = false
        if starts_with(line, "#") then
            isOk = true
        end
        if trim(line) == "" then
            isOk = true
        end
        if not isOk then
            local s = split(line, "=")
            for k, v in pairs(s) do
                if has_value(valid_params, v) then
                    if v == "ENABLED" then
                        local value = s[2]
                        if not has_value(valid_truefalse_values, s[2]) then
                            ngx.log(ngx.ERR, "unsupported value '" .. s[2] .. "' for variable '" .. v .. "'. Using default value 'true' instead")
                            break
                        end
                    end
                    if v == "BOUNCING_ON_TYPE" then
                        local value = s[2]
                        if not has_value(valid_bouncing_on_type_values, s[2]) then
                            ngx.log(ngx.ERR, "unsupported value '" .. s[2] .. "' for variable '" .. v .. "'. Using default value 'ban' instead")
                            break
                        end
                    end
                    if v == "MODE" then
                        local value = s[2]
                        if not has_value({'stream', 'live'}, s[2]) then
                            ngx.log(ngx.ERR, "unsupported value '" .. s[2] .. "' for variable '" .. v .. "'. Using default value 'stream' instead")
                            break
                        end
                    end
                    if v == "EXCLUDE_LOCATION" then
                        local value = s[2]
                        exclude_location = {}
                        if value ~= "" then
                            for match in (value..","):gmatch("(.-)"..",") do
                                table.insert(exclude_location, match)
                            end
                        end
                        local n = next(s, k)
                        conf[v] = exclude_location
                        break
                    end
                    if v == "FALLBACK_REMEDIATION" then
                        local value = s[2]
                        if not has_value({'captcha', 'ban'}, s[2]) then
                            ngx.log(ngx.ERR, "unsupported value '" .. s[2] .. "' for variable '" .. v .. "'. Using default value 'ban' instead")
                            local n = next(s, k)
                            conf[v] = "ban"
                            break
                        end
                    end
                    local n = next(s, k)
                    conf[v] = s[n]
                    break
                elseif has_value(valid_int_params, v) then
                    local n = next(s, k)
                    conf[v] = tonumber(s[n])
                    break
                else
                    ngx.log(ngx.ERR, "unsupported configuration '" .. v .. "'")
                    break
                end
            end
        end
    end
    for k, v in pairs(default_values) do
        if conf[k] == nil then
            conf[k] = v
        end
    end
    return conf, nil
end
return config