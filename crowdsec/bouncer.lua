package.path = package.path .. ";./?.lua"

local config = require "crowdsec.config"
local iputils = require "crowdsec.iputils"
local http = require "resty.http"
local cjson = require "cjson"
local recaptcha = require "crowdsec.recaptcha"
local utils = require "crowdsec.utils"
local ban = require "crowdsec.ban"

-- contain runtime = {}
local runtime = {}
-- remediations are stored in cache as int (shared dict tags)
-- we need to translate IDs to text with this.
runtime.remediations = {}
runtime.remediations["1"] = "ban"
runtime.remediations["2"] = "captcha"


local csmod = {}



-- init function
function csmod.init(configFile, userAgent)
  local conf, err = config.loadConfig(configFile)
  if conf == nil then
    return nil, err
  end
  runtime.conf = conf
  runtime.userAgent = userAgent
  runtime.cache = ngx.shared.crowdsec_cache
  runtime.fallback = runtime.conf["FALLBACK_REMEDIATION"]

  if runtime.conf["ENABLED"] == "false" then
    return "Disabled", nil
  end

  if runtime.conf["REDIRECT_LOCATION"] == "/" then
    ngx.log(ngx.ERR, "redirect location is set to '/' this will lead into infinite redirection")
  end

  local captcha_ok = true
  local err = recaptcha.New(runtime.conf["SITE_KEY"], runtime.conf["SECRET_KEY"], runtime.conf["CAPTCHA_TEMPLATE_PATH"])
  if err ~= nil then
    --ngx.log(ngx.ERR, "error loading recaptcha plugin: " .. err)
    captcha_ok = false
  end
  local succ, err, forcible = runtime.cache:set("captcha_ok", captcha_ok)
  if not succ then
    ngx.log(ngx.ERR, "failed to add captcha state key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end


  local err = ban.new(runtime.conf["BAN_TEMPLATE_PATH"], runtime.conf["REDIRECT_LOCATION"], runtime.conf["RET_CODE"])
  if err ~= nil then
    ngx.log(ngx.ERR, "error loading ban plugins: " .. err)
  end

  if runtime.conf["REDIRECT_LOCATION"] ~= "" then
    table.insert(runtime.conf["EXCLUDE_LOCATION"], runtime.conf["REDIRECT_LOCATION"])
  end


  -- if stream mode, add callback to stream_query and start timer
  if runtime.conf["MODE"] == "stream" then
    local succ, err, forcible = runtime.cache:set("startup", true)
    if not succ then
      ngx.log(ngx.ERR, "failed to add startup key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    local succ, err, forcible = runtime.cache:set("first_run", true)
    if not succ then
      ngx.log(ngx.ERR, "failed to add first_run key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
  end

  return true, nil
end


function csmod.validateCaptcha(g_captcha_res, remote_ip)
  return recaptcha.Validate(g_captcha_res, remote_ip)
end


function get_http_request(link)
  local httpc = http.new()
  httpc:set_timeout(runtime.conf['REQUEST_TIMEOUT'])
  local res, err = httpc:request_uri(link, {
    method = "GET",
    headers = {
      ['Connection'] = 'close',
      ['X-Api-Key'] = runtime.conf["API_KEY"],
      ['User-Agent'] = runtime.userAgent
    },
  })
  httpc:close()
  return res, err
end

function parse_duration(duration)
  local match, err = ngx.re.match(duration, "^((?<hours>[0-9]+)h)?((?<minutes>[0-9]+)m)?(?<seconds>[0-9]+)")
  local ttl = 0
  if not match then
    if err then
      return ttl, err
    end
  end
  if match["hours"] ~= nil and match["hours"] ~= false then
    local hours = tonumber(match["hours"])
    ttl = ttl + (hours * 3600)
  end
  if match["minutes"] ~= nil and match["minutes"] ~= false then
    local minutes = tonumber(match["minutes"])
    ttl = ttl + (minutes * 60)
  end
  if match["seconds"] ~= nil and match["seconds"] ~= false then
    local seconds = tonumber(match["seconds"])
    ttl = ttl + seconds
  end
  return ttl, nil
end

function get_remediation_id(remediation)
  for key, value in pairs(runtime.remediations) do
    if value == remediation then
      return tonumber(key)
    end
  end
  return nil
end

function item_to_string(item, scope)
  local ip, cidr, ip_version
  if scope:lower() == "ip" then
    ip = item
  end
  if scope:lower() == "range" then
    ip, cidr = iputils.splitRange(item, scope)
  end

  local ip_network_address, is_ipv4 = iputils.parseIPAddress(ip)
  if is_ipv4 then
    ip_version = "ipv4"
    if cidr == nil then
      cidr = 32
    end
  else
    ip_version = "ipv6"
    ip_network_address = ip_network_address.uint32[3]..":"..ip_network_address.uint32[2]..":"..ip_network_address.uint32[1]..":"..ip_network_address.uint32[0]
    if cidr == nil then
      cidr = 128
    end
  end

  if ip_version == nil then
    return "normal_"..item
  end
  local ip_netmask = iputils.cidrToInt(cidr, ip_version)
  return ip_version.."_"..ip_netmask.."_"..ip_network_address
end

function stream_query()
  -- As this function is running inside coroutine (with ngx.timer.every), 
  -- we need to raise error instead of returning them
  local is_startup = runtime.cache:get("startup")
  ngx.log(ngx.DEBUG, "Stream Query from worker : " .. tostring(ngx.worker.id()) .. " with startup "..tostring(is_startup))
  local link = runtime.conf["API_URL"] .. "/v1/decisions/stream?startup=" .. tostring(is_startup)
  local res, err = get_http_request(link)
  if not res then
    if ngx.timer.every == nil then
      local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream_query)
      if not ok then
        error("Failed to create the timer: " .. (err or "unknown"))
      end
    end    
    error("request failed: ".. err)
  end

  local status = res.status
  local body = res.body
  if status~=200 then
    if ngx.timer.every == nil then
      local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream_query)
      if not ok then
        error("Failed to create the timer: " .. (err or "unknown"))
      end
    end
    error("HTTP error while request to Local API '" .. status .. "' with message (" .. tostring(body) .. ")")
  end

  local decisions = cjson.decode(body)
  -- process deleted decisions
  if type(decisions.deleted) == "table" then
    if not is_startup then
      for i, decision in pairs(decisions.deleted) do
        if decision.type == "captcha" then
          runtime.cache:delete("captcha_" .. decision.value)
        end
        local key = item_to_string(decision.value, decision.scope)
        runtime.cache:delete(key)
        ngx.log(ngx.DEBUG, "Deleting '" .. key .. "'")
      end
    end
  end

  -- process new decisions
  if type(decisions.new) == "table" then
    for i, decision in pairs(decisions.new) do
      if runtime.conf["BOUNCING_ON_TYPE"] == decision.type or runtime.conf["BOUNCING_ON_TYPE"] == "all" then
        local ttl, err = parse_duration(decision.duration)
        if err ~= nil then
          ngx.log(ngx.ERR, "[Crowdsec] failed to parse ban duration '" .. decision.duration .. "' : " .. err)
        end
        local remediation_id = get_remediation_id(decision.type)
        if remediation_id == nil then
          remediation_id = get_remediation_id(runtime.fallback)
        end
        local key = item_to_string(decision.value, decision.scope)
        local succ, err, forcible = runtime.cache:set(key, false, ttl, remediation_id)
        if not succ then
          ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
        end
        if forcible then
          ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
        end
        ngx.log(ngx.DEBUG, "Adding '" .. key .. "' in cache for '" .. ttl .. "' seconds")
      end
    end
  end

  -- not startup anymore after first callback
  local succ, err, forcible = runtime.cache:set("startup", false)
  if not succ then
    ngx.log(ngx.ERR, "failed to set startup key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end  

  -- re-occuring timer if there is no timer.every available
  if ngx.timer.every == nil then
    local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream_query)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    end
  end
  return nil
end

function live_query(ip)
  local link = runtime.conf["API_URL"] .. "/v1/decisions?ip=" .. ip
  local res, err = get_http_request(link)
  if not res then
    return true, nil, "request failed: ".. err
  end

  local status = res.status
  local body = res.body
  if status~=200 then
    return true, nil, "Http error " .. status .. " while talking to LAPI (" .. link .. ")" 
  end
  if body == "null" then -- no result from API, no decision for this IP
    -- set ip in cache and DON'T block it
    local key = item_to_string(ip, "ip")
    local succ, err, forcible = runtime.cache:set(key, true, runtime.conf["CACHE_EXPIRATION"], 1)
    if not succ then
      ngx.log(ngx.ERR, "failed to add ip '" .. ip .. "' in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return true, nil, nil
  end
  local decision = cjson.decode(body)[1]

  if runtime.conf["BOUNCING_ON_TYPE"] == decision.type or runtime.conf["BOUNCING_ON_TYPE"] == "all" then
    local remediation_id = get_remediation_id(decision.type)
    if remediation_id == nil then
      remediation_id = get_remediation_id(runtime.fallback)
    end
    local key = item_to_string(decision.value, decision.scope)
    local succ, err, forcible = runtime.cache:set(key, false, runtime.conf["CACHE_EXPIRATION"], remediation_id)
    if not succ then
      ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    ngx.log(ngx.DEBUG, "Adding '" .. key .. "' in cache for '" .. runtime.conf["CACHE_EXPIRATION"] .. "' seconds")
    return false, decision.type, nil
  else
    return true, nil, nil
  end
end


function csmod.GetCaptchaTemplate()
  return recaptcha.GetTemplate()
end


function csmod.SetupStream()
  -- if it stream mode and startup start timer
  if runtime.cache:get("first_run") == true and runtime.conf["MODE"] == "stream" then
    local ok, err
    if ngx.timer.every == nil then
      ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream_query)
    else
      ok, err = ngx.timer.every(runtime.conf["UPDATE_FREQUENCY"], stream_query)
    end
    if not ok then
      local succ, err, forcible = runtime.cache:set("first_run", true)
      if not succ then
        ngx.log(ngx.ERR, "failed to set startup key in cache: "..err)
      end
      if forcible then
        ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
      end  
      return true, nil, "Failed to create the timer: " .. (err or "unknown")
    end
    local succ, err, forcible = runtime.cache:set("first_run", false)
    if not succ then
      ngx.log(ngx.ERR, "failed to set first_run key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end  
    ngx.log(ngx.DEBUG, "Timer launched")
  end
end

function csmod.allowIp(ip)
  if runtime.conf == nil then
    return true, nil, "Configuration is bad, cannot run properly"
  end

  csmod.SetupStream()

  local key = item_to_string(ip, "ip")
  local key_parts = {}
  for i in key.gmatch(key, "([^_]+)") do
    table.insert(key_parts, i)
  end

  local key_type = key_parts[1]
  if key_type == "normal" then
    local in_cache, remediation_id = runtime.cache:get(key)
    if in_cache ~= nil then -- we have it in cache
      ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache")
      return in_cache, runtime.remediations[tostring(remediation_id)], nil
    end
  end
  
  local ip_network_address = key_parts[3]
  local netmasks = iputils.netmasks_by_key_type[key_type]
  for i, netmask in pairs(netmasks) do
    local item
    if key_type == "ipv4" then
      item = key_type.."_"..netmask.."_"..iputils.ipv4_band(ip_network_address, netmask)
    end
    if key_type == "ipv6" then
      item = key_type.."_"..table.concat(netmask, ":").."_"..iputils.ipv6_band(ip_network_address, netmask)
    end
    local in_cache, remediation_id = runtime.cache:get(item)
    if in_cache ~= nil then -- we have it in cache
      ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache")
      return in_cache, runtime.remediations[tostring(remediation_id)], nil
    end
  end

  -- if live mode, query lapi
  if runtime.conf["MODE"] == "live" then
    local ok, remediation, err = live_query(ip)
    return ok, remediation, err
  end
  return true, nil, nil
end

function csmod.Allow(ip)
  
  if runtime.conf["ENABLED"] == "false" then
    return "Disabled", nil
  end

  if utils.table_len(runtime.conf["EXCLUDE_LOCATION"]) > 0 then
    for k, v in pairs(runtime.conf["EXCLUDE_LOCATION"]) do
      if ngx.var.uri == v then
        ngx.log(ngx.ERR,  "whitelisted location: " .. v)
        return
      end
      local uri_to_check = v
      if utils.ends_with(uri_to_check, "/") == false then
        uri_to_check = uri_to_check .. "/"
      end
      if utils.starts_with(ngx.var.uri, uri_to_check) then
        ngx.log(ngx.ERR,  "whitelisted location: " .. uri_to_check)
      end
    end
  end

  local ok, remediation, err = csmod.allowIp(ip)
  if err ~= nil then
    ngx.log(ngx.ERR, "[Crowdsec] bouncer error: " .. err)
  end

  -- if the ip is now allowed, try to delete its captcha state in cache
  if ok == true then
    ngx.shared.crowdsec_cache:delete("captcha_" .. ip)
  end

  local captcha_ok = runtime.cache:get("captcha_ok")

  if runtime.fallback ~= "" then
    -- if we can't use recaptcha, fallback
    if remediation == "captcha" and captcha_ok == false then
      remediation = runtime.fallback
    end

    -- if remediation is not supported, fallback
    if remediation ~= "captcha" and remediation ~= "ban" then
      remediation = runtime.fallback
    end
  end

  if captcha_ok then -- if captcha can be use (configuration is valid)
    -- we check if the IP need to validate its captcha before checking it against crowdsec local API
    local previous_uri, state_id = ngx.shared.crowdsec_cache:get("captcha_"..ngx.var.remote_addr)
    if previous_uri ~= nil and state_id == recaptcha.GetStateID(recaptcha._VERIFY_STATE) then
        ngx.req.read_body()
        local recaptcha_res = ngx.req.get_post_args()["g-recaptcha-response"] or 0
        if recaptcha_res ~= 0 then
            local valid, err = csmod.validateCaptcha(recaptcha_res, ngx.var.remote_addr)
            if err ~= nil then
              ngx.log(ngx.ERR, "Error while validating captcha: " .. err)
            end
            if valid == true then
                -- captcha is valid, we redirect the IP to its previous URI but in GET method
                local succ, err, forcible = ngx.shared.crowdsec_cache:set("captcha_"..ngx.var.remote_addr, previous_uri, runtime.conf["CAPTCHA_EXPIRATION"], recaptcha.GetStateID(recaptcha._VALIDATED_STATE))
                if not succ then
                  ngx.log(ngx.ERR, "failed to add key about captcha for ip '" .. ngx.var.remote_addr .. "' in cache: "..err)
                end
                if forcible then
                  ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
                end
                
                ngx.req.set_method(ngx.HTTP_GET)
                ngx.redirect(previous_uri)
                return
            else
                ngx.log(ngx.ALERT, "Invalid captcha from " .. ngx.var.remote_addr)
            end
        end
    end
  end

  if not ok then
      if remediation == "ban" then
        ngx.log(ngx.ALERT, "[Crowdsec] denied '" .. ngx.var.remote_addr .. "' with '"..remediation.."'")
        ban.apply()
        return
      end
      -- if the remediation is a captcha and captcha is well configured
      if remediation == "captcha" and captcha_ok and ngx.var.uri ~= "/favicon.ico" then
          local previous_uri, state_id = ngx.shared.crowdsec_cache:get("captcha_"..ngx.var.remote_addr)
          -- we check if the IP is already in cache for captcha and not yet validated
          if previous_uri == nil or state_id ~= recaptcha.GetStateID(recaptcha._VALIDATED_STATE) then
              ngx.header.content_type = "text/html"
              ngx.say(csmod.GetCaptchaTemplate())
              local uri = ngx.var.uri
              -- in case its not a GET request, we prefer to fallback on referer
              if ngx.req.get_method() ~= "GET" then
                local headers, err = ngx.req.get_headers()
                for k, v in pairs(headers) do
                  if k == "referer" then
                    uri = v
                  end
                end
              end
              local succ, err, forcible = ngx.shared.crowdsec_cache:set("captcha_"..ngx.var.remote_addr, uri , 60, recaptcha.GetStateID(recaptcha._VERIFY_STATE))
              if not succ then
                ngx.log(ngx.ERR, "failed to add key about captcha for ip '" .. ngx.var.remote_addr .. "' in cache: "..err)
              end
              if forcible then
                ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
              end
              ngx.log(ngx.ALERT, "[Crowdsec] denied '" .. ngx.var.remote_addr .. "' with '"..remediation.."'")
          end
      end
  end
end


-- Use it if you are able to close at shuttime
function csmod.close()
end

function csmod.allowed()
	local ok, remediation, err = csmod.allowIp(ngx.var.remote_addr)
	if err ~= nil then
		return false, err, nil
	end
	if remediation ~= nil then
		return true, nil, false
	end
	return true, nil, true
end

return csmod
