local http = require "resty.http"
local cjson = require "cjson"
local template = require "crowdsec.template"
local utils = require "crowdsec.utils"


local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

local recaptcha_verify_url = "https://www.google.com/recaptcha/api/siteverify"

M._VERIFY_STATE = "to_verify"
M._VALIDATED_STATE = "validated"


M.State = {}
M.State["1"] = M._VERIFY_STATE
M.State["2"] = M._VALIDATED_STATE

M.SecretKey = ""
M.SiteKey = ""
M.Template = ""


function M.GetStateID(state)
    for k, v in pairs(M.State) do
        if v == state then
            return tonumber(k)
        end
    end
    return nil
end



function M.New(siteKey, secretKey, TemplateFilePath)

    if siteKey == nil or siteKey == "" then
      return "no recaptcha site key provided, can't use recaptcha"
    end
    M.SiteKey = siteKey

    if secretKey == nil or secretKey == "" then
      return "no recaptcha secret key provided, can't use recaptcha"
    end

    M.SecretKey = secretKey

    if TemplateFilePath == nil then
      return "CAPTCHA_TEMPLATE_PATH variable is empty, will ban without template"
    end
    if utils.file_exist(TemplateFilePath) == false then
      return "captcha template file doesn't exist, can't use recaptcha"
    end

    local captcha_template = utils.read_file(TemplateFilePath)
    if captcha_template == nil then
        return "Template file " .. TemplateFilePath .. "not found."
    end

    local template_data = {}
    template_data["recaptcha_site_key"] =  M.SiteKey
    local view = template.compile(captcha_template, template_data)
    M.Template = view

    return nil
end


function M.GetTemplate()
    return M.Template
end


function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do table.insert(params, k .. '=' .. v) end
    return table.concat(params, "&")
end

function M.Validate(g_captcha_res, remote_ip)
    local body = {
        secret   = M.SecretKey,
        response = g_captcha_res,
        remoteip = remote_ip
    }

    local data = table_to_encoded_url(body)
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(recaptcha_verify_url, {
      method = "POST",
      body = data,
      headers = {
          ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    httpc:close()
    if err ~= nil then
      return true, err
    end

    local result = cjson.decode(res.body)

    if result.success == false then
      for k, v in pairs(result["error-codes"]) do
        if v == "invalid-input-secret" then
          ngx.log(ngx.ERR, "reCaptcha secret key is invalid")
          return true, nil
        end
      end 
    end

    return result.success, nil
end


return M