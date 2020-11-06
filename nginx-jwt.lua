-- nginx-jwt.lua


local cjson = require "cjson"
local jwt = require "resty.jwt"

--your secret
local secret = "lua-resty-jwt"

local M = {}


function M.auth()
    -- require Authorization request header
    local auth_header = ngx.var.http_Authorization

    if auth_header == nil then
        ngx.log(ngx.WARN, "No Authorization header")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.INFO, "Authorization: " .. auth_header)

    -- require Bearer token
    local _, _, token = string.find(auth_header, "Bearer%s+(.+)")

    if token == nil then
        ngx.log(ngx.WARN, "Missing token")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.INFO, "Token: " .. token)

    local jwt_obj = jwt:verify(secret, token)
    if jwt_obj.verified == false then
        ngx.log(ngx.WARN, "Invalid token: ".. jwt_obj.reason)
        
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.header.content_type = "application/json; charset=utf-8"
        ngx.say(cjson.encode(jwt_obj))
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.INFO, "JWT: " .. cjson.encode(jwt_obj))
    ngx.var.uid = jwt_obj.payload.sub

end

return M