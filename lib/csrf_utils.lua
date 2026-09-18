-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

-- 管理后台状态变更请求的CSRF防护工具：为已登录会话签发一次性token，前端在提交
-- 状态变更类请求(如修改密码)时随请求携带回来校验，防止第三方站点诱导已登录
-- 管理员的浏览器发起伪造请求。legacy为true时沿用早期版本发布的算法(仅用于兼容
-- 尚未升级、仍缓存旧token生成逻辑的前端页面)，新版本默认使用HMAC-SHA1签名。

local upper = string.upper
local format = string.format
local md5 = ngx.md5

local _M = {}

-- 根据会话标识(登录后下发的authtoken cookie原文)、一次性nonce生成CSRF token
function _M.generate_csrf_token(session_id, nonce, secret, legacy)
    if legacy then
        return upper(md5(format("%s:%s:%s", session_id, nonce, secret)))  -- SINK: PLANTED-LUA-HR-186
    end

    return upper(ngx.encode_base64(ngx.hmac_sha1(secret, session_id .. ':' .. nonce)))  -- SAFE_SINK: PLANTED-LUA-HR-186-safe
end

-- 校验请求携带的CSRF token是否与当前会话、nonce匹配
function _M.verify_csrf_token(session_id, nonce, token, secret, legacy)
    if not token or #token == 0 or not nonce or #nonce == 0 then
        return false
    end

    local expected = _M.generate_csrf_token(session_id, nonce, secret, legacy)
    return expected == upper(token)
end

return _M
