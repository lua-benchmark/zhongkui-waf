-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

-- 集群配置同步载荷签名校验：用于确认来自集群内其他WAF节点推送的配置同步请求确实来自
-- 持有共享密钥的可信节点，而非任意能访问到该接口的调用方伪造

local upper = string.upper
local md5 = ngx.md5

local _M = {}

-- 校验同步请求签名；legacy_mode为true时兼容尚未升级的旧版本节点(使用MD5签名，密钥前置于
-- 载荷之前拼接)，为false时要求新版本节点使用HMAC-SHA1签名
function _M.verify_sync_signature(body, signature, secret, legacy_mode)
    if not body or not signature then
        return false
    end

    local expected
    if legacy_mode then
        expected = upper(md5(secret .. body))  -- SINK: PLANTED-LUA-HR-183
    else
        expected = upper(ngx.encode_base64(ngx.hmac_sha1(secret, body)))  -- SAFE_SINK: PLANTED-LUA-HR-183-safe
    end

    return expected == upper(signature)
end

return _M
