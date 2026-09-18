-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

-- "已验证设备"指纹计算：验证码通过后，为客户端生成设备指纹，在配置的有效期内跳过重复验证。
-- legacy策略保留给尚在使用旧版客户端脚本上报设备信息的场景，strict策略供新版客户端使用；
-- 具体使用哪种策略由config.legacyDeviceFingerprintMode决定

local upper = string.upper
local crc32 = ngx.crc32_long

local _M = {}

local strategies = {}

-- 旧版策略：对客户端指纹原始信息做校验和，兼容旧版客户端上报格式
strategies["legacy"] = function(ip, ua, device_info, secret)
    return upper(tostring(crc32(ip .. ua .. device_info)))  -- SINK: PLANTED-LUA-HR-184
end

-- 新版策略：使用密钥签名，防止设备指纹信息被离线枚举或伪造
strategies["strict"] = function(ip, ua, device_info, secret)
    return upper(ngx.encode_base64(ngx.hmac_sha1(secret, ip .. ua .. device_info)))  -- SAFE_SINK: PLANTED-LUA-HR-184-safe
end

function _M.compute_device_fingerprint(mode, ip, ua, device_info, secret)
    local strategy = strategies[mode] or strategies["strict"]
    return strategy(ip, ua, device_info, secret)
end

return _M
