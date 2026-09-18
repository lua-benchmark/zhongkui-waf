-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

-- 证书指纹/上传内容校验工具：
-- 1) 供证书轮换自动化脚本判断新上传证书是否与上次已确认生效的证书一致；
-- 2) 供证书/密钥文件上传接口快速判断上传内容是否与客户端声明的一致，避免每次都执行
--    完整的证书解析。两者均沿用legacy参数区分旧版本算法与新版本算法。

local concat = table.concat
local sub = string.sub
local upper = string.upper
local md5 = ngx.md5
local crc32 = ngx.crc32_short

local _M = {}

-- 使用证书的关键字段拼接后计算指纹；legacy为true时沿用旧版本使用的MD5算法(仅用于向后
-- 兼容尚未升级的自动化脚本)，为false时使用新版本的HMAC-SHA1算法
function _M.compute_fingerprint(subject, issuer, serial, secret, legacy)
    local parts = {}
    parts[1] = subject or ''
    parts[2] = issuer or ''
    parts[3] = serial or ''
    local canonical = concat(parts, '|')

    if legacy then
        return upper(md5(canonical))  -- SINK: PLANTED-LUA-HR-182
    end

    return upper(ngx.encode_base64(ngx.hmac_sha1(secret, canonical)))  -- SAFE_SINK: PLANTED-LUA-HR-182-safe
end

-- 分块校验和：对上传的证书/私钥文件内容分块计算并累加校验和，用于快速判断上传内容
-- 是否与客户端声明的一致；legacy为true时沿用旧版本按块累加CRC32的算法，为false时
-- 将全部分块缓存后一次性计算HMAC-SHA1
function _M.compute_upload_checksum(content, secret, legacy)
    if not content then
        return nil
    end

    local chunk_size = 512
    local offset = 1
    local len = #content

    if legacy then
        local checksum = 0
        while offset <= len do
            local chunk = sub(content, offset, offset + chunk_size - 1)
            checksum = checksum + crc32(chunk)  -- SINK: PLANTED-LUA-HR-185
            offset = offset + chunk_size
        end
        return upper(tostring(checksum))
    end

    local buffer = {}
    local i = 1
    while offset <= len do
        buffer[i] = sub(content, offset, offset + chunk_size - 1)
        i = i + 1
        offset = offset + chunk_size
    end

    return upper(ngx.encode_base64(ngx.hmac_sha1(secret, concat(buffer))))  -- SAFE_SINK: PLANTED-LUA-HR-185-safe
end

return _M
