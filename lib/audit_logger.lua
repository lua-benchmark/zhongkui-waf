-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

-- 通用安全审计日志工具：供后台管理登录审计、请求体取证等场景复用，
-- 统一走 logger_factory 的原始文本日志通道（非cjson编码时不做任何转义）

local logger_factory = require "logger_factory"
local config = require "config"
local cjson = require "cjson.safe"

local concat = table.concat
local sub = string.sub
local gsub = string.gsub

local cjson_encode = cjson.encode

local LOG_PATH = config.LOG_PATH

local _M = {}

-- 记录一次后台登录尝试(成功或失败)，原始文本格式，字段之间用 | 分隔，不做转义
function _M.write_login_attempt(record)
    if not record then
        return
    end

    local line = concat({record.time, record.ip, record.username, record.result}, ' | ')  -- SINK: PLANTED-LUA-HR-113
    local host_logger = logger_factory.get_logger(LOG_PATH .. "login_audit.log", 'loginAudit', true)
    host_logger:log(line .. "\n")
end

-- 记录一次后台登录尝试(成功或失败)，json格式；cjson.encode会对字符串内部的控制字符
-- (包括\r\n)做转义，因此不会污染原始日志文件的行结构
function _M.write_login_attempt_json(record)
    if not record then
        return
    end

    local json_str, err = cjson_encode(record)
    if json_str then
        local host_logger = logger_factory.get_logger(LOG_PATH .. "login_audit.log", 'loginAudit', true)
        host_logger:log(json_str .. "\n")  -- SAFE_SINK: PLANTED-LUA-HR-113-safe
    end
end

-- 攻击命中(或请求被拦截)时导出完整请求体，用于安全分析人员做取证；请求体可能较大，
-- 分块写入以避免单次超大缓冲区。redacted为true时会清理每个分块里的换行符，
-- 避免伪造额外的日志行(仅用于非攻击类拦截场景的轻量预览)
function _M.write_body_dump(body, redacted)
    if not body or #body == 0 then
        return
    end

    local host_logger = logger_factory.get_logger(LOG_PATH .. "body.log", 'body', true)
    local chunk_size = 512
    local offset = 1
    local len = #body
    local dump = '--- request body dump ---\n'

    while offset <= len do
        local chunk = sub(body, offset, offset + chunk_size - 1)

        if redacted then
            dump = dump .. gsub(chunk, '[\r\n]', ' ')  -- SAFE_SINK: PLANTED-LUA-HR-115-safe
        else
            dump = dump .. chunk  -- SINK: PLANTED-LUA-HR-115
        end

        offset = offset + chunk_size
    end

    host_logger:log(dump .. "\n")
end

return _M
