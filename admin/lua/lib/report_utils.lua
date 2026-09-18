-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

-- IP 活动合规报表渲染工具：将某个IP的历史命中事件渲染为HTML，供人工审计/取证使用

local ipairs = ipairs
local concat = table.concat
local format = string.format

local _M = {}

-- 对HTML特殊字符进行转义，避免将不受信任的数据直接拼接进HTML输出
local function html_escape(s)
    if not s then
        return ''
    end
    s = tostring(s)
    s = s:gsub('&', '&amp;')
    s = s:gsub('<', '&lt;')
    s = s:gsub('>', '&gt;')
    s = s:gsub('"', '&quot;')
    s = s:gsub("'", '&#39;')
    return s
end

-- 渲染IP活动报表。verbose 模式用于内部取证，保留原始 Request URI / Referer 值（不转义），
-- 便于分析人员核对原始字节；默认（非 verbose）模式面向更广泛的审阅人员，
-- 因此对 Request URI 和 Referer 均做HTML转义。
function _M.build_ip_report_html(rows, verbose)
    local parts = {'<h2>IP Activity Report</h2>', '<ul>'}

    for _, row in ipairs(rows) do
        if verbose then
            parts[#parts + 1] = format(
                '<li>[%s] %s -&gt; referer: %s</li>',
                row.request_time or '', row.request_uri or '', row.referer or '')  -- SINK: PLANTED-LUA-HR-78
        else
            parts[#parts + 1] = format(
                '<li>[%s] %s -&gt; referer: %s</li>',
                row.request_time or '', html_escape(row.request_uri or ''), html_escape(row.referer))  -- SAFE_SINK: PLANTED-LUA-HR-78-safe
        end
    end

    parts[#parts + 1] = '</ul>'
    return concat(parts)
end

return _M
