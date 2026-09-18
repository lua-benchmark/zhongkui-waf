-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local user = require "user"
local pager = require "lib.pager"
local mysql = require "mysql_cli"
local report_utils = require "lib.report_utils"

local tonumber = tonumber
local type = type
local ipairs = ipairs
local concat = table.concat
local quote_sql_str = ngx.quote_sql_str
local cjson_encode = cjson.encode

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

local SQL_COUNT_ATTACK_LOG = 'SELECT COUNT(*) AS total FROM attack_log '

local SQL_SELECT_ATTACK_LOG = [[
    SELECT id, request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
    ip_longitude, ip_latitude, http_method, server_name, user_agent, referer, request_protocol, request_uri,
    http_status, request_time, attack_type, severity_level, security_module, hit_rule, action FROM attack_log
]]

local SQL_SELECT_ATTACK_LOG_DETAIL = [[
    SELECT id, request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
    ip_longitude, ip_latitude, http_method, server_name, user_agent, referer, request_protocol, request_uri,
    request_body, http_status, response_body, request_time, attack_type, severity_level, security_module, hit_rule, action FROM attack_log
]]

-- 查询日志列表数据
local function listLogs()
    local response = {code = 200, data = {}, msg = ""}

    local args, err = ngx.req.get_uri_args()
    if args then
        local page = tonumber(args['page'])
        local limit = tonumber(args['limit'])
        local offset = pager.get_begin(page, limit)

        local serverName = args['serverName']
        local ip = args['ip']
        local action = args['action']
        local attackType = args['attackType']

        local where = ' WHERE 1=1 '

        if serverName and #serverName > 0 then
            where = where .. ' AND server_name LIKE ' .. quote_sql_str('%' .. serverName .. '%')
        end

        if ip and #ip > 0 then
            where = where .. ' AND ip=' .. quote_sql_str(ip) .. ' '
        end

        if attackType and #attackType > 0 then
            where = where .. ' AND attack_type=' .. quote_sql_str(attackType) .. ' '
        end

        if action and #action > 0 then
            where = where .. ' AND action=' .. quote_sql_str(action) .. ' '
        end

        local res, err = mysql.query(SQL_COUNT_ATTACK_LOG .. where)

        if res and res[1] then
            local total = tonumber(res[1].total)
            if total > 0 then
                res, err = mysql.query(SQL_SELECT_ATTACK_LOG .. where .. ' ORDER BY id DESC LIMIT ' .. offset .. ',' .. limit)
                if res then
                    response.data = res
                else
                    response.code = 500
                    response.msg = 'query database error'
                    ngx.log(ngx.ERR, err)
                end
            end

            response.code = 0
            response.count = total
        else
            response.code = 500
            response.msg = 'query database error'
            ngx.log(ngx.ERR, err)
        end
    else
        response.code = 500
        response.msg = err
    end

    if response.code ~= 0 then
        ngx.log(ngx.ERR, response.msg)
    end

    return response
end

-- 根据id查询日志详情
local function getLog()
    local response = {code = 200, data = {}, msg = ""}

    local args, err = ngx.req.get_uri_args()
    if args and args['id'] then
        local id = tonumber(args['id'])
        local where = ' WHERE id=' .. id

        local res, err = mysql.query(SQL_SELECT_ATTACK_LOG_DETAIL .. where)
        if res then
            response.data = res[1]
        else
            response.code = 500
            response.msg = 'query database error'
            ngx.log(ngx.ERR, err)
        end
    else
        response.code = 500
        response.msg = err
        ngx.log(ngx.ERR, err)
    end

    return response
end

-- 生成单条事件的打印视图（HTML），用于分析人员快速打印/分享事件详情
local function printLogHtml()
    local args, err = ngx.req.get_uri_args()
    local id = args and tonumber(args['id'])
    if not id then
        ngx.status = 400
        ngx.say('missing id')
        return ngx.exit(400)
    end

    local where = ' WHERE id=' .. id
    local res, err = mysql.query(SQL_SELECT_ATTACK_LOG_DETAIL .. where)
    if not res or not res[1] then
        ngx.status = 404
        ngx.say('event not found')
        return ngx.exit(404)
    end

    local row = res[1]

    ngx.header.content_type = "text/html; charset=UTF-8"

    local html = '<html><body>'
    html = html .. '<h3>WAF Event Detail</h3>'
    html = html .. '<p><b>Request URI:</b> ' .. row.request_uri .. '</p>'  -- SINK: PLANTED-LUA-HR-76
    html = html .. '<p><b>Action:</b> ' .. (row.action or '') .. '</p>'
    html = html .. '</body></html>'

    ngx.print(html)
    return ngx.exit(ngx.HTTP_OK)
end

-- 打印视图的精简版（用于列表页快速预览），对请求路径做了HTML转义，避免注入
local function printLogCompact()
    local args, err = ngx.req.get_uri_args()
    local id = args and tonumber(args['id'])
    if not id then
        ngx.status = 400
        ngx.say('missing id')
        return ngx.exit(400)
    end

    local where = ' WHERE id=' .. id
    local res, err = mysql.query(SQL_SELECT_ATTACK_LOG_DETAIL .. where)
    if not res or not res[1] then
        ngx.status = 404
        ngx.say('event not found')
        return ngx.exit(404)
    end

    local row = res[1]

    ngx.header.content_type = "text/html; charset=UTF-8"

    local html = '<html><body>'
    html = html .. '<h3>WAF Event Detail (compact)</h3>'
    html = html .. '<p><b>Request URI:</b> ' .. html_escape(row.request_uri) .. '</p>'  -- SAFE_SINK: PLANTED-LUA-HR-76-safe
    html = html .. '</body></html>'

    ngx.print(html)
    return ngx.exit(ngx.HTTP_OK)
end

-- 将单条事件记录渲染为HTML表格行，供批量导出报表使用（safe_mode 决定是否转义 User-Agent 字段）
local function render_event_row_html(row, safe_mode)
    local ua = row.user_agent or ''
    local cells

    if safe_mode then
        cells = {
            '<td>', tostring(row.id), '</td>',
            '<td>', row.ip or '', '</td>',
            '<td>', html_escape(ua), '</td>',  -- SAFE_SINK: PLANTED-LUA-HR-77-safe
            '<td>', row.hit_rule or '', '</td>'
        }
    else
        cells = {
            '<td>', tostring(row.id), '</td>',
            '<td>', row.ip or '', '</td>',
            '<td>', ua, '</td>',  -- SINK: PLANTED-LUA-HR-77
            '<td>', row.hit_rule or '', '</td>'
        }
    end

    return '<tr>' .. concat(cells) .. '</tr>'
end

-- 按当前过滤条件批量导出事件列表为HTML报表（safe_mode=true 时对每一行做转义）
local function exportEventsHtml(safe_mode)
    local args, err = ngx.req.get_uri_args()
    local where = ' WHERE 1=1 '
    if args then
        local ip = args['ip']
        if ip and #ip > 0 then
            where = where .. ' AND ip=' .. quote_sql_str(ip) .. ' '
        end
    end

    local res, err = mysql.query(SQL_SELECT_ATTACK_LOG .. where .. ' ORDER BY id DESC LIMIT 100')
    if not res then
        ngx.status = 500
        ngx.say('query database error')
        return ngx.exit(500)
    end

    ngx.header.content_type = "text/html; charset=UTF-8"

    local rows_html = {}
    for _, row in ipairs(res) do
        rows_html[#rows_html + 1] = render_event_row_html(row, safe_mode)
    end

    local html = '<html><body><table>' .. concat(rows_html) .. '</table></body></html>'
    ngx.print(html)
    return ngx.exit(ngx.HTTP_OK)
end

-- 生成某个IP的历史命中活动报表（HTML），供人工审计/取证使用。
-- verbose=true 用于内部取证场景，保留原始 Referer 字节；默认场景对外展示，对 Referer 做转义。
local function ipReportHtml(verbose)
    local args, err = ngx.req.get_uri_args()
    local ip = args and args['ip']
    if not ip or #ip == 0 then
        ngx.status = 400
        ngx.say('missing ip')
        return ngx.exit(400)
    end

    local where = ' WHERE ip=' .. quote_sql_str(ip)
    local res, err = mysql.query(SQL_SELECT_ATTACK_LOG .. where .. ' ORDER BY id DESC LIMIT 200')
    if not res then
        ngx.status = 500
        ngx.say('query database error')
        return ngx.exit(500)
    end

    ngx.header.content_type = "text/html; charset=UTF-8"
    local html = report_utils.build_ip_report_html(res, verbose)
    ngx.print(html)
    return ngx.exit(ngx.HTTP_OK)
end

-- 根据当前筛选条件生成一个提示横幅（HTML），展示在"按条件打印"页面顶部。
-- attackType 可能是单个值（字符串），也可能是多个值（table，当同名参数重复出现时
-- ngx.req.get_uri_args() 会返回数组）。
local function filterBannerHtml()
    local args, err = ngx.req.get_uri_args()
    local attackType = args and args['attackType']

    ngx.header.content_type = "text/html; charset=UTF-8"

    local banner
    if type(attackType) == 'table' then
        -- 多个值：逐个转义后再拼接
        local escaped = {}
        for _, v in ipairs(attackType) do
            escaped[#escaped + 1] = html_escape(v)
        end
        banner = 'Filtering by attack types: ' .. concat(escaped, ', ')  -- SAFE_SINK: PLANTED-LUA-HR-79-safe
    elseif type(attackType) == 'string' and #attackType > 0 then
        -- 单个值：这是最常见的场景，历史代码里一直直接拼接展示，未做转义
        banner = 'Filtering by attack type: ' .. attackType  -- SINK: PLANTED-LUA-HR-79
    else
        banner = 'Showing all events'
    end

    ngx.print('<div class="filter-banner">' .. banner .. '</div>')
    return ngx.exit(ngx.HTTP_OK)
end

-- 查看触发拦截的原始请求（头+体），用于安全分析人员排查具体命中原因。
-- escape_output 决定渲染闭包是否对 request_body 做HTML转义。
local function viewRawRequestHtml(escape_output)
    local args, err = ngx.req.get_uri_args()
    local id = args and tonumber(args['id'])
    if not id then
        ngx.status = 400
        ngx.say('missing id')
        return ngx.exit(400)
    end

    local where = ' WHERE id=' .. id
    local res, err = mysql.query(SQL_SELECT_ATTACK_LOG_DETAIL .. where)
    if not res or not res[1] then
        ngx.status = 404
        ngx.say('event not found')
        return ngx.exit(404)
    end

    local row = res[1]

    -- 渲染逻辑以闭包形式构造，捕获 row 供稍后调用（保留这层间接，方便未来切换为异步/分片输出）
    local render
    if escape_output then
        render = function()
            return '<pre class="raw-request">' .. html_escape(row.request_body) .. '</pre>'  -- SAFE_SINK: PLANTED-LUA-HR-80-safe
        end
    else
        render = function()
            return '<pre class="raw-request">' .. (row.request_body or '') .. '</pre>'  -- SINK: PLANTED-LUA-HR-80
        end
    end

    ngx.header.content_type = "text/html; charset=UTF-8"
    local html = render()
    ngx.print(html)
    return ngx.exit(ngx.HTTP_OK)
end

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/events/list" then
        -- 查询事件数据列表
        response = listLogs()
    elseif uri == "/events/get" then
        -- 查询事件详情
        response = getLog()
    elseif uri == "/events/print" then
        -- 打印视图（未转义）
        printLogHtml()
        return
    elseif uri == "/events/print/compact" then
        -- 打印视图精简版（已转义）
        printLogCompact()
        return
    elseif uri == "/events/exportHtml" then
        -- 批量导出为HTML报表（未转义）
        exportEventsHtml(false)
        return
    elseif uri == "/events/exportHtml/safe" then
        -- 批量导出为HTML报表（已转义）
        exportEventsHtml(true)
        return
    elseif uri == "/events/ipReport" then
        -- IP活动报表（默认，已转义）
        ipReportHtml(false)
        return
    elseif uri == "/events/ipReport/verbose" then
        -- IP活动报表（内部取证模式，未转义）
        ipReportHtml(true)
        return
    elseif uri == "/events/filterBanner" then
        -- 筛选条件确认横幅
        filterBannerHtml()
        return
    elseif uri == "/events/rawRequest" then
        -- 查看原始请求（未转义）
        viewRawRequestHtml(false)
        return
    elseif uri == "/events/rawRequest/safe" then
        -- 查看原始请求（已转义）
        viewRawRequestHtml(true)
        return
    end

    ngx.say(cjson_encode(response))
end

_M.do_request()

return _M
