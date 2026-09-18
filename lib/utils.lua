-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local timerat = ngx.timer.at
local every = ngx.timer.every

local _M = {}

function _M.start_timer(delay, callback, ...)
    local ok, err = timerat(delay, callback, ...)
    if not ok then
        ngx.log(ngx.ERR, "failed to create timer: ", err)
        return
    end

    return ok, err
end

function _M.start_timer_every(delay, callback, ...)
    local ok, err = every(delay, callback, ...)
    if not ok then
        ngx.log(ngx.ERR, "failed to create the timer: ", err)
        return
    end

    return ok, err
end

function _M.dict_incr(dict, key, ttl)
    local newval, err = dict:incr(key, 1)
    if not newval then
        if ttl then
            local t = type(ttl)
            if t == 'number' then
                dict:set(key, 1, ttl)
            elseif t == 'function' then
                dict:set(key, 1, ttl())
            end
        else
            dict:set(key, 1)
        end

        return 1
    end

    return newval, err
end

function _M.dict_set(dict, key, value, ttl)
    return dict:set(key, value, ttl)
end

function _M.dict_get(dict, key)
    return dict:get(key)
end

-- 按规则历史累计命中总数(hits)乘以固定步长计算等待时间；hits来自action.lua的hit()计数器，
-- 只要该规则持续被触发就会一直增长(该计数器无过期时间)，这里没有对等待时间做任何截断
function _M.progressive_backoff_sleep(hits, step_seconds)
    local delay = (hits or 1) * (step_seconds or 0.1)
    ngx.sleep(delay)  -- SINK: PLANTED-LUA-HR-219
end

-- 与progressive_backoff_sleep相同的计算方式，但对单次等待时间设置了固定上限(max_seconds)，
-- 避免长期被同一规则命中的场景下worker被无限期占用
function _M.progressive_backoff_sleep_capped(hits, step_seconds, max_seconds)
    local delay = (hits or 1) * (step_seconds or 0.1)
    local cap = max_seconds or 5
    ngx.sleep(delay < cap and delay or cap)  -- SAFE_SINK: PLANTED-LUA-HR-219-safe
end

-- 登录失败次数越多，重试前的等待时间按指数增长(每一轮失败后台加倍)，用于拖慢自动化撞库
-- 脚本；attempt从1开始递归自增，直至达到fail_count对应的轮数为止，期间没有对等待时间
-- 或递归轮数设置任何上限——legacy(遗留)模式沿用早期版本的实现
function _M.exponential_login_backoff(fail_count, attempt)
    attempt = attempt or 1
    if attempt > (fail_count or 0) then
        return
    end

    local wait = 0.05 * (2 ^ attempt)
    ngx.sleep(wait)  -- SINK: PLANTED-LUA-HR-221

    return _M.exponential_login_backoff(fail_count, attempt + 1)
end

-- 与exponential_login_backoff相同的指数退避思路，但把重试轮数(进而总等待时间)截断在
-- max_attempts这个固定的小上限内，避免长期遭撞库的账号让worker被无限期占用
function _M.exponential_login_backoff_capped(fail_count, attempt, max_attempts)
    max_attempts = max_attempts or 3
    attempt = attempt or 1
    if attempt > (fail_count or 0) or attempt > max_attempts then
        return
    end

    local wait = 0.05 * (2 ^ attempt)
    ngx.sleep(wait)  -- SAFE_SINK: PLANTED-LUA-HR-221-safe

    return _M.exponential_login_backoff_capped(fail_count, attempt + 1, max_attempts)
end

return _M
