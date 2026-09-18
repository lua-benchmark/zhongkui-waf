# zhongkui-waf - Lua SAST benchmark snapshot

Frozen snapshot of an upstream project, republished for Lua static-analysis benchmarking.
**This is not a fork for contribution.** File issues and pull requests upstream.

## Provenance

| | |
|---|---|
| Upstream | <https://github.com/bukaleyang/zhongkui-waf> |
| Branch | `master` |
| Commit | `bb3a9cdb8df8ff23be12a428fefaa240780e9985` |
| Snapshot taken | 2026-09-18 |
| Upstream stars at snapshot | 185 |
| Deliberately vulnerable (GOAT) | No |

The tree is byte-identical to upstream at that commit, with two exceptions: the `.git` directory
was removed and replaced by a single `initial version` commit, and this `BENCHMARK.md` was added.
No upstream file was modified, so every line number still matches upstream.

## Corpus metadata

**Project type:** Web application firewall (nginx/OpenResty module) + admin web UI and REST API

**Lua version:** 5.1 / LuaJIT 2.1 (OpenResty 1.25.3.2)

**Frameworks and libraries:** OpenResty/ngx_lua, lua-cjson, lua-resty-redis, lua-resty-mysql, lua-resty-cookie, lua-resty-ipmatcher, lua-resty-string/aes, resty.maxminddb + libinjection (FFI), luafilesystem

**Size class:** Small (~7508 LOC)

## Taint sources of interest

HTTP query parameters (ngx.req.get_uri_args), HTTP request body (ngx.req.get_body_data, get_body_file, get_post_args, multipart parsing), HTTP headers and cookies (ngx.req.get_headers, ngx.var.http_cookie, resty.cookie :get), HTTP path and method (ngx.var.request_uri, ngx.req.get_method), Database read (resty.mysql db:query), Shared storage (ngx.ctx, ngx.shared DICT, redis get), Local file read (io.open, lfs.dir)
