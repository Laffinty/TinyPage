"""生成 tp/lib/http_util.wll —— admin 路由 / 表单 / 响应构造（卡 S4-3）。

⚠ 输出的 .wll 由本文件生成，不要手改。

**为什么是纯函数**：`MATCH_ROUTE` / `PARSE_FORM` / `BUILD_RESPONSE` / `REDIRECT`
全都不碰 socket、不 import `tls` ⇒ 路由与响应语义可以在**无网络**下逐字节测
（`tp/bin/serve_admin.wll` 只做「收请求 → 调这些 → 发响应」）。

**权威落点**（逐条对齐；出入见夹具 `meta.findings`）：
  `_GET_ROUTES` / `_POST_ROUTES` / `_CSRF_EXEMPT_POST` / `MAX_POST_SIZE`
      == tinypage/admin/app.py:58-89
  `/login` `/logout` 分支与「先会话后 method」的判定顺序 == app.py:154-181
  `PARSE_FORM` 的可用性          == std.http::PARSE_FORM（实测可用，见 D-HU-1）
  `error_response` / `redirect_response` / `json_error_response` /
  `html_response` 的头序          == tinypage/admin/responses.py:17-55
  ⚠ 导出的 `TEXT_ERROR_RESPONSE` 就是 `error_response`：**故意不叫 ERROR_RESPONSE**
    —— `static_serve.wll` 内部有个同名私有函数，顶层名跨模块共享（坑 52）⇒
    同名会把它的实现覆盖掉（实测确认存在该私有名），故改用无冲突的名字。
  登录页头序（安全头在**最后**）  == app.py:226-237 `_route_login_get`
  CSP 策略串                      == tinypage/security.py:342-352
  请求体上限 10MB                 == app.py:58（原 nginx `client_max_body_size 10m`）

**与 Python 的有据偏离**（全部登记在夹具 `meta.divergences`）：
  D-HU-1 `PARSE_FORM` 直接用 `std.http`（R1 成员），不自己写解析器
  D-HU-2 非 `application/x-www-form-urlencoded` ⇒ **空表单**（Python 不判这个头）
  D-HU-3 非法 percent 转义 ⇒ **空表单**（Python 的 parse_qs 原样保留 `%ZZ`）
  D-HU-4 空值字段**剔除**（对齐 parse_qs 的 `keep_blank_values=False` 缺省）
  D-HU-5 JSON 错误体只转义 `"` `\\` 与控制字符，非 ASCII 不转 `\\uXXXX`

用法：python gen_http_util.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'http_util.wll')


def wl(s):
    """Python 字符串 → WLWL 字面量。⚠ `${...}` / `$x` 是插值 ⇒ 字面美元符写 \\$。"""
    out = []
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '$':
            out.append('\\$')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def index_set_chain(pairs):
    """[(k, v)] → 一条嵌套 INDEX_SET 表达式（键序 = 插入序 = 线上头序）。

    ⚠ 只能**单行**：paren_check / check_semis 按逐行 `(` 深度判定顶层语句。
    """
    expr = 'DICT()'
    for k, v in pairs:
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl(k), wl(v))
    return expr


# ── 路由表（逐字抄 tinypage/admin/app.py:60-89，**顺序即源码顺序**）─────────
GET_ROUTES = [
    ('/', 'dashboard'),
    ('/dashboard', 'dashboard'),
    ('/pages', 'pages_dashboard'),
    ('/new', 'new_article'),
    ('/new-page', 'new_page'),
    ('/edit', 'edit_article'),
    ('/edit-page', 'edit_page'),
    ('/theme', 'theme'),
    ('/login', 'login'),
]

POST_ROUTES = [
    ('/upload', 'upload_image'),
    ('/create', 'create_article'),
    ('/create-page', 'create_page'),
    ('/save', 'save_article'),
    ('/save-page', 'save_page'),
    ('/delete', 'delete_article'),
    ('/delete-page', 'delete_page'),
    ('/regen', 'regenerate'),
    ('/preview', 'live_preview'),
    ('/set-theme', 'set_theme'),
    ('/ai-assist', 'ai_assist'),
    ('/translate', 'translate_article'),
    ('/login', 'login_handler'),
    ('/logout', 'logout_handler'),
]

CSRF_EXEMPT = ['/upload']
AUTH_PATHS = ['/login', '/logout']

MAX_POST_SIZE = 10 * 1024 * 1024

# 状态行表（串取自 admin/app.py + responses.py + actions.py 的实际用法）
STATUS_REASONS = [
    ('200', 'OK'),
    ('302', 'Found'),
    ('400', 'Bad Request'),
    ('403', 'Forbidden'),
    ('404', 'Not Found'),
    ('405', 'Method Not Allowed'),
    ('409', 'Conflict'),
    ('429', 'Too Many Requests'),
    ('500', 'Internal Server Error'),
    ('503', 'Service Unavailable'),
]

URLENCODED = 'application/x-www-form-urlencoded'

# security.py:342-352 get_csp_header() 的 policy，逐字（含结尾分号）
CSP = ("default-src 'self'; "
       "style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: https:; "
       "font-src 'self'; "
       "script-src 'self' 'unsafe-inline'; "
       "connect-src 'self'; "
       "frame-ancestors 'none'; "
       "base-uri 'self';")

# app.py:140
RATE_LIMIT_BODY = 'Rate limit exceeded. Please try again later.'


def main():
    src = []
    A = src.append
    A('// tp/lib/http_util.wll —— admin 路由 / 表单 / 响应构造（卡 S4-3）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_http_util.py 生成 —— 请勿手改。')
    A('//')
    A('// 本模块是**纯函数**：不碰 socket、不 import `tls`、不写文件。')
    A('// 传输在入口里（tp/bin/serve_admin.wll）⇒ 路由 / 表单 / 响应可脱网逐字节测。')
    A('//')
    A('// 权威落点（逐条对齐，出入见夹具 meta.findings）：')
    A('//   路由表          == tinypage/admin/app.py:60-89（GET 9 条 + POST 14 条）')
    A('//   CSRF 豁免表     == app.py:89 `_CSRF_EXEMPT_POST = {"/upload"}`')
    A('//   判定顺序        == app.py:154-181（/login /logout 免会话；其余**先会话**再 method）')
    A('//   响应头序        == tinypage/admin/responses.py:17-55')
    A('//   登录页头序      == app.py:226-237（5 个安全头在**最后**，与 html_response 相反）')
    A('//   CSP 策略        == tinypage/security.py:342-352')
    A('//   请求体上限      == app.py:58 MAX_POST_SIZE = 10MB')
    A('//')
    A('// ⚠ 顶层名一律加 `HU_` 前缀（坑 52：顶层绑定**跨模块共享**，同名的会被互相覆盖）；')
    A('//   导出名（EXPORT）是契约名，保持与卡片一致 —— **例外一个**：')
    A('//   `TEXT_ERROR_RESPONSE`（= responses.error_response）。叫 ERROR_RESPONSE 会覆盖')
    A('//   `static_serve.wll` 里的同名私有函数（顶层名跨模块共享，坑 52）。')
    A('')
    A('IMPORT("wlwl:std.str", ["INDEX_OF", "CAT"]);')
    A('IMPORT("wlwl:std.text", ["TO_LOWER", "TO_UPPER"]);')
    A('IMPORT("wlwl:std.encode", ["BYTE_LEN"]);')
    A('// ⚠ std.http 的 PARSE_FORM 与本模块**导出的** PARSE_FORM 同名 ⇒ 必须改名导入')
    A('//   （§9：`IMPORT(path, ["orig": "alias"])`；顶层作用域共享，原样导入会被覆盖）')
    A('IMPORT("wlwl:std.http", ["PARSE_FORM": "HTTP_PARSE_FORM"]);')
    A('// 5 个安全头**复用**已交付的 static_serve.wll（不重写，S3-1 已全绿）')
    A('IMPORT("./static_serve.wll", ["SECURITY_HEADERS"]);')
    A('// CSRF Set-Cookie **复用**已交付的 security.wll（S4-1/S4-2 已全绿）')
    A('IMPORT("./security.wll", ["CSRF_COOKIE_HEADER"]);')
    A('')

    # ── 常量 ──────────────────────────────────────────────────────────
    A('// GET 路由表（app.py:60-70，9 条；`/` 与 `/dashboard` 同指 dashboard）')
    A('LET(HU_GET_ROUTES, ' + index_set_chain(GET_ROUTES) + ');')
    A('')
    A('// POST 路由表（app.py:72-87，14 条）')
    A('LET(HU_POST_ROUTES, ' + index_set_chain(POST_ROUTES) + ');')
    A('')
    A('// CSRF 豁免（app.py:89；注意：豁免只改**失败时的响应格式**，不跳过校验）')
    A('LET(HU_CSRF_EXEMPT, [' + ', '.join(wl(x) for x in CSRF_EXEMPT) + ']);')
    A('')
    A('// 免会话路径（app.py:155）')
    A('LET(HU_AUTH_PATHS, [' + ', '.join(wl(x) for x in AUTH_PATHS) + ']);')
    A('')
    A('// 请求体上限（app.py:58 `MAX_POST_SIZE = 10 * 1024 * 1024`）')
    A('LET(HU_MAX_POST_SIZE_BYTES, %d);' % MAX_POST_SIZE)
    A('')
    A('LET(HU_URLENCODED, %s);' % wl(URLENCODED))
    A('')
    A('LET(HU_STATUS_REASONS, ' + index_set_chain(STATUS_REASONS) + ');')
    A('')
    A('LET(HU_CSP, %s);' % wl(CSP))
    A('')
    A('LET(HU_RATE_LIMIT_BODY, %s);' % wl(RATE_LIMIT_BODY))
    A('')
    A('// JSON 转义的单字符表（键是**一个字符**）')
    A('LET(HU_JSON_MAP, ' + index_set_chain([
        ('"', '\\"'),
        ('\\', '\\\\'),
        ('\n', '\\n'),
        ('\r', '\\r'),
        ('\t', '\\t'),
    ]) + ');')
    A('')

    # ── 小工具 ────────────────────────────────────────────────────────
    src += fn('HU_AS_STRING', 'v, dflt', [
        '// 取字符串值；非 STRING ⇒ 默认值（坑 56：类型问题用 TYPE 前置判断，别指望 IS_ERR）',
        'IF(==(TYPE(v), "STRING"), v, dflt)',
    ], '// 非 STRING ⇒ 默认值')

    src += fn('HU_AS_DICT', 'v', [
        '// 非 DICT ⇒ 空字典（坑 35：AT_K(NULL, k, d) 是运行时 E0030）',
        'IF(==(TYPE(v), "DICT"), v, DICT())',
    ], '// 非 DICT ⇒ 空字典')

    src += fn('HU_STRIP_QUERY', 'p', [
        '// 请求目标里 "?" 之前的部分（TCP_SERVE 的 path 是**原样**目标）',
        'LET(i, INDEX_OF(p, "?"))',
        'IF(<(i, 0), p, SUB(p, 0, i))',
    ], '// 去掉查询串')

    src += fn('MAX_POST_SIZE', '', [
        '// app.py:58 —— 10MB（原 nginx `client_max_body_size 10m` 的 admin 侧语义）',
        'HU_MAX_POST_SIZE_BYTES',
    ], '// 请求体上限（字节）')

    src += fn('FORM_TOO_LARGE', 'opts', [
        '// opts 键：body / max_bytes（缺省 10MB）',
        '// Python 比的是 CONTENT_LENGTH 头；这里比**实际字节数**（入口拿到的就是 body）',
        'LET(body, AT_K(opts, "body", ""))',
        'LET(maxb, AT_K(opts, "max_bytes", HU_MAX_POST_SIZE_BYTES))',
        '>(IF(==(TYPE(body), "STRING"), BYTE_LEN(body), 0), maxb)',
    ], '// 请求体是否超上限')

    src += fn('IS_URLENCODED', 'ct', [
        '// 只认 application/x-www-form-urlencoded（卡 S4-3）/ 缺头也认（Python 不判这个头）',
        'LET(lc, TO_LOWER(HU_AS_STRING(ct, "")))',
        'IF(==(lc, ""), TRUE, ==(SUB(lc, 0, LEN(HU_URLENCODED)), HU_URLENCODED))',
    ], '// Content-Type 是否为表单编码')

    src += fn('HEADER_VALUE', 'opts', [
        '// opts 键：headers（请求头 DICT，键**已小写**）/ name',
        '// 多值头（PARSE_REQUEST 给 ARRAY[STRING]）⇒ 取**第一个**，对齐 WSGI 的单值口径',
        'LET(h, HU_AS_DICT(AT_K(opts, "headers", NULL)))',
        'LET(v, AT_K(h, TO_LOWER(HU_AS_STRING(AT_K(opts, "name", ""), "")), ""))',
        C('IF', '==(TYPE(v), "ARRAY")',
          ['IF(>(LEN(v), 0), HU_AS_STRING(AT(v, 0, ""), ""), "")'],
          ['HU_AS_STRING(v, "")']),
    ], '// 取请求头（单值）')

    src += fn('COOKIE_VALUE', 'opts', [
        '// opts 键：cookie（Cookie 头原文）/ prefix（如 "csrf_token="）',
        '// 对齐 app.py:303-312：按 ";" 切 → strip → 前缀比对 → **首个命中即停**',
        'LET(cookie, HU_AS_STRING(AT_K(opts, "cookie", ""), ""))',
        'LET(prefix, HU_AS_STRING(AT_K(opts, "prefix", ""), ""))',
        'LET MUT(out, "")',
        'LET MUT(stop, FALSE)',
        C('IF', '==(prefix, "")', ['NULL'],
          [C('FOR', 'part, SPLIT(cookie, ";")', [
              C('IF', 'stop', ['NULL'],
                ['LET(t, TRIM(part))',
                 C('IF', '==(SUB(t, 0, LEN(prefix)), prefix)',
                   ['SET(out, SUB(t, LEN(prefix)))', 'SET(stop, TRUE)'],
                   ['NULL'])])])]),
        'out',
    ], '// 从 Cookie 头取一个值（首个命中）')

    # ── 表单 ─────────────────────────────────────────────────────────
    src += fn('HU_FORM_DROP', 'v', [
        '// 去掉空值：对齐 parse_qs 的 keep_blank_values=False 缺省（D-HU-4）',
        '// 返回 NULL 表示「这个键整体剔除」',
        C('IF', '==(TYPE(v), "ARRAY")',
          ['LET MUT(kept, [])',
           C('FOR', 'x, v',
             ['IF(==(HU_AS_STRING(x, ""), ""), NULL, (SET(kept, PUSH(kept, x))))']),
           'IF(==(LEN(kept), 0), NULL, IF(==(LEN(kept), 1), AT(kept, 0, ""), kept))'],
          ['IF(==(HU_AS_STRING(v, ""), ""), NULL, v)']),
    ], '// 去掉空值')

    src += fn('HU_FORM_CLEAN', 'fields', [
        '// 逐键清洗（同名多值 ⇒ ARRAY；单值 ⇒ STRING，与 std.http::PARSE_FORM 同形）',
        'LET MUT(out, DICT())',
        C('FOR', 'k, KEYS(fields)', [
            'LET(v, HU_FORM_DROP(AT_K(fields, k, NULL)))',
            C('IF', '==(TYPE(v), "NULL")', ['NULL'], ['SET(out, INDEX_SET(out, k, v))']),
        ]),
        'out',
    ], '// 清洗表单')

    src += fn('PARSE_FORM', 'opts', [
        '// opts 键：body / content_type / max_bytes（缺省 10MB）',
        '// 返回 fields 字典：单值 STRING、同名多值 ARRAY[STRING]（空值已剔除）',
        '// ⚠ 解析器**直接用** std.http::PARSE_FORM（R1 成员，实测可用 ⇒ 不自己重写，D-HU-1）',
        'LET(body, HU_AS_STRING(AT_K(opts, "body", ""), ""))',
        C('IF', 'FORM_TOO_LARGE(opts)', ['DICT()'],
          [C('IF', 'NOT(IS_URLENCODED(AT_K(opts, "content_type", "")))', ['DICT()'],
             [C('IF', '==(body, "")', ['DICT()'],
                [C('IF', 'IS_ERR(HTTP_PARSE_FORM(body))', ['DICT()'],
                   ['HU_FORM_CLEAN(HTTP_PARSE_FORM(body))'])])])]),
    ], '// 解析表单（x-www-form-urlencoded）')

    src += fn('FORM_FIELD', 'opts', [
        '// opts 键：fields / key / default',
        '// 对齐 Python 的 `post_data.get(k, [""])[0]`',
        'LET(fields, HU_AS_DICT(AT_K(opts, "fields", NULL)))',
        'LET(dflt, AT_K(opts, "default", ""))',
        'LET(v, AT_K(fields, HU_AS_STRING(AT_K(opts, "key", ""), ""), dflt))',
        C('IF', '==(TYPE(v), "ARRAY")',
          ['IF(>(LEN(v), 0), HU_AS_STRING(AT(v, 0, dflt), dflt), dflt)'],
          ['HU_AS_STRING(v, dflt)']),
    ], '// 取一个表单字段（单值）')

    # ── 路由 ─────────────────────────────────────────────────────────
    src += fn('HU_ROUTE', 'route, kind, status, needs_session, csrf_exempt', [
        '// 命中形状：{status, route, kind, requires_session, csrf_exempt}',
        'INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", status), "route", route), "kind", kind), "requires_session", needs_session), "csrf_exempt", csrf_exempt)',
    ], '// 命中')

    src += fn('HU_MISS', 'status, needs_session', [
        '// 未命中（404）/ 方法不符（405）：route 与 kind 都是空串',
        'INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", status), "route", ""), "kind", ""), "requires_session", needs_session), "csrf_exempt", FALSE)',
    ], '// 未命中')

    src += fn('HU_MATCH_AUTH', 'method, path', [
        '// /login 与 /logout（app.py:154-166）：**不需要**会话 —— 未登录也能进登录页',
        C('IF', '&&(==(method, "GET"), ==(path, "/login"))',
          ['HU_ROUTE("login", "login", 200, FALSE, FALSE)'],
          [C('IF', '&&(==(method, "POST"), ==(path, "/login"))',
             ['HU_ROUTE("login_handler", "login_post", 200, FALSE, FALSE)'],
             [C('IF', '&&(==(method, "POST"), ==(path, "/logout"))',
                ['HU_ROUTE("logout_handler", "logout_post", 200, FALSE, FALSE)'],
                ['HU_MISS(405, FALSE)'])])]),
    ], '// /login /logout 分支')

    src += fn('HU_MATCH_PROTECTED', 'method, path', [
        '// 其余路径（app.py:168-181）：**先要会话** → 再看 method → 再查表',
        '// ⚠ 顺序是语义：未登录 PUT /x 先 302（不是 405）；有会话才可能 404 / 405',
        'LET(get_route, AT_K(HU_GET_ROUTES, path, ""))',
        'LET(post_route, AT_K(HU_POST_ROUTES, path, ""))',
        C('IF', '==(method, "GET")',
          [C('IF', '==(get_route, "")',
             ['HU_MISS(404, TRUE)'],
             ['HU_ROUTE(get_route, "get", 200, TRUE, FALSE)'])],
          [C('IF', '==(method, "POST")',
             [C('IF', '==(post_route, "")',
                ['HU_MISS(404, TRUE)'],
                ['HU_ROUTE(post_route, "post", 200, TRUE, CONTAINS(HU_CSRF_EXEMPT, path))'])],
             ['HU_MISS(405, TRUE)'])]),
    ], '// 需会话的路径')

    src += fn('MATCH_ROUTE', 'opts', [
        '// opts 键：method / path（path 可带查询串）',
        '// 返回 {status, route, kind, requires_session, csrf_exempt}',
        '// kind：login | login_post | logout_post | get | post（空串 = 未命中）',
        'LET(path0, HU_STRIP_QUERY(HU_AS_STRING(AT_K(opts, "path", "/"), "/")))',
        'LET(path, IF(==(path0, ""), "/", path0))',
        'LET(method, TO_UPPER(HU_AS_STRING(AT_K(opts, "method", "GET"), "GET")))',
        C('IF', 'CONTAINS(HU_AUTH_PATHS, path)',
          ['HU_MATCH_AUTH(method, path)'],
          ['HU_MATCH_PROTECTED(method, path)']),
    ], '// (method, path) → 路由名 + 判定结果')

    # ── 响应构造 ─────────────────────────────────────────────────────
    src += fn('STATUS_LINE', 'status', [
        '// 状态行 = "<code> <reason>"（串逐字取自 admin/app.py + responses.py）',
        'CAT(STR(status), " ", AT_K(HU_STATUS_REASONS, STR(status), "Unknown"))',
    ], '// 状态行')

    src += fn('HU_RESPONSE', 'status, headers, body', [
        '// handler 契约形（TCP_SERVE 只要求这三个键；实测多余键被忽略）',
        'INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", status), "headers", headers), "body", body)',
    ], '// 响应字典')

    src += fn('HU_MERGE', 'a, b', [
        '// 把 b 的键按插入序并入 a（同键覆盖值，位置保留 —— dict 语义）',
        'LET MUT(out, a)',
        C('FOR', 'k, KEYS(b)', ['SET(out, INDEX_SET(out, k, AT_K(b, k, "")))']),
        'out',
    ], '// 合并头字典')

    src += fn('HU_PAIR_DICT', 'pair', [
        '// ["Set-Cookie", "<cookie>"] → {Set-Cookie: <cookie>}（security.wll 的返回形状）',
        'IF(>(LEN(pair), 1), INDEX_SET(DICT(), AT(pair, 0, "Set-Cookie"), AT(pair, 1, "")), DICT())',
    ], '// 头对 → 单键字典')

    src += fn('HU_ADDON', 'token, secure, csp, set_cookie', [
        '// 业务附加头，顺序 = responses.py 的追加顺序：',
        '//   set_cookie（调用方给的 [name, value]）→ CSRF Set-Cookie（有 token 才发）→ CSP',
        'LET MUT(out, DICT())',
        C('IF', '==(TYPE(set_cookie), "ARRAY")',
          [C('IF', '>(LEN(set_cookie), 1)',
             ['SET(out, INDEX_SET(out, AT(set_cookie, 0, "Set-Cookie"), AT(set_cookie, 1, "")))'],
             ['NULL'])],
          ['NULL']),
        C('IF', '==(token, "")', ['NULL'],
          ['SET(out, HU_MERGE(out, HU_PAIR_DICT(CSRF_COOKIE_HEADER(INDEX_SET(INDEX_SET(DICT(), "token", token), "secure", secure)))))']),
        C('IF', 'csp',
          ['SET(out, INDEX_SET(out, "Content-Security-Policy", HU_CSP))'],
          ['NULL']),
        'out',
    ], '// 附加业务头')

    src += fn('BUILD_RESPONSE', 'opts', [
        '// opts 键：status / headers（基础头 DICT，**键序即线序**）/ body / method；',
        '//          csrf_token / secure / csp / security（缺省 TRUE）/ security_last / set_cookie',
        '// 头序：基础头 → [安全头] → set_cookie → CSRF cookie → CSP',
        '//   security_last = TRUE 时安全头**移到最后**（app.py:231-235 登录页的真实头序）',
        '// ⚠ 不补 Content-Length：wsgiref 也是传输层补（实测 TCP_SERVE 会补）',
        'LET(status, AT_K(opts, "status", 200))',
        'LET(base, HU_AS_DICT(AT_K(opts, "headers", NULL)))',
        'LET(token, HU_AS_STRING(AT_K(opts, "csrf_token", ""), ""))',
        'LET(addon, HU_ADDON(token, AT_K(opts, "secure", FALSE), AT_K(opts, "csp", FALSE), AT_K(opts, "set_cookie", NULL)))',
        'LET(sec, IF(AT_K(opts, "security", TRUE), SECURITY_HEADERS(), DICT()))',
        'LET MUT(h, base)',
        C('IF', 'AT_K(opts, "security_last", FALSE)',
          ['SET(h, HU_MERGE(h, addon))', 'SET(h, HU_MERGE(h, sec))'],
          ['SET(h, HU_MERGE(h, sec))', 'SET(h, HU_MERGE(h, addon))']),
        'LET(body, HU_AS_STRING(AT_K(opts, "body", ""), ""))',
        'LET(is_head, ==(TO_UPPER(HU_AS_STRING(AT_K(opts, "method", "GET"), "GET")), "HEAD"))',
        'HU_RESPONSE(status, h, IF(is_head, "", body))',
    ], '// 通用响应构造')

    src += fn('TEXT_ERROR_RESPONSE', 'status, message', [
        '// responses.py:23 error_response —— Content-Type text/plain + 5 个安全头',
        '// ⚠ 名字里带 TEXT 是为了避开 static_serve.wll 的同名私有函数（坑 52，见文件头）',
        'BUILD_RESPONSE(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", status), "headers", INDEX_SET(DICT(), "Content-Type", "text/plain")), "body", message))',
    ], '// 纯文本错误响应')

    src += fn('JSON_ESCAPE', 's', [
        '// 逐字符转义 " 与 \\ 与 \\n / \\r / \\t（Python 的 json.dumps 还会把非 ASCII 转 \\uXXXX）',
        '// ⇒ 非 ASCII 原样发：仍是合法 UTF-8 JSON，只是**字面**与 Python 不同（D-HU-5）',
        'LET MUT(out, "")',
        'LET(n, LEN(s))',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, n)', [
            'LET(c, SUB(s, i, 1))',
            'LET(esc, AT_K(HU_JSON_MAP, c, NULL))',
            'SET(out, CAT(out, IF(==(TYPE(esc), "NULL"), c, esc)))',
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// JSON 字符串转义')

    src += fn('JSON_ERROR_RESPONSE', 'status, message', [
        '// responses.py:31 json_error_response —— {"success": false, "error": "..."}',
        '// ⚠ 空格与键序逐字对齐 json.dumps 的缺省输出',
        'LET(body, CAT("{\\"success\\": false, \\"error\\": \\"", JSON_ESCAPE(message), "\\"}"))',
        'BUILD_RESPONSE(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", status), "headers", INDEX_SET(DICT(), "Content-Type", "application/json")), "body", body))',
    ], '// JSON 错误响应')

    src += fn('JSON_RESPONSE', 'opts', [
        '// 业务 JSON 响应（upload / ai）：Content-Type application/json + 5 个安全头',
        'BUILD_RESPONSE(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", AT_K(opts, "status", 200)), "headers", INDEX_SET(DICT(), "Content-Type", "application/json")), "body", AT_K(opts, "body", "")))',
    ], '// JSON 响应')

    src += fn('HTML_RESPONSE', 'opts', [
        '// responses.py:39 html_response：Content-Type → 5 安全头 → CSRF cookie → CSP',
        '// security_last = TRUE ⇒ Content-Type → CSRF cookie → CSP → 5 安全头',
        '//   （app.py:226-237 `_route_login_get` 的真实头序）',
        'BUILD_RESPONSE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", AT_K(opts, "status", 200)), "headers", INDEX_SET(DICT(), "Content-Type", "text/html; charset=utf-8")), "body", AT_K(opts, "body", "")), "method", AT_K(opts, "method", "GET")), "csrf_token", AT_K(opts, "csrf_token", "")), "secure", AT_K(opts, "secure", FALSE)), "csp", TRUE), "security_last", AT_K(opts, "security_last", FALSE)))',
    ], '// HTML 响应')

    src += fn('REDIRECT', 'opts', [
        '// responses.py:17 redirect_response —— Location + 5 安全头，302，body 空',
        '// opts 可再给 set_cookie（[name, value]），排在 Location 之后（logout 用它清会话，',
        '//   那时必须同时给 security_last = TRUE —— actions.py:433-436 的头序是',
        '//   Location → Set-Cookie → 5 个安全头）',
        'BUILD_RESPONSE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", 302), "headers", INDEX_SET(DICT(), "Location", AT_K(opts, "location", "/login"))), "body", ""), "set_cookie", AT_K(opts, "set_cookie", NULL)), "security_last", AT_K(opts, "security_last", FALSE)))',
    ], '// 302 重定向')

    src += fn('RATE_LIMIT_RESPONSE', 'opts', [
        '// app.py:132-140 —— 429 + Content-Type / Retry-After + 5 个安全头',
        'LET(h, INDEX_SET(INDEX_SET(DICT(), "Content-Type", "text/plain"), "Retry-After", STR(AT_K(opts, "retry_after", 1))))',
        'BUILD_RESPONSE(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", 429), "headers", h), "body", HU_RATE_LIMIT_BODY))',
    ], '// 429 响应')

    src += fn('STATIC_RESPONSE', 'opts', [
        '// app.py:142-152 —— 注入的 CSS/JS 不发会话；**显式**给 Content-Length',
        '// 头序：Content-Type / Content-Length / Cache-Control + 5 个安全头',
        'LET(body, HU_AS_STRING(AT_K(opts, "body", ""), ""))',
        'LET(h, INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "Content-Type", AT_K(opts, "content_type", "text/plain")), "Content-Length", STR(BYTE_LEN(body))), "Cache-Control", AT_K(opts, "cache_control", "max-age=3600")))',
        'BUILD_RESPONSE(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", 200), "headers", h), "body", body))',
    ], '// 静态资源响应')

    A('')
    A('EXPORT(["PARSE_FORM", "FORM_FIELD", "FORM_TOO_LARGE", "MAX_POST_SIZE",')
    A('    "MATCH_ROUTE", "COOKIE_VALUE", "HEADER_VALUE", "STATUS_LINE", "JSON_ESCAPE",')
    A('    "BUILD_RESPONSE", "TEXT_ERROR_RESPONSE", "JSON_ERROR_RESPONSE", "JSON_RESPONSE",')
    A('    "HTML_RESPONSE", "REDIRECT", "RATE_LIMIT_RESPONSE", "STATIC_RESPONSE"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
