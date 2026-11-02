"""生成 tp/test/test_http_util.wll —— admin 路由/表单/响应的脱网测试（卡 S4-3）。

⚠ 输出的 .wll 由本文件生成，不要手改。

**为什么能脱网**：`tp/lib/http_util.wll` 是纯函数（不碰 socket），所以测试直接调
`MATCH_ROUTE` / `PARSE_FORM` / `BUILD_RESPONSE` 比对 `status` / `route` / `kind` /
头序 / 头值 / body。

**基准**：tp/test/fixtures/http_util_baseline.json
（由 `gen_http_util_baseline.py` 生成：期望值 + 出处，且**生成期已与真 Python 对拍**——
路由表对 `AdminApp`、表单对 `parse_qs`、响应对 `responses.py`）。

**覆盖**：
  · 路由表逐条（GET 9 / POST 14 → 路由名 + status）
  · 13 条分发用例（status / route / kind / requires_session / csrf_exempt）
    —— 其中「未登录先 302 而不是 405/403」是判定**顺序**的证据
  · 14 条表单用例（+ / percent / 多值 / 空值剔除 / 非法转义 / 非 urlencoded）
  · 上限边界（MAX_POST_SIZE = 10MB；`>` 而不是 `>=`）
  · 10 条响应用例（status / 头序 / 每个头的值 / body）
  · 10 条状态行
  · 反向守卫：未登录 PUT 不得直接 405/403；只有 /upload 是 CSRF 豁免；
    错误响应**不发** CSP；重定向 body 为空

**自己把关退出码**：`RUN_TESTS()` 的失败**不影响退出码**（规范明载）
⇒ 末尾必须 `IF(>(failed, 0), PANIC(...), NULL)`。

用法：python gen_test_http_util.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_http_util.wll')

TOK = 'TESTTOKEN0123456789'

# 响应用例名 → 被测调用（与夹具里的期望一一对应）
RESPONSE_CALLS = {
    'error_404': 'TEXT_ERROR_RESPONSE(404, "Not Found")',
    'error_405': 'TEXT_ERROR_RESPONSE(405, "Method not allowed")',
    'error_403': 'TEXT_ERROR_RESPONSE(403, "CSRF validation failed")',
    'redirect_login': 'REDIRECT(INDEX_SET(DICT(), "location", "/login"))',
    'redirect_theme': 'REDIRECT(INDEX_SET(DICT(), "location", "/theme"))',
    'json_error_403': 'JSON_ERROR_RESPONSE(403, "CSRF validation failed")',
    'html_csrf': 'HTML_RESPONSE(INDEX_SET(INDEX_SET(DICT(), "body", "<b>x</b>"), '
                 '"csrf_token", "TESTTOKEN0123456789"))',
    'html_no_csrf': 'HTML_RESPONSE(INDEX_SET(DICT(), "body", "<b>x</b>"))',
    'login_page': 'HTML_RESPONSE(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "body", "LOGIN"), '
                  '"csrf_token", "TESTTOKEN0123456789"), "security_last", TRUE))',
    'rate_limit': 'RATE_LIMIT_RESPONSE(INDEX_SET(DICT(), "retry_after", 42))',
    'static_asset': 'STATIC_RESPONSE(INDEX_SET(INDEX_SET(DICT(), "content_type", "text/css"), '
                    '"body", "body{}"))',
}


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


def wl_value(v):
    """夹具里的值（str 或 list[str]）→ WLWL 表达式。"""
    if isinstance(v, list):
        return '[' + ', '.join(wl(x) for x in v) + ']'
    return wl(v)


def route_opts(case):
    return 'INDEX_SET(INDEX_SET(DICT(), "method", %s), "path", %s)' % (
        wl(case['method']), wl(case['path']))


def form_opts(case):
    return 'INDEX_SET(INDEX_SET(DICT(), "body", %s), "content_type", %s)' % (
        wl(case['body']), wl(case['content_type']))


def main():
    with open(os.path.join(FIXTURES, 'http_util_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)

    routes = base['routes']
    route_cases = base['route_cases']
    form_cases = base['form_cases']
    size_cases = base['size_cases']
    response_cases = base['response_cases']
    status_lines = base['status_lines']
    csp = base['csp']
    max_post = routes['max_post_size']

    n_tests = 0
    src = []
    A = src.append
    A('// tp/test/test_http_util.wll —— admin 路由/表单/响应的脱网测试（卡 S4-3）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_http_util.py 生成 —— 请勿手改。')
    A('//')
    A('// 被测：tp/lib/http_util.wll 的 MATCH_ROUTE / PARSE_FORM / BUILD_RESPONSE 族。')
    A('// 基准：tp/test/fixtures/http_util_baseline.json')
    A('//   · 每条期望都带出处（app.py / responses.py / actions.py 行号）')
    A('//   · 生成期已与**真 Python** 对拍（AdminApp 分发 / parse_qs / responses.py）')
    A('//')
    A('// 本文件是**脱网**的：被测模块不碰 socket、不 import tls。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["JOIN", "CAT"]);')
    A('IMPORT("./../lib/http_util.wll", ["PARSE_FORM", "FORM_FIELD", "FORM_TOO_LARGE",')
    A('    "MAX_POST_SIZE", "MATCH_ROUTE", "COOKIE_VALUE", "HEADER_VALUE", "STATUS_LINE",')
    A('    "BUILD_RESPONSE", "TEXT_ERROR_RESPONSE", "JSON_ERROR_RESPONSE", "JSON_RESPONSE",')
    A('    "HTML_RESPONSE", "REDIRECT", "RATE_LIMIT_RESPONSE", "STATIC_RESPONSE"]);')
    A('')

    # ── 预计算（⚠ LET 不能放进 TEST 的 FUN 体）───────────────────────
    A('// ── 预计算响应与路由判定（⚠ LET 不能放进 TEST 的 FUN 体）──────────')
    for c in response_cases:
        name = c['name']
        if name not in RESPONSE_CALLS:
            raise SystemExit('夹具里有未登记的响应用例: %s' % name)
        A('// resp_%s —— %s（%s）' % (name, c['note'], c['source']))
        A('LET(resp_%s, %s);' % (name, RESPONSE_CALLS[name]))
    A('')
    for c in route_cases:
        A('// route_%s —— %s' % (c['name'], c['note']))
        A('LET(route_%s, MATCH_ROUTE(%s));' % (c['name'], route_opts(c)))
    A('')
    for c in form_cases:
        A('// form_%s —— %s' % (c['name'], c['note']))
        A('LET(form_%s, PARSE_FORM(%s));' % (c['name'], form_opts(c)))
    A('')

    # ── 路由表逐条 ──────────────────────────────────────────────────
    A('// ── 路由表逐条（app.py:60-87）：路径 → 路由名 / status ─────────────')
    for method, table in (('GET', routes['get']), ('POST', routes['post'])):
        for path, route in table:
            safe = (method.lower() + '_' + path.strip('/').replace('/', '_')
                    .replace('-', '_')) or (method.lower() + '_root')
            A('LET(tr_%s, MATCH_ROUTE(INDEX_SET(INDEX_SET(DICT(), "method", %s), "path", %s)));'
              % (safe, wl(method), wl(path)))
            A('TEST("table/%s/%s/route", FUN(() ,' % (method, safe))
            A('    (ASSERT_EQ(AT_K(tr_%s, "route", "<missing>"), %s));'
              % (safe, wl(route)))
            A('    TRUE));')
            A('TEST("table/%s/%s/status", FUN(() ,' % (method, safe))
            A('    (ASSERT_EQ(AT_K(tr_%s, "status", -1), 200));' % safe)
            A('    TRUE));')
            n_tests += 2
    A('')

    # ── 分发用例 ────────────────────────────────────────────────────
    A('// ── 分发用例（13 条）：status / route / kind / requires_session / csrf_exempt')
    A('//   ⚠ 这批用例的期望值与**真 Python 的 AdminApp 实测**生成期对过拍')
    for c in route_cases:
        name = c['name']
        A('// %s —— %s' % (name, c['note']))
        A('TEST("match/%s/status", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(route_%s, "status", -1), %d));' % (name, c['match_status']))
        A('    TRUE));')
        A('TEST("match/%s/route", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(route_%s, "route", "<missing>"), %s));'
          % (name, wl(c['match_route'])))
        A('    TRUE));')
        A('TEST("match/%s/kind", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(route_%s, "kind", "<missing>"), %s));'
          % (name, wl(c['match_kind'])))
        A('    TRUE));')
        A('TEST("match/%s/requires_session", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(route_%s, "requires_session", "<missing>"), %s));'
          % (name, 'TRUE' if c['match_requires_session'] else 'FALSE'))
        A('    TRUE));')
        A('TEST("match/%s/csrf_exempt", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(route_%s, "csrf_exempt", "<missing>"), %s));'
          % (name, 'TRUE' if c['match_csrf_exempt'] else 'FALSE'))
        A('    TRUE));')
        n_tests += 5
    A('')

    # ── 表单用例 ────────────────────────────────────────────────────
    A('// ── 表单用例：键序 / 键数 / 每个键的值（多值用 "|" 拼）──────────────')
    for c in form_cases:
        name = c['name']
        expect = c['expect']
        keys = '|'.join(k for k, _ in expect)
        A('// %s —— %s（%s）' % (name, c['note'], c['source']))
        A('TEST("form/%s/keys", FUN(() ,' % name)
        A('    (ASSERT_EQ(JOIN(KEYS(form_%s), "|"), %s));' % (name, wl(keys)))
        A('    TRUE));')
        A('TEST("form/%s/count", FUN(() ,' % name)
        A('    (ASSERT_EQ(LEN(KEYS(form_%s)), %d));' % (name, len(expect)))
        A('    TRUE));')
        n_tests += 2
        for k, v in expect:
            tid = k if k else '<empty>'
            A('TEST("form/%s/%s", FUN(() ,' % (name, tid))
            if isinstance(v, list):
                A('    (ASSERT_EQ(JOIN(AT_K(form_%s, %s, []), "|"), %s));'
                  % (name, wl(k), wl('|'.join(v))))
            else:
                A('    (ASSERT_EQ(AT_K(form_%s, %s, "<missing>"), %s));'
                  % (name, wl(k), wl(v)))
            A('    TRUE));')
            n_tests += 1
    A('')

    # ── 上限边界 ────────────────────────────────────────────────────
    A('// ── 请求体上限（app.py:58 / :324：判据是 `>` 不是 `>=`）─────────────')
    A('TEST("size/max_post_size_bytes", FUN(() ,')
    A('    (ASSERT_EQ(MAX_POST_SIZE(), %d));' % max_post)
    A('    TRUE));')
    A('TEST("size/max_post_size_is_10mb", FUN(() ,')
    A('    (ASSERT_EQ(MAX_POST_SIZE(), *(10, 1048576)));')
    A('    TRUE));')
    n_tests += 2
    for c in size_cases:
        # 用小体积 + 注入 max_bytes 钉「> 而不是 >=」这条判据
        A('// %s —— %s' % (c['name'], c['note']))
        A('TEST("size/%s", FUN(() ,' % c['name'])
        A('    (ASSERT_EQ(FORM_TOO_LARGE(INDEX_SET(INDEX_SET(DICT(), "body", %s), '
          '"max_bytes", %d)), %s));'
          % (wl(c['body']), c['max_bytes'], 'TRUE' if c['too_large'] else 'FALSE'))
        A('    TRUE));')
        n_tests += 1
    A('// 缺省阈值就是 10MB（短体在缺省阈值下不可能超）')
    A('TEST("size/default_threshold_is_max", FUN(() ,')
    A('    (ASSERT_EQ(FORM_TOO_LARGE(INDEX_SET(DICT(), "body", "abcde")), FALSE));')
    A('    TRUE));')
    n_tests += 1
    A('')

    # ── 响应用例 ────────────────────────────────────────────────────
    A('// ── 响应用例：status / 头序 / 每个头的值 / body ────────────────────')
    for c in response_cases:
        name = c['name']
        names = [k for k, _ in c['headers']]
        A('')
        A('// %s —— %s（%s）' % (name, c['note'], c['source']))
        A('TEST("resp/%s/status", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(resp_%s, "status", -1), %d));' % (name, c['status']))
        A('    TRUE));')
        A('TEST("resp/%s/status_line", FUN(() ,' % name)
        A('    (ASSERT_EQ(STATUS_LINE(AT_K(resp_%s, "status", -1)), %s));'
          % (name, wl(c['status_line'])))
        A('    TRUE));')
        A('TEST("resp/%s/header_order", FUN(() ,' % name)
        A('    (ASSERT_EQ(JOIN(KEYS(AT_K(resp_%s, "headers", DICT())), "|"), %s));'
          % (name, wl('|'.join(names))))
        A('    TRUE));')
        A('TEST("resp/%s/header_count", FUN(() ,' % name)
        A('    (ASSERT_EQ(LEN(KEYS(AT_K(resp_%s, "headers", DICT()))), %d));'
          % (name, len(names)))
        A('    TRUE));')
        for k, v in c['headers']:
            A('TEST("resp/%s/header/%s", FUN(() ,' % (name, k))
            A('    (ASSERT_EQ(AT_K(AT_K(resp_%s, "headers", DICT()), %s, "<missing>"), %s));'
              % (name, wl(k), wl(v)))
            A('    TRUE));')
            n_tests += 1
        A('TEST("resp/%s/body", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(resp_%s, "body", "<missing>"), %s));'
          % (name, wl(c['body'])))
        A('    TRUE));')
        n_tests += 4 + len(c['headers'])
    A('')

    # ── 状态行 ──────────────────────────────────────────────────────
    A('// ── 状态行（串逐字取自 app.py / responses.py）──────────────────────')
    for code, line in status_lines:
        A('TEST("status_line/%s", FUN(() ,' % code)
        A('    (ASSERT_EQ(STATUS_LINE(%s), %s));' % (code, wl(line)))
        A('    TRUE));')
        n_tests += 1
    A('')

    # ── 反向守卫 ────────────────────────────────────────────────────
    A('// ── 反向守卫（卡 S4-3 明确要求的三条 + 三条实现约束）───────────────')
    A('// ① 未登录访问 / ⇒ 入口必须 302（这里钉的是「MATCH_ROUTE 说这路径要会话」）')
    A('TEST("guard/anon_root_needs_session", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(MATCH_ROUTE(INDEX_SET(INDEX_SET(DICT(), "method", "GET"), '
      '"path", "/")), "requires_session", FALSE), TRUE));')
    A('    TRUE));')
    A('// ② 未登录 PUT /create 也**先要会话**（不是 405、不是 403）—— 顺序守卫')
    A('TEST("guard/anon_put_needs_session_first", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(MATCH_ROUTE(INDEX_SET(INDEX_SET(DICT(), "method", "PUT"), '
      '"path", "/create")), "requires_session", FALSE), TRUE));')
    A('    TRUE));')
    A('// ③ CSRF 豁免**只有** /upload（app.py:89）；其余 POST 都不是豁免')
    A('TEST("guard/csrf_exempt_only_upload", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(MATCH_ROUTE(INDEX_SET(INDEX_SET(DICT(), "method", "POST"), '
      '"path", "/upload")), "csrf_exempt", FALSE), TRUE));')
    A('    TRUE));')
    A('TEST("guard/csrf_exempt_not_create", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(MATCH_ROUTE(INDEX_SET(INDEX_SET(DICT(), "method", "POST"), '
      '"path", "/create")), "csrf_exempt", TRUE), FALSE));')
    A('    TRUE));')
    A('TEST("guard/csrf_exempt_not_save", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(MATCH_ROUTE(INDEX_SET(INDEX_SET(DICT(), "method", "POST"), '
      '"path", "/save")), "csrf_exempt", TRUE), FALSE));')
    A('    TRUE));')
    A('// ④ 登录页**不要**会话（否则未登录永远进不去 ⇒ 死循环）')
    A('TEST("guard/login_page_no_session", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(MATCH_ROUTE(INDEX_SET(INDEX_SET(DICT(), "method", "GET"), '
      '"path", "/login")), "requires_session", TRUE), FALSE));')
    A('    TRUE));')
    A('// ⑤ 错误响应**不发** CSP（security.py:342 是 HTML 页专用）')
    A('TEST("guard/error_has_no_csp", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(AT_K(resp_error_404, "headers", DICT()), '
      '"Content-Security-Policy", "<absent>"), "<absent>"));')
    A('    TRUE));')
    A('TEST("guard/html_has_csp", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(AT_K(resp_html_csrf, "headers", DICT()), '
      '"Content-Security-Policy", "<absent>"), %s));' % wl(csp))
    A('    TRUE));')
    A('// ⑥ 重定向 body 必须为空（不能把页面塞进 302）')
    A('TEST("guard/redirect_body_empty", FUN(() ,')
    A('    (ASSERT_EQ(LEN(AT_K(resp_redirect_login, "body", "x")), 0));')
    A('    TRUE));')
    A('// ⑦ 只读工具：Cookie 解析「首个命中即停」/ 头取值大小写不敏感')
    A('LET(cv, COOKIE_VALUE(INDEX_SET(INDEX_SET(DICT(), "cookie", '
      '"x=1; csrf_token=FIRST; csrf_token=SECOND"), "prefix", "csrf_token=")));')
    A('TEST("guard/cookie_first_match", FUN(() ,')
    A('    (ASSERT_EQ(cv, "FIRST"));')
    A('    TRUE));')
    A('LET(hv, HEADER_VALUE(INDEX_SET(INDEX_SET(DICT(), "headers", '
      'INDEX_SET(DICT(), "content-type", "text/plain")), "name", "Content-Type")));')
    A('TEST("guard/header_lower_insensitive", FUN(() ,')
    A('    (ASSERT_EQ(hv, "text/plain"));')
    A('    TRUE));')
    A('// ⑧ 字段取值对齐 `post_data.get(k, [""])[0]`（多值时取第一个）')
    A('LET(ff, FORM_FIELD(INDEX_SET(INDEX_SET(DICT(), "fields", '
      'PARSE_FORM(INDEX_SET(DICT(), "body", "k=1&k=2"))), "key", "k")));')
    A('TEST("guard/form_field_first_value", FUN(() ,')
    A('    (ASSERT_EQ(ff, "1"));')
    A('    TRUE));')
    A('LET(ff_missing, FORM_FIELD(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "fields", DICT()), '
      '"key", "k"), "default", "dflt")));')
    A('TEST("guard/form_field_default", FUN(() ,')
    A('    (ASSERT_EQ(ff_missing, "dflt"));')
    A('    TRUE));')
    A('// ⑨ HEAD：body 清空但头一个不少（wsgiref / TCP_SERVE 的 HEAD 语义）')
    A('//   ⚠ 用**同一份 opts** 只换 method，才是「头不变」的严格对比')
    A('LET(head_base, INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", 200), "headers", '
      'INDEX_SET(DICT(), "Content-Type", "text/plain")), "body", "hello"));')
    A('LET(head_resp, BUILD_RESPONSE(head_base));')
    A('LET(head_resp2, BUILD_RESPONSE(INDEX_SET(head_base, "method", "HEAD")));')
    A('TEST("guard/head_body_empty", FUN(() ,')
    A('    (ASSERT_EQ(LEN(AT_K(head_resp2, "body", "x")), 0));')
    A('    TRUE));')
    A('TEST("guard/head_headers_kept", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(AT_K(head_resp2, "headers", DICT())), "|"), '
      'JOIN(KEYS(AT_K(head_resp, "headers", DICT())), "|")));')
    A('    TRUE));')
    n_tests += 12

    # ── 跑测试 + 自己把关退出码 ─────────────────────────────────────
    A('')
    A('// ── 跑测试 + 自己把关退出码 ─────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_http_util: ", LEN(records), " test(s) run");')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"), " :: ", '
      'AT_K(rec, "error", ""))))));')
    A('PRINT("test_http_util: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_http_util: FAILED"); '
      'PANIC("http_util tests failed")), NULL);')
    A('PRINT("test_http_util: OK");')

    chars, lines = write(OUT, src)
    # ⚠ n_tests 只是**估算**（.wll 里实际注册数由 RUN_TESTS 报）；别照它核对
    print('wrote %s (%d chars, %d lines, ~%d tests)' % (OUT, chars, lines, n_tests))


if __name__ == '__main__':
    main()
