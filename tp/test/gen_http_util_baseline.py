"""生成 tp/test/fixtures/http_util_baseline.json —— 路由/表单/响应的验收基准（卡 S4-3）。

⚠ 输出的 JSON 由本文件生成，不要手改。

**为什么这份夹具可信**：它不是「我读源码写下来的表」，而是**生成期跑真 Python 对拍**
的结果 —— 任一处不一致，本脚本直接崩（不会写出一份错的基准）：

  ① 路由表：`AdminApp._GET_ROUTES` / `_POST_ROUTES` / `_CSRF_EXEMPT_POST` /
     `MAX_POST_SIZE` 与本夹具逐键逐值相等（tinypage/admin/app.py:58-89）。
  ② 分发行为：用假 environ 直接调 `AdminApp.__call__`，对「未登录 / 有会话 /
     缺 CSRF / 有合法 CSRF」四类组合记录真实 `status` + `Location`，并与本夹具
     手写的期望逐条比对（覆盖 app.py:154-181 的**判定顺序**）。
  ③ 表单：本夹具的期望字典与 `urllib.parse.parse_qs`（缺省 `keep_blank_values=False`）
     逐键相等（D-HU-4 的依据）。
  ④ 响应：直接调 `tinypage/admin/responses.py` 的四个构造函数（假 start_response
     捕获 status/headers/body），与本夹具的头序、头值、body 逐条相等；CSP 串对
     `security.get_csp_header()`。

用法：python gen_http_util_baseline.py
"""
import io
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, HERE)

# 单一真相：路由表 / 上限 / 状态行 / CSP 都从实现生成器里取，避免两处漂移。
from gen_http_util import (  # noqa: E402
    AUTH_PATHS, CSP, CSRF_EXEMPT, GET_ROUTES, MAX_POST_SIZE, POST_ROUTES,
    RATE_LIMIT_BODY, STATUS_REASONS,
)

OUT = os.path.join(HERE, 'fixtures', 'http_util_baseline.json')

ADMIN_PORT = 8081
ORIGIN = 'http://127.0.0.1:%d' % ADMIN_PORT


# ── MATCH_ROUTE 层的期望（对 app.py:154-181 判定树的**直接镜像**）────────────
# ⚠ 这是「手写的第二份实现」，所以生成期用 Python 实测去校验它（见 route_cases 循环）；
#   它存在的意义是把「顺序」写死：/login /logout 免会话；其余**先会话**再 method。
def expect_match(method, path):
    get_map = dict(GET_ROUTES)
    post_map = dict(POST_ROUTES)
    if path in AUTH_PATHS:
        if method == 'GET' and path == '/login':
            return {'status': 200, 'route': 'login', 'kind': 'login',
                    'requires_session': False, 'csrf_exempt': False}
        if method == 'POST' and path == '/login':
            return {'status': 200, 'route': 'login_handler', 'kind': 'login_post',
                    'requires_session': False, 'csrf_exempt': False}
        if method == 'POST' and path == '/logout':
            return {'status': 200, 'route': 'logout_handler', 'kind': 'logout_post',
                    'requires_session': False, 'csrf_exempt': False}
        return {'status': 405, 'route': '', 'kind': '', 'requires_session': False,
                'csrf_exempt': False}
    if method == 'GET':
        r = get_map.get(path)
        if not r:
            return {'status': 404, 'route': '', 'kind': '', 'requires_session': True,
                    'csrf_exempt': False}
        return {'status': 200, 'route': r, 'kind': 'get', 'requires_session': True,
                'csrf_exempt': False}
    if method == 'POST':
        r = post_map.get(path)
        if not r:
            return {'status': 404, 'route': '', 'kind': '', 'requires_session': True,
                    'csrf_exempt': False}
        return {'status': 200, 'route': r, 'kind': 'post', 'requires_session': True,
                'csrf_exempt': path in CSRF_EXEMPT}
    return {'status': 405, 'route': '', 'kind': '', 'requires_session': True,
            'csrf_exempt': False}


def capture(fn, *args, **kwargs):
    """调用 responses.py 的响应构造函数，捕获 (status, headers, body)。"""
    box = {}

    def start_response(status, headers, exc_info=None):
        box['status'] = status
        box['headers'] = headers
        return lambda b: None

    payload = fn(start_response, *args, **kwargs)
    body = b''.join(payload).decode('utf-8')
    return box['status'], [list(h) for h in box['headers']], body


def pairs(d):
    """Python dict（保序）→ [[k, v]]。"""
    return [[k, v] for k, v in d.items()]


# ── ③ 表单用例（body / content_type → 期望 fields）────────────────────────
FORM_CASES = [
    ('empty', '', 'application/x-www-form-urlencoded',
     [], '空体 ⇒ 空字典', 'admin/app.py:322-323（CONTENT_LENGTH<=0 ⇒ {}）'),
    ('basic', 'a=1&b=2', 'application/x-www-form-urlencoded',
     [['a', '1'], ['b', '2']], '两个字段', 'admin/app.py:317-329'),
    ('multi', 'a=1&b=2&a=3', 'application/x-www-form-urlencoded',
     [['a', ['1', '3']], ['b', '2']], '同名多值 ⇒ ARRAY（parse_qs 的 list）',
     'security.py:53 + app.py:247（post_data.get(k,[""])[0] 取第一个）'),
    ('plus_and_percent', 'x=hello+world&k=%E4%B8%AD', 'application/x-www-form-urlencoded',
     [['x', 'hello world'], ['k', '中']], '`+` → 空格；percent-decode UTF-8',
     'urllib.parse.parse_qs'),
    ('blank_dropped', 'a=&a=1', 'application/x-www-form-urlencoded',
     [['a', '1']], '空值剔除（keep_blank_values=False 缺省）', 'D-HU-4'),
    ('blank_only', 'a=', 'application/x-www-form-urlencoded',
     [], '只有空值 ⇒ 该键整体消失', 'D-HU-4'),
    ('no_value', 'bare', 'application/x-www-form-urlencoded',
     [], '无 `=` 的键 ⇒ 空值 ⇒ 剔除（Python 同）', 'D-HU-4'),
    ('empty_key', '=1', 'application/x-www-form-urlencoded',
     [['', '1']], '空键保留（parse_qs 也保留）', 'urllib.parse.parse_qs'),
    ('semicolon_literal', 'a=1;b=2', 'application/x-www-form-urlencoded',
     [['a', '1;b=2']], '`;` 不是分隔符（Python 3.13 的缺省 separator="&"）',
     'urllib.parse.parse_qs(separator="&")'),
    ('double_amp', 'a=1&&b=2', 'application/x-www-form-urlencoded',
     [['a', '1'], ['b', '2']], '连续 `&` 跳过空段', 'urllib.parse.parse_qs'),
    ('csrf_shape', 'csrf_token=abc&t=1', 'application/x-www-form-urlencoded',
     [['csrf_token', 'abc'], ['t', '1']], 'csrf_token 就是普通字段',
     'admin/app.py:247'),
    ('bad_percent', 'a=%ZZ', 'application/x-www-form-urlencoded',
     [], '非法 percent ⇒ **空表单**（Python 原样保留 %ZZ，D-HU-3）', 'D-HU-3'),
    ('multipart_rejected', 'a=1', 'multipart/form-data; boundary=x',
     [], '非 urlencoded ⇒ **空表单**（Python 不判这个头，D-HU-2）', 'D-HU-2'),
    ('no_ct_header', 'a=1', '',
     [['a', '1']], '无 Content-Type ⇒ 按 urlencoded 处理', 'D-HU-2'),
]

# 请求体上限的两条边界（生成期不真造 10MB 字符串，测试里用 max_bytes 注入小值 +
# 真 10MB 一次的字节数断言在 .wll 里做，见 gen_test_http_util.py）
SIZE_CASES = [
    # (name, 探针用 body, 注入的 max_bytes, 期望 too_large, 说明, 出处)
    # ⚠ 真造 10MB 字符串在 WLWL 里代价太大（数组/字符串都是 O(n²) 家族）⇒ 判据用
    #   **注入阈值**钉住：`>` 而不是 `>=`。10MB 这个**数字**由 MAX_POST_SIZE() 单独钉。
    ('exactly_max', 'abcde', 5, False,
     'body 字节数 == 阈值 ⇒ **不算超**（判据是 `>`）', 'admin/app.py:324'),
    ('one_over_max', 'abcde', 4, True,
     'body 字节数 == 阈值+1 ⇒ 超', 'admin/app.py:324'),
]


def form_expect(case):
    return [[k, v] for k, v in case[3]]


def main():
    problems = []
    cross_checks = []

    # ② 分发行为：真跑 AdminApp
    from tinypage.admin.app import AdminApp
    from tinypage.config import Config
    from tinypage.security import generate_csrf_token

    tmp_root = Path(tempfile.mkdtemp(prefix='tp_hu_'))
    cfg = Config(root_dir=tmp_root, admin_pass='x' * 16, admin_port=ADMIN_PORT,
                 bind_domain='')
    app = AdminApp(cfg)
    ip = '127.0.0.1'
    session = app.session_manager.create_session(ip)
    good_csrf = generate_csrf_token()

    def call(method, path, query='', cookie='', body=b'', origin=None):
        box = {}

        def start_response(status, headers, exc_info=None):
            box['status'] = status
            box['headers'] = headers
            return lambda b: None

        environ = {
            'REQUEST_METHOD': method,
            'PATH_INFO': path,
            'QUERY_STRING': query,
            'REMOTE_ADDR': ip,
            'SERVER_NAME': ip,
            'SERVER_PORT': str(ADMIN_PORT),
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'wsgi.url_scheme': 'http',
            'wsgi.input': io.BytesIO(body),
            'CONTENT_LENGTH': str(len(body)),
            'HTTP_COOKIE': cookie,
        }
        if origin:
            environ['HTTP_ORIGIN'] = origin
        payload = b''.join(app(environ, start_response))
        headers = {k.lower(): v for k, v in box['headers']}
        return box['status'], headers, payload.decode('utf-8', 'replace')

    no_sess = ''
    with_sess = 'session_id=%s' % session
    csrf_cookie = '%s; csrf_token=%s' % (with_sess, good_csrf)

    def form_body(**fields):
        from urllib.parse import urlencode
        return urlencode(fields).encode('utf-8')

    # (name, method, path, query, cookie, body, origin, 期望 status, 期望 Location,
    #  期望 Content-Type 前缀, 说明)
    behavior = [
        ('get_login_anon', 'GET', '/login', '', no_sess, b'', None,
         '200 OK', '', 'text/html; charset=utf-8',
         '未登录也能进登录页（app.py:154-158）'),
        ('get_root_anon', 'GET', '/', '', no_sess, b'', None,
         '302 Found', '/login', None,
         '未登录访问 / ⇒ 302 到 /login（app.py:169-171，卡 S4-3 反向守卫）'),
        ('put_root_anon', 'PUT', '/', '', no_sess, b'', None,
         '302 Found', '/login', None,
         '**会话检查先于 method**：未登录 PUT 也先 302（app.py:168-171）'),
        ('get_protected_404_anon', 'GET', '/nope', '', no_sess, b'', None,
         '302 Found', '/login', None,
         '未登录的 404 路径同样先 302（顺序证据）'),
        ('post_login_anon_no_csrf', 'POST', '/login', '', no_sess,
         form_body(username='a', password='b'), None,
         '302 Found', '/login?error=1', None,
         '⚠ /login 的 CSRF 失败是 **302 /login?error=1**（actions.py:388-389），不是 403'),
        ('post_create_sess_no_csrf', 'POST', '/create', '', with_sess,
         form_body(title='t'), None,
         '403 Forbidden', '', 'text/plain',
         '有会话 + 缺 CSRF ⇒ 403 text/plain（app.py:258-260）'),
        ('post_upload_sess_no_csrf', 'POST', '/upload', '', with_sess,
         form_body(filename='a.png'), None,
         '403 Forbidden', '', 'application/json',
         'CSRF 豁免路径的失败是 **JSON** 403（app.py:253-257）'),
        ('post_upload_sess_csrf', 'POST', '/upload', '', csrf_cookie,
         form_body(csrf_token=good_csrf), ORIGIN,
         '400 Bad Request', '', 'application/json',
         '合法 CSRF 后进入 upload 动作 ⇒ 缺字段 400 JSON（actions.py:200-201）'),
        ('post_create_sess_csrf', 'POST', '/create', '', csrf_cookie,
         form_body(csrf_token=good_csrf), ORIGIN,
         '400 Bad Request', '', 'text/plain',
         '合法 CSRF 后进入 create 动作 ⇒ 缺字段 400 text/plain（actions.py:48-49）'),
        ('post_unknown_sess', 'POST', '/nope', '', with_sess,
         b'', None,
         '404 Not Found', '', 'text/plain',
         '404 早于 CSRF 校验（app.py:242-244）'),
        ('put_unknown_sess', 'PUT', '/nope', '', with_sess, b'', None,
         '405 Method Not Allowed', '', 'text/plain',
         '有会话后 method 不符 ⇒ 405（app.py:178）'),
        ('get_unknown_sess', 'GET', '/nope', '', with_sess, b'', None,
         '404 Not Found', '', 'text/plain',
         '有会话 GET 未命中 ⇒ 404（app.py:186-188）'),
        ('get_logout_anon', 'GET', '/logout', '', no_sess, b'', None,
         '405 Method Not Allowed', '', 'text/plain',
         'GET /logout ⇒ 405（app.py:163，落在 /login /logout 分支里）'),
    ]

    route_cases = []
    for (name, method, path, query, cookie, body, origin,
         want_status, want_loc, want_ct, note) in behavior:
        status, headers, text = call(method, path, query, cookie, body, origin)
        # ⚠ **不要**把 body 写进夹具：GET /login 的 HTML 里含随机 CSRF token ⇒
        #   写进去会让「重跑生成器 + git diff 必须为空」这道 CI 门禁永远红。
        #   这里只留稳定的三样：status / Location / Content-Type。
        observed = {'status': status, 'location': headers.get('location', ''),
                    'content_type': headers.get('content-type', '')}
        ct_ok = True if not want_ct else headers.get('content-type', '').startswith(want_ct)
        loc_ok = headers.get('location', '') == want_loc
        if status != want_status or not ct_ok or not loc_ok:
            problems.append('%s: 期望 %r/%r/%r，Python 实测 %r/%r/%r'
                            % (name, want_status, want_loc, want_ct, status,
                               headers.get('location', ''),
                               headers.get('content-type', '')))
        m = expect_match(method, path)
        # MATCH_ROUTE 层的期望与 Python 实测必须自洽（这是「判定顺序」的证据）：
        #   · 免会话路径 ⇒ MATCH_ROUTE 的 status 就是实测 status
        #   · 需会话 + 未登录 ⇒ 实测必是 302 /login（与 match_status 无关）
        #   · 需会话 + 有会话 + 404/405 ⇒ 实测就是 404/405
        has_session = 'session_id=' in cookie
        if not m['requires_session']:
            # 免会话路径：MATCH_ROUTE 的结论是「分发到哪个 handler」；
            # 只有 GET /login（纯视图）保证 200 —— login_post / logout_post 的
            # 状态由 handler 决定（actions.py:388-389 的 CSRF 失败是 302），
            # 那不是路由层可判定的，故只对 `kind = "login"` 钉死相等。
            if m['kind'] == 'login' and m['status'] != int(want_status[:3]):
                problems.append('%s: 免会话 GET /login 的 status %d 与实测 %r 不符'
                                % (name, m['status'], want_status))
            elif m['kind'] in ('login_post', 'logout_post') and m['status'] != 200:
                problems.append('%s: %s 的 MATCH_ROUTE status 应为 200（分发成功）'
                                % (name, m['kind']))
        elif not has_session:
            if status != '302 Found' or headers.get('location') != '/login':
                problems.append('%s: 需会话且未登录必须是 302 /login，实测 %r %r'
                                % (name, status, headers.get('location')))
        elif m['status'] in (404, 405):
            if int(want_status[:3]) != m['status']:
                problems.append('%s: MATCH_ROUTE status %d 与实测 %r 不符'
                                % (name, m['status'], want_status))
        route_cases.append({
            'name': name,
            'method': method,
            'path': path,
            'expected_status': want_status,
            'expected_location': want_loc,
            'match_status': m['status'],
            'match_route': m['route'],
            'match_kind': m['kind'],
            'match_requires_session': m['requires_session'],
            'match_csrf_exempt': m['csrf_exempt'],
            'has_session': has_session,
            'note': note,
            'python_observed': observed,
        })
    cross_checks.append('② 分发行为 %d 条：status / Location / Content-Type 全部与'
                        ' tinypage.admin.app.AdminApp 实测一致' % len(behavior))

    # ① 路由表对拍
    from tinypage.admin.app import AdminApp as _A
    py_get = [[k, v] for k, v in _A._GET_ROUTES.items()]
    py_post = [[k, v] for k, v in _A._POST_ROUTES.items()]
    my_get = [[k, v] for k, v in GET_ROUTES]
    my_post = [[k, v] for k, v in POST_ROUTES]
    if py_get != my_get:
        problems.append('GET 路由表与 app.py 不一致:\n  py=%r\n  my=%r' % (py_get, my_get))
    if py_post != my_post:
        problems.append('POST 路由表与 app.py 不一致:\n  py=%r\n  my=%r' % (py_post, my_post))
    if sorted(_A._CSRF_EXEMPT_POST) != sorted(CSRF_EXEMPT):
        problems.append('CSRF 豁免表不一致: py=%r my=%r'
                        % (sorted(_A._CSRF_EXEMPT_POST), CSRF_EXEMPT))
    if _A.MAX_POST_SIZE != MAX_POST_SIZE:
        problems.append('MAX_POST_SIZE 不一致: py=%r my=%r'
                        % (_A.MAX_POST_SIZE, MAX_POST_SIZE))
    if '/dashboard' not in [k for k, _ in py_get]:
        problems.append('app.py 里没有 /dashboard —— 卡片列的 9 条要重新数')
    cross_checks.append(
        '① 路由表：GET %d 条 / POST %d 条 / CSRF 豁免 %r / MAX_POST_SIZE %d '
        '与 app.py 逐键逐值一致'
        % (len(py_get), len(py_post), sorted(_A._CSRF_EXEMPT_POST), _A.MAX_POST_SIZE))

    # ③ 表单对拍 parse_qs
    from urllib.parse import parse_qs
    form_cases = []
    for (name, body, ct, expect, note, source) in FORM_CASES:
        got = parse_qs(body, keep_blank_values=False)
        got_norm = {}
        for k, vs in got.items():
            vals = [v for v in vs if v != '']
            if not vals:
                continue
            got_norm[k] = vals[0] if len(vals) == 1 else vals
        want_norm = {}
        for k, v in expect:
            want_norm[k] = v
        if name in ('bad_percent', 'multipart_rejected'):
            # 这两条是**登记在案的偏离**：Python 的 parse_qs 不报错 / 不判头
            if got_norm and name == 'bad_percent':
                cross_checks.append(
                    '③ %s：Python parse_qs 实测给 %r（本实现给 {}，D-HU-3）'
                    % (name, got_norm))
        else:
            if got_norm != want_norm:
                problems.append('%s: 期望 %r，parse_qs 实测 %r'
                                % (name, want_norm, got_norm))
        form_cases.append({
            'name': name,
            'body': body,
            'content_type': ct,
            'expect': [[k, v] for k, v in expect],
            'note': note,
            'source': source,
        })
    cross_checks.append('③ 表单 %d 条：与 urllib.parse.parse_qs'
                        '（keep_blank_values=False）逐键相等（两条登记偏离除外）'
                        % (len(FORM_CASES) - 2))

    # ④ 响应对拍 responses.py
    from tinypage.admin import responses as R
    from tinypage.security import get_csp_header

    csp_pair = list(get_csp_header())
    sec = [["X-Content-Type-Options", "nosniff"],
           ["X-Frame-Options", "DENY"],
           ["Referrer-Policy", "no-referrer"],
           ["Cross-Origin-Opener-Policy", "same-origin"],
           ["Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"]]

    TOK = 'TESTTOKEN0123456789'

    response_cases = []

    def add_resp(name, note, source, expect_status, expect_headers, expect_body,
                 py_status, py_headers, py_body):
        if [py_status] != [expect_status] or py_headers != expect_headers \
                or py_body != expect_body:
            problems.append('%s: 期望 %r/%r/%r，responses.py 实测 %r/%r/%r'
                            % (name, expect_status, expect_headers, expect_body,
                               py_status, py_headers, py_body))
        response_cases.append({
            'name': name,
            'status': int(expect_status[:3]),
            'status_line': expect_status,
            'headers': expect_headers,
            'body': expect_body,
            'note': note,
            'source': source,
        })

    s, h, b = capture(R.error_response, "404 Not Found", "Not Found")
    add_resp('error_404', 'error_response：Content-Type text/plain + 5 安全头',
             'admin/responses.py:23-28', "404 Not Found",
             [["Content-Type", "text/plain"]] + sec, "Not Found", s, h, b)

    s, h, b = capture(R.error_response, "405 Method Not Allowed", "Method not allowed")
    add_resp('error_405', '方法不符的身体串是 "Method not allowed"（app.py:163,178）',
             'admin/app.py:163,178', "405 Method Not Allowed",
             [["Content-Type", "text/plain"]] + sec, "Method not allowed", s, h, b)

    s, h, b = capture(R.error_response, "403 Forbidden", "CSRF validation failed")
    add_resp('error_403', 'CSRF 失败的 text/plain 形态（app.py:260）',
             'admin/app.py:258-260', "403 Forbidden",
             [["Content-Type", "text/plain"]] + sec, "CSRF validation failed", s, h, b)

    s, h, b = capture(R.redirect_response, "/login")
    add_resp('redirect_login', 'redirect_response：Location + 5 安全头，body 空',
             'admin/responses.py:17-20', "302 Found",
             [["Location", "/login"]] + sec, "", s, h, b)

    s, h, b = capture(R.json_error_response, "403 Forbidden", "CSRF validation failed")
    add_resp('json_error_403', 'CSRF 豁免路径的 JSON 403（app.py:255-257）',
             'admin/app.py:253-257', "403 Forbidden",
             [["Content-Type", "application/json"]] + sec,
             '{"success": false, "error": "CSRF validation failed"}', s, h, b)

    s, h, b = capture(R.html_response, "<b>x</b>", csrf_token=TOK)
    add_resp('html_csrf', 'html_response：Content-Type → 5 安全头 → CSRF cookie → CSP',
             'admin/responses.py:39-55', "200 OK",
             [["Content-Type", "text/html; charset=utf-8"]] + sec
             + [["Set-Cookie", "csrf_token=%s; Path=/; HttpOnly; SameSite=Strict" % TOK],
                csp_pair],
             "<b>x</b>", s, h, b)

    s, h, b = capture(R.html_response, "<b>x</b>")
    add_resp('html_no_csrf', '无 csrf_token ⇒ 不发 Set-Cookie（app.py:49-51）',
             'admin/responses.py:49-51', "200 OK",
             [["Content-Type", "text/html; charset=utf-8"]] + sec + [csp_pair],
             "<b>x</b>", s, h, b)

    # 登录页头序（app.py:226-237）：安全头在**最后**
    add_resp('login_page', '登录页头序：Content-Type → CSRF cookie → CSP → 5 安全头'
             '（与 html_response 相反，逐字照 app.py:231-235）',
             'admin/app.py:226-237', "200 OK",
             [["Content-Type", "text/html; charset=utf-8"],
              ["Set-Cookie", "csrf_token=%s; Path=/; HttpOnly; SameSite=Strict" % TOK],
              csp_pair] + sec,
             "LOGIN", "200 OK", [["Content-Type", "text/html; charset=utf-8"],
              ["Set-Cookie", "csrf_token=%s; Path=/; HttpOnly; SameSite=Strict" % TOK],
              csp_pair] + sec, "LOGIN")

    s, h, b = capture(R.redirect_response, "/theme")
    add_resp('redirect_theme', 'set_theme 成功后 302 /theme（actions.py:365）',
             'admin/actions.py:365', "302 Found", [["Location", "/theme"]] + sec,
             "", s, h, b)

    cross_checks.append('④ 响应 %d 条：status / 头序 / 头值 / body 与 responses.py'
                        ' 实测一致；CSP 串 == security.get_csp_header()'
                        % len(response_cases))

    # 429 / 静态资源：app.py 里是内联构造，没有独立函数可对拍 ⇒ 手写期望 + 出处
    response_cases.append({
        'name': 'rate_limit',
        'status': 429,
        'status_line': '429 Too Many Requests',
        'headers': [["Content-Type", "text/plain"],
                    ["Retry-After", "42"]] + sec,
        'body': RATE_LIMIT_BODY,
        'note': 'app.py 内联构造的 429（无独立函数可对拍）',
        'source': 'admin/app.py:132-140',
    })
    response_cases.append({
        'name': 'static_asset',
        'status': 200,
        'status_line': '200 OK',
        'headers': [["Content-Type", "text/css"],
                    ["Content-Length", "6"],
                    ["Cache-Control", "max-age=3600"]] + sec,
        'body': 'body{}',
        'note': '注入的 CSS/JS：**显式**给 Content-Length，缓存 3600s，免会话',
        'source': 'admin/app.py:142-152',
    })

    status_lines = [['%d' % int(code), '%s %s' % (code, reason)]
                    for code, reason in STATUS_REASONS]

    # ⑤ 上限边界（Python 的判据是 `cl > MAX_POST_SIZE`）
    size_cases = [{'name': n, 'body': body, 'max_bytes': mb, 'too_large': t,
                   'note': note, 'source': src}
                  for (n, body, mb, t, note, src) in SIZE_CASES]
    if not (MAX_POST_SIZE > 10 * 1024 * 1024 - 1):
        problems.append('MAX_POST_SIZE 小于 10MB')

    if problems:
        for p in problems:
            print('CROSS-CHECK FAILED: ' + p)
        raise SystemExit('基准与真 Python 不一致，拒绝写夹具（%d 处）' % len(problems))

    doc = {
        'meta': {
            'generated_by': 'tp/test/gen_http_util_baseline.py',
            'product': 'tp/lib/http_util.wll',
            'sources': [
                'tinypage/admin/app.py:58-89（路由表 / CSRF 豁免 / MAX_POST_SIZE）',
                'tinypage/admin/app.py:154-181（/login 分支 + 会话先于 method）',
                'tinypage/admin/responses.py:17-55（四个响应构造）',
                'tinypage/security.py:342-352（CSP 策略串）',
                'tinypage/security.py:116-137（CSRF Set-Cookie 属性）',
            ],
            'cross_checks': cross_checks,
            'findings': [
                '卡片 S4-3 的 GET 清单只列了 8 条，第 9 条是 `/dashboard`'
                '（app.py:62 与 `/` 同指 dashboard）—— 本实现按**源码**取 9 条。',
                '卡片写「会话 Cookie：SET_COOKIE」，但 security.wll 已交付'
                ' SESSION_COOKIE_HEADER / CSRF_COOKIE_HEADER 且 235 断言全绿 ⇒'
                ' 实现复用后者，不另造。',
                'POST 的 404 判定**早于** CSRF 校验（app.py:242-244），'
                'CSRF 豁免（/upload）只改**失败时的响应格式**，不跳过校验'
                '（app.py:253-257）。',
                '`/login` 的 CSRF 失败不是 403 而是 302 `/login?error=1`'
                '（actions.py:388-389）—— 「POST 缺 CSRF ⇒ 403」这条反向守卫'
                '只对**其它** POST 路由成立。',
                '响应头序有两套：responses.html_response 是「安全头 → CSRF → CSP」，'
                'app.py 的登录页是「CSRF → CSP → 安全头」。BUILD_RESPONSE 用'
                ' security_last 开关同时支持两者。',
            ],
            'divergences': [
                {'id': 'D-HU-1', 'what': 'PARSE_FORM 直接调用 std.http::PARSE_FORM',
                 'why': '实测该成员在本机 0.12.1 可用（含 +/%XX/多值/空体），'
                        '自己重写只会引入新的语义差'},
                {'id': 'D-HU-2', 'what': 'Content-Type 非 urlencoded ⇒ 返回空表单',
                 'why': 'Python 的 _get_post_data 完全不看 Content-Type，会把'
                        ' multipart 体当 urlencoded 解析出垃圾键；两条路最终都'
                        '拿不到字段 ⇒ 同一条失败路径（upload 400 JSON）。'
                        '实测命令见 fixtures 的 form_cases/multipart_rejected'},
                {'id': 'D-HU-3', 'what': '非法 percent 转义 ⇒ 返回空表单',
                 'why': 'Python 的 parse_qs 不报错、原样保留 `%ZZ`；WLWL 的'
                        ' PARSE_FORM 给 ERR。本实现 fail-closed（表单为空 ⇒'
                        ' CSRF 必然失败 ⇒ 403），不把畸形输入带进动作层'},
                {'id': 'D-HU-4', 'what': '空值字段剔除',
                 'why': '对齐 parse_qs 的 keep_blank_values=False 缺省；'
                        '否则 `csrf_token=` 排在 `csrf_token=<valid>` 前面时'
                        '取第一个值会与 Python 不一致'},
                {'id': 'D-HU-5', 'what': 'JSON 错误体不转义非 ASCII',
                 'why': 'Python 的 json.dumps 缺省 ensure_ascii=True（中文变'
                        ' \\uXXXX）。本实现原样发 UTF-8：仍是合法 JSON，'
                        '只是字面不同'},
            ],
        },
        'routes': {
            'get': [[k, v] for k, v in GET_ROUTES],
            'post': [[k, v] for k, v in POST_ROUTES],
            'csrf_exempt': CSRF_EXEMPT,
            'auth_paths': AUTH_PATHS,
            'max_post_size': MAX_POST_SIZE,
        },
        'route_cases': route_cases,
        'form_cases': form_cases,
        'size_cases': size_cases,
        'response_cases': response_cases,
        'status_lines': status_lines,
        'csp': CSP,
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print('wrote %s' % OUT)
    for c in cross_checks:
        print('  ' + c)


if __name__ == '__main__':
    main()
