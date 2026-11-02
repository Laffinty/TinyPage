"""生成 tp/bin/serve_admin.wll —— admin 后台的传输入口（卡 S4-3）。

⚠ 输出的 .wll 由本文件生成，不要手改。

**分工**：HTTP 语义全在 `tp/lib/http_util.wll`（纯函数，脱网可测）；本文件只做
「收请求 → MATCH_ROUTE → 会话/CSRF（security.wll）→ 动作（admin_actions.wll）→ 发响应」。

**绑定**：**仅 127.0.0.1**（业主裁决，卡 S4-3 的反向守卫）。地址是**字面量**，
`TP_ADMIN_HOST` 一旦被设成别的值就启动即 PANIC —— 钉死「别绑 0.0.0.0」，
而不是留一个开关。

**配置（环境变量；`wlwl run` 不透传脚本参数 —— 坑 49）**：
  TP_ADMIN_PORT / ADMIN_PORT   监听端口（缺省 8081，对齐 config.py:35-37）
  TP_ADMIN_USER / ADMIN_USER   登录用户名（缺省 admin，config.py:25）
  TP_ADMIN_PASS / ADMIN_PASS   登录口令（**空 ⇒ 登录一律 503**，actions.py:394-400）
  TP_ROOT                      站点根（缺省 pages，config.py:48）
  BIND_DOMAIN                  非空 ⇒ cookie 加 Secure（security.py:130-132）

**已知缺口（诚实登记，不粉饰）**：
  ① 视图层（views.py / admin 模板）**尚未交付** ⇒ GET 页面是占位 HTML；
     登录页是能用的最小表单（含 csrf_token 隐藏域）。
  ② `admin_actions.wll` 没有 login/logout handler ⇒ 本入口按 actions.py:382-437 的
     顺序直接调 security 原语。S4-4 若补 LOGIN_HANDLER，这里应改成一行调用。
  ③ `/ai-assist`、`/translate` 两个动作在 admin_actions.wll 里没有实现 ⇒ 500。
  ④ 注入的静态资源（app.py:142-152 的 `_get_injected_assets`）需要资产管线 ⇒
     本入口不服务它（`STATIC_RESPONSE` 已在 http_util 里交付并测过，等接线）。

**⚠ 生成器自身的纪律**：所有嵌套 `INDEX_SET` 链一律用 `chain()` **程序化拼**，
不手写括号 —— 手写时实测三处各差一个 `)`，而 `wlwl check` 只会在很远的地方报
「missing closing )」。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'bin', 'serve_admin.wll')

# app.py:288-298 的页面标题
TITLES = [
    ('dashboard', '仪表盘'),
    ('pages_dashboard', '独立页面'),
    ('new_article', '新建文章'),
    ('edit_article', '编辑文章'),
    ('new_page', '新建页面'),
    ('edit_page', '编辑页面'),
    ('theme', '主题管理'),
]

# 动作成功后的落点（actions.py 各 return redirect_response(...) 的实参）
ACTION_REDIRECTS = [
    ('create_article', '/'),
    ('save_article', '/'),
    ('delete_article', '/'),
    ('create_page', '/pages'),
    ('save_page', '/pages'),
    ('delete_page', '/pages'),
    ('set_theme', '/theme'),
]

REGEN_HTML = ('<span style="color:var(--a-primary);font-size:0.9rem;">'
              '✓ 已重新生成</span>')

# ── HTML 片段（视图层未交付 ⇒ 占位页）────────────────────────────────────
PAGE_HEAD = ('<!doctype html>\n<html lang="zh-CN">\n'
             '<head><meta charset="utf-8"><title>')
PAGE_MID = '</title></head>\n<body>\n'
PAGE_TAIL = '\n</body>\n</html>\n'

LOGIN_HEAD = ('<h1>登录</h1>\n<form method="post" action="/login">\n'
              '<input type="hidden" name="csrf_token" value="')
LOGIN_MID = ('">\n<label>用户名 <input name="username" '
             'autocomplete="username"></label>\n'
             '<label>密码 <input type="password" name="password" '
             'autocomplete="current-password"></label>\n'
             '<button type="submit">登录</button>\n</form>\n')

PH_HEAD = '<h1>'
PH_MID = ('</h1>\n<p>本页是卡 S4-3 的 <b>路由占位</b>：admin 的视图层'
          '（views.py / 模板）尚未交付。</p>\n<p>route=<code>')
PH_TAIL = '</code></p>\n'


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


def chain(pairs, base='DICT()'):
    """[(k, 表达式)] → 一条嵌套 INDEX_SET 链（**程序化**，不手数括号）。"""
    expr = base
    for k, v in pairs:
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl(k), v)
    return expr


def call(name, *args):
    return '%s(%s)' % (name, ', '.join(args))


def ffield(key, fields_var='fields'):
    """表单字段取值（对齐 post_data.get(k, [""])[0]）。"""
    return call('FORM_FIELD', chain([('fields', fields_var), ('key', wl(key))]))


def opts(*pairs):
    return chain(list(pairs))


def main():
    A = []
    W = A.append
    W('// tp/bin/serve_admin.wll —— admin 后台入口（卡 S4-3）')
    W('//')
    W('// ⚠ 本文件由 tp/test/gen_serve_admin.py 生成 —— 请勿手改。')
    W('//')
    W('// 传输在此，**HTTP 语义全在** tp/lib/http_util.wll（MATCH_ROUTE / PARSE_FORM /')
    W('// BUILD_RESPONSE 都是纯函数）；会话与 CSRF 走 tp/lib/security.wll，')
    W('// 写操作用 tp/lib/admin_actions.wll。')
    W('//')
    W('// ⚠⚠ **仅绑 127.0.0.1**（业主裁决，卡 S4-3 反向守卫）：地址是**字面量**，')
    W('//   `TP_ADMIN_HOST` 一旦设成别的值 ⇒ 启动即 PANIC（不提供「改绑」开关）。')
    W('//')
    W('// 配置（环境变量；`wlwl run` 不透传脚本参数 —— 坑 49）：')
    W('//   TP_ADMIN_PORT / ADMIN_PORT    监听端口（缺省 8081 == config.py:35-37）')
    W('//   TP_ADMIN_USER / ADMIN_USER    登录用户名（缺省 admin == config.py:25）')
    W('//   TP_ADMIN_PASS / ADMIN_PASS    登录口令（空 ⇒ 登录 503 == actions.py:394-400）')
    W('//   TP_ROOT                       站点根（缺省 pages == config.py:48）')
    W('//   BIND_DOMAIN                   非空 ⇒ cookie 加 Secure（security.py:130-132）')
    W('//')
    W('// 本机跑法：')
    W('//   $env:TP_ADMIN_PORT="18081"; $env:TP_ADMIN_PASS="0123456789abcdef"')
    W('//   & D:\\wlwl_v0.12.1\\wlwl.exe run tp\\bin\\serve_admin.wll')
    W('//   curl -s -o NUL -w "%{http_code}" http://127.0.0.1:18081/login')
    W('//')
    W('// ⚠ 已知缺口（不粉饰）：视图层未交付 ⇒ GET 页面是占位 HTML；login/logout 走')
    W('//   security 原语（admin_actions 没有这两个 handler）；/ai-assist /translate ⇒ 500。')
    W('')
    W('IMPORT("wlwl:std.net", ["TCP_LISTEN", "TCP_SERVE", "TCP_CLOSE_LISTENER",')
    W('    "TCP_LOCAL_ADDR"]);')
    W('IMPORT("wlwl:std.signal", ["ON_SIGNAL", "STOP"]);')
    W('IMPORT("wlwl:std.env", ["ENV_GET"]);')
    W('IMPORT("wlwl:std.text", ["TO_INT"]);')
    W('IMPORT("wlwl:std.fs", ["PATH_JOIN", "PATH_CANONICAL"]);')
    W('IMPORT("wlwl:std.str", ["CAT"]);')
    W('IMPORT("wlwl:std.encode", ["TIMING_SAFE_EQ"]);')
    W('IMPORT("./../lib/http_util.wll", ["MATCH_ROUTE", "PARSE_FORM", "FORM_FIELD",')
    W('    "HEADER_VALUE", "COOKIE_VALUE", "BUILD_RESPONSE", "TEXT_ERROR_RESPONSE",')
    W('    "JSON_ERROR_RESPONSE", "JSON_RESPONSE", "HTML_RESPONSE", "REDIRECT",')
    W('    "RATE_LIMIT_RESPONSE", "JSON_ESCAPE"]);')
    W('IMPORT("./../lib/security.wll", ["NEW_CSRF_TOKEN", "VALIDATE_CSRF_TOKEN",')
    W('    "SESSION_FROM_COOKIE", "SESSION_VALIDATE", "SESSION_CREATE",')
    W('    "SESSION_DESTROY", "SESSION_COOKIE_HEADER", "SESSION_CLEAR_COOKIE_HEADER",')
    W('    "RATE_LIMIT"]);')
    W('IMPORT("./../lib/admin_actions.wll", ["CREATE_ARTICLE", "SAVE_ARTICLE",')
    W('    "DELETE_ARTICLE", "CREATE_PAGE", "SAVE_PAGE", "DELETE_PAGE", "SET_THEME",')
    W('    "PREVIEW", "REGEN", "UPLOAD_IMAGE"]);')
    W('')

    # ── 配置 ──────────────────────────────────────────────────────────
    W('// ── 配置（环境变量；缺省值对齐 tinypage/config.py）──────────────────')
    W('LET(SAD_LOOPBACK, "127.0.0.1");')
    W('LET(host_env, ENV_GET("TP_ADMIN_HOST", SAD_LOOPBACK));')
    W('IF(!=(host_env, SAD_LOOPBACK), (')
    W('     PRINT_ERR("serve_admin: TP_ADMIN_HOST must be 127.0.0.1 (loopback only): ",')
    W('               host_env);')
    W('     PANIC("admin must bind loopback")')
    W('), NULL);')
    W('')
    W('LET(port_s, ENV_GET("TP_ADMIN_PORT", ENV_GET("ADMIN_PORT", "8081")));')
    W('LET(port_t, TO_INT(port_s));')
    W('LET(SAD_PORT, IF(IS_ERR(port_t), -1, port_t));')
    W('IF(<(SAD_PORT, 1), (')
    W('     PRINT_ERR("serve_admin: TP_ADMIN_PORT is not a valid port: ", port_s);')
    W('     PANIC("bad TP_ADMIN_PORT")')
    W('), NULL);')
    W('')
    W('LET(SAD_USER, ENV_GET("TP_ADMIN_USER", ENV_GET("ADMIN_USER", "admin")));')
    W('LET(SAD_PASS, ENV_GET("TP_ADMIN_PASS", ENV_GET("ADMIN_PASS", "")));')
    W('LET(SAD_BIND_DOMAIN, ENV_GET("BIND_DOMAIN", ""));')
    W('// cookie 的 Secure 属性：非空 bind_domain ⇒ 视为 HTTPS 部署（security.py:130）')
    W('LET(SAD_SECURE, !=(SAD_BIND_DOMAIN, ""));')
    W('')
    W('LET(SAD_ROOT, PATH_CANONICAL(ENV_GET("TP_ROOT", "pages")));')
    W('LET(SAD_ARTICLE_DIR, PATH_JOIN(SAD_ROOT, "article"));')
    W('LET(SAD_STANDALONE_DIR, PATH_JOIN(SAD_ROOT, "standalone"));')
    W('LET(SAD_STATIC_DIR, PATH_JOIN(SAD_ROOT, "static"));')
    W('// 会话/限流按客户端 IP 计；admin **只**绑回环 ⇒ 客户端恒为回环地址')
    W('// （Python 的 get_real_ip 在 trusted_proxies 为空时也返回 REMOTE_ADDR）')
    W('LET(SAD_CLIENT_IP, SAD_LOOPBACK);')
    W('')
    W('// 页面标题（app.py:288-298）')
    W('LET(SAD_TITLES, ' + chain([(k, wl(v)) for k, v in TITLES]) + ');')
    W('')

    # ── HTML 片段 ─────────────────────────────────────────────────────
    W('// ── HTML 片段（视图层未交付 ⇒ 占位页；登录页是**能用**的最小表单）────────')
    W('// ⚠ WLWL 不做字面量拼接（`"a" "b"` 是 E0002）⇒ 每段都是**一个**字面量，用 CAT 连。')
    W('LET(SAD_PAGE, FUN((title, body), (')
    W('     ' + call('CAT', wl(PAGE_HEAD), 'title', wl(PAGE_MID), 'body', wl(PAGE_TAIL)))
    W(')));')
    W('')
    W('LET(SAD_LOGIN_FORM, FUN((csrf), (')
    W('     ' + call('CAT', wl(LOGIN_HEAD), 'csrf', wl(LOGIN_MID)))
    W(')));')
    W('')
    W('LET(SAD_PLACEHOLDER, FUN((route), (')
    W('     ' + call('CAT', wl(PH_HEAD), 'AT_K(SAD_TITLES, route, "管理后台")',
                      wl(PH_MID), 'route', wl(PH_TAIL)))
    W(')));')
    W('')

    # ── 请求工具 ──────────────────────────────────────────────────────
    W('// ── 请求工具 ─────────────────────────────────────────────────────')
    W('LET(SAD_HDRS, FUN((req), (')
    W('     AT_K(req, "headers", DICT())')
    W(')));')
    W('')
    W('LET(SAD_HEADER, FUN((req, name), (')
    W('     ' + call('HEADER_VALUE', opts(('headers', 'SAD_HDRS(req)'), ('name', 'name'))))
    W(')));')
    W('')
    W('LET(SAD_FIELDS, FUN((req), (')
    W('     // app.py:317-329：只解析 x-www-form-urlencoded；>10MB ⇒ 空表单')
    W('     ' + call('PARSE_FORM', opts(('body', 'AT_K(req, "body", "")'),
                                      ('content_type', 'SAD_HEADER(req, "content-type")'))))
    W(')));')
    W('')
    W('LET(SAD_EXISTING_CSRF, FUN((cookie), (')
    W('     // app.py:303-312：cookie 里已有的 csrf_token 能复用就复用，否则新生成。')
    W('     // ⚠ Python 用的是 `is_valid_csrf_format`（格式+签名+1h）；security.wll 没导出它，')
    W('     //   这里用 VALIDATE_CSRF_TOKEN + **自造的同值 cookie** 等价替代：')
    W('     //   双提交必然一致，剩下的正是「格式/签名/时限」三道 ⇒ 与 is_valid_csrf_format 同义。')
    W('     LET(t, ' + call('COOKIE_VALUE', opts(('cookie', 'cookie'),
                                                  ('prefix', wl('csrf_token=')))) + ');')
    W('     IF(==(t, ""), (NEW_CSRF_TOKEN(DICT())), (')
    W('          IF(VALIDATE_CSRF_TOKEN(' + opts(('token', 't'),
                                                 ('cookie', 'CAT("csrf_token=", t)')) + '),')
    W('             (t), (NEW_CSRF_TOKEN(DICT())))')
    W('     ))')
    W(')));')
    W('')
    W('LET(SAD_CSRF_OK, FUN((fields, cookie, req), (')
    W('     // app.py:247-251：token 取自表单第一个值；Origin/Referer 白名单在 security.wll 里')
    W('     ' + call('VALIDATE_CSRF_TOKEN', opts(
        ('token', ffield('csrf_token')),
        ('cookie', 'cookie'),
        ('origin', 'SAD_HEADER(req, "origin")'),
        ('referer', 'SAD_HEADER(req, "referer")'),
        ('admin_port', 'SAD_PORT'),
        ('bind_domain', 'SAD_BIND_DOMAIN'))))
    W(')));')
    W('')

    # ── 动作结果 → 响应 ───────────────────────────────────────────────
    W('// ── 动作结果（admin_actions 的 {ok, ...}）→ 响应 ────────────────────')
    W('LET(SAD_ERR_STATUS, FUN((res), (')
    W('     // ⚠ admin_actions 只回 {ok, error}，**丢了 HTTP 状态**；Python 的两处特例是')
    W('     //   409 "Page already exists"（actions.py:130）与其余 400 ⇒ 按消息映射回来。')
    W('     IF(==(AT_K(res, "error", ""), "Page already exists"), (409), (400))')
    W(')));')
    W('')
    W('LET(SAD_ERR_TEXT, FUN((res), (')
    W('     TEXT_ERROR_RESPONSE(SAD_ERR_STATUS(res), AT_K(res, "error", "Server error"))')
    W(')));')
    W('')
    W('LET(SAD_REDIRECT_RESULT, FUN((res, location), (')
    W('     IF(!AT_K(res, "ok", FALSE), (SAD_ERR_TEXT(res)), (')
    W('          REDIRECT(' + opts(('location', 'location')) + ')')
    W('     ))')
    W(')));')
    W('')
    W('LET(SAD_DELETE_RESULT, FUN((res, htmx, location), (')
    W('     // actions.py:107-112 / 190-192：htmx 回 200 + **只有** 5 个安全头（无 body）')
    W('     IF(!AT_K(res, "ok", FALSE), (SAD_ERR_TEXT(res)), (')
    W('          IF(htmx, (')
    W('               BUILD_RESPONSE(' + opts(('status', '200'), ('body', '""')) + ')')
    W('          ), (')
    W('               REDIRECT(' + opts(('location', 'location')) + ')')
    W('          ))')
    W('     ))')
    W(')));')
    W('')
    W('LET(SAD_PREVIEW_RESULT, FUN((res), (')
    W('     // actions.py:289-294：Content-Type text/html + 5 个安全头（**不发** CSP）')
    W('     IF(!AT_K(res, "ok", FALSE), (SAD_ERR_TEXT(res)), (')
    W('          BUILD_RESPONSE(' + opts(
        ('status', '200'),
        ('headers', 'INDEX_SET(DICT(), "Content-Type", "text/html; charset=utf-8")'),
        ('body', 'AT_K(res, "html", "")')) + ')')
    W('     ))')
    W(')));')
    W('')
    W('LET(SAD_REGEN_RESULT, FUN((res, htmx), (')
    W('     // actions.py:268-283：htmx ⇒ 200 + 一段 HTML；否则 302 /')
    W('     IF(!AT_K(res, "ok", FALSE), (SAD_ERR_TEXT(res)), (')
    W('          IF(htmx, (')
    W('               BUILD_RESPONSE(' + opts(
        ('status', '200'),
        ('headers', 'INDEX_SET(DICT(), "Content-Type", "text/html; charset=utf-8")'),
        ('body', wl(REGEN_HTML))) + ')')
    W('          ), (')
    W('               REDIRECT(' + opts(('location', '"/"')) + ')')
    W('          ))')
    W('     ))')
    W(')));')
    W('')
    W('LET(SAD_UPLOAD_RESULT, FUN((res), (')
    W('     // actions.py:261-265：成功 {"success": true, "url": ...}；失败 JSON 400')
    W('     IF(!AT_K(res, "ok", FALSE), (')
    W('          JSON_ERROR_RESPONSE(400, AT_K(res, "error", "Server error"))')
    W('     ), (')
    W('          LET(url_json, ' + call('CAT', wl('{"success": true, "url": "'),
                                           'JSON_ESCAPE(AT_K(res, "url", ""))',
                                           wl('"}')) + ');')
    W('          JSON_RESPONSE(' + opts(('body', 'url_json')) + ')')
    W('     ))')
    W(')));')
    W('')

    # ── 动作分发 ──────────────────────────────────────────────────────
    W('// ── 动作分发（路由名 → admin_actions）────────────────────────────────')
    W('// ⚠ 路由名逐字取自 app.py:98-115（`_POST_HANDLERS` / `_POST_HANDLERS_NO_BODY`）')
    W('LET(SAD_ACTION, FUN((route, fields, req), (')
    W('     LET(htmx, ==(SAD_HEADER(req, "hx-request"), "true"));')
    W('     LET(art, SAD_ARTICLE_DIR);')
    W('     LET(sad, SAD_STANDALONE_DIR);')
    for route, location in ACTION_REDIRECTS:
        W('     IF(==(route, %s), (RETURN(%s)), NULL);'
          % (wl(route), _action_call(route, location)))
    W('     // ⚠ 路由名是 `live_preview`（app.py:81），不是动作名 PREVIEW')
    W('     IF(==(route, "live_preview"), (RETURN(SAD_PREVIEW_RESULT('
      + call('PREVIEW', opts(('content', ffield('content')))) + '))), NULL);')
    W('     IF(==(route, "regenerate"), (RETURN(SAD_REGEN_RESULT(REGEN(DICT()), htmx))), NULL);')
    W('     IF(==(route, "upload_image"), (RETURN(SAD_UPLOAD_RESULT('
      + call('UPLOAD_IMAGE', opts(('filename', ffield('filename')),
                                  ('data', ffield('data')),
                                  ('static_dir', 'SAD_STATIC_DIR'))) + '))), NULL);')
    W('     // /ai-assist 与 /translate：admin_actions.wll 里没有实现（见文件头缺口 ③）')
    W('     TEXT_ERROR_RESPONSE(500, CAT("action not implemented: ", route))')
    W(')));')
    W('')

    # ── 各 kind 的响应 ────────────────────────────────────────────────
    W('// ── 各 kind 的响应 ───────────────────────────────────────────────')
    W('LET(SAD_LOGIN_GET, FUN((cookie), (')
    W('     // app.py:226-237：头序 = Content-Type → CSRF cookie → CSP → 5 个安全头')
    W('     LET(csrf, SAD_EXISTING_CSRF(cookie));')
    W('     HTML_RESPONSE(' + opts(
        ('body', 'SAD_PAGE("登录", SAD_LOGIN_FORM(csrf))'),
        ('csrf_token', 'csrf'),
        ('security_last', 'TRUE')) + ')')
    W(')));')
    W('')
    W('LET(SAD_VIEW, FUN((route, cookie), (')
    W('     // app.py:185-224：GET 页面（render_admin_page 也发 CSRF cookie）')
    W('     LET(csrf, SAD_EXISTING_CSRF(cookie));')
    W('     HTML_RESPONSE(' + opts(
        ('body', 'SAD_PAGE(AT_K(SAD_TITLES, route, "管理后台"), SAD_PLACEHOLDER(route))'),
        ('csrf_token', 'csrf')) + ')')
    W(')));')
    W('')
    W('LET(SAD_LOGOUT, FUN((cookie), (')
    W('     // actions.py:426-437：销毁会话 + 清 cookie + 302 /login')
    W('     LET(tok, SESSION_FROM_COOKIE(' + opts(('cookie', 'cookie')) + '));')
    W('     SESSION_DESTROY(' + opts(('token', 'tok')) + ');')
    W('     REDIRECT(' + opts(
        ('location', '"/login"'),
        ('set_cookie', 'SESSION_CLEAR_COOKIE_HEADER(' + opts(
            ('secure', 'SAD_SECURE')) + ')'),
        ('security_last', 'TRUE')) + ')')
    W(')));')
    W('')
    W('LET(SAD_LOGIN_POST, FUN((req, cookie), (')
    W('     // actions.py:382-423 的顺序：CSRF → 口令未配置(503) → 锁定(302) → 凭据(302) → 302 /')
    W('     LET(fields, SAD_FIELDS(req));')
    W('     IF(!SAD_CSRF_OK(fields, cookie, req), (')
    W('          RETURN(REDIRECT(' + opts(('location', '"/login?error=1"')) + '))')
    W('     ), NULL);')
    W('     IF(==(SAD_PASS, ""), (')
    W('          RETURN(TEXT_ERROR_RESPONSE(503, '
      '"Admin password is not configured. Set ADMIN_PASS and restart."))')
    W('     ), NULL);')
    W('     LET(lock, RATE_LIMIT(' + opts(('client_ip', 'SAD_CLIENT_IP'),
                                          ('event', '"auth_check"')) + '));')
    W('     IF(AT_K(lock, "locked", FALSE), (')
    W('          RETURN(REDIRECT(' + opts(('location', '"/login?locked=1"')) + '))')
    W('     ), NULL);')
    W('     LET(user, ' + ffield('username') + ');')
    W('     LET(pass, ' + ffield('password') + ');')
    W('     IF(!&&(TIMING_SAFE_EQ(user, SAD_USER), TIMING_SAFE_EQ(pass, SAD_PASS)), (')
    W('          // 记一次认证失败（security.wll 的锁定计数；5 次 ⇒ 302 /login?locked=1）')
    W('          RATE_LIMIT(' + opts(('client_ip', 'SAD_CLIENT_IP'),
                                     ('event', '"auth_failure"')) + ');')
    W('          RETURN(REDIRECT(' + opts(('location', '"/login?error=1"')) + '))')
    W('     ), NULL);')
    W('     LET(tok, SESSION_CREATE(' + opts(('client_ip', 'SAD_CLIENT_IP')) + '));')
    W('     // actions.py:419-423：Location "/" → session cookie → 5 个安全头')
    W('     REDIRECT(' + opts(
        ('location', '"/"'),
        ('set_cookie', 'SESSION_COOKIE_HEADER(' + opts(
            ('token', 'tok'), ('secure', 'SAD_SECURE')) + ')'),
        ('security_last', 'TRUE')) + ')')
    W(')));')
    W('')
    W('LET(SAD_POST, FUN((m, req, cookie), (')
    W('     // app.py:241-271：404 已在上面判掉；这里 CSRF → 动作')
    W('     LET(fields, SAD_FIELDS(req));')
    W('     IF(!SAD_CSRF_OK(fields, cookie, req), (')
    W('          // app.py:253-257：豁免路径的失败是 JSON，其余是 text/plain')
    W('          RETURN(IF(AT_K(m, "csrf_exempt", FALSE), (')
    W('               JSON_ERROR_RESPONSE(403, "CSRF validation failed")')
    W('          ), (')
    W('               TEXT_ERROR_RESPONSE(403, "CSRF validation failed")')
    W('          )))')
    W('     ), NULL);')
    W('     SAD_ACTION(AT_K(m, "route", ""), fields, req)')
    W(')));')
    W('')
    W('LET(SAD_DISPATCH, FUN((m, req, cookie), (')
    W('     LET(kind, AT_K(m, "kind", ""));')
    W('     IF(==(kind, "login"), (RETURN(SAD_LOGIN_GET(cookie))), NULL);')
    W('     IF(==(kind, "login_post"), (RETURN(SAD_LOGIN_POST(req, cookie))), NULL);')
    W('     IF(==(kind, "logout_post"), (RETURN(SAD_LOGOUT(cookie))), NULL);')
    W('     IF(==(kind, "get"), (RETURN(SAD_VIEW(AT_K(m, "route", ""), cookie))), NULL);')
    W('     SAD_POST(m, req, cookie)')
    W(')));')
    W('')
    W('LET(SAD_ROUTE, FUN((req), (')
    W('     // app.py:154-181 的顺序：路由判定 → 会话（未登录 302）→ 404 / 405 → 分发')
    W('     LET(m, MATCH_ROUTE(' + opts(
        ('method', 'AT_K(req, "method", "GET")'),
        ('path', 'AT_K(req, "path", "/")')) + '));')
    W('     LET(cookie, SAD_HEADER(req, "cookie"));')
    W('     LET(sess_tok, SESSION_FROM_COOKIE(' + opts(('cookie', 'cookie')) + '));')
    W('     LET(sess_ok, IF(==(sess_tok, ""), (FALSE), (')
    W('          SESSION_VALIDATE(' + opts(('token', 'sess_tok'),
                                          ('client_ip', 'SAD_CLIENT_IP')) + ')')
    W('     )));')
    W('     IF(&&(AT_K(m, "requires_session", TRUE), !sess_ok), (')
    W('          REDIRECT(' + opts(('location', '"/login"')) + ')')
    W('     ), (')
    W('          IF(==(AT_K(m, "status", 200), 404), (')
    W('               TEXT_ERROR_RESPONSE(404, "Not Found")')
    W('          ), (')
    W('               IF(==(AT_K(m, "status", 200), 405), (')
    W('                    TEXT_ERROR_RESPONSE(405, "Method not allowed")')
    W('               ), (')
    W('                    SAD_DISPATCH(m, req, cookie)')
    W('               ))')
    W('          ))')
    W('     ))')
    W(')));')
    W('')
    W('LET(SAD_HANDLE_REQUEST, FUN((req), (')
    W('     // app.py:132-140：限流先判（60 次 / 60 秒，按 IP）')
    W('     LET(rl, RATE_LIMIT(' + opts(('client_ip', 'SAD_CLIENT_IP')) + '));')
    W('     IF(!AT_K(rl, "allowed", TRUE), (')
    W('          RATE_LIMIT_RESPONSE(' + opts(
        ('retry_after', 'AT_K(rl, "retry_after", 1)')) + ')')
    W('     ), (')
    W('          SAD_ROUTE(req)')
    W('     ))')
    W(')));')
    W('')

    # ── 主循环 ────────────────────────────────────────────────────────
    W('// ── 优雅停机 + 主循环（照 tp/bin/serve_public.wll 的骨架）──────────────')
    W('LET MUT(running, TRUE);')
    W('LET MUT(served, 0);')
    W('ON_SIGNAL("SIGINT", FUN(() , (SET(running, FALSE); STOP())));')
    W('ON_SIGNAL("SIGTERM", FUN(() , (SET(running, FALSE); STOP())));')
    W('')
    W('// ⚠ read_timeout_ms 给 5000：缺省 0 = 无截止时间，一个慢客户端就能把循环卡住')
    W('LET(serve_opts, INDEX_SET(DICT(), "read_timeout_ms", 5000));')
    W('LET(l, TCP_LISTEN(SAD_LOOPBACK, SAD_PORT));')
    W('IF(IS_ERR(l), (')
    W('     PRINT_ERR("serve_admin: TCP_LISTEN failed: ", ERR_PAYLOAD(l));')
    W('     PANIC("listen failed")')
    W('), (')
    W('     PRINT("serve_admin: listening on ", SAD_LOOPBACK, ":",')
    W('           AT_K(TCP_LOCAL_ADDR(l), "port", 0), " root=", SAD_ROOT);')
    W('     WHILE(running, (')
    W('          LET(cnt, TCP_SERVE(l, 1000, serve_opts, SAD_HANDLE_REQUEST));')
    W('          IF(IS_ERR(cnt), (')
    W('               PRINT_ERR("serve_admin: TCP_SERVE failed: ", ERR_PAYLOAD(cnt));')
    W('               SET(running, FALSE)')
    W('          ), (')
    W('               SET(served, +(served, IF(IS_ERR(cnt), 0, cnt)))')
    W('          ))')
    W('     ))')
    W('));')
    W('')
    W('TCP_CLOSE_LISTENER(l);')
    W('PRINT("serve_admin: served=", served, " — bye");')

    chars, lines = write(OUT, A)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


def _action_call(route, location):
    """「构造 opts → 调动作 → 转响应」的表达式（**单行**，括号由 chain/call 保证）。"""
    if route == 'create_article':
        o = opts(('article_dir', 'art'), ('title', ffield('title')),
                 ('date', ffield('date')), ('content', ffield('content')),
                 ('tags', ffield('tags')), ('category', ffield('category')),
                 ('status', ffield('status')))
        return 'SAD_REDIRECT_RESULT(CREATE_ARTICLE(%s), %s)' % (o, wl(location))
    if route == 'save_article':
        o = opts(('article_dir', 'art'), ('file', ffield('file')),
                 ('title', ffield('title')), ('date', ffield('date')),
                 ('content', ffield('content')), ('tags', ffield('tags')),
                 ('category', ffield('category')), ('status', ffield('status')))
        return 'SAD_REDIRECT_RESULT(SAVE_ARTICLE(%s), %s)' % (o, wl(location))
    if route == 'delete_article':
        o = opts(('article_dir', 'art'), ('file', ffield('file')))
        return 'SAD_DELETE_RESULT(DELETE_ARTICLE(%s), htmx, %s)' % (o, wl(location))
    if route == 'create_page':
        o = opts(('standalone_dir', 'sad'), ('title', ffield('title')),
                 ('slug', ffield('slug')), ('content', ffield('content')))
        return 'SAD_REDIRECT_RESULT(CREATE_PAGE(%s), %s)' % (o, wl(location))
    if route == 'save_page':
        o = opts(('standalone_dir', 'sad'), ('file', ffield('file')),
                 ('title', ffield('title')), ('slug', ffield('slug')),
                 ('content', ffield('content')))
        return 'SAD_REDIRECT_RESULT(SAVE_PAGE(%s), %s)' % (o, wl(location))
    if route == 'delete_page':
        o = opts(('standalone_dir', 'sad'), ('file', ffield('file')))
        return 'SAD_DELETE_RESULT(DELETE_PAGE(%s), htmx, %s)' % (o, wl(location))
    if route == 'set_theme':
        o = opts(('theme', ffield('theme')))
        return 'SAD_REDIRECT_RESULT(SET_THEME(%s), %s)' % (o, wl(location))
    raise SystemExit('未登记的动作: %s' % route)


if __name__ == '__main__':
    main()
