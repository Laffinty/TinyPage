"""生成 tp/bin/serve_admin.wll —— admin 后台的传输入口（卡 S4-3 / S4-7 接线）。

⚠ 输出的 .wll 由本文件生成，不要手改。

**分工**：HTTP 语义全在 `tp/lib/http_util.wll`（纯函数，脱网可测）；GET 页面在
`tp/lib/admin_views.wll`（6 个 `*_VIEW` + `NAV_HTML`）；`/ai-assist` 与 `/translate`
在 `tp/lib/admin_ai.wll`（`*_JSON` 直接给响应体）；模板替换用 `tp/lib/template.wll`
的 `SAFE_SUBSTITUTE`（== `templates.py:27 render_template`）。本文件只做
「收请求 → MATCH_ROUTE → 会话/CSRF（security.wll）→ 取数据 → 渲染/动作 → 发响应」。

**绑定**：**仅 127.0.0.1**（业主裁决，卡 S4-3 的反向守卫）。地址是**字面量**，
`TP_ADMIN_HOST` 一旦被设成别的值就启动即 PANIC —— 钉死「别绑 0.0.0.0」，
而不是留一个开关。

**配置（环境变量；`wlwl run` 不透传脚本参数 —— 坑 49）**：
  TP_ADMIN_PORT / ADMIN_PORT   监听端口（缺省 8081，对齐 config.py:35-37）
  TP_ADMIN_USER / ADMIN_USER   登录用户名（缺省 admin，config.py:25）
  TP_ADMIN_PASS / ADMIN_PASS   登录口令（**空 ⇒ 登录一律 503**，actions.py:394-400）
  TP_ROOT                      站点根（缺省 pages，config.py:48）
  BIND_DOMAIN                  非空 ⇒ cookie 加 Secure（security.py:130-132）
  TP_AI_ENABLED                "1"/"true" ⇒ cfg.ai_enabled（config.py:63-68 的 AI 段；
                               其余取缺省 ⇒ `/ai-assist` 返回**未配置** JSON，仍是 200）
  TP_AI_API_KEY / TP_AI_MODEL / TP_AI_PROVIDER / TP_AI_ENDPOINT  AI 参数
  TP_THEME                     cfg.theme_name（缺省 default，config.py:42）
  TP_THEMES_DIR                主题目录（缺省 themes，views.py:244 的字面量）

**base.html 外壳**：`admin_templates/base.html` **逐字**搬在下面的 `BASE_TEMPLATE`，
生成期与磁盘比对（`check_base_template`）—— 上游改了模板，本生成器必须同步。
外壳六键 == `responses.py:58 render_admin_page`：`title`（先 `escape_html`）/ `body` /
`csrf_token` / `current_path` / `nav_html`（用 `NAV_HTML`）/ `htmx_script`。

**已知缺口（诚实登记，不粉饰）**：
  ① 新建文章表单的**日期不预填**（Python 用 `datetime.now()`；WLWL 没有本地时区
     格式化，不拿 UTC 硬凑 —— 差 8 小时比空值更误导）。
  ② `/translate` 只接**文本层**（表单 `text` + `lang`）：dashboard 上「翻译」下拉框
     发的是 `file`，不产出译文；文章层（定位文件 / summarize(200) / 落盘）未接。
  ③ 编辑页取正文只读兄弟 `.md` 或 HTML 内嵌正文，**不做** Python 的懒迁移写盘
     （GET 不该写文件）；两者都取不到时回落 `summary`。
  ④ 静态资源（`/admin.css` / `/admin.js` / `/htmx.min.js`）本入口不服务
     （app.py:142-152 的注入资产需要资产管线）。
  ⑤ `admin_actions.wll` 没有 login/logout handler ⇒ 登录/登出仍直接调 security 原语。

**⚠ 生成器自身的纪律**：所有嵌套 `INDEX_SET` 链一律用 `chain()` **程序化拼**，
不手写括号 —— 手写时实测三处各差一个 `)`，而 `wlwl check` 只会在很远的地方报
「missing closing )」。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

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

# ── base.html 外壳（逐字搬自 admin_templates/base.html）──────────────────
# ⚠ 与磁盘**逐字**一致（生成期 check_base_template 比对）。Python 侧
#   templates.py:23 的 `path.read_text(encoding="utf-8")` 会把 CRLF 归一成 LF，
#   `Template` 实际收到的就是下面这份 LF 文本。
BASE_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>$title - TinyPage Admin</title>
<link rel="stylesheet" href="/admin.css">
$htmx_script
<script>
(function(){
  var m = localStorage.getItem('theme');
  if (m === 'light' || (!m && window.matchMedia('(prefers-color-scheme: light)').matches)) {
    document.documentElement.classList.add('light');
  }
})();
</script>
</head>
<body>
<button class="mobile-menu-toggle" aria-label="打开菜单" onclick="document.body.classList.toggle('menu-open')">☰</button>
<div class="admin-layout">
  <aside class="admin-sidebar">
    <div class="brand">
      <span class="brand-logo">TinyPage</span>
      <span class="brand-tag">Admin</span>
    </div>
    <nav>
      $nav_html
    </nav>
    <div class="sidebar-footer">
      <button class="theme-toggle" aria-label="切换主题" onclick="toggleTheme()">🌓</button>
      <form method="post" action="/logout" class="logout-form">
        <input type="hidden" name="csrf_token" value="$csrf_token">
        <button type="submit" class="logout-btn">退出登录</button>
      </form>
    </div>
  </aside>
  <main class="admin-main">
    $body
  </main>
</div>
<div id="toast-container"></div>
<script src="/admin.js"></script>
</body>
</html>
"""

TEMPLATES_DIR = os.path.join(HERE, '..', '..', 'admin_templates')

# responses.py:69-75 的 nav_items（href, label, icon_name）
NAV_ITEMS = [
    ('/', '仪表盘', 'dashboard'),
    ('/new', '新建文章', 'article'),
    ('/new-page', '新建页面', 'page'),
    ('/pages', '管理页面', 'pages'),
    ('/theme', '主题', 'theme'),
]

# app.py:192-212：这几条路由的 render_admin_page(htmx=True)
HTMX_ROUTES = ['pages_dashboard', 'new_article', 'edit_article',
               'new_page', 'edit_page']

# content.py:662 SAFE_PAGE_FILENAME（CJK 用**字面**，`\uXXXX` 在 WLWL 正则里不生效）
PAGE_NAME_RE = '^[a-zA-Z0-9一-龥_-]+[.]html$'

# config.py:44-48 的缺省（本入口没有 toml 解析 ⇒ 只沿用缺省）
MAX_FILE_SIZE = 10 * 1024 * 1024
PAGE_SIZE = 10
MAX_TITLE_LENGTH = 200
MAX_CONTENT_LENGTH = 50000


def check_base_template():
    """生成期漂移守卫：BASE_TEMPLATE 必须与磁盘上的 base.html 逐字一致。"""
    path = os.path.join(TEMPLATES_DIR, 'base.html')
    # ⚠ 用 read_text 的默认换行处理（CRLF → LF）：templates.py:23 就是这口径，
    #   即 Template 实际收到的字符串。
    with open(path, encoding='utf-8') as f:
        got = f.read()
    if got != BASE_TEMPLATE:
        i = 0
        while i < min(len(got), len(BASE_TEMPLATE)) and got[i] == BASE_TEMPLATE[i]:
            i += 1
        lo = max(0, i - 40)
        raise SystemExit(
            'admin_templates/base.html 与生成器里的 BASE_TEMPLATE 不一致'
            '（首个差异在第 %d 个字符）：\n  磁盘: %r\n  生成器: %r\n'
            '  ⇒ 上游改了外壳，本生成器必须同步。'
            % (i, got[lo:i + 40], BASE_TEMPLATE[lo:i + 40]))


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
    W('// ⚠ 已知缺口（不粉饰）：新建文章日期不预填（WLWL 无本地时区格式化）；')
    W('//   /translate 只到文本层；静态资源（/admin.css 等）本入口不服务。')
    W('')
    W('IMPORT("wlwl:std.net", ["TCP_LISTEN", "TCP_SERVE", "TCP_CLOSE_LISTENER",')
    W('    "TCP_LOCAL_ADDR"]);')
    W('IMPORT("wlwl:std.signal", ["ON_SIGNAL", "STOP"]);')
    W('IMPORT("wlwl:std.env", ["ENV_GET"]);')
    W('IMPORT("wlwl:std.text", ["TO_INT", "TO_LOWER"]);')
    W('IMPORT("wlwl:std.fs", ["PATH_JOIN", "PATH_CANONICAL", "LIST_DIR", "PATH_BASE",')
    W('    "PATH_EXT", "READ_FILE", "FILE_META", "EXISTS"]);')
    W('IMPORT("wlwl:std.str", ["CAT", "INDEX_OF"]);')
    W('IMPORT("wlwl:std.regex", ["RE", "RE_TEST"]);')
    W('IMPORT("wlwl:std.encode", ["TIMING_SAFE_EQ", "URL_DECODE"]);')
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
    W('// 视图层 / 模板 / 主题 / 元数据 / 排序 —— 全部复用已交付模块，不重写')
    W('IMPORT("./../lib/admin_views.wll", ["DASHBOARD_VIEW", "ARTICLE_FORM_VIEW",')
    W('    "PAGE_FORM_VIEW", "PAGES_DASHBOARD_VIEW", "THEME_SELECTOR_VIEW",')
    W('    "LOGIN_VIEW", "NAV_HTML"]);')
    W('IMPORT("./../lib/admin_ai.wll", ["AI_ASSIST_JSON", "TRANSLATE_JSON"]);')
    W('IMPORT("./../lib/template.wll", ["SAFE_SUBSTITUTE"]);')
    W('IMPORT("./../lib/esc.wll", ["ESCAPE_HTML"]);')
    W('IMPORT("./../lib/frontmatter.wll", ["PARSE_META"]);')
    W('IMPORT("./../lib/article_store.wll", ["VALIDATE_FILENAME", "SOURCE_PATH",')
    W('    "DECODE_CONTENT"]);')
    W('IMPORT("./../lib/sort_util.wll", ["SORT_BY_DATE", "SORT_BY_TITLE_OR_FILE"]);')
    W('IMPORT("./../lib/theme.wll", ["LIST_THEMES"]);')
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
    W('// 主题目录 / 当前主题（views.py:244 用字面量 Path("themes")；config.py:42）')
    W('LET(SAD_THEMES_DIR, ENV_GET("TP_THEMES_DIR", "themes"));')
    W('LET(SAD_THEME_NAME, ENV_GET("TP_THEME", "default"));')
    W('')
    W('// AI 配置（config.py:63-68；只认布尔 TRUE，见 admin_ai 的 IS_ENABLED 口径）')
    W('LET(SAD_AI_FLAG, TO_LOWER(ENV_GET("TP_AI_ENABLED", "")));')
    W('LET(SAD_AI_ENABLED, ||(==(SAD_AI_FLAG, "1"), ==(SAD_AI_FLAG, "true")));')
    W('LET(SAD_CFG, ' + chain([
        ('page_size', str(PAGE_SIZE)),
        ('max_file_size', str(MAX_FILE_SIZE)),
        ('max_title_length', str(MAX_TITLE_LENGTH)),
        ('max_content_length', str(MAX_CONTENT_LENGTH)),
        ('ai_enabled', 'SAD_AI_ENABLED'),
        ('ai_api_key', 'ENV_GET("TP_AI_API_KEY", "")'),
        ('ai_model', 'ENV_GET("TP_AI_MODEL", "gpt-3.5-turbo")'),
        ('ai_provider', 'ENV_GET("TP_AI_PROVIDER", "openai")'),
        ('ai_endpoint', 'ENV_GET("TP_AI_ENDPOINT", "")'),
    ]) + ');')
    W('')
    W('// 侧边导航项（responses.py:69-75）；NAV_HTML 读 [href, label, icon_name]')
    W('LET(SAD_NAV_ITEMS, ' + '[' + ', '.join(
        '[' + ', '.join(wl(x) for x in item) + ']' for item in NAV_ITEMS) + ']);')
    W('// app.py:192-212：这几条路由的 render_admin_page(htmx=True)')
    W('LET(SAD_HTMX_ROUTES, [' + ', '.join(wl(r) for r in HTMX_ROUTES) + ']);')
    W('LET(SAD_HTMX_SCRIPT, ' + wl('<script src="/htmx.min.js"></script>') + ');')
    W('')

    # ── base.html 外壳 + 数据 ────────────────────────────────────────
    W('// ── base.html 外壳（responses.py:58 render_admin_page）─────────────')
    W('// ⚠ 模板正文逐字搬在生成器里，生成期与磁盘比对；`$` 在 WLWL 字面量里是插值')
    W('//   ⇒ 全部发射成 `\\$`（wl() 负责，反斜杠先、美元符后）。')
    W('LET(SAD_T_BASE, ' + wl(BASE_TEMPLATE) + ');')
    W('')
    A.extend(fn('SAD_NAV', 'cur', [
        '// templates.py:35 build_nav_html（复用视图层的 NAV_HTML）',
        'NAV_HTML(' + opts(('nav_items', 'SAD_NAV_ITEMS'), ('current_path', 'cur')) + ')',
    ], '// 侧边导航'))

    A.extend(fn('SAD_SHELL', 'title, body, csrf, path, htmx', [
        '// responses.py:79-87 的六键：title 先 escape_html；body/nav_html 是**片段**',
        'LET MUT(m, DICT())',
        'SET(m, INDEX_SET(m, "title", ESCAPE_HTML(title)))',
        'SET(m, INDEX_SET(m, "body", body))',
        'SET(m, INDEX_SET(m, "csrf_token", csrf))',
        'SET(m, INDEX_SET(m, "current_path", path))',
        'SET(m, INDEX_SET(m, "nav_html", SAD_NAV(path)))',
        'SET(m, INDEX_SET(m, "htmx_script", htmx))',
        'SAFE_SUBSTITUTE(SAD_T_BASE, m)',
    ], '// 整页外壳（base.html + SAFE_SUBSTITUTE，缺键原样保留）'))

    W('// ── 数据（读目录；口径 == content.py:153 list_articles / :674 list_standalones）')
    W('// ⚠ 入口不做 Python 的「懒迁移写盘」：GET 一律只读。')
    A.extend(fn('SAD_AS_STR', 'v, d', [
        'IF(==(TYPE(v), "STRING"), v, d)',
    ]))
    A.extend(fn('SAD_READ_OR', 'p, fb', [
        '// ⚠ `LET(r, READ_FILE(p))` 绑定**不算消费** ERR（坑 25）',
        'IF(IS_ERR(READ_FILE(p)), fb, READ_FILE(p))',
    ]))
    A.extend(fn('SAD_FILE_SIZE', 'p', [
        '// 取不到给 -1（Python 侧 entry.stat() 抛错时整篇跳过；这里放过大小门）',
        'IF(IS_ERR(FILE_META(p)), -1, AT_K(FILE_META(p), "size", 0))',
    ]))
    A.extend(fn('SAD_TAG_LIST', 'tags', [
        '// == ArticleMeta.tag_list：split(",") → strip → 丢空',
        'LET MUT(out, [])',
        C('IF', '!=(tags, "")', [
            C('FOR', 't0, SPLIT(tags, ",")', [
                'LET(t, TRIM(t0))',
                C('IF', '==(t, "")', ['NULL'], ['SET(out, PUSH(out, t))']),
            ]),
        ], ['NULL']),
        'out',
    ]))
    A.extend(fn('SAD_ART_REC', 'meta, name', [
        '// meta 是 PARSE_META 的 DICT；补 ArticleMeta 的派生字段',
        'LET MUT(r, meta)',
        'LET(status, TO_LOWER(SAD_AS_STR(AT_K(r, "status", "published"), "published")))',
        'SET(r, INDEX_SET(r, "file", name))',
        'SET(r, INDEX_SET(r, "tag_list", SAD_TAG_LIST(SAD_AS_STR(AT_K(r, "tags", ""), ""))))',
        'SET(r, INDEX_SET(r, "is_draft", ==(status, "draft")))',
        '// models.py:50 is_published == status.lower() != "draft"',
        'SET(r, INDEX_SET(r, "is_published", !=(status, "draft")))',
        'r',
    ]))
    A.extend(fn('SAD_LIST_ARTICLES', 'dir, max_size', [
        '// content.py:171-196：.html + validate_filename + 大小 + 日期可解析；收草稿',
        'LET MUT(out, [])',
        C('IF', '!IS_ERR(LIST_DIR(dir))', [
            C('FOR', 'e, LIST_DIR(dir)', [
                'LET(name, PATH_BASE(e))',
                C('IF', '!=(PATH_EXT(name), "html")', ['NULL'], [
                    C('IF', '!VALIDATE_FILENAME(name)', ['NULL'], [
                        C('IF', '>(SAD_FILE_SIZE(e), max_size)', ['NULL'], [
                            'LET(meta, PARSE_META(SAD_READ_OR(e, "")))',
                            'SET(out, PUSH(out, SAD_ART_REC(meta, name)))',
                        ]),
                    ]),
                ]),
            ]),
        ], ['NULL']),
        '// == arts.sort(key=date_obj, reverse=True)（sort_util 稳定降序）',
        'SORT_BY_DATE(out)',
    ]))
    W('// 独立页文件名白名单 == content.py:662 SAFE_PAGE_FILENAME')
    W('// ⚠ CJK 用**字面** `一-龥`（坑 20：`\\u4e00` 在 WLWL 正则里不生效）')
    W('LET(SAD_PAGE_NAME_RE, RE(' + wl(PAGE_NAME_RE) + '));')
    A.extend(fn('SAD_LIST_PAGES', 'dir, max_size', [
        'LET MUT(out, [])',
        C('IF', '!IS_ERR(LIST_DIR(dir))', [
            C('FOR', 'e, LIST_DIR(dir)', [
                'LET(name, PATH_BASE(e))',
                C('IF', '!RE_TEST(SAD_PAGE_NAME_RE, name)', ['NULL'], [
                    C('IF', '>(SAD_FILE_SIZE(e), max_size)', ['NULL'], [
                        'LET MUT(r, SAD_ART_REC(PARSE_META(SAD_READ_OR(e, "")), name))',
                        '// slug = 去掉 ".html" 的干名（Python: entry.stem）',
                        'SET(r, INDEX_SET(r, "slug", SUB(name, 0, -(LEN(name), 5))))',
                        'SET(out, PUSH(out, r))',
                    ]),
                ]),
            ]),
        ], ['NULL']),
        '// == pages.sort(key=lambda x: x.title or x.file)',
        'SORT_BY_TITLE_OR_FILE(out)',
    ]))
    A.extend(fn('SAD_FIND', 'arr, key, val', [
        '// 线性找第一条 arr[i][key] == val（Python 的 next((a for a in ...), None)）',
        'LET MUT(out, NULL)',
        'LET(n, LEN(arr))',
        'LET MUT(i, 0)',
        C('WHILE', '&&(<(i, n), ==(TYPE(out), "NULL"))', [
            'LET(it, AT(arr, i, DICT()))',
            C('IF', '==(SAD_AS_STR(AT_K(it, key, ""), ""), val)',
              ['SET(out, it)'], ['NULL']),
            'SET(i, +(i, 1))',
        ]),
        'out',
    ]))
    A.extend(fn('SAD_RAW', 'dir, fname', [
        '// content.py:493 get_raw_content 的**只读**部分：兄弟 .md → HTML 内嵌正文 → summary',
        'LET MUT(out, "")',
        C('IF', '==(fname, "")', ['NULL'], [
            'LET(p, PATH_JOIN(dir, fname))',
            'LET(md, SOURCE_PATH(p))',
            C('IF', 'EXISTS(md)', [
                'SET(out, SAD_READ_OR(md, ""))',
            ], [
                'LET(html, SAD_READ_OR(p, ""))',
                'LET(d, DECODE_CONTENT(html))',
                C('IF', '==(TYPE(d), "STRING")', [
                    'SET(out, d)',
                ], [
                    'LET(meta, PARSE_META(html))',
                    'SET(out, SAD_AS_STR(AT_K(meta, "summary", ""), ""))',
                ]),
            ]),
        ]),
        'out',
    ]))
    A.extend(fn('SAD_PATH_OF', 'req', [
        '// PATH_INFO（去掉查询串）：nav 高亮与 MATCH_ROUTE 都不看 query',
        'LET(p, SAD_AS_STR(AT_K(req, "path", ""), ""))',
        'LET(i, INDEX_OF(p, "?"))',
        'IF(<(i, 0), p, SUB(p, 0, i))',
    ]))
    A.extend(fn('SAD_QUERY', 'req, key', [
        '// QUERY_STRING 里 key 的第一个值（Python：parse_qs(...).get(k, [""])[0]）',
        'LET(p, SAD_AS_STR(AT_K(req, "path", ""), ""))',
        'LET(qi, INDEX_OF(p, "?"))',
        'LET MUT(out, "")',
        'LET MUT(found, FALSE)',
        C('IF', '>=(qi, 0)', [
            C('FOR', 'part, SPLIT(SUB(p, +(qi, 1)), "&")', [
                'LET(eq, INDEX_OF(part, "="))',
                C('IF', '||(found, <(eq, 0))', ['NULL'], [
                    C('IF', '==(SUB(part, 0, eq), key)', [
                        'LET(rawv, SUB(part, +(eq, 1)))',
                        '// 非法 percent 转义 ⇒ 原样（fail open：只影响查询参数取值）',
                        'SET(out, IF(IS_ERR(URL_DECODE(rawv)), rawv, URL_DECODE(rawv)))',
                        'SET(found, TRUE)',
                    ], ['NULL']),
                ]),
            ]),
        ], ['NULL']),
        'out',
    ]))
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
    W('     // /ai-assist（actions.py:296-329）：**永远** 200 + application/json')
    W('     //   action / text / lang 三个表单字段 == actions.py:299-314 的取法')
    W('     IF(==(route, "ai_assist"), (RETURN(JSON_RESPONSE(' + opts(
        ('status', '200'),
        ('body', 'AI_ASSIST_JSON(' + opts(
            ('action', ffield('action')),
            ('text', ffield('text')),
            ('target', ffield('lang')),
            ('cfg', 'SAD_CFG')) + ')')) + '))), NULL);')
    W('     // /translate（content.py:757-842 的**文本层**）：收 text + lang，不出文件')
    W('     IF(==(route, "translate_article"), (RETURN(JSON_RESPONSE(' + opts(
        ('status', '200'),
        ('body', 'TRANSLATE_JSON(' + opts(
            ('text', ffield('text')),
            ('target', ffield('lang')),
            ('cfg', 'SAD_CFG')) + ')')) + '))), NULL);')
    W('     TEXT_ERROR_RESPONSE(500, CAT("action not implemented: ", route))')
    W(')));')
    W('')

    # ── 各 kind 的响应 ────────────────────────────────────────────────
    W('// ── 各 kind 的响应 ───────────────────────────────────────────────')
    W('LET(SAD_LOGIN_GET, FUN((req, cookie), (')
    W('     // app.py:226-237：login.html 是**整页**（不走 base.html）；头序照旧：')
    W('     //   Content-Type → CSRF cookie → CSP → 5 个安全头')
    W('     LET(csrf, SAD_EXISTING_CSRF(cookie));')
    W('     LET(body, LOGIN_VIEW(' + opts(
        ('csrf_token', 'csrf'),
        ('error', 'SAD_QUERY(req, "error")'),
        ('locked', 'SAD_QUERY(req, "locked")')) + '));')
    W('     HTML_RESPONSE(' + opts(
        ('body', 'body'),
        ('csrf_token', 'csrf'),
        ('security_last', 'TRUE')) + ')')
    W(')));')
    W('')
    A.extend(fn('SAD_VIEW_BODY', 'route, req, csrf', [
        '// app.py:194-214 的 GET 分派：每条路由取自己的数据，交给视图层渲染**正文**',
        '// ⚠ 视图层已处理「取不到就显示未找到」⇒ 这里不做额外兜底',
        'LET(mfs, AT_K(SAD_CFG, "max_file_size", 10485760))',
        C('IF', '==(route, "dashboard")', [
            'RETURN(DASHBOARD_VIEW(' + opts(
                ('csrf_token', 'csrf'),
                ('articles', 'SAD_LIST_ARTICLES(SAD_ARTICLE_DIR, mfs)'),
                ('standalones', 'SAD_LIST_PAGES(SAD_STANDALONE_DIR, mfs)'),
                ('page', 'SAD_QUERY(req, "page")'),
                ('cfg', 'SAD_CFG')) + '))',
        ], ['NULL']),
        C('IF', '==(route, "pages_dashboard")', [
            'RETURN(PAGES_DASHBOARD_VIEW(' + opts(
                ('csrf_token', 'csrf'),
                ('pages', 'SAD_LIST_PAGES(SAD_STANDALONE_DIR, mfs)')) + '))',
        ], ['NULL']),
        C('IF', '==(route, "new_article")', [
            '// views.py:132 的分类 datalist 要**全部**文章（含草稿）',
            '// ⚠ Python 的 date 缺省是 datetime.now()；WLWL 无本地时区格式化 ⇒ 空串',
            'RETURN(ARTICLE_FORM_VIEW(' + opts(
                ('csrf_token', 'csrf'),
                ('is_edit', 'FALSE'),
                ('now', '""'),
                ('articles', 'SAD_LIST_ARTICLES(SAD_ARTICLE_DIR, mfs)'),
                ('content', '""'),
                ('cfg', 'SAD_CFG')) + '))',
        ], ['NULL']),
        C('IF', '==(route, "edit_article")', [
            '// views.py:94-117：按 ?file= 定位；拿不到 ⇒ 视图回 "Article not found"',
            'LET(fname, SAD_QUERY(req, "file"))',
            'LET(arts, SAD_LIST_ARTICLES(SAD_ARTICLE_DIR, mfs))',
            'RETURN(ARTICLE_FORM_VIEW(' + opts(
                ('csrf_token', 'csrf'),
                ('is_edit', 'TRUE'),
                ('now', '""'),
                ('articles', 'arts'),
                ('article', 'SAD_FIND(arts, "file", fname)'),
                ('content', 'SAD_RAW(SAD_ARTICLE_DIR, fname)'),
                ('cfg', 'SAD_CFG')) + '))',
        ], ['NULL']),
        C('IF', '==(route, "new_page")', [
            'RETURN(PAGE_FORM_VIEW(' + opts(
                ('csrf_token', 'csrf'),
                ('is_edit', 'FALSE'),
                ('content', '""'),
                ('cfg', 'SAD_CFG')) + '))',
        ], ['NULL']),
        C('IF', '==(route, "edit_page")', [
            'LET(fname, SAD_QUERY(req, "file"))',
            'LET(pgs, SAD_LIST_PAGES(SAD_STANDALONE_DIR, mfs))',
            'RETURN(PAGE_FORM_VIEW(' + opts(
                ('csrf_token', 'csrf'),
                ('is_edit', 'TRUE'),
                ('page', 'SAD_FIND(pgs, "file", fname)'),
                ('content', 'SAD_RAW(SAD_STANDALONE_DIR, fname)'),
                ('cfg', 'SAD_CFG')) + '))',
        ], ['NULL']),
        C('IF', '==(route, "theme")', [
            'RETURN(THEME_SELECTOR_VIEW(' + opts(
                ('csrf_token', 'csrf'),
                ('themes', 'LIST_THEMES(SAD_THEMES_DIR)'),
                ('current_theme', 'SAD_THEME_NAME')) + '))',
        ], ['NULL']),
        '""',
    ], '// GET 正文（视图层输出；外壳由 SAD_VIEW 套）'))
    W('LET(SAD_VIEW, FUN((route, req, cookie), (')
    W('     // app.py:185-224：render_admin_page（也发 CSRF cookie）')
    W('     LET(csrf, SAD_EXISTING_CSRF(cookie));')
    W('     LET(body, SAD_VIEW_BODY(route, req, csrf));')
    W('     LET(shell, SAD_SHELL(AT_K(SAD_TITLES, route, "管理后台"), body, csrf,')
    W('          SAD_PATH_OF(req),')
    W('          IF(CONTAINS(SAD_HTMX_ROUTES, route), SAD_HTMX_SCRIPT, "")));')
    W('     HTML_RESPONSE(' + opts(
        ('body', 'shell'),
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
    W('     IF(==(kind, "login"), (RETURN(SAD_LOGIN_GET(req, cookie))), NULL);')
    W('     IF(==(kind, "login_post"), (RETURN(SAD_LOGIN_POST(req, cookie))), NULL);')
    W('     IF(==(kind, "logout_post"), (RETURN(SAD_LOGOUT(cookie))), NULL);')
    W('     IF(==(kind, "get"), (RETURN(SAD_VIEW(AT_K(m, "route", ""), req, cookie))), NULL);')
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


def main_guarded():
    """先跑模板漂移守卫，再生成（上游改了 base.html ⇒ 生成即失败）。"""
    check_base_template()
    main()


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
    main_guarded()
