"""生成 tp/lib/admin_views.wll —— admin 视图层（卡 S4-6）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**对齐目标（真 Python 源码树 `tinypage/admin/`）**：

| 导出 | Python 实现 | 行号 |
|---|---|---|
| `DASHBOARD_VIEW(opts)`        | `views.py:dashboard_view`        | 14 |
| `ARTICLE_FORM_VIEW(opts)`     | `views.py:article_form_view`     | 90 |
| `PAGE_FORM_VIEW(opts)`        | `views.py:page_form_view`        | 162 |
| `PAGES_DASHBOARD_VIEW(opts)`  | `views.py:pages_dashboard_view`  | 213 |
| `THEME_SELECTOR_VIEW(opts)`   | `views.py:theme_selector_view`   | 239 |
| `LOGIN_VIEW(opts)`            | `views.py:login_view`            | 275 |
| `AI_PANEL(opts)`              | `views.py:_build_ai_panel`       | 291 |
| `NAV_HTML(opts)`              | `templates.py:build_nav_html`    | 35 |

逐字节对照基准：`tp/test/fixtures/admin_views_baseline.json`
    （由 `tp/test/gen_admin_views_baseline.py` 用**真 Python** 生成）

**模板替换的口径**（`templates.py:27`）：Python 用的是
`Template(...).safe_substitute({k: str(v)})` —— **不是** `substitute`。
（任务书里写的「缺键即错」与源码不符，本模块以源码为准。）
⇒ 直接复用 `tp/lib/template.wll` 的 `SAFE_SUBSTITUTE`，不重写扫描器。

**为什么所有 `$` 都写成 `\\$`**（本卡最大的坑）：WLWL 的字符串字面量里
`$var` / `${...}` 是**插值**（README #32）。模板正文里全是 `$total` / `$rows`
这类**要交给 SAFE_SUBSTITUTE 的占位符**，若原样写进字面量，WLWL 会在**加载期**
就去求值 `total` 这个变量 ⇒ `E0020 undefined name`；而 `"\\${"` 这种形态还会
`E0002`。实测（2026-11-02）：`"\\$a"` ⇒ 字面 `$a`，`"\\${b}"` ⇒ 字面 `${b}`，
`"\\$\\$"` ⇒ 字面 `$$`；**但** `"\\\\${b}"`（双反斜杠 + 插值）会真的去求值
`b` —— 所以转义必须**逐字符**做，且反斜杠先于 `$` 处理（`wl_string` 里
`\\`→`\\\\` 在前、`$`→`\\$` 在后，天然满足）。

**escape 口径（逐条照 `views.py` 的调用点，不搞「一律 escape」）**：
  · 会 escape 的只有：文章标题(`escape_html`)、标签串、分类、日期、正文原文、
    主题名/描述、登录标题；属性位置用 `escape_attr`。
  · 已构造好的 HTML 片段**必须原样代入**：`rows` / `nav_html` / `datalist` /
    `ai_panel` / `file_input` / `theme_cards` / `error_msg` / `pub_selected` …
    一律 escape 会把编辑器/表单整体弄坏。
  · `escape_attr` 实测与 `escape_html` **逐字节相同**（`security.py:39` 的
    `.replace('"', '&quot;')` 是空操作，`html.escape(quote=True)` 已经转过 `"`）
    ⇒ 本模块用同一个 `ESCAPE_HTML`，并在生成期用真 Python 断言二者等价。

**与 Python 的三处**契约**差异（都是为了可测性，已在基准里登记 note）**：
  ① `dashboard_view` 的 `page` 来自 `QUERY_STRING` 的 `int()` + `try/except`
     ⇒ 本模块取显式键 `page`（INTEGER 或数字串），**解析 QUERY_STRING 属传输层**
     （`http_util.wll`）。口径：非法/越界 ⇒ 1（`max(1, …)`）。
     已知差异：Python 的 `int()` 还接受 `" 2 "` / `"+2"`，本模块不认 ⇒ 1。
  ② `article_form_view` 的 `datetime.now()` 不可测 ⇒ 取显式键 `now`
     （`"%Y-%m-%d %H:%M"` 形态的字符串），调用方负责格式化。
  ③ 文件系统判定（`is_file()` / `get_raw_content()` / `list_articles`）全部
     上移到调用方：本模块收 `articles` / `standalones` / `article` / `page` /
     `content` 等**已取好的数据**（纯函数，脱网可测）。
     `is_edit=TRUE` 而 `article` 不是 DICT ⇒ 返回 `<p>Article not found</p>`
     （对齐 `views.py:101` 的 not-found 分支）。
     ⚠ `views.py:98` 的 `<p>Invalid filename</p>` 分支属于文件名校验
     （`security.wll::VALIDATE_FILENAME`），不在本模块。

**未交付（诚实登记）**：`responses.py:58 render_admin_page`（base.html 外壳 +
导航）**不在本卡契约内** —— 它属于传输层接线，且本卡已导出 `NAV_HTML` 供其使用。
`admin_templates/base.html` 仍在本文件里逐字保留并核对（生成期防上游漂移），
但**不产出 WLWL 常量**（没有消费方时留一段死代码只会误导）。

用法：python gen_admin_views.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'admin_views.wll')
TEMPLATES_DIR = os.path.join(HERE, '..', '..', 'admin_templates')


# ── WLWL 字面量 ──────────────────────────────────────────────────
def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 转义白名单：`\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`（README #7）。
    ⚠⚠ `$` **必须**写 `\\$`：模板正文里的 `$total` 是**要传给 SUBSTITUTE** 的
      占位符，原样写进字面量会被 WLWL 当插值、加载期直接报错（README #32）。
    ⚠ 顺序：`\\` 先转成 `\\\\`，`$` 再转成 `\\$` —— 反过来会把 `$` 的转义
      反斜杠又变成双反斜杠，运行时剩一个反斜杠（实测见文件头）。
    """
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
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\0':
            out.append('\\0')
        elif ch == '$':
            out.append('\\$')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


class Raw(str):
    """标记「这是 WLWL 表达式，不是要转义的字面量」。"""


def R(expr):
    return Raw(expr)


def E(*parts):
    """把混合片段拼成 WLWL 的 `CAT(...)` 表达式。

    str 片段 ⇒ 自动转成 WLWL 字面量；`Raw` 片段 ⇒ 原样当表达式。
    只有一个片段时直接返回它（`CAT` 单参没意义）。
    """
    items = []
    for p in parts:
        if isinstance(p, Raw):
            items.append(str(p))
        elif isinstance(p, str):
            items.append(wl_string(p))
        else:
            raise TypeError('bad part: %r' % (p,))
    if len(items) == 1:
        return items[0]
    return 'CAT(' + ', '.join(items) + ')'


# ── 模板正文（逐字抄自 admin_templates/，生成期与磁盘比对）──────────
# ⚠ 抄错一个字节 ⇒ gen 直接 SystemExit（见 check_templates）。
T_DASHBOARD = """<div class="admin-wrapper">
  <h1>仪表盘</h1>
  <div class="bento-grid stats-grid">
    <div class="stat-card">
      <div class="stat-value">$total</div>
      <div class="stat-label">文章总数</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">$draft_count</div>
      <div class="stat-label">草稿</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">$page_count</div>
      <div class="stat-label">独立页面</div>
    </div>
  </div>
  <div class="glass-banner">
    <span class="pulse-dot"></span>
    <strong>安全提醒：</strong>所有操作已记录审计日志 | CSRF保护已启用
  </div>
  <div class="actions">
    <a href="/new" class="btn-primary btn-glow">+ 新建文章</a>
    <a href="/new-page" class="btn-primary">+ 新建页面</a>
    <a href="/pages" class="btn-secondary">📄 管理页面</a>
    <form method="post" action="/regen" hx-post="/regen" hx-target="#regen-status" style="display:inline;">
      <input type="hidden" name="csrf_token" value="$csrf_token">
      <button type="submit" class="btn-secondary" id="regen-btn">
        <span class="btn-icon">↻</span> 重新生成静态页
      </button>
    </form>
    <span id="regen-status"></span>
    <a href="/theme" class="btn-secondary">◐ 主题</a>
    <div class="search-wrap">
      <input type="search" id="article-search" placeholder="搜索文章标题..." oninput="filterArticles(this.value)">
    </div>
  </div>
  <div class="table-card">
    <table class="admin-table">
      <thead>
        <tr>
          <th style="width:55%">标题</th>
          <th style="width:25%">发布时间</th>
          <th style="width:20%">操作</th>
        </tr>
      </thead>
      <tbody>$rows</tbody>
    </table>
  </div>
  $nav_html
  <p class="table-meta">共 $total 篇文章，第 $page/$pages 页</p>
</div>
"""

T_ARTICLE_FORM = """<div class="admin-wrapper">
  <h1>$heading</h1>
  <div class="editor-grid">
    <div class="editor-form">
      <form method="post" action="$form_action" id="article-form">
        <input type="hidden" name="csrf_token" value="$csrf_token">
        $file_input
        <div class="form-group">
          <input name="title" value="$title" placeholder="文章标题" required maxlength="$max_title_length">
        </div>
        <div class="form-group">
          <input name="date" value="$date" required pattern="\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}">
        </div>
        <div class="form-group">
          <input name="category" list="category-list" value="$category" placeholder="分类">
          $datalist
        </div>
        <div class="form-group">
          <input name="tags" value="$tags" placeholder="标签，用逗号分隔">
        </div>
        <div class="form-group">
          <select name="status">
            <option value="published"$pub_selected>发布</option>
            <option value="draft"$draft_selected>草稿</option>
          </select>
        </div>
        $ai_panel
        <div id="drop-zone" onclick="document.getElementById('file-input').click()" ondragover="event.preventDefault();this.classList.add('dragover')" ondragleave="this.classList.remove('dragover')" ondrop="handleDrop(event)">
          <span class="drop-icon">📎</span>
          <span>拖拽图片到此处上传，或点击选择文件</span>
          <input type="file" id="file-input" accept="image/*" style="display:none" onchange="handleFileSelect(event)">
        </div>
        <div class="form-group">
          <textarea name="content" placeholder="支持 Markdown：# 标题、**粗体**、*斜体*、`代码`、[链接](url)、```代码块```" required maxlength="$max_content_length" hx-trigger="keyup changed delay:500ms" hx-post="/preview" hx-target="#live-preview" hx-include="#article-form">$content</textarea>
        </div>
        <div class="form-actions">
          <button type="submit" class="btn-primary btn-glow">$submit_label</button>
          <a href="/" class="btn-secondary">返回</a>
        </div>
      </form>
    </div>
    <div class="editor-preview">
      <div class="preview-header">
        <span class="preview-badge">Live Preview</span>
      </div>
      <div id="live-preview" class="preview-box">
        <p class="preview-placeholder">在左侧输入内容，预览将显示在这里...</p>
      </div>
    </div>
  </div>
</div>
"""

T_PAGE_FORM = """<div class="admin-wrapper">
  <h1>$heading</h1>
  <div class="editor-grid">
    <div class="editor-form">
      <form method="post" action="$form_action" id="page-form">
        <input type="hidden" name="csrf_token" value="$csrf_token">
        $file_input
        <div class="form-group">
          <input name="title" value="$title" placeholder="页面标题" required maxlength="$max_title_length">
        </div>
        <div class="form-group">
          <input name="slug" value="$slug" placeholder="URL 标识（如 about）" required pattern="[a-zA-Z0-9\\u4e00-\\u9fa5_-]+" title="字母、数字、中文、下划线、连字符">
        </div>
        $ai_panel
        <div id="drop-zone" onclick="document.getElementById('file-input').click()" ondragover="event.preventDefault();this.classList.add('dragover')" ondragleave="this.classList.remove('dragover')" ondrop="handleDrop(event)">
          <span class="drop-icon">📎</span>
          <span>拖拽图片到此处上传，或点击选择文件</span>
          <input type="file" id="file-input" accept="image/*" style="display:none" onchange="handleFileSelect(event)">
        </div>
        <div class="form-group">
          <textarea name="content" placeholder="支持 Markdown" required maxlength="$max_content_length" hx-trigger="keyup changed delay:500ms" hx-post="/preview" hx-target="#live-preview" hx-include="#page-form">$content</textarea>
        </div>
        <div class="form-actions">
          <button type="submit" class="btn-primary btn-glow">$submit_label</button>
          <a href="/pages" class="btn-secondary">返回</a>
        </div>
      </form>
    </div>
    <div class="editor-preview">
      <div class="preview-header">
        <span class="preview-badge">Live Preview</span>
      </div>
      <div id="live-preview" class="preview-box">
        <p class="preview-placeholder">在左侧输入内容，预览将显示在这里...</p>
      </div>
    </div>
  </div>
</div>
"""

T_PAGES_DASHBOARD = """<div class="admin-wrapper">
  <h1>独立页面管理</h1>
  <div class="actions">
    <a href="/new-page" class="btn-primary btn-glow">+ 新建页面</a>
    <a href="/" class="btn-secondary">返回文章</a>
  </div>
  <div class="table-card">
    <table class="admin-table">
      <thead>
        <tr>
          <th style="width:45%">标题</th>
          <th style="width:35%">路径</th>
          <th style="width:20%">操作</th>
        </tr>
      </thead>
      <tbody>$rows</tbody>
    </table>
  </div>
  <p class="table-meta">共 $total 个页面</p>
</div>
"""

T_THEME_SELECTOR = """<div class="admin-wrapper">
  <h1>主题管理</h1>
  <div class="actions">
    <a href="/" class="btn-secondary">返回后台</a>
  </div>
  <p class="theme-current">当前主题：<strong>$current_theme</strong></p>
  <div class="theme-grid">
    $theme_cards
  </div>
</div>
"""

T_LOGIN = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>登录 - TinyPage Admin</title>
<link rel="stylesheet" href="/admin.css">
<script>
(function(){
  var m = localStorage.getItem('theme');
  if (m === 'light' || (!m && window.matchMedia('(prefers-color-scheme: light)').matches)) {
    document.documentElement.classList.add('light');
  }
})();
</script>
</head>
<body class="login-body">
<button class="theme-toggle login-theme-toggle" aria-label="切换主题" onclick="toggleTheme()">🌓</button>
<div class="login-bg"></div>
<div class="login-container">
  <div class="login-card glass-panel">
    <div class="login-brand">
      <span class="brand-logo">TinyPage</span>
    </div>
    <div class="login-subtitle">管理后台登录</div>
    $error_msg
    <form method="post" action="/login" class="login-form">
      <input type="hidden" name="csrf_token" value="$csrf_token">
      <div class="input-group">
        <input type="text" id="username" name="username" required autocomplete="username" autofocus placeholder=" ">
        <label for="username">用户名</label>
      </div>
      <div class="input-group">
        <input type="password" id="password" name="password" required autocomplete="current-password" placeholder=" ">
        <label for="password">密码</label>
      </div>
      <button type="submit" class="btn-primary btn-glow">登录</button>
    </form>
    <div class="login-footer">所有登录尝试已记录审计日志</div>
  </div>
</div>
<script src="/admin.js"></script>
</body>
</html>
"""

# base.html 只用于**防漂移核对**（本卡不产出它的 WLWL 常量，见文件头「未交付」）。
T_BASE = """<!DOCTYPE html>
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

TEMPLATES = {
    'base.html': T_BASE,
    'dashboard.html': T_DASHBOARD,
    'article_form.html': T_ARTICLE_FORM,
    'page_form.html': T_PAGE_FORM,
    'pages_dashboard.html': T_PAGES_DASHBOARD,
    'theme_selector.html': T_THEME_SELECTOR,
    'login.html': T_LOGIN,
}


def check_templates():
    """生成期漂移守卫：模板正文必须与磁盘逐字一致，且文件清单不多不少。"""
    on_disk = sorted(n for n in os.listdir(TEMPLATES_DIR) if n.endswith('.html'))
    if on_disk != sorted(TEMPLATES):
        raise SystemExit(
            'admin_templates/ 的文件清单变了：磁盘=%r / 生成器=%r\n'
            '  ⇒ 上游新增/删除了模板，本生成器必须同步。'
            % (on_disk, sorted(TEMPLATES)))
    for name in sorted(TEMPLATES):
        path = os.path.join(TEMPLATES_DIR, name)
        # ⚠ 用 read_text 的**默认**换行处理（CRLF/孤立 CR → LF）：
        #   templates.py:23 的 path.read_text(encoding="utf-8") 就是这个口径，
        #   即「Template 实际收到的字符串」。
        with open(path, encoding='utf-8') as f:
            got = f.read()
        want = TEMPLATES[name]
        if got != want:
            i = 0
            while i < min(len(got), len(want)) and got[i] == want[i]:
                i += 1
            raise SystemExit(
                '%s 与生成器里的副本不一致（首个差异在偏移 %d）\n'
                '  磁盘：%r\n  生成器：%r\n  len: 磁盘=%d / 生成器=%d'
                % (name, i, got[max(0, i - 40):i + 40], want[max(0, i - 40):i + 40],
                   len(got), len(want)))


def main():
    check_templates()

    src = []
    A = src.append
    A('// tp/lib/admin_views.wll —— admin 视图层（卡 S4-6）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_admin_views.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树 tinypage/admin/）：')
    A('//   DASHBOARD_VIEW(opts)       == views.py:14   dashboard_view')
    A('//   ARTICLE_FORM_VIEW(opts)    == views.py:90   article_form_view')
    A('//   PAGE_FORM_VIEW(opts)       == views.py:162  page_form_view')
    A('//   PAGES_DASHBOARD_VIEW(opts) == views.py:213  pages_dashboard_view')
    A('//   THEME_SELECTOR_VIEW(opts)  == views.py:239  theme_selector_view')
    A('//   LOGIN_VIEW(opts)           == views.py:275  login_view')
    A('//   AI_PANEL(opts)             == views.py:291  _build_ai_panel')
    A('//   NAV_HTML(opts)             == templates.py:35 build_nav_html')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/admin_views_baseline.json')
    A('//   （由 tp/test/gen_admin_views_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ 模板替换的口径是 safe_substitute（templates.py:32），**不是** substitute：')
    A('//   缺键 ⇒ 原样保留占位符。直接复用 ./template.wll 的 SAFE_SUBSTITUTE。')
    A('//')
    A('// ⚠ 模板正文里的 `$var` 是**要交给 SAFE_SUBSTITUTE 的占位符**，')
    A('//   在 WLWL 源码里必须写成 `\\$var`（README #32：字面量里的 `$x` 是插值）。')
    A('//   实测 `"\\$a"` ⇒ `$a`、`"\\${b}"` ⇒ `${b}`、`"\\$\\$"` ⇒ `$$`。')
    A('//')
    A('// ⚠ escape 只照 views.py 的调用点做：`rows` / `nav_html` / `datalist` /')
    A('//   `ai_panel` / `file_input` / `theme_cards` 等是**已构造好的 HTML 片段**，')
    A('//   一律原样代入（全 escape 会把编辑器与表单弄坏）。')
    A('//')
    A('// ⚠ 顶层名全部加 `AV_` 前缀（README #52：顶层绑定跨模块共享，且诊断行号会错标）；')
    A('//   只有 8 个契约导出名不加前缀（已核实全仓无同名顶层绑定）。')
    A('')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("wlwl:std.text", ["TO_INT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_TEST"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('IMPORT("./template.wll", ["SAFE_SUBSTITUTE"]);')
    A('IMPORT("./sort_util.wll", ["SORT_STRINGS"]);')
    A('')

    # ── 模板常量 ─────────────────────────────────────────────────
    A('// ── 模板正文（逐字来自 admin_templates/*.html，生成期已与磁盘比对）──')
    A('// ⚠ 每个 `$` 都是 `\\$`：它们是 SAFE_SUBSTITUTE 的占位符，不是 WLWL 插值。')
    for name, key in (('dashboard.html', 'AV_T_DASHBOARD'),
                      ('article_form.html', 'AV_T_ARTICLE_FORM'),
                      ('page_form.html', 'AV_T_PAGE_FORM'),
                      ('pages_dashboard.html', 'AV_T_PAGES_DASHBOARD'),
                      ('theme_selector.html', 'AV_T_THEME_SELECTOR'),
                      ('login.html', 'AV_T_LOGIN')):
        A('// %s' % name)
        A('LET(%s, %s);' % (key, wl_string(TEMPLATES[name])))
    A('')

    # ── 导航图标表（templates.py:43-49）───────────────────────────
    A('// 图标表 —— 逐字照 templates.py:43-49（未知 icon_name ⇒ "•"）')
    icons = [('dashboard', '◈'), ('article', '+'), ('page', '◉'),
             ('pages', '☰'), ('theme', '◐')]
    expr = 'DICT()'
    for k, v in icons:
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl_string(k), wl_string(v))
    A('LET(AV_ICONS, %s);' % expr)
    A('// 合法页码的形态（只用 ASCII 数字：WLWL 正则不认 \\d，README #20）')
    A(r'LET(AV_PAGE_RE, RE("^[0-9]+\$"));')
    A('')

    # ── 小工具 ───────────────────────────────────────────────────
    src += fn('AV_S', 'd, k', [
        '// 取字符串字段：键缺失**或值为 NULL** ⇒ ""（Python 侧这些字段恒为 str）',
        '// ⚠ 不能只靠 AT_K 的缺省值：键存在但值为 NULL 时 AT_K 返回 NULL。',
        'LET(v, AT_K(d, k, ""))',
        'IF(==(TYPE(v), "NULL"), "", v)',
    ], '// 字符串字段（缺失或 NULL ⇒ ""）')

    src += fn('AV_ARR', 'd, k', [
        '// 取数组字段：键缺失**或值为 NULL** ⇒ []',
        'LET(v, AT_K(d, k, []))',
        'IF(==(TYPE(v), "NULL"), [], v)',
    ], '// 数组字段（缺失或 NULL ⇒ []）')

    src += fn('AV_JOIN', 'sep, items', [
        '// sep.join(items) —— 元素一律过 STR（Python 侧 ", ".join 只吃 str）',
        '// ⚠ 长度缓存到局部变量（README #21：数组的 LEN 是 O(n)，热循环里不能反复读）',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        'LET(n, LEN(items))',
        C('WHILE', '<(i, n)', [
            C('IF', '>(i, 0)', ['SET(out, +(out, sep))'], ['NULL']),
            'SET(out, +(out, STR(AT(items, i, ""))))',
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// 字符串数组连接（对齐 sep.join）')

    src += fn('AV_ATTR', 's', [
        '// security.py:39 escape_attr —— 实测与 escape_html **逐字节相同**：',
        '//   html.escape(quote=True) 已经把 " 转成 &quot;，后面那次 .replace 是空操作',
        '//   （生成期由 gen_admin_views_baseline.py 用真 Python 断言）。',
        'ESCAPE_HTML(s)',
    ], '// 属性转义（== escape_html）')

    src += fn('AV_PAGE', 'v', [
        '// 对齐 views.py:17-20：page = max(1, int(qs["page"][0]))，非法 ⇒ 1',
        '// ⚠ TO_INT 失败返 ERR ⇒ 不能先绑定（README #25）⇒ 照 http_client_tls.wll:51',
        '//   的既有形态：IS_ERR(...) 判别 + 分支里再算一次。',
        'LET(p, IF(!=(TYPE(v), "STRING"), IF(==(TYPE(v), "INTEGER"), v, 1), '
        'IF(RE_TEST(AV_PAGE_RE, v), IF(IS_ERR(TO_INT(v)), 1, TO_INT(v)), 1)))',
        'IF(<(p, 1), 1, p)',
    ], '// 页码归一化（非法/越界 ⇒ 1）')

    src += fn('AV_CATS', 'arts', [
        '// views.py:133 sorted({a.category for a in all_arts if a.category})',
        '// ① 去重（保持首次出现序）② 再排序（SORT_STRINGS == Python sorted，码点序稳定）',
        'LET MUT(out, [])',
        'LET MUT(i, 0)',
        'LET(n, LEN(arts))',
        C('WHILE', '<(i, n)', [
            'LET(c, AV_S(AT(arts, i, DICT()), "category"))',
            C('IF', '&&(!=(c, ""), !CONTAINS(out, c))',
              ['SET(out, PUSH(out, c))'], ['NULL']),
            'SET(i, +(i, 1))',
        ]),
        'SORT_STRINGS(out)',
    ], '// 分类去重 + 排序（对齐 sorted({…})）')

    src += fn('AV_OPTIONS', 'cats', [
        '// views.py:136 "\\n".join(f\'<option value="{escape_attr(c)}">\')',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        'LET(n, LEN(cats))',
        C('WHILE', '<(i, n)', [
            C('IF', '>(i, 0)', ['SET(out, +(out, "\\n"))'], ['NULL']),
            'SET(out, +(out, ' + E('<option value="', R('AV_ATTR(AT(cats, i, ""))'), '">') + '))',
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// datalist 的 <option> 行（换行分隔）')

    # ── dashboard 的行片段 ───────────────────────────────────────
    # views.py:43-55 的 translate 表单
    src += fn('AV_TRANSLATE', 'art, csrf', [
        '// views.py:43-56（⚠ 缩进逐字节照抄：6 空格 input / 8 空格 option；csrf 走 escape_attr）',
        E(
            '<form method="post" action="/translate" style="display:inline;">\n'
            '      <input type="hidden" name="csrf_token" value="', R('AV_ATTR(csrf)'), '">\n'
            '      <input type="hidden" name="file" value="', R('AV_ATTR(AV_S(art, "file"))'), '">\n'
            '      <select name="lang" onchange="if(this.value)this.form.submit()"\n'
            '              style="padding:0.25rem 0.5rem;font-size:0.8rem;border-radius:var(--a-radius-sm);\n'
            '                     background:var(--a-surface);color:var(--a-text);border:1px solid var(--a-border);">\n'
            '        <option value="">翻译▼</option>\n'
            '        <option value="en">English</option>\n'
            '        <option value="ja">日本語</option>\n'
            '      </select>\n'
            '    </form>'),
    ], '// 翻译表单（views.py:43）')

    src += fn('AV_ROW', 'art, csrf, ai_on', [
        '// views.py:32-68 的一行 —— 逐字节照抄（含 2/4/6 空格缩进与行尾换行）',
        'LET(safe_title, ESCAPE_HTML(SUB(AV_S(art, "title"), 0, 80)))',
        'LET(tags, AV_ARR(art, "tag_list"))',
        '// views.py:34-37：标签整体进一个 <span class=\'tag\'>（单引号形态照抄）',
        'LET(tags_display, IF(==(LEN(tags), 0), "", '
        + E("<span class='tag'>", R('ESCAPE_HTML(AV_JOIN(", ", tags))'), '</span>') + '))',
        'LET(is_draft, AT_K(art, "is_draft", FALSE))',
        'LET(draft_label, IF(is_draft, ' + wl_string('<span class="draft-badge">草稿</span>') + ', ""))',
        'LET(cat, AV_S(art, "category"))',
        '// views.py:39-42：分类标记（不是属性位置，用 escape_html）',
        'LET(cat_display, IF(==(cat, ""), "", ' + E(
            '<span style="color:var(--a-text-dim);font-size:0.8rem;margin-left:0.5rem;">[',
            R('ESCAPE_HTML(cat)'), ']</span>') + '))',        '// views.py:55：cfg.ai_enabled and cfg.ai_api_key —— 两个都要真',
        'LET(translate_html, IF(ai_on, AV_TRANSLATE(art, csrf), ""))',
        '// views.py:57：草稿行加内联底色（注意是**单引号**属性，照抄）',
        'LET(row_style, IF(is_draft, ' + wl_string(" style='background:var(--a-surface-elevated);'") + ', ""))',
        E(
            '<tr', R('row_style'), '>\n'
            '  <td><a href="/edit?file=', R('AV_ATTR(AV_S(art, "file"))'), '">', R('safe_title'),
            '</a>', R('cat_display'), R('draft_label'), ' ', R('tags_display'), '</td>\n'
            '  <td>', R('ESCAPE_HTML(AV_S(art, "date"))'), '</td>\n'
            '  <td>\n'
            '    <form method="post" action="/delete" hx-post="/delete" hx-target="closest tr" '
            'hx-swap="outerHTML swap:0.3s" hx-confirm="删除不可恢复，确定？" style="display:inline;">\n'
            '      <input type="hidden" name="csrf_token" value="', R('AV_ATTR(csrf)'), '">\n'
            '      <input type="hidden" name="file" value="', R('AV_ATTR(AV_S(art, "file"))'), '">\n'
            "      <button type=\"submit\" class=\"btn-danger btn-sm\" "
            "onclick=\"return confirm('删除不可恢复，确定？')\">删除</button>\n"
            '    </form>\n'
            '    ', R('translate_html'), '\n'
            '  </td>\n'
            '</tr>'),
    ], '// 文章列表的一行（views.py:32）')

    src += fn('AV_PAGES_ROW', 'pg, csrf', [
        '// views.py:218-229 —— ⚠ safe_title 的 or 对**空串**也回落文件名',
        'LET(t80, SUB(AV_S(pg, "title"), 0, 80))',
        'LET(safe_title, ESCAPE_HTML(IF(==(t80, ""), AV_S(pg, "file"), t80)))',
        E(
            '<tr>\n  <td><a href="/edit-page?file=', R('AV_ATTR(AV_S(pg, "file"))'), '">',
            R('safe_title'), '</a></td>\n'
            '  <td>/standalone/', R('AV_ATTR(AV_S(pg, "file"))'), '</td>\n'
            '  <td>\n'
            '    <form method="post" action="/delete-page" hx-post="/delete-page" '
            'hx-target="closest tr" hx-swap="outerHTML swap:0.3s" '
            'hx-confirm="删除不可恢复，确定？" style="display:inline;">\n'
            '      <input type="hidden" name="csrf_token" value="', R('AV_ATTR(csrf)'), '">\n'
            '      <input type="hidden" name="file" value="', R('AV_ATTR(AV_S(pg, "file"))'), '">\n'
            "      <button type=\"submit\" class=\"btn-danger btn-sm\" "
            "onclick=\"return confirm('删除不可恢复，确定？')\">删除</button>\n"
            '    </form>\n'
            '  </td>\n'
            '</tr>'),
    ], '// 独立页面列表的一行（views.py:218）')

    src += fn('AV_THEME_CARD', 'th, csrf, current_theme', [
        '// views.py:248-265 —— 逐字节照抄（含 2/4 空格缩进与 {disabled} 前的空格）',
        'LET(name, AV_S(th, "name"))',
        'LET(is_active, ==(name, current_theme))',
        'LET(active_cls, IF(is_active, " active", ""))',
        'LET(default_badge, IF(is_active, ' + wl_string(' <span class="draft-badge">当前</span>') + ', ""))',
        '// views.py:253：layouts 为空/缺失 ⇒ "blog"',
        'LET(lk, AV_ARR(th, "layouts"))',
        'LET(layouts, IF(==(LEN(lk), 0), "blog", AV_JOIN(", ", lk)))',
        '// views.py:254：描述 escape',
        'LET(desc, ESCAPE_HTML(AV_S(th, "description")))',
        'LET(disabled, IF(is_active, ' + wl_string('disabled style="opacity:0.5;"') + ', ""))',
        '// views.py:257：theme.get("display_name", theme["name"]) —— 只在**缺键**时回落',
        'LET(disp, AT_K(th, "display_name", name))',
        E(
            '<div class="theme-card', R('active_cls'), '">\n'
            '  <h3>', R('ESCAPE_HTML(disp)'), R('default_badge'), '</h3>\n'
            '  <p>', R('desc'), '</p>\n'
            '  <p class="theme-meta">布局: ', R('layouts'), '</p>\n'
            '  <form method="post" action="/set-theme" style="margin:0;">\n'
            '    <input type="hidden" name="csrf_token" value="', R('AV_ATTR(csrf)'), '">\n'
            '    <input type="hidden" name="theme" value="', R('AV_ATTR(name)'), '">\n'
            '    <button type="submit" class="btn-primary btn-sm" ', R('disabled'), '>选择</button>\n'
            '  </form>\n'
            '</div>'),
    ], '// 主题卡片（views.py:248）')

    src += fn('AV_AI_PANEL', 'cfg, _csrf, suggest_tags', [
        '// views.py:291-306 —— cfg.ai_enabled and cfg.ai_api_key 都为真才输出',
        '// ⚠ csrf 参数 Python 接了但**正文里没用到** ⇒ 这里同样不读（不自己发挥）；',
        '//   形参名写 `_csrf` 只为消掉 W0011（未使用参数），调用点仍是位置传参。',
        'LET(tags_btn, IF(suggest_tags, ' + wl_string(
            '<button type="button" class="ai-btn" onclick="aiSuggestTags()">推荐标签</button>') + ', ""))',
        'IF(!(&&(AT_K(cfg, "ai_enabled", FALSE), !=(AT_K(cfg, "ai_api_key", ""), ""))), "", ' + E(
            '<div id="ai-panel" class="ai-panel">\n'
            '  <div class="ai-panel-header">\n'
            '    <span class="ai-label">AI 助手</span>\n'
            '    <button type="button" class="ai-btn" onclick="aiComplete()">续写</button>\n'
            '    <button type="button" class="ai-btn" onclick="aiPolish()">润色</button>\n'
            "    <button type=\"button\" class=\"ai-btn\" onclick=\"aiTranslate('en')\">译英</button>\n"
            "    <button type=\"button\" class=\"ai-btn\" onclick=\"aiTranslate('ja')\">译日</button>\n"
            '    ', R('tags_btn'), '\n'
            '    <span id="ai-status"></span>\n'
            '  </div>\n'
            '</div>') + ')',
    ], '// AI 助手面板（views.py:291）')

    # ── DASHBOARD_VIEW ──────────────────────────────────────────
    dash = [
        '// opts 键：csrf_token / articles / standalones / page / cfg',
        '//   cfg：page_size / ai_enabled / ai_api_key',
        '//   articles：ARRAY[DICT{title, file, date, category, tag_list, is_draft}]',
        'LET(cfg, AT_K(opts, "cfg", DICT()))',
        'LET(csrf, AV_S(opts, "csrf_token"))',
        'LET(arts, AV_ARR(opts, "articles"))',
        'LET(standalones, AV_ARR(opts, "standalones"))',
        'LET(pg, AV_PAGE(AT_K(opts, "page", 1)))',
        'LET(ps, AT_K(cfg, "page_size", 10))',
        'LET(total, LEN(arts))',
        '// views.py:24 pages = max(1, (total + page_size - 1) // page_size)',
        'LET(cnt_pages, IF(<(total, 1), 1, /(-(+(total, ps), 1), ps)))',
        '// views.py:25 start_idx = (page - 1) * page_size',
        'LET(start_idx, *(-(pg, 1), ps))',
        '// views.py:55 cfg.ai_enabled and cfg.ai_api_key',
        'LET(ai_on, &&(AT_K(cfg, "ai_enabled", FALSE), !=(AT_K(cfg, "ai_api_key", ""), "")))',
        '// views.py:28 draft_count = sum(1 for a in arts if a.is_draft)',
        'LET MUT(draft_count, 0)',
        'LET MUT(k, 0)',
        C('WHILE', '<(k, total)', [
            C('IF', 'AT_K(AT(arts, k, DICT()), "is_draft", FALSE)',
              ['SET(draft_count, +(draft_count, 1))'], ['NULL']),
            'SET(k, +(k, 1))',
        ]),
        '// views.py:29 page_count = len(list_standalones(...))',
        'LET(page_count, LEN(standalones))',
        '// views.py:26 page_arts = arts[start_idx : start_idx + page_size]',
        '// ⚠ 越界不切片：用下标上界（README #21 下标 O(1)、LEN 已缓存）',
        'LET MUT(rows, "")',
        'LET MUT(i, start_idx)',
        'LET(end_idx, +(start_idx, ps))',
        C('WHILE', '&&(<(i, end_idx), <(i, total))', [
            'SET(rows, +(rows, AV_ROW(AT(arts, i, DICT()), csrf, ai_on)))',
            'SET(i, +(i, 1))',
        ]),
        '// views.py:70-75 分页导航',
        'LET MUT(navs, [])',
        'IF(>(pg, 1), (SET(navs, PUSH(navs, ' + E(
            '<a href="/?page=', R('STR(-(pg, 1))'), '">← 上一页</a>') + '))), NULL)',
        'IF(<(pg, cnt_pages), (SET(navs, PUSH(navs, ' + E(
            '<a href="/?page=', R('STR(+(pg, 1))'), '">下一页 →</a>') + '))), NULL)',
        'LET(nav_html, IF(==(LEN(navs), 0), "", ' + E(
            '<div class="nav-links">', R('AV_JOIN(" ", navs)'), '</div>') + '))',
        '// views.py:77-87 的渲染：rows / nav_html 是**片段**（不 escape）',
        'LET MUT(m, DICT())',
        'SET(m, INDEX_SET(m, "total", STR(total)))',
        'SET(m, INDEX_SET(m, "draft_count", STR(draft_count)))',
        'SET(m, INDEX_SET(m, "page_count", STR(page_count)))',
        'SET(m, INDEX_SET(m, "csrf_token", csrf))',
        'SET(m, INDEX_SET(m, "rows", rows))',
        'SET(m, INDEX_SET(m, "nav_html", nav_html))',
        'SET(m, INDEX_SET(m, "page", STR(pg)))',
        'SET(m, INDEX_SET(m, "pages", STR(cnt_pages)))',
        'SAFE_SUBSTITUTE(AV_T_DASHBOARD, m)',
    ]
    src += fn('DASHBOARD_VIEW', 'opts', dash,
              '// 仪表盘（views.py:14 dashboard_view）')

    # ── ARTICLE_FORM_VIEW ───────────────────────────────────────
    af = [
        '// opts 键：csrf_token / is_edit / now / articles / content / article / cfg',
        '//   cfg：max_title_length / max_content_length / ai_enabled / ai_api_key',
        '//   article：DICT{title, date, category, tags, is_published, is_draft, file}',
        'LET(cfg, AT_K(opts, "cfg", DICT()))',
        'LET(csrf, AV_S(opts, "csrf_token"))',
        'LET(is_edit, AT_K(opts, "is_edit", FALSE))',
        'LET(raw_art, AT_K(opts, "article", NULL))',
        'LET(has_art, ==(TYPE(raw_art), "DICT"))',
        'LET(art, IF(has_art, raw_art, DICT()))',
        '// views.py:101 的 not-found 分支（本模块由「article 不是 DICT」承载）',
        'LET MUT(heading, "")',
        'LET MUT(form_action, "")',
        'LET MUT(file_input, "")',
        'LET MUT(title_val, "")',
        'LET MUT(date_val, "")',
        'LET MUT(cat_val, "")',
        'LET MUT(tags_val, "")',
        'LET MUT(pub_selected, "")',
        'LET MUT(draft_selected, "")',
        'LET MUT(content_val, "")',
        'LET MUT(submit_label, "")',
        C('IF', '&&(is_edit, !has_art)', ['"<p>Article not found</p>"'], [
            C('IF', 'is_edit', [
                '// views.py:107-117',
                'SET(heading, ' + E('编辑: ', R('ESCAPE_HTML(AV_S(art, "title"))')) + ')',
                'SET(form_action, "/save")',
                'SET(file_input, ' + E('<input type="hidden" name="file" value="',
                                       R('AV_ATTR(AV_S(art, "file"))'), '">') + ')',
                'SET(title_val, AV_ATTR(AV_S(art, "title")))',
                'SET(date_val, ESCAPE_HTML(AV_S(art, "date")))',
                'SET(cat_val, AV_ATTR(AV_S(art, "category")))',
                'SET(tags_val, AV_ATTR(AV_S(art, "tags")))',
                'SET(pub_selected, IF(AT_K(art, "is_published", FALSE), " selected", ""))',
                'SET(draft_selected, IF(AT_K(art, "is_draft", FALSE), " selected", ""))',
                'SET(content_val, ESCAPE_HTML(AV_S(opts, "content")))',
                'SET(submit_label, "保存更改")',
            ], [
                '// views.py:119-130（⚠ Python 用 datetime.now()，本模块取显式键 now）',
                'SET(heading, "新建文章")',
                'SET(form_action, "/create")',
                'SET(file_input, "")',
                'SET(title_val, "")',
                'SET(date_val, AV_S(opts, "now"))',
                'SET(cat_val, "")',
                'SET(tags_val, "")',
                'SET(pub_selected, " selected")',
                'SET(draft_selected, "")',
                'SET(content_val, "")',
                'SET(submit_label, "发布")',
            ]),
            '// views.py:132-137 分类 datalist（跨全部文章，含草稿）',
            'LET(cats, AV_CATS(AV_ARR(opts, "articles")))',
            'LET(datalist, IF(==(LEN(cats), 0), "", ' + E(
                '<datalist id="category-list">', R('AV_OPTIONS(cats)'), '</datalist>') + '))',
            '// views.py:139 _build_ai_panel(cfg, csrf_token, suggest_tags=True)',
            'LET(ai_panel, AV_AI_PANEL(cfg, csrf, TRUE))',
            'LET MUT(m, DICT())',
            'SET(m, INDEX_SET(m, "heading", heading))',
            'SET(m, INDEX_SET(m, "form_action", form_action))',
            'SET(m, INDEX_SET(m, "csrf_token", csrf))',
            'SET(m, INDEX_SET(m, "file_input", file_input))',
            'SET(m, INDEX_SET(m, "title", title_val))',
            'SET(m, INDEX_SET(m, "date", date_val))',
            'SET(m, INDEX_SET(m, "category", cat_val))',
            'SET(m, INDEX_SET(m, "tags", tags_val))',
            'SET(m, INDEX_SET(m, "datalist", datalist))',
            'SET(m, INDEX_SET(m, "pub_selected", pub_selected))',
            'SET(m, INDEX_SET(m, "draft_selected", draft_selected))',
            'SET(m, INDEX_SET(m, "ai_panel", ai_panel))',
            'SET(m, INDEX_SET(m, "max_title_length", STR(AT_K(cfg, "max_title_length", 200))))',
            'SET(m, INDEX_SET(m, "max_content_length", STR(AT_K(cfg, "max_content_length", 50000))))',
            'SET(m, INDEX_SET(m, "content", content_val))',
            'SET(m, INDEX_SET(m, "submit_label", submit_label))',
            'SAFE_SUBSTITUTE(AV_T_ARTICLE_FORM, m)',
        ]),
    ]
    src += fn('ARTICLE_FORM_VIEW', 'opts', af,
              '// 文章表单（views.py:90 article_form_view）')

    # ── PAGE_FORM_VIEW ──────────────────────────────────────────
    pf = [
        '// opts 键：csrf_token / is_edit / page / content / cfg',
        '//   page：DICT{title, slug, file}；cfg：max_title_length / max_content_length',
        '//        / ai_enabled / ai_api_key',
        'LET(cfg, AT_K(opts, "cfg", DICT()))',
        'LET(csrf, AV_S(opts, "csrf_token"))',
        'LET(is_edit, AT_K(opts, "is_edit", FALSE))',
        'LET(raw_pg, AT_K(opts, "page", NULL))',
        'LET(has_pg, ==(TYPE(raw_pg), "DICT"))',
        'LET(pg, IF(has_pg, raw_pg, DICT()))',
        '// views.py:173 的 not-found 分支',
        'LET MUT(heading, "")',
        'LET MUT(form_action, "")',
        'LET MUT(file_input, "")',
        'LET MUT(title_val, "")',
        'LET MUT(slug_val, "")',
        'LET MUT(content_val, "")',
        'LET MUT(submit_label, "")',
        C('IF', '&&(is_edit, !has_pg)', ['"<p>Page not found</p>"'], [
            C('IF', 'is_edit', [
                '// views.py:179-185',
                'SET(heading, ' + E('编辑: ', R('ESCAPE_HTML(AV_S(pg, "title"))')) + ')',
                'SET(form_action, "/save-page")',
                'SET(file_input, ' + E('<input type="hidden" name="file" value="',
                                       R('AV_ATTR(AV_S(pg, "file"))'), '">') + ')',
                'SET(title_val, AV_ATTR(AV_S(pg, "title")))',
                'SET(slug_val, AV_ATTR(AV_S(pg, "slug")))',
                'SET(content_val, ESCAPE_HTML(AV_S(opts, "content")))',
                'SET(submit_label, "保存更改")',
            ], [
                '// views.py:186-193',
                'SET(heading, "新建独立页面")',
                'SET(form_action, "/create-page")',
                'SET(file_input, "")',
                'SET(title_val, "")',
                'SET(slug_val, "")',
                'SET(content_val, "")',
                'SET(submit_label, "创建")',
            ]),
            '// views.py:195 _build_ai_panel(cfg, csrf_token, suggest_tags=False)',
            'LET(ai_panel, AV_AI_PANEL(cfg, csrf, FALSE))',
            'LET MUT(m, DICT())',
            'SET(m, INDEX_SET(m, "heading", heading))',
            'SET(m, INDEX_SET(m, "form_action", form_action))',
            'SET(m, INDEX_SET(m, "csrf_token", csrf))',
            'SET(m, INDEX_SET(m, "file_input", file_input))',
            'SET(m, INDEX_SET(m, "title", title_val))',
            'SET(m, INDEX_SET(m, "slug", slug_val))',
            'SET(m, INDEX_SET(m, "ai_panel", ai_panel))',
            'SET(m, INDEX_SET(m, "max_title_length", STR(AT_K(cfg, "max_title_length", 200))))',
            'SET(m, INDEX_SET(m, "max_content_length", STR(AT_K(cfg, "max_content_length", 50000))))',
            'SET(m, INDEX_SET(m, "content", content_val))',
            'SET(m, INDEX_SET(m, "submit_label", submit_label))',
            'SAFE_SUBSTITUTE(AV_T_PAGE_FORM, m)',
        ]),
    ]
    src += fn('PAGE_FORM_VIEW', 'opts', pf,
              '// 独立页面表单（views.py:162 page_form_view）')

    # ── PAGES_DASHBOARD_VIEW ────────────────────────────────────
    pd = [
        '// opts 键：csrf_token / pages（ARRAY[DICT{title, file}]）',
        'LET(csrf, AV_S(opts, "csrf_token"))',
        'LET(pages, AV_ARR(opts, "pages"))',
        'LET(n, LEN(pages))',
        'LET MUT(rows, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, n)', [
            'SET(rows, +(rows, AV_PAGES_ROW(AT(pages, i, DICT()), csrf)))',
            'SET(i, +(i, 1))',
        ]),
        'LET MUT(m, DICT())',
        'SET(m, INDEX_SET(m, "csrf_token", csrf))',
        'SET(m, INDEX_SET(m, "rows", rows))',
        'SET(m, INDEX_SET(m, "total", STR(n)))',
        'SAFE_SUBSTITUTE(AV_T_PAGES_DASHBOARD, m)',
    ]
    src += fn('PAGES_DASHBOARD_VIEW', 'opts', pd,
              '// 独立页面列表（views.py:213 pages_dashboard_view）')

    # ── THEME_SELECTOR_VIEW ─────────────────────────────────────
    ts = [
        '// opts 键：csrf_token / themes / current_theme',
        '//   themes：ARRAY[DICT{name, display_name?, description?, layouts?}]',
        'LET(csrf, AV_S(opts, "csrf_token"))',
        'LET(themes, AV_ARR(opts, "themes"))',
        'LET(current, AV_S(opts, "current_theme"))',
        'LET(n, LEN(themes))',
        'LET MUT(cards, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, n)', [
            'SET(cards, +(cards, AV_THEME_CARD(AT(themes, i, DICT()), csrf, current)))',
            'SET(i, +(i, 1))',
        ]),
        'LET MUT(m, DICT())',
        'SET(m, INDEX_SET(m, "csrf_token", csrf))',
        '// views.py:270 current_theme=escape_html(current_theme)',
        'SET(m, INDEX_SET(m, "current_theme", ESCAPE_HTML(current)))',
        'SET(m, INDEX_SET(m, "theme_cards", cards))',
        'SAFE_SUBSTITUTE(AV_T_THEME_SELECTOR, m)',
    ]
    src += fn('THEME_SELECTOR_VIEW', 'opts', ts,
              '// 主题选择（views.py:239 theme_selector_view）')

    # ── LOGIN_VIEW ──────────────────────────────────────────────
    lv = [
        '// opts 键：csrf_token / error / locked（"1" 表示命中，照 qs 的取值口径）',
        'LET(csrf, AV_S(opts, "csrf_token"))',
        'LET MUT(error_msg, "")',
        '// views.py:279-280（先判 error）',
        C('IF', '==(AV_S(opts, "error"), "1")', [
            'SET(error_msg, ' + wl_string('<div class="login-error">用户名或密码错误</div>') + ')',
        ], ['NULL']),
        '// views.py:281-282（后判 locked ⇒ **覆盖** error，顺序照抄）',
        C('IF', '==(AV_S(opts, "locked"), "1")', [
            'SET(error_msg, ' + wl_string('<div class="login-error">登录尝试过多，请稍后再试</div>') + ')',
        ], ['NULL']),
        'LET MUT(m, DICT())',
        'SET(m, INDEX_SET(m, "csrf_token", csrf))',
        'SET(m, INDEX_SET(m, "error_msg", error_msg))',
        'SAFE_SUBSTITUTE(AV_T_LOGIN, m)',
    ]
    src += fn('LOGIN_VIEW', 'opts', lv,
              '// 登录页（views.py:275 login_view）')

    # ── AI_PANEL / NAV_HTML（薄包装，保持与 Python 的签名同形）──────
    src += fn('AI_PANEL', 'opts', [
        '// opts 键：cfg / csrf_token / suggest_tags（Python 缺省 True）',
        'AV_AI_PANEL(AT_K(opts, "cfg", DICT()), AV_S(opts, "csrf_token"), '
        'AT_K(opts, "suggest_tags", TRUE))',
    ], '// AI 面板入口（views.py:291 _build_ai_panel）')

    nav = [
        '// opts 键：nav_items（ARRAY[ARRAY[href, label, icon_name]]）/ current_path',
        'LET(items, AV_ARR(opts, "nav_items"))',
        'LET(cur, AV_S(opts, "current_path"))',
        'LET(n, LEN(items))',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, n)', [
            'LET(it, AT(items, i, []))',
            'LET(href, STR(AT(it, 0, "")))',
            'LET(label, STR(AT(it, 1, "")))',
            '// templates.py:51 icon = icons.get(icon_name, "•")',
            'LET(icon, AT_K(AV_ICONS, STR(AT(it, 2, "")), "•"))',
            '// templates.py:52-53 高亮：href == current_path（**逐字**比较）',
            'LET(is_cur, ==(href, cur))',
            'LET(active, IF(is_cur, ' + wl_string(' aria-current="page"') + ', ""))',
            'LET(active_cls, IF(is_cur, " nav-active", ""))',
            C('IF', '>(i, 0)', ['SET(out, +(out, "\\n"))'], ['NULL']),
            'SET(out, +(out, ' + E(
                '<a href="', R('href'), '" class="nav-item', R('active_cls'), '"', R('active'),
                '><span class="nav-icon">', R('icon'), '</span><span class="nav-label">',
                R('label'), '</span></a>') + '))',
            'SET(i, +(i, 1))',
        ]),
        'out',
    ]
    src += fn('NAV_HTML', 'opts', nav,
              '// 侧边导航（templates.py:35 build_nav_html）')

    A('EXPORT(["DASHBOARD_VIEW", "ARTICLE_FORM_VIEW", "PAGE_FORM_VIEW", '
      '"PAGES_DASHBOARD_VIEW", "THEME_SELECTOR_VIEW", "LOGIN_VIEW", '
      '"AI_PANEL", "NAV_HTML"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
