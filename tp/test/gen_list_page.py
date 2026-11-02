"""生成 tp/lib/list_page.wll —— 列表页 / 分类页 / 搜索页（卡 S2-4）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出；
WLWL 的括号诊断只说「expected ')' got X」，不告诉你缺了几层）。

**对齐目标（真 Python 源码树）**：
  · `LIST_PAGE(opts)`     == generator.py:298 `generate_list_page`
  · `CATEGORY_PAGE(opts)` == generator.py:484 `generate_category_page`
  · `SEARCH_PAGE(opts)`   == generator.py:389 `generate_search_page`

**逐字节对照基准**：tp/test/fixtures/list_page_baseline.json
    （由 tp/test/gen_list_page_baseline.py 用**真 Python** 生成）

**接口形态**：三者都收一个 DICT（键名与 Python 的具名参数同名、可缺省）——
WLWL 没有关键字参数与默认参数。

**复用的东西（不重写，避免漂移）**：
  · `page_common.wll::COMMON_CONTEXT` —— 页面公共上下文（含 nav / 暗色 / PWA …）
  · `template.wll::RENDER_SKELETON`   —— 整页骨架（string.Template 复刻）
  · `esc.wll::ESCAPE_HTML`            —— html.escape(quote=True)
  · 排序：本卡**不排序** —— `generate_list_page` 拿到的是调用方已排好序的
    `articles`（generator.py:658 的 `articles[start:start+page_size]`）⇒ 这里
    若擅自排序就会与真 Python 不一致。同理 `page_size` 也不在本模块里，
    分页由调用方构造 `page_info`。

**本机实测得到的语义点（都写进代码注释）**：
  ① `escape_attr(x)` **等价于** `escape_html(x)`：Python 的
     `html.escape(s, quote=True)` 已把 `"` 变成 `&quot;`，`escape_attr` 的
     `.replace('"', "&quot;")` 是空操作 ⇒ `datetime="{escape_attr(art.date)}"`
     直接复用 `ESCAPE_HTML`。
  ② 摘要的处理**顺序**是「先 escape，再删字面 `<p>`/`</p>`」
     （generator.py:315）⇒ escape 之后串里已不可能出现 `<p>` ⇒ 那两条 replace
     实际是**空操作**；但顺序照抄，免得日后 Python 侧改动时我们悄悄漂移。
     正因如此，正则必须**匹配字节**：`[<]p[>]`（裸 `<p>` 也能用，
     但本仓库约定字面点/尖括号一律用字符类，见 tp/README.md 坑 26）。
  ③ `if art.tags:` 判的是**原串**非空（generator.py:317），而 tag 项来自
     `tag_list`（split + strip + 过滤空）⇒ `tags=" , "` 时 `art.tags` 为真、
     `tag_list` 为空 ⇒ 输出**空的** `<div class="post-tags"></div>`。
  ④ `art.title[:80]` 用 `SUB(s, 0, 80)`（实测短串会自动截到串长；LEN/SUB 是
     **码点**口径，与 Python str 索引一致）。
  ⑤ 搜索页把 `vt_meta` **显式**传成 `""`（generator.py:421）⇒ 即使
     `enable_view_transitions=True`，搜索页也**没有** view-transition meta。
  ⑥ `description` 在列表页/分类页是**先 escape 再交给骨架**（generator.py:370 /
     523），骨架里又 escape 一遍 ⇒ 分类名里的 `&` 会出现**两次**转义
     （`&amp;amp;`）。这是 Python 的既有行为，复刻它。

**已知差异（与真 Python 的偏差，无法在 WLWL 侧复刻）**：
  · **D1** `tag_list` 的 `t.strip()`：Python 的 `str.strip()` 按 `str.isspace()`
    剥**Unicode** 空白（NBSP U+00A0、全角空格 U+3000 都算），而 WLWL 的 `TRIM`
    实测**只剥 ASCII 空白**（`TRIM("\\u00a0a\\u00a0")` 原样返回）。
    ⇒ `tags="a, \\u00a0b"` 时 Python 的 tag 是 `"b"`，WLWL 的是 `"\\u00a0b"`
    （escape 后多一个 NBSP）。夹具里**不放**这类用例（会红），差异只登记在此。

用法：python gen_list_page.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'list_page.wll')


def wl(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 白名单 `\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`；`$` 必须转义
      （WLWL 字面量里 `${...}` / `$name` 是**插值**，见 tp/README.md 坑 32）。
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


def cat(*parts):
    """把「字面串 / 表达式」混排拼成一个 WLWL `CAT(...)` 调用表达式。

    字面串走 `wl()` 转义；表达式原样嵌入（用它来插变量）。
    ⚠ 单个字面串也包一层 CAT —— 与 Python 的 f-string 逐段对应，便于核对。
    """
    args = []
    for p in parts:
        if isinstance(p, tuple):
            args.append(p[1])
        else:
            args.append(wl(p))
    return 'CAT(%s)' % ', '.join(args)


def main():
    src = []
    A = src.append
    A('// tp/lib/list_page.wll —— 列表页 / 分类页 / 搜索页（卡 S2-4）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_list_page.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树）：')
    A('//   LIST_PAGE(opts)     == generator.py:298  generate_list_page')
    A('//   CATEGORY_PAGE(opts) == generator.py:484  generate_category_page')
    A('//   SEARCH_PAGE(opts)   == generator.py:389  generate_search_page')
    A('//')
    A('// 复用的东西（不重写，避免漂移）：')
    A('//   page_common.wll::COMMON_CONTEXT / template.wll::RENDER_SKELETON /')
    A('//   esc.wll::ESCAPE_HTML')
    A('//')
    A('// ⚠ 本模块**不排序**：真 Python 的 generate_list_page 拿到的是调用方已排好序的')
    A('//   articles（generator.py:658）⇒ 这里擅自排序就与 Python 不一致。')
    A('//   （排序能力在 sort_util.wll；本模块不引用它，也不得用内建 SORT —— 二次复杂度。）')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/list_page_baseline.json')
    A('//')
    A('// 已知差异：D1 tags 的 t.strip() —— Python 剥 Unicode 空白，WLWL 的 TRIM')
    A('//   只剥 ASCII 空白（NBSP / 全角空格不被剥）⇒ 夹具里不放这类用例。')
    A('')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_REPLACE"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('IMPORT("./page_common.wll", ["COMMON_CONTEXT"]);')
    A('IMPORT("./template.wll", ["RENDER_SKELETON"]);')
    A('')

    # ── 常量 ─────────────────────────────────────────────────────
    A('// 字面 "<p>" / "</p>" 的模式 —— 用在「先 escape 再删」的空操作上（见 docstring ②）。')
    A('// ⚠ 尖括号/斜杠用字符类写，不用裸字符（本仓库约定，见 tp/README.md 坑 26）。')
    A('LET(P_OPEN_RE, RE("[<]p[>]"));')
    A('LET(P_CLOSE_RE, RE("[<][/]p[>]"));')
    A('')

    # ── SAFE_SUMMARY ─────────────────────────────────────────────
    # Python（generator.py:315 / 501）：
    #   safe_summary = escape_html(art.summary).replace("<p>", "").replace("</p>", "")
    src += fn('SAFE_SUMMARY', 's', [
        '// 对齐 Python：先 escape_html，再删字面 "<p>" / "</p>"（顺序照抄）。',
        '// ⚠ escape 之后串里已无 "<p>" ⇒ 这两条 replace 是**空操作**，',
        '//   但保留它，Python 侧一旦改序我们跟着红，而不是悄悄漂移。',
        'RE_REPLACE(P_CLOSE_RE, RE_REPLACE(P_OPEN_RE, ESCAPE_HTML(s), ""), "")',
    ], '// 摘要：escape 后删字面 <p>/</p>（对齐 generator.py:315）')

    # ── TAG_HTML ─────────────────────────────────────────────────
    # Python（generator.py:316-319）：
    #   tag_html = ""
    #   if art.tags:
    #       tags = [f'<span class="tag">{escape_html(t)}</span>' for t in art.tag_list]
    #       tag_html = f'<div class="post-tags">{" ".join(tags)}</div>'
    # tag_list == [t.strip() for t in self.tags.split(",") if t.strip()]
    src += fn('TAG_HTML', 'tags', [
        '// tags 是**原串**（逗号分隔）；tag_list 是 split + strip + 过滤空。',
        '// ⚠ 判据是**原串非空**（Python 的 `if art.tags:`）—— 不是「过滤后非空」',
        '//   ⇒ tags=" , " 时输出**空的** <div class="post-tags"></div>。',
        'LET MUT(joined, "")',
        C('FOR', 't0', 'SPLIT(tags, ",")', [
            'LET(t, TRIM(t0))',
            C('IF', '!=(t, "")', [
                # 项与项之间是单个空格（对齐 " ".join(tags)）
                C('IF', '!=(joined, "")', ['SET(joined, +(joined, " "))'], ['NULL']),
                'SET(joined, CAT(joined, "<span class=\\"tag\\">", '
                'ESCAPE_HTML(t), "</span>"))',
            ], [
                'NULL',
            ]),
        ]),
        'IF(==(tags, ""), "", CAT("<div class=\\"post-tags\\">", joined, "</div>"))',
    ], '// 标签区（对齐 generator.py:316）')

    # ── ARTICLE_ITEM ─────────────────────────────────────────────
    # Python 列表页（generator.py:313-334）与分类页（499-511）的预览块**有两处**
    # 结构差异（不是一处）：
    #   ① 列表页在 </time> 之后有一行 `    {category_badge}`（badge 空时留 4 个空格）；
    #      分类页**整行都没有**。
    #   ② 列表页在 </p> 之后有一行 `  {tag_html}`（标签区）；分类页**整行都没有**。
    #   ⇒ 用一个开关 `list_layout` 同时管这两段（其余字节完全相同）。
    item_tail_parts = [
        '  </header>\n  <p class="post-summary">',
        ('e', 'summary'),
        '</p>',
        ('e', 'tag_seg'),
        '\n  <a href="',
        ('e', 'url'),
        '" class="read-more">阅读全文 →</a>\n</article>\n',
    ]
    item_head_parts = [
        '\n<article class="post-preview">\n  <header>\n'
        '    <h2 class="post-title"><a href="',
        ('e', 'url'),
        '">',
        ('e', 'safe_title'),
        '</a></h2>\n    <time class="post-date" datetime="',
        ('e', 'safe_date'),
        '">',
        ('e', 'safe_date'),
        '</time>\n',
        ('e', 'badge_seg'),
    ]
    item_expr = cat(*(item_head_parts + item_tail_parts))

    src += fn('ARTICLE_ITEM', 'art, list_layout', [
        '// opts: art = 一篇文章的 DICT（title/date/tags/summary/category/file）',
        '//       list_layout = TRUE ⇒ 列表页版（有 category-badge 行 + 标签行）；',
        '//                     FALSE ⇒ 分类页版（两者都**没有**，其余字节相同）',
        '// ⚠ title 先截 80 码点再 escape（Python 是 escape_html(art.title[:80])）',
        'LET(safe_title, ESCAPE_HTML(SUB(AT_K(art, "title", ""), 0, 80)))',
        'LET(summary, SAFE_SUMMARY(AT_K(art, "summary", "")))',
        '// escape_attr(x) 与 escape_html(x) 等价（html.escape(quote=True) 已处理 "）',
        'LET(safe_date, ESCAPE_HTML(AT_K(art, "date", "")))',
        '// Python 的 art.url == f"/article/{art.file}"（未 escape，原样进 href）',
        'LET(url, CAT("/article/", AT_K(art, "file", "")))',
        'LET(cat0, AT_K(art, "category", ""))',
        'LET(badge, IF(==(cat0, ""), "", CAT('
        '"<span class=\\"category-badge\\">", ESCAPE_HTML(cat0), "</span>")))',
        '// ① 列表页那一行是 `    {badge}` + 换行 —— badge 为空时留下 4 个空格；',
        '//    分类页整行都没有 ⇒ list_layout 为 FALSE 时该段是空串。',
        'LET(badge_seg, IF(list_layout, CAT("    ", badge, "\\n"), ""))',
        '// ② 标签行同理：列表页 `  {tag_html}`（**空串也占那一行**），分类页没有。',
        'LET(tag_seg, IF(list_layout, CAT("\\n  ", TAG_HTML(AT_K(art, "tags", ""))), ""))',
        item_expr,
    ], '// 一篇文章的预览块（对齐 generator.py:323 / 502）')

    # ── SKELETON_OPTS ────────────────────────────────────────────
    # 三个页面函数传给 render_skeleton 的 kwargs 完全同构（只差 vt_meta / 各字段值）。
    src += fn('SKELETON_OPTS', 'ctx, cfg, pt, desc, body, vt', [
        '// 构造 RENDER_SKELETON 的 opts（对齐三个 generate_* 里的关键字实参）。',
        '// ⚠ og_html / json_ld_html / mermaid_script 三个页面都是 ""（Python 显式传',
        '//   og_html=""，另两个用默认值）⇒ 这里不设，交给 RENDER_SKELETON 的缺省。',
        'LET MUT(so, DICT())',
        'SET(so, INDEX_SET(so, "site_title", AT_K(ctx, "site_title", "")))',
        'SET(so, INDEX_SET(so, "page_title", pt))',
        'SET(so, INDEX_SET(so, "description", desc))',
        'SET(so, INDEX_SET(so, "body_content", body))',
        'SET(so, INDEX_SET(so, "theme_css", AT_K(ctx, "theme_css", "")))',
        'SET(so, INDEX_SET(so, "dark_css", AT_K(ctx, "dark_css", "")))',
        'SET(so, INDEX_SET(so, "has_dark", AT_K(ctx, "has_dark", FALSE)))',
        'SET(so, INDEX_SET(so, "nav_links", AT_K(ctx, "nav", "")))',
        'SET(so, INDEX_SET(so, "theme_toggle", AT_K(ctx, "theme_toggle", "")))',
        '// Python: footer_text=cfg.footer_text or ""（空串保持空，骨架再判一次）',
        'SET(so, INDEX_SET(so, "footer_text", AT_K(cfg, "footer_text", "")))',
        'SET(so, INDEX_SET(so, "lang", AT_K(cfg, "lang", "zh-CN")))',
        'SET(so, INDEX_SET(so, "dark_mode_meta", AT_K(ctx, "dark_mode_meta", "")))',
        'SET(so, INDEX_SET(so, "pwa_meta", AT_K(ctx, "pwa_meta", "")))',
        'SET(so, INDEX_SET(so, "pwa_manifest", AT_K(ctx, "pwa_manifest", "")))',
        'SET(so, INDEX_SET(so, "vt_meta", vt))',
        'SET(so, INDEX_SET(so, "dark_mode_script", AT_K(ctx, "dark_mode_script", "")))',
        'SET(so, INDEX_SET(so, "search_script", AT_K(ctx, "search_script", "")))',
        'so',
    ], '// RENDER_SKELETON 的 opts（三个页面共用）')

    # ── COMMON_CTX ───────────────────────────────────────────────
    src += fn('COMMON_CTX', 'opts, path', [
        '// 对齐 generator.py:308 / 397 / 494 的 _build_common_context(..., current_path)',
        '// ⚠ current_path 三个页面各不相同（"/" / "/search.html" / "/category/<cat>.html"）',
        '//   —— 它只影响 nav 里的 aria-current。',
        '// ⚠ theme_css / dark_css / has_dark 必须从 opts **显式**传下去：',
        '//   COMMON_CONTEXT 只在 theme_css 为空时才去按 config.theme_dir 加载主题，',
        '//   而真 Python 侧基准确认过「主题已加载好再传进来」这条路 ⇒ 显式传。',
        'LET MUT(co, DICT())',
        'SET(co, INDEX_SET(co, "config", AT_K(opts, "config", DICT())))',
        'SET(co, INDEX_SET(co, "theme_css", AT_K(opts, "theme_css", "")))',
        'SET(co, INDEX_SET(co, "dark_css", AT_K(opts, "dark_css", "")))',
        'SET(co, INDEX_SET(co, "has_dark", AT_K(opts, "has_dark", FALSE)))',
        'SET(co, INDEX_SET(co, "standalones", AT_K(opts, "standalones", [])))',
        'SET(co, INDEX_SET(co, "current_path", path))',
        'COMMON_CONTEXT(co)',
    ], '// 页面公共上下文（对齐 generator.py:79）')

    # ── LIST_PAGE ────────────────────────────────────────────────
    nav_lit_open = ('\n<nav class="pagination" aria-label="分页导航">\n'
                    '  <div class="nav-links">')
    nav_lit_mid = ('</div>\n  <div class="page-numbers">')
    nav_lit_close = '</div>\n</nav>'
    body_lit = ('<h1 class="page-title" style="position:absolute;left:-9999px;">'
                '文章列表</h1>\n    <div class="posts">\n      ')
    body_lit_mid = '\n    </div>\n    '

    src += fn('LIST_PAGE', 'opts', [
        '// opts 键：articles / page_info / config / theme_css / dark_css / '
        'has_dark / standalones',
        '// 对齐 generator.py:298 generate_list_page',
        'LET(cfg, AT_K(opts, "config", DICT()))',
        'LET(articles, AT_K(opts, "articles", []))',
        'LET(info, AT_K(opts, "page_info", DICT()))',
        'LET(cur, AT_K(info, "current", 1))',
        'LET(total, AT_K(info, "total", 1))',
        '// Python: f"第{current}页" if current > 1 else "首页"',
        '// ⚠ `+` 不隐式转串 ⇒ 数字先 STR()，再交给 CAT（坑 34）',
        'LET(pt, IF(>(cur, 1), CAT("第", STR(cur), "页"), "首页"))',
        '// ⚠ 逐项取元素（读数组绑定会深拷贝 ⇒ 用 FOR 只读一次，避免 O(n²)，坑 21）',
        'LET MUT(items, "")',
        'FOR(a, articles, SET(items, +(items, ARTICLE_ITEM(a, TRUE))))',
        '// 分页链接：只有 has_prev / has_next 为真才出现',
        'LET(prev_part, IF(AT_K(info, "has_prev", FALSE), CAT('
        '"<a href=\\"", AT_K(info, "prev_url", ""), "\\" class=\\"prev\\">← 上一页</a>"), ""))',
        'LET(next_part, IF(AT_K(info, "has_next", FALSE), CAT('
        '"<a href=\\"", AT_K(info, "next_url", ""), "\\" class=\\"next\\">下一页 →</a>"), ""))',
        '// 页码：当前页用 <span class="current">，第 1 页指 "/"，其余 /list/<p>.html',
        'LET MUT(nums, "")',
        'LET MUT(p, 1)',
        C('WHILE', '<=(p, total)', [
            'LET(pn, IF(==(p, cur), '
            'CAT("<span class=\\"current\\" aria-current=\\"page\\">", STR(p), "</span>"), '
            'IF(==(p, 1), "<a href=\\"/\\">1</a>", '
            'CAT("<a href=\\"/list/", STR(p), ".html\\">", STR(p), "</a>"))))',
            'SET(nums, +(nums, pn))',
            'SET(p, +(p, 1))',
        ]),
        '// total > 1 才有分页 nav（注意它**前导**换行、无尾部换行）',
        'LET(nav_html, IF(>(total, 1), ' + cat(nav_lit_open, ('e', 'prev_part'),
                                                 ('e', 'next_part'), nav_lit_mid,
                                                 ('e', 'nums'), nav_lit_close) + ', ""))',
        'LET(body, ' + cat(body_lit, ('e', 'items'), body_lit_mid, ('e', 'nav_html')) + ')',
        'LET(ctx, COMMON_CTX(opts, "/"))',
        '// ⚠ description 是「先 escape 再交给骨架」（骨架里再 escape 一次），照抄 Python。',
        'RENDER_SKELETON("list", SKELETON_OPTS(ctx, cfg, pt, '
        'ESCAPE_HTML(AT_K(cfg, "site_description", "")), body, '
        'AT_K(ctx, "vt_meta", "")))',
    ], '// 列表页（对齐 generator.py:298）')

    # ── CATEGORY_PAGE ────────────────────────────────────────────
    cat_body_lit = '<h1 class="page-title">分类：'
    cat_body_mid = ('</h1>\n    <p style="color:#666;margin-bottom:1.5rem;">共 ')
    cat_body_mid2 = ' 篇文章</p>\n    <div class="posts">\n      '
    cat_body_close = '\n    </div>'

    src += fn('CATEGORY_PAGE', 'opts', [
        '// opts 键：category / articles / config / theme_css / dark_css / '
        'has_dark / standalones',
        '// 对齐 generator.py:484 generate_category_page',
        'LET(cfg, AT_K(opts, "config", DICT()))',
        'LET(category, AT_K(opts, "category", ""))',
        'LET(articles, AT_K(opts, "articles", []))',
        'LET(safe_category, ESCAPE_HTML(category))',
        '// ⚠ 分类页的预览块**没有** category-badge 行、**也没有**标签行 ⇒ list_layout=FALSE',
        'LET MUT(items, "")',
        'FOR(a, articles, SET(items, +(items, ARTICLE_ITEM(a, FALSE))))',
        'LET(body, ' + cat(cat_body_lit, ('e', 'safe_category'), cat_body_mid,
                           ('e', 'STR(LEN(articles))'), cat_body_mid2,
                           ('e', 'items'), cat_body_close) + ')',
        '// ⚠ current_path 用的是**未 escape** 的原分类名（Python 如此）',
        'LET(ctx, COMMON_CTX(opts, CAT("/category/", category, ".html")))',
        '// description = f"{safe_category} 分类下的文章 - {ctx[\'site_title\']}"',
        '//   ⇒ safe_category 已经 escape 过一次，骨架再 escape ⇒ 二次转义（照抄）。',
        'RENDER_SKELETON("category", SKELETON_OPTS(ctx, cfg, '
        'CAT("分类：", safe_category), '
        'CAT(safe_category, " 分类下的文章 - ", AT_K(ctx, "site_title", "")), '
        'body, AT_K(ctx, "vt_meta", "")))',
    ], '// 分类页（对齐 generator.py:484）')

    # ── SEARCH_PAGE ──────────────────────────────────────────────
    search_body = (
        '<h1 class="page-title">搜索文章</h1>\n    <div class="search-box">\n'
        '      <input type="search" id="search-input" placeholder="输入关键词..." '
        'autocomplete="off" aria-label="搜索关键词">\n'
        '      <div id="search-results" class="search-results"></div>\n    </div>')

    src += fn('SEARCH_PAGE', 'opts', [
        '// opts 键：config / theme_css / dark_css / has_dark / standalones',
        '// 对齐 generator.py:389 generate_search_page',
        'LET(cfg, AT_K(opts, "config", DICT()))',
        'LET(ctx, COMMON_CTX(opts, "/search.html"))',
        '// ⚠ 搜索页把 vt_meta 显式传成 ""（generator.py:421）⇒ 即使',
        '//   enable_view_transitions=True 也**没有** view-transition meta。',
        'RENDER_SKELETON("search", SKELETON_OPTS(ctx, cfg, "搜索", "搜索站内文章", '
        + wl(search_body) + ', ""))',
    ], '// 搜索页（对齐 generator.py:389）')

    A('EXPORT(["CATEGORY_PAGE", "LIST_PAGE", "SEARCH_PAGE"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
