"""生成 tp/lib/page_common.wll —— 页面公共上下文（卡 S2-4 的共享基础）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**为什么单独抽出来**：`tinypage/generator.py` 里 `build_json_ld` / `_nav_links` /
`_build_common_context` 被 **5 个页面生成函数共用**（article / standalone / list /
category / search）。各模块自己抄一份必然漂移 ⇒ 只留**一份**实现。

**对齐目标（真 Python 源码树）**：
  · `JSON_LD(opts)`        == generator.py:18  `build_json_ld`
  · `NAV_LINKS(opts)`      == generator.py:66  `_nav_links`
  · `COMMON_CONTEXT(opts)` == generator.py:79  `_build_common_context`

**接口形态**：三者都收一个 DICT（键名与 Python 的具名参数同名、可缺省），
因为 WLWL 没有关键字参数与默认参数。

**本机实测的一条关键差异（JSON-LD 的字节口径）**：
  Python 用 `json.dumps(schema, ensure_ascii=False)` ⇒ **插入序** + 分隔符 `", "` / `": "`；
  WLWL 的 `std.json::STRINGIFY` 是**紧凑分隔符 + 键名字典序**
  （实测 `{"@context":"…","@type":"…","author":…,"headline":…}`）。
  ⇒ **不能**整体序列化。本模块**手工拼装**：键序与分隔符照 Python 默认值；
    单个**标量**的转义复用 `STRINGIFY(s)`（实测与 Python 对单字符串的转义逐字一致：
    `"`→`\\"`、`\\`→`\\\\`、换行→`\\n`、非 ASCII 原样保留）。

**已知差异（D9）**：控制字符里除 `\\n\\r\\t\\b\\f` 之外的那些，Python 会写成 `\\u00XX`；
WLWL 没有 `ORD`/`CHR`、构造不出十六进制 ⇒ 原样输出 ⇒ 仅当标量真的含这类字符才有差异
（夹具里单独登记一条）。

用法：python gen_page_common.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'page_common.wll')


def main():
    src = []
    A = src.append
    A('// tp/lib/page_common.wll —— 页面公共上下文（卡 S2-4 的共享基础）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_page_common.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树）：')
    A('//   JSON_LD(opts)        == generator.py:18   build_json_ld')
    A('//   NAV_LINKS(opts)      == generator.py:66   _nav_links')
    A('//   COMMON_CONTEXT(opts) == generator.py:79   _build_common_context')
    A('//')
    A('// 为什么单独抽出来：这三个被 article / standalone / list / category / search')
    A('// 五个页面函数共用 ⇒ 只留一份，避免各抄一份而漂移。')
    A('//')
    A('// ⚠ JSON-LD 的字节口径：Python 用 json.dumps(..., ensure_ascii=False)')
    A('//   ⇒ **插入序** + 分隔符 ", " / ": "。而 std.json::STRINGIFY 是**紧凑**')
    A('//   分隔符 + **键名字典序** ⇒ 不能整体序列化。本模块手工拼装，单标量转义')
    A('//   复用 STRINGIFY(s)（实测与 Python 对单个字符串的转义逐字一致）。')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/page_common_baseline.json')
    A('')
    A('IMPORT("wlwl:std.json", ["STRINGIFY"]);')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("wlwl:std.fs", ["PATH_JOIN"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('IMPORT("./theme.wll", ["LOAD_THEME_CSS"]);')
    A('')

    # ── 通用小工具 ─────────────────────────────────────────────────
    src += fn('RSTRIP_SLASH', 's', [
        '// 去掉结尾所有 "/"（对齐 Python 的 s.rstrip("/")）',
        'LET MUT(out, s)',
        'LET MUT(i, LEN(out))',
        C('WHILE', '>(i, 0)', [
            C('IF', '==(SUB(out, -(i, 1), 1), "/")', [
                'SET(out, SUB(out, 0, -(i, 1)))',
                'SET(i, -(i, 1))',
            ], [
                'SET(i, 0)',
            ]),
        ]),
        'out',
    ], '// 去掉结尾所有 /（对齐 rstrip("/")）')

    src += fn('JSON_STR', 's', [
        '// JSON 字符串标量 —— 复用 STRINGIFY，它与 Python 对单个字符串的转义逐字一致。',
        '// ⚠ STRINGIFY 对**容器**是紧凑 + 键名排序，与 Python json.dumps 不同；',
        '//   但**单个字符串**没有键序/分隔符问题 ⇒ 可以安全复用。',
        'STRINGIFY(s)',
    ], '// JSON 字符串标量（复用 STRINGIFY）')

    # ── JSON_LD ───────────────────────────────────────────────────
    # Python（generator.py:18）：
    #   article_url = f"{site_url.rstrip('/')}/article/{slug}.html"
    #   schema = {"@context": "https://schema.org", "@type": "Article",
    #             "headline": title, "description": description, "url": article_url,
    #             "datePublished": date,
    #             "author": {"@type": "Person", "name": author or "Anonymous"},
    #             "publisher": {"@type": "Organization", "name": site_url}}
    #   if tags: schema["keywords"] = ", ".join(tags)
    #   return f'<script type="application/ld+json">{json.dumps(schema, ensure_ascii=False)}</script>'
    # ⚠ **仅当 site_url 非空才输出**（卡片 S2-4 明确要求）。
    src += fn('JOIN_TAGS', 'tags', [
        '// tags 用 ", " 连接（对齐 Python 的 ", ".join(tags)）',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, LEN(tags))', [
            C('IF', '>(i, 0)', [
                'SET(out, +(out, ", "))',
            ], [
                'NULL',
            ]),
            'SET(out, +(out, AT(tags, i, "")))',
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// tags 用 ", " 连接')

    src += fn('JSON_LD', 'opts', [
        '// opts 键：title / description / date / slug / tags / site_url / author',
        'LET(title, AT_K(opts, "title", ""))',
        'LET(desc, AT_K(opts, "description", ""))',
        'LET(date, AT_K(opts, "date", ""))',
        'LET(slug, AT_K(opts, "slug", ""))',
        'LET(site_url, AT_K(opts, "site_url", ""))',
        'LET(tags, AT_K(opts, "tags", []))',
        'LET(author, AT_K(opts, "author", ""))',
        C('IF', '==(site_url, "")', [
            '// ⚠ site_url 为空 ⇒ 整段不输出（卡片 S2-4）',
            '""',
        ], [
            'LET(url, +(RSTRIP_SLASH(site_url), +("/article/", +(slug, ".html"))))',
            '// author.name = author or "Anonymous"（Python 的 or 对空串也回落）',
            'LET(a_name, IF(==(author, ""), "Anonymous", author))',
            '// 键序与分隔符照 Python json.dumps 的默认值；标量用 JSON_STR 转义',
            'LET(head, CAT("{\\"@context\\": ", JSON_STR("https://schema.org"), '
            '", \\"@type\\": \\"Article\\"", ", \\"headline\\": ", JSON_STR(title), '
            '", \\"description\\": ", JSON_STR(desc), ", \\"url\\": ", JSON_STR(url), '
            '", \\"datePublished\\": ", JSON_STR(date)))',
            '// author / publisher 是两个嵌套对象 —— 展开拼装',
            'LET(mid, CAT(", \\"author\\": {\\"@type\\": \\"Person\\", \\"name\\": ", '
            'JSON_STR(a_name), "}", ", \\"publisher\\": {\\"@type\\": \\"Organization\\", '
            '\\"name\\": ", JSON_STR(site_url), "}"))',
            '// keywords 仅在 tags 非空时出现',
            'LET(kw, IF(==(LEN(tags), 0), "", '
            'CAT(", \\"keywords\\": ", JSON_STR(JOIN_TAGS(tags)))))',
            'LET(body, CAT(head, mid, kw, "}"))',
            'CAT("<script type=\\"application/ld+json\\">", body, "</script>")',
        ]),
    ], '// JSON-LD 结构化数据（对齐 generator.py:18）')

    # ── NAV_LINKS ─────────────────────────────────────────────────
    # Python（generator.py:66）：
    #   links = ['<a href="/">首页</a>']
    #   if standalones:
    #       for page in standalones:
    #           active = ' aria-current="page"' if current_path == f"/standalone/{page.file}" else ""
    #           links.append(f'<a href="/standalone/{page.file}"{active}>{escape_html(page.title[:20] or page.file)}</a>')
    #   if cfg.enable_search:
    #       active = ' aria-current="page"' if current_path == "/search.html" else ""
    #       links.append(f'<a href="/search.html"{active}>搜索</a>')
    #   return "\n      ".join(links)
    src += fn('NAV_LINKS', 'opts', [
        '// opts 键：cfg / standalones / current_path',
        'LET(cfg, AT_K(opts, "cfg", DICT()))',
        'LET(pages, AT_K(opts, "standalones", []))',
        'LET(cur, AT_K(opts, "current_path", ""))',
        '// 分隔符是"换行 + 6 个空格"（对齐 Python 的 "\\n      ".join）',
        'LET MUT(out, "<a href=\\"/\\">首页</a>")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, LEN(pages))', [
            'LET(p, AT(pages, i, DICT()))',
            'LET(file, AT_K(p, "file", ""))',
            '// label = escape_html(title[:20] or file) —— ⚠ 空串也回落文件名',
            'LET(t20, SUB(AT_K(p, "title", ""), 0, 20))',
            'LET(label, IF(==(t20, ""), file, t20))',
            'LET(active, IF(==(cur, +("/standalone/", file)), '
            '" aria-current=\\"page\\"", ""))',
            'SET(out, CAT(out, "\\n      ", "<a href=\\"/standalone/", file, "\\"", '
            'active, ">", ESCAPE_HTML(label), "</a>"))',
            'SET(i, +(i, 1))',
        ]),
        C('IF', 'AT_K(cfg, "enable_search", FALSE)', [
            'LET(active, IF(==(cur, "/search.html"), '
            '" aria-current=\\"page\\"", ""))',
            'SET(out, CAT(out, "\\n      ", "<a href=\\"/search.html\\"", active, '
            '">搜索</a>"))',
        ], [
            'NULL',
        ]),
        'out',
    ], '// 站点导航链接（对齐 generator.py:66）')

    # ── COMMON_CONTEXT ────────────────────────────────────────────
    # Python（generator.py:79）：
    #   cfg = config or Config()
    #   if not theme_css: theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)
    #   site_title = escape_html(cfg.site_title)
    #   dark_mode_meta  = '<meta name="color-scheme" content="light dark">' if has_dark else ""
    #   dark_mode_script = """<script>(function(){...})();</script>""" if has_dark else ""
    #   if cfg.enable_pwa: pwa_meta = 两个 theme-color meta；pwa_manifest = link rel=manifest
    #   vt_meta = ... if cfg.enable_view_transitions else ""
    #   search_script = '<script src="/search.js" defer></script>' if cfg.enable_search else ""
    #   nav = _nav_links(cfg, standalones, current_path)
    #   theme_toggle = '<button class="theme-toggle" ...>🌓</button>' if has_dark else ''
    DARK_MODE_META = '<meta name="color-scheme" content="light dark">'
    DARK_MODE_SCRIPT = (
        "<script>(function(){try{var m=localStorage.getItem('theme');"
        "if(m==='light'||(!m&&window.matchMedia('(prefers-color-scheme: light)').matches))"
        "{document.documentElement.classList.add('light')}}catch(e){}})();</script>"
    )
    PWA_MANIFEST = '<link rel="manifest" href="/manifest.json">'
    VT_META = '<meta name="view-transition" content="same-origin">'
    SEARCH_SCRIPT = '<script src="/search.js" defer></script>'
    THEME_TOGGLE = (
        '<button class="theme-toggle" aria-label="切换主题" '
        'onclick="var d=document.documentElement;d.classList.toggle(\'light\');'
        'try{localStorage.setItem(\'theme\',d.classList.contains(\'light\')?\'light\':\'dark\')}'
        'catch(e){}">🌓</button>'
    )

    def wl(s):
        """Python 字符串 → WLWL 字符串字面量（转义 \\ 与 "）。"""
        return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'

    src += fn('COMMON_CONTEXT', 'opts', [
        '// opts 键：config / theme_css / dark_css / has_dark / standalones / current_path',
        'LET(cfg, AT_K(opts, "config", DICT()))',
        'LET(theme_css, AT_K(opts, "theme_css", ""))',
        'LET(dark_css, AT_K(opts, "dark_css", ""))',
        'LET(has_dark, AT_K(opts, "has_dark", FALSE))',
        'LET(pages, AT_K(opts, "standalones", []))',
        'LET(cur, AT_K(opts, "current_path", ""))',
        '// ⚠ Python: if not theme_css ⇒ 从主题目录加载（空串也算 falsy）',
        '//   WLWL 侧要求 config 带 theme_dir；没有就保持空，不猜路径。',
        'LET MUT(css, theme_css)',
        'LET MUT(dcss, dark_css)',
        'LET MUT(hd, has_dark)',
        C('IF', '&&(==(css, ""), CONTAINS(KEYS(cfg), "theme_dir"))', [
            'LET(t, LOAD_THEME_CSS(AT_K(cfg, "theme_dir", "")))',
            'SET(css, AT_K(t, "css", ""))',
            'SET(dcss, AT_K(t, "dark_css", ""))',
            'SET(hd, AT_K(t, "has_dark", FALSE))',
        ], [
            'NULL',
        ]),
        'LET(site_title, ESCAPE_HTML(AT_K(cfg, "site_title", "")))',
        'LET MUT(ctx, DICT())',
        'SET(ctx, INDEX_SET(ctx, "site_title", site_title))',
        'SET(ctx, INDEX_SET(ctx, "theme_css", css))',
        'SET(ctx, INDEX_SET(ctx, "dark_css", dcss))',
        'SET(ctx, INDEX_SET(ctx, "has_dark", hd))',
        'SET(ctx, INDEX_SET(ctx, "dark_mode_meta", '
        'IF(hd, ' + wl(DARK_MODE_META) + ', "")))',
        'SET(ctx, INDEX_SET(ctx, "dark_mode_script", '
        'IF(hd, ' + wl(DARK_MODE_SCRIPT) + ', "")))',
        '// PWA：两个 theme-color meta（颜色过 escape_attr；实测它与 ESCAPE_HTML 等价）',
        C('IF', 'AT_K(cfg, "enable_pwa", FALSE)', [
            'SET(ctx, INDEX_SET(ctx, "pwa_meta", CAT('
            '"<meta name=\\"theme-color\\" content=\\"", '
            'ESCAPE_HTML(AT_K(cfg, "pwa_theme_color", "")), '
            '"\\" media=\\"(prefers-color-scheme: light)\\"><meta name=\\"theme-color\\" '
            'content=\\"", ESCAPE_HTML(AT_K(cfg, "pwa_bg_color", "")), '
            '"\\" media=\\"(prefers-color-scheme: dark)\\">")))',
            'SET(ctx, INDEX_SET(ctx, "pwa_manifest", ' + wl(PWA_MANIFEST) + '))',
        ], [
            'SET(ctx, INDEX_SET(ctx, "pwa_meta", ""))',
            'SET(ctx, INDEX_SET(ctx, "pwa_manifest", ""))',
        ]),
        'SET(ctx, INDEX_SET(ctx, "vt_meta", IF(AT_K(cfg, "enable_view_transitions", FALSE), '
        + wl(VT_META) + ', "")))',
        'SET(ctx, INDEX_SET(ctx, "search_script", IF(AT_K(cfg, "enable_search", FALSE), '
        + wl(SEARCH_SCRIPT) + ', "")))',
        'SET(ctx, INDEX_SET(ctx, "nav", NAV_LINKS(INDEX_SET(INDEX_SET('
        'INDEX_SET(DICT(), "cfg", cfg), "standalones", pages), "current_path", cur))))',
        'SET(ctx, INDEX_SET(ctx, "theme_toggle", IF(hd, ' + wl(THEME_TOGGLE) + ', "")))',
        'ctx',
    ], '// 页面公共上下文（对齐 generator.py:79）')

    A('EXPORT(["COMMON_CONTEXT", "JSON_LD", "NAV_LINKS"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
