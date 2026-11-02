"""生成 tp/lib/article_page.wll —— 文章页 / 独立页（卡 S2-4）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。
   改实现请改生成器（WLWL 的括号诊断只说「expected ')' got X」，不告诉你缺了几层）。

**对齐目标（真 Python 源码树）**：
  · `ARTICLE_PAGE(opts)`    == tinypage/generator.py:154 `generate_article_html`
  · `STANDALONE_PAGE(opts)` == tinypage/generator.py:429 `generate_standalone_html`

**接口形态**：两者都收**一个 DICT**（键名与 Python 的具名参数同名、可缺省），
因为 WLWL 没有关键字参数与默认参数。`config` 键是与 `tinypage/config.py::Config`
同名的 DICT（**部分键**也算数：缺的走 Python 的默认值，见 `CFG_OF`）。

**复用，不重写**（本卡明确要求，重写必漂移）：
  · `page_common.wll` 的 `COMMON_CONTEXT` / `JSON_LD`（ctx 12 字段、JSON-LD、nav 已与真 Python 对齐）
  · `template.wll` 的 `RENDER_SKELETON`（页面骨架 + `string.Template` 替换）
  · `esc.wll` 的 `ESCAPE_HTML`
本模块**只**负责 generate_article_html / generate_standalone_html 自己的那段拼装。

**边界（不在本卡范围）**：脚注 / TOC / 双链 / Markdown / 代码高亮都在 Python 侧由
`content.py` 的调用方渲染好；`generate_article_html` 只接**已渲染好的** `content`
（`toc_html` / `footnotes_html` / `backlinks_html` 同理）⇒ 本模块一律**原样嵌入**，
不解析、不 escape。

**逐字节对照基准**：tp/test/fixtures/article_page_baseline.json
    （由 tp/test/gen_article_page_baseline.py 用**真 Python** 生成）

**本机实测踩到的坑（每条都有探针依据）**：
  ① 内建 `TRIM` **只去 ASCII 空白**：实测 `TRIM(U+3000 + "a" + U+3000)` 原样保留
     U+3000、`TRIM(U+00A0+"a"+U+00A0)` 保留 NBSP。而 Python 的 `str.strip()` 去的是
     `str.isspace()` 全集（含 U+3000 / U+00A0 / U+1680 / U+2000–200A / U+2028 /
     U+2029 / U+202F / U+205F / U+0085 / \x1c-\x1f）。
     ⇒ tags 的 `t.strip()` **不能**用 `TRIM`，本模块用 `PY_WS()` + 两条正则精确复刻
       （`PY_STRIP`）。基准用例 a12 专门用 U+3000 / U+00A0 钉住这条。
  ② `escape_attr(x)` **等价于** `escape_html(x)`：`security.py` 里它是
     `html.escape(quote=True).replace('"', '&quot;')`，而 `html.escape` 已经把 `"` 换成
     `&quot;` ⇒ 后一个 replace 是空操作。⇒ 两类转义统一用 `ESCAPE_HTML`。
  ③ `$` 不是「一律闭眼转义就完」：它**只在字面量里**是插值（`\\$` ⇒ 字面 `$`）；
     而本模块的**运行期**值（`content`、`theme_css` …）经 `SUBSTITUTE` 只做**一遍**
     替换 ⇒ 值里的 `${x}` 不会被二次展开（基准 a10 / s04 钉住）。
  ④ `generate_article_html` 的 og:url 走 `rstrip("/")`，但 share 按钮的 url
     **不**走 rstrip（Python 侧就是直接拼）⇒ site_url 以 `/` 结尾时产物里
     **同时**出现单斜杠与双斜杠两种形态。基准 a08 钉住，别「顺手修正」。
  ⑤ `render_skeleton` 会对 `page_title` / `site_title` / `description` / `footer_text`
     再 escape 一次 ⇒ 本模块传进去的已是 escape 过的串，产物里是**双重转义**
     （`A&B` → `A&amp;amp;B`）。这是 Python 的真实行为，不是 bug。

**已知差异**：预期为 0（基准 `_meta.known_difference_count == 0`）。
  唯一的结构性边界是**空 theme_css**：Python 会去读主题目录（环境相关），
  WLWL 侧保持空串 ⇒ 基准的用例一律显式传非空 theme_css（见基准生成器的断言）。

用法：python gen_article_page.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'article_page.wll')


class Lit(str):
    """标记：这是一个**字面量**（要转义成 WLWL 字符串）。普通 str 当表达式用。"""


def w(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 转义白名单只有 `\\" \\/ \\n \\r \\t \\b \\f \\0 \\$`（README 坑 7）
      ⇒ 其余控制字符写不进去（本模块的拼接段都是 HTML，不含控制字符；
        生成期用断言钉住，避免悄悄写坏）。
    ⚠ `$` 一律写成 `\\$`：裸 `$` 会被当插值（README 坑 32；实测 `\\$` ⇒ 字面 `$`）。
    """
    out = []
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '$':
            out.append('\\$')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        else:
            assert ord(ch) >= 32, '控制字符 %r 无法写进 WLWL 字面量' % (ch,)
            out.append(ch)
    return '"' + ''.join(out) + '"'


def cat(*parts):
    """`CAT(...)` —— 字面量用 `Lit("…")`，表达式用裸 `str`。

    ⚠ 用**变参 CAT** 而不是二元 `+`：`+` 是二元的（README 坑 1）、
      且不做隐式转串（坑 34）⇒ 多段拼接用 CAT 能消灭嵌套括号错误。
    """
    chunks = []
    for p in parts:
        chunks.append(w(p) if isinstance(p, Lit) else p)
    return 'CAT(' + ', '.join(chunks) + ')'


# ── Python 侧常量（逐字抄自 generator.py；⚠ 改动会让基准对不上）────────
MERMAID = (
    '<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js">'
    '</script><script>mermaid.initialize({startOnLoad:true,'
    "theme:document.documentElement.classList.contains('dark')?'dark':'default',"
    "securityLevel:'strict'});</script>"
)

DRAFT_BADGE = '<span class="draft-badge">草稿</span>'

# Python: str.isspace() 为真的全部字符（Python 3 str.strip() 的默认集合）
# 逐字符 UTF-8 字节（⚠ UTF8_DECODE 吃的是**字节**，不是码点）
PY_WS_BYTES = (
    [9, 10, 11, 12, 13]              # \t \n \v \f \r
    + list(range(28, 32))            # \x1c \x1d \x1e \x1f
    + [32]                           # 空格
    + [194, 133]                     # U+0085
    + [194, 160]                     # U+00A0
    + [225, 154, 128]                # U+1680
    + [b for x in range(128, 139) for b in (226, 128, x)]   # U+2000–U+200A（11 个）
    + [226, 128, 168]                # U+2028
    + [226, 128, 169]                # U+2029
    + [226, 128, 175]                # U+202F
    + [226, 129, 159]                # U+205F
    + [227, 128, 128]                # U+3000
)


def main():
    src = []
    A = src.append
    A('// tp/lib/article_page.wll —— 文章页 / 独立页（卡 S2-4）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_article_page.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树）：')
    A('//   ARTICLE_PAGE(opts)    == generator.py:154 generate_article_html')
    A('//   STANDALONE_PAGE(opts) == generator.py:429 generate_standalone_html')
    A('//')
    A('// 复用（不重写，重写必漂移）：')
    A('//   page_common.wll  COMMON_CONTEXT / JSON_LD   （ctx 12 字段 / JSON-LD）')
    A('//   template.wll     RENDER_SKELETON            （页面骨架）')
    A('//   esc.wll          ESCAPE_HTML                （html.escape 逐字节对齐）')
    A('//')
    A('// 边界：脚注 / TOC / 双链 / Markdown 在 Python 侧由调用方渲染好，')
    A('//   本模块只接**已渲染好的** content / toc_html / footnotes_html / backlinks_html，')
    A('//   一律**原样嵌入**（不解析、不 escape）。')
    A('//')
    A('// ⚠ 本机实测的三条（详见生成器 docstring）：')
    A('//   ① 内建 TRIM **只去 ASCII 空白** ⇒ Python 的 str.strip() 用 PY_STRIP 复刻；')
    A('//   ② escape_attr == escape_html（replace 是空操作）⇒ 统一用 ESCAPE_HTML；')
    A('//   ③ og:url 走 rstrip("/")，share 的 url **不**走 ⇒ 两种斜杠形态并存（a08）。')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/article_page_baseline.json')
    A('')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("wlwl:std.text", ["TO_LOWER"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_REPLACE"]);')
    A('IMPORT("wlwl:std.encode", ["UTF8_DECODE"]);')
    A('IMPORT("./page_common.wll", ["COMMON_CONTEXT", "JSON_LD"]);')
    A('IMPORT("./template.wll", ["RENDER_SKELETON"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('')

    # ── Python 的 str.strip() 空白集合 ────────────────────────────
    src += fn('PY_WS', '', [
        '// Python 的 str.isspace() 全集（10 个 ASCII 空白 \\t\\n\\v\\f\\r \\x1c-\\x1f 空格',
        '// + U+0085 / U+00A0 / U+1680 / U+2000-200A / U+2028 / U+2029 / U+202F',
        '// + U+205F / U+3000，共 29 个字符）。',
        '// ⚠ 内建 TRIM **只去 ASCII 空白**（实测：TRIM 对 U+3000 / U+00A0 无效）',
        '// ⇒ tags 的 t.strip() 不能直接用 TRIM。',
        '// ⚠ UTF8_DECODE 的实参是**字节**（0-255），不是码点。',
        'UTF8_DECODE([' + ', '.join(str(b) for b in PY_WS_BYTES) + '])',
    ], '// Python str.strip() 去掉的字符集合（逐字节构造）')

    A('// 首尾空白模式（运行期用上面的集合拼出来 —— 字符类是**字面**字符，无转义问题）')
    A('LET(WS_LEAD_RE, RE(CAT("^[", PY_WS(), "]+")));')
    A('// ⚠ 结尾锚 `$` 要写成 `\\$`（裸 `$` 在字面量里是插值）；')
    A('//   WLWL 正则的 `$` = 正文末尾，与 Python 的 `$`（也允许结尾一个 \\n）不同 ——')
    A('//   但换行本身在空白集合里 ⇒ 剥空白时两者结果一致（不会漏剥也不会多剥）。')
    A('LET(WS_TRAIL_RE, RE(CAT("[", PY_WS(), "]+\\$")));')
    A('')

    src += fn('PY_STRIP', 's', [
        '// 对齐 Python 的 s.strip()（默认空白集合）',
        'RE_REPLACE(WS_TRAIL_RE, RE_REPLACE(WS_LEAD_RE, s, ""), "")',
    ], '// Python str.strip() 的逐字节复刻')

    src += fn('RSTRIP_SLASH', 's', [
        '// 对齐 Python 的 s.rstrip("/")',
        '// ⚠ 不用正则 `[.]+\\$`：WLWL 的 `$` 只认正文末尾，且这里手写循环更直白。',
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

    # ── 入参归一化 ────────────────────────────────────────────────
    src += fn('AS_STR', 'v', [
        '// 非 STRING 一律当空串（对齐 Python 侧「缺省 = ""」；也兜住显式传 NULL）',
        'IF(==(TYPE(v), "STRING"), v, "")',
    ], '// 归一化成字符串')

    src += fn('AS_ARR', 'v', [
        '// 非 ARRAY 一律当空数组（Python 侧 None / 缺省都是 falsy）',
        'IF(==(TYPE(v), "ARRAY"), v, [])',
    ], '// 归一化成数组')

    # ── Config 的默认值与合并 ─────────────────────────────────────
    # Python: cfg = config or Config()；Config 的默认值见 tinypage/config.py:12
    src += fn('DEFAULT_CONFIG', '', [
        '// tinypage/config.py::Config 的默认值（⚠ 只列页面生成用到的 17 个键）',
        '// 为什么必须有一份：WLWL 侧 config 是 DICT，缺键时要回落到 Python 的默认值，',
        '// 而不是空串（例如 footer_text 的默认是 "Powered by TinyPage"）。',
        'LET MUT(d, DICT())',
        'SET(d, INDEX_SET(d, "site_title", "TinyPage"))',
        'SET(d, INDEX_SET(d, "site_description", "A modern static blog"))',
        'SET(d, INDEX_SET(d, "site_url", ""))',
        'SET(d, INDEX_SET(d, "site_author", ""))',
        'SET(d, INDEX_SET(d, "footer_text", "Powered by TinyPage"))',
        'SET(d, INDEX_SET(d, "lang", "zh-CN"))',
        'SET(d, INDEX_SET(d, "theme_name", "default"))',
        'SET(d, INDEX_SET(d, "page_size", 10))',
        'SET(d, INDEX_SET(d, "enable_pwa", TRUE))',
        'SET(d, INDEX_SET(d, "enable_dark_mode", TRUE))',
        'SET(d, INDEX_SET(d, "enable_search", TRUE))',
        'SET(d, INDEX_SET(d, "enable_rss", TRUE))',
        'SET(d, INDEX_SET(d, "enable_sitemap", TRUE))',
        'SET(d, INDEX_SET(d, "enable_view_transitions", TRUE))',
        'SET(d, INDEX_SET(d, "pwa_short_name", "TinyPage"))',
        'SET(d, INDEX_SET(d, "pwa_theme_color", "#2c3e50"))',
        'SET(d, INDEX_SET(d, "pwa_bg_color", "#ffffff"))',
        'd',
    ], '// Config 的默认值（缺键回落用）')

    cfg_keys = [
        'site_title', 'site_description', 'site_url', 'site_author',
        'footer_text', 'lang', 'theme_name', 'page_size',
        'enable_pwa', 'enable_dark_mode', 'enable_search', 'enable_rss',
        'enable_sitemap', 'enable_view_transitions',
        'pwa_short_name', 'pwa_theme_color', 'pwa_bg_color',
    ]
    merge_lines = [
        '// opts 键：config（DICT；与 Config 同名，**可只给一部分**）',
        '// Python: cfg = config or Config() ⇒ 缺键回落默认值，不回落空串。',
        'LET(c, AT_K(opts, "config", DICT()))',
        'LET MUT(o, DEFAULT_CONFIG())',
        C('IF', '==(TYPE(c), "DICT")', [
            '// 逐键覆盖：只有**真给了**的键才盖掉默认值',
        ] + [
            'SET(o, INDEX_SET(o, "%s", AT_K(c, "%s", AT_K(o, "%s", ""))))'
            % (k, k, k) for k in cfg_keys
        ], [
            'NULL',
        ]),
        'o',
    ]
    src += fn('CFG_OF', 'opts', merge_lines, '// 合并 config（部分键 ⇒ 其余走 Config 默认值）')

    # ── tags ─────────────────────────────────────────────────────
    src += fn('TAG_LIST', 'tags', [
        '// Python: [t.strip() for t in tags.split(",") if t.strip()]',
        '// ⚠ t.strip() 用 PY_STRIP（内建 TRIM 只去 ASCII 空白）',
        'LET(parts, SPLIT(tags, ","))',
        'LET MUT(out, [])',
        'LET MUT(i, 0)',
        'LET(n, LEN(parts))',
        C('WHILE', '<(i, n)', [
            'LET(t, PY_STRIP(AT(parts, i, "")))',
            C('IF', '!=(t, "")', [
                'SET(out, PUSH(out, t))',
            ], [
                'NULL',
            ]),
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// tags 串 → 去空白后的数组（对齐 tag_list）')

    src += fn('TAGS_HTML', 'lst', [
        '// Python: 有 tag_items 才输出 <div class="post-tags">…</div>，项间用**一个空格**',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        'LET(n, LEN(lst))',
        C('WHILE', '<(i, n)', [
            C('IF', '>(i, 0)', [
                'SET(out, +(out, " "))',
            ], [
                'NULL',
            ]),
            'SET(out, ' + cat(
                'out',
                Lit('<span class="tag">'),
                'ESCAPE_HTML(AT(lst, i, ""))',
                Lit('</span>')) + ')',
            'SET(i, +(i, 1))',
        ]),
        'IF(==(n, 0), "", ' + cat(Lit('<div class="post-tags">'), 'out', Lit('</div>')) + ')',
    ], '// tags 的 HTML（无 tag ⇒ 空串）')

    # ── category / 草稿徽章 ──────────────────────────────────────
    src += fn('CATEGORY_HTML', 'c', [
        '// Python: if category: <span class="post-category"><a href="/category/{escape_attr(c)}.html">…',
        '// ⚠ escape_attr 与 escape_html 等价（见文件头的实测②）',
        'IF(==(c, ""), "", ' + cat(
            Lit('<span class="post-category"><a href="/category/'),
            'ESCAPE_HTML(c)',
            Lit('.html">'),
            'ESCAPE_HTML(c)',
            Lit('</a></span>')) + ')',
    ], '// 分类徽章（无分类 ⇒ 空串）')

    src += fn('DRAFT_BADGE', 'status', [
        '// Python: if status.lower() == "draft" ⇒ 草稿徽章',
        '// ⚠ 必须 TO_LOWER（`DRAFT` 也算；基准 a03 钉住）',
        'IF(==(TO_LOWER(status), "draft"), ' + w(DRAFT_BADGE) + ', "")',
    ], '// 草稿徽章')

    # ── Open Graph ───────────────────────────────────────────────
    src += fn('ARTICLE_OG', 'page_title, safe_summary, article_url', [
        '// Python（generator.py:209-215）：og:title / og:description / og:type=article',
        '//   / og:url（escape_attr）/ twitter:card / twitter:title / twitter:description',
        '// ⚠ article_url 在调用方已做过 rstrip("/")',
        cat(
            Lit('<meta property="og:title" content="'), 'page_title',
            Lit('">\n<meta property="og:description" content="'), 'safe_summary',
            Lit('">\n<meta property="og:type" content="article">'
                '\n<meta property="og:url" content="'),
            'ESCAPE_HTML(article_url)',
            Lit('">\n<meta name="twitter:card" content="summary">'
                '\n<meta name="twitter:title" content="'), 'page_title',
            Lit('">\n<meta name="twitter:description" content="'), 'safe_summary',
            Lit('">')),
    ], '// 文章页的 og / twitter meta')

    src += fn('STANDALONE_OG', 'page_title, safe_summary', [
        '// Python（generator.py:447-450）：注意**没有** og:url，og:type 是 website',
        cat(
            Lit('<meta property="og:title" content="'), 'page_title',
            Lit('">\n<meta property="og:description" content="'), 'safe_summary',
            Lit('">\n<meta property="og:type" content="website">'
                '\n<meta name="twitter:card" content="summary">')),
    ], '// 独立页的 og meta')

    src += fn('MERMAID', '', [
        '// Python（generator.py:228）：文章页**恒**带 mermaid',
        '// ⚠ 独立页没有这一段（见 STANDALONE_PAGE 传 ""）',
        w(MERMAID),
    ], '// mermaid 脚本（文章页恒有）')

    src += fn('SHARE_HTML', 'page_title, safe_summary, site_url_esc, slug', [
        '// Python（generator.py:233）：share 按钮的 url **不做** rstrip("/")',
        '// ⇒ site_url 以 "/" 结尾时这里会出现 `//article/…`（基准 a08 钉住）',
        '// ⚠ 值里的 `{` / `}` 是 JS 语法，与 WLWL 无关（本串是**字面量**）',
        cat(
            Lit('<button class="share-btn" onclick="navigator.share?.({title:\''),
            'page_title',
            Lit("',text:'"), 'safe_summary',
            Lit("',url:'"), 'site_url_esc',
            Lit('/article/'), 'slug',
            Lit(".html'}).catch(()=>{})\" hidden>分享</button>")),
    ], '// 分享按钮（仅 site_url 非空时输出）')

    # ── 相关文章 ─────────────────────────────────────────────────
    rel_item = (
        '\n      <div class="related-item">\n        <a href="'
    )
    src += fn('RELATED_HTML', 'related', [
        '// Python（generator.py:236-251）：每项前有换行、缩进 6 空格；',
        '//   `art.url` = f"/article/{art.file}"（models.py:39 的 ArticleMeta.url）',
        '//   ⇒ 元素只需 title / date / file 三个键',
        'LET MUT(items, "")',
        'LET MUT(i, 0)',
        'LET(n, LEN(related))',
        C('WHILE', '<(i, n)', [
            'LET(a0, AT(related, i, DICT()))',
            'LET(a, IF(==(TYPE(a0), "DICT"), a0, DICT()))',
            'LET(url, CAT("/article/", AS_STR(AT_K(a, "file", ""))))',
            'SET(items, ' + cat(
                'items',
                Lit(rel_item),
                'url',
                Lit('">'),
                'ESCAPE_HTML(AS_STR(AT_K(a, "title", "")))',
                Lit('</a>\n        <span class="related-date">'),
                'ESCAPE_HTML(AS_STR(AT_K(a, "date", "")))',
                Lit('</span>\n      </div>')) + ')',
            'SET(i, +(i, 1))',
        ]),
        C('IF', '==(n, 0)', [
            '""',
        ], [
            cat(
                Lit('\n    <section class="related-articles">\n      <h2>相关文章</h2>'
                    '\n      <div class="related-list">\n        '),
                'items',
                Lit('\n      </div>\n    </section>')),
        ]),
    ], '// 相关文章段（空列表 ⇒ 空串）')

    # ── 文章正文体 ───────────────────────────────────────────────
    src += fn('ARTICLE_BODY', 'b', [
        '// Python（generator.py:253-271）的 body_content —— 逐字节照抄其缩进与换行',
        '// 键：page_title / safe_date / category_html / draft_badge / share_html /',
        '//     toc_html / content / tags_html / footnotes_html / backlinks_html / related_html',
        '// ⚠ content 与三个 *_html 一律**原样嵌入**（不在本卡解析）',
        cat(
            Lit('<article class="post">\n      <header class="post-header">'
                '\n        <h1 class="post-title">'),
            'AT_K(b, "page_title", "")',
            Lit('</h1>\n        <div class="post-meta">\n          '),
            'AT_K(b, "category_html", "")',
            Lit('\n          <time datetime="'),
            'AT_K(b, "safe_date", "")',
            Lit('">'),
            'AT_K(b, "safe_date", "")',
            Lit('</time>\n          '),
            'AT_K(b, "draft_badge", "")',
            Lit('\n          '),
            'AT_K(b, "share_html", "")',
            Lit('\n        </div>\n      </header>\n      '),
            'AT_K(b, "toc_html", "")',
            Lit('\n      <div class="post-content">\n'),
            'AT_K(b, "content", "")',
            Lit('\n      </div>\n      '),
            'AT_K(b, "tags_html", "")',
            Lit('\n      '),
            'AT_K(b, "footnotes_html", "")',
            Lit('\n      '),
            'AT_K(b, "backlinks_html", "")',
            Lit('\n    </article>\n    '),
            'AT_K(b, "related_html", "")'),
    ], '// 文章页 body_content（对齐 generator.py:253）')

    src += fn('STANDALONE_BODY', 'page_title, content', [
        '// Python（generator.py:452-459）的 body_content',
        cat(
            Lit('<article class="post standalone">\n      <header class="post-header">'
                '\n        <h1 class="post-title">'),
            'page_title',
            Lit('</h1>\n      </header>\n      <div class="post-content">\n'),
            'content',
            Lit('\n      </div>\n    </article>')),
    ], '// 独立页 body_content（对齐 generator.py:452）')

    # ── render_skeleton 的 opts ──────────────────────────────────
    # Python 传的是**关键字参数**；WLWL 侧组装成同名键的 DICT。
    src += fn('SKEL_OPTS', 'ctx, cfg, page_title, desc, body, og, ld, mermaid', [
        '// 对齐 generate_article_html / generate_standalone_html 里 render_skeleton(...) 的实参',
        '// ⚠ page_title / desc 传进来时**已** escape 过，而 render_skeleton 会再 escape 一次',
        '//   ⇒ 产物里是双重转义（这是 Python 的真实行为，见文件头实测⑤）',
        '// ⚠ has_dark / mermaid_script 在骨架里没被用到（骨架无 $has_dark 占位符），',
        '//   但 Python 侧确实传了 ⇒ 这里照传，别自作主张删。',
        'LET MUT(o, DICT())',
        'SET(o, INDEX_SET(o, "lang", AS_STR(AT_K(cfg, "lang", "zh-CN"))))',
        'SET(o, INDEX_SET(o, "site_title", AT_K(ctx, "site_title", "")))',
        'SET(o, INDEX_SET(o, "page_title", page_title))',
        'SET(o, INDEX_SET(o, "description", desc))',
        'SET(o, INDEX_SET(o, "body_content", body))',
        'SET(o, INDEX_SET(o, "theme_css", AT_K(ctx, "theme_css", "")))',
        'SET(o, INDEX_SET(o, "dark_css", AT_K(ctx, "dark_css", "")))',
        'SET(o, INDEX_SET(o, "has_dark", AT_K(ctx, "has_dark", FALSE)))',
        'SET(o, INDEX_SET(o, "nav_links", AT_K(ctx, "nav", "")))',
        'SET(o, INDEX_SET(o, "theme_toggle", AT_K(ctx, "theme_toggle", "")))',
        'SET(o, INDEX_SET(o, "footer_text", AS_STR(AT_K(cfg, "footer_text", ""))))',
        'SET(o, INDEX_SET(o, "dark_mode_meta", AT_K(ctx, "dark_mode_meta", "")))',
        'SET(o, INDEX_SET(o, "pwa_meta", AT_K(ctx, "pwa_meta", "")))',
        'SET(o, INDEX_SET(o, "vt_meta", AT_K(ctx, "vt_meta", "")))',
        'SET(o, INDEX_SET(o, "og_html", og))',
        'SET(o, INDEX_SET(o, "json_ld_html", ld))',
        'SET(o, INDEX_SET(o, "pwa_manifest", AT_K(ctx, "pwa_manifest", "")))',
        'SET(o, INDEX_SET(o, "dark_mode_script", AT_K(ctx, "dark_mode_script", "")))',
        'SET(o, INDEX_SET(o, "search_script", AT_K(ctx, "search_script", "")))',
        'SET(o, INDEX_SET(o, "mermaid_script", mermaid))',
        'o',
    ], '// render_skeleton 的 opts（对齐 Python 的关键字实参）')

    # ── ARTICLE_PAGE ─────────────────────────────────────────────
    ctx_opts = (
        'INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), '
        '"config", cfg), "theme_css", AS_STR(AT_K(opts, "theme_css", ""))), '
        '"dark_css", AS_STR(AT_K(opts, "dark_css", ""))), "has_dark", '
        '==(AT_K(opts, "has_dark", FALSE), TRUE)), "standalones", pages), '
        '"current_path", CAT("/article/", slug, ".html"))'
    )
    ld_opts = (
        'INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), '
        '"title", title), "description", summary), "date", date), "slug", slug), '
        '"tags", tag_list), "site_url", site_url), "author", '
        'AS_STR(AT_K(cfg, "site_author", "")))'
    )

    src += fn('ARTICLE_PAGE', 'opts', [
        '// opts 键（与 generate_article_html 的具名参数同名）：',
        '//   title date slug content tags(STRING，逗号分隔) summary category',
        '//   status(默认 "published") config(DICT) theme_css dark_css has_dark',
        '//   standalones(ARRAY[DICT]，键 title/file) toc_html footnotes_html',
        '//   backlinks_html related_articles(ARRAY[DICT]，键 title/date/file)',
        'LET(title, AS_STR(AT_K(opts, "title", "")))',
        'LET(date, AS_STR(AT_K(opts, "date", "")))',
        'LET(slug, AS_STR(AT_K(opts, "slug", "")))',
        'LET(content, AS_STR(AT_K(opts, "content", "")))',
        'LET(tags, AS_STR(AT_K(opts, "tags", "")))',
        'LET(summary, AS_STR(AT_K(opts, "summary", "")))',
        'LET(category, AS_STR(AT_K(opts, "category", "")))',
        'LET(status, AS_STR(AT_K(opts, "status", "published")))',
        'LET(pages, AS_ARR(AT_K(opts, "standalones", [])))',
        'LET(toc, AS_STR(AT_K(opts, "toc_html", "")))',
        'LET(foot, AS_STR(AT_K(opts, "footnotes_html", "")))',
        'LET(back, AS_STR(AT_K(opts, "backlinks_html", "")))',
        'LET(related, AS_ARR(AT_K(opts, "related_articles", [])))',
        'LET(cfg, CFG_OF(opts))',
        '// Python: page_title = escape_html(title) 等三处',
        'LET(page_title, ESCAPE_HTML(title))',
        'LET(safe_date, ESCAPE_HTML(date))',
        'LET(safe_summary, ESCAPE_HTML(summary))',
        'LET(tag_list, TAG_LIST(tags))',
        'LET(site_url, AS_STR(AT_K(cfg, "site_url", "")))',
        '// Python: `if cfg.site_url:` ⇒ 空则 og / JSON-LD / share 全不输出',
        'LET MUT(og, "")',
        'LET MUT(ld, "")',
        'LET MUT(share, "")',
        C('IF', '!=(site_url, "")', [
            '// og:url 与 JSON-LD 的 url 都走 rstrip("/")',
            'LET(article_url, CAT(RSTRIP_SLASH(site_url), "/article/", slug, ".html"))',
            'SET(og, ARTICLE_OG(page_title, safe_summary, article_url))',
            '// ⚠ JSON_LD 自己也会在 site_url 为空时返回 ""（卡片要求不加门控，这里不重复判）',
            'SET(ld, JSON_LD(' + ld_opts + '))',
            '// ⚠ share 的 url **不** rstrip（见文件头实测④）',
            'SET(share, SHARE_HTML(page_title, safe_summary, ESCAPE_HTML(site_url), slug))',
        ], [
            'NULL',
        ]),
        'LET(ctx, COMMON_CONTEXT(' + ctx_opts + '))',
        'LET MUT(b, DICT())',
        'SET(b, INDEX_SET(b, "page_title", page_title))',
        'SET(b, INDEX_SET(b, "safe_date", safe_date))',
        'SET(b, INDEX_SET(b, "category_html", CATEGORY_HTML(category)))',
        'SET(b, INDEX_SET(b, "draft_badge", DRAFT_BADGE(status)))',
        'SET(b, INDEX_SET(b, "share_html", share))',
        'SET(b, INDEX_SET(b, "toc_html", toc))',
        'SET(b, INDEX_SET(b, "content", content))',
        'SET(b, INDEX_SET(b, "tags_html", TAGS_HTML(tag_list)))',
        'SET(b, INDEX_SET(b, "footnotes_html", foot))',
        'SET(b, INDEX_SET(b, "backlinks_html", back))',
        'SET(b, INDEX_SET(b, "related_html", RELATED_HTML(related)))',
        '// Python 传 description=safe_summary（不是 summary）',
        'RENDER_SKELETON("article", SKEL_OPTS(ctx, cfg, page_title, safe_summary, '
        'ARTICLE_BODY(b), og, ld, MERMAID()))',
    ], '// 文章页（对齐 generator.py:154 generate_article_html）')

    # ── STANDALONE_PAGE ──────────────────────────────────────────
    ctx_opts_s = (
        'INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), '
        '"config", cfg), "theme_css", AS_STR(AT_K(opts, "theme_css", ""))), '
        '"dark_css", AS_STR(AT_K(opts, "dark_css", ""))), "has_dark", '
        '==(AT_K(opts, "has_dark", FALSE), TRUE)), "standalones", pages), '
        '"current_path", "/")'
    )
    src += fn('STANDALONE_PAGE', 'opts', [
        '// opts 键：title content summary config theme_css dark_css has_dark standalones',
        '// ⚠ Python 侧 `${standalones}` 只是导航用；current_path 是 "/"（不是 /standalone/…）',
        'LET(title, AS_STR(AT_K(opts, "title", "")))',
        'LET(content, AS_STR(AT_K(opts, "content", "")))',
        'LET(summary, AS_STR(AT_K(opts, "summary", "")))',
        'LET(pages, AS_ARR(AT_K(opts, "standalones", [])))',
        'LET(cfg, CFG_OF(opts))',
        'LET(page_title, ESCAPE_HTML(title))',
        'LET(safe_summary, ESCAPE_HTML(summary))',
        'LET(site_url, AS_STR(AT_K(cfg, "site_url", "")))',
        'LET MUT(og, "")',
        C('IF', '!=(site_url, "")', [
            'SET(og, STANDALONE_OG(page_title, safe_summary))',
        ], [
            'NULL',
        ]),
        'LET(ctx, COMMON_CONTEXT(' + ctx_opts_s + '))',
        '// ⚠ 独立页**没有** mermaid，也**没有** JSON-LD（Python 侧都没传）',
        'RENDER_SKELETON("standalone", SKEL_OPTS(ctx, cfg, page_title, safe_summary, '
        'STANDALONE_BODY(page_title, content), og, "", ""))',
    ], '// 独立页（对齐 generator.py:429 generate_standalone_html）')

    A('EXPORT(["ARTICLE_PAGE", "STANDALONE_PAGE"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
