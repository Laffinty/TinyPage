"""合成站点语料 —— 构建编排层（`tp/bin/build.wll`）端到端对照用的**唯一**数据源。

⚠ **本文件刻意不叫 `gen_*.py`**：CI 第 3 步会把所有 `gen_*.py` 重跑一遍并要求
`git diff` 为空，而本模块是**被两个生成器共用**的数据源，自己不产出任何文件。

三方共用同一份 spec：

```
site_corpus.spec()          →  DICT（可 JSON 序列化）     语料的唯一真相
        │
        ├── gen_build_baseline.py  →  在临时目录里 build_tree() → 跑**真 Python** → 夹具
        └── gen_test_build.py      →  把 spec 灌进 test_build.wll → WLWL 在 TEMP_DIR() 里 build_tree()
```

## 语料的硬约束（每一条都有原因，改语料前先读）

1. **确定性**：没有随机、没有时间戳、没有 `iterdir()` 顺序依赖 ⇒ 两个生成器的产物恒定。
2. **文章文件名必须是 `YYYY-MM-DD-<slug>.html`**：`security.validate_filename` 的
   `SAFE_FILENAME_PATTERN` + 「按 `-` 切至少 4 段」都要求它；且**日期全不相同** ——
   `list_articles` 的排序是「按日期倒序**稳定**排序」，日期相同的两篇会保持**输入顺序**，
   而 Python 的输入顺序来自 `iterdir()`、WLWL 的来自 `LIST_DIR`（按名排序）
   ⇒ 日期相同就会掩盖/制造差异。
3. **每篇都写 `summary`**：`parse_meta` 在 summary 为空时会走
   `_extract_body_from_html`（剥标签 + `\\s+` 压空白 + 截 200 字）自动生成摘要，
   那条分支没有对应的 `.wll` 积木（不在 S2 范围内）⇒ 语料一律显式给 summary。
4. **正文里不放围栏代码块**：`render_markdown` 之后 Python 还会跑
   `highlight_code_blocks`（Pygments），而业主已裁定**代码高亮改前端**（D7）
   ⇒ 语料不放 ```` ```lang ```` 就不会触发它，两侧同为恒等变换。
5. **标签里不放非 ASCII 空白**（NBSP / 全角空格）：`tags` 的 `t.strip()` 是 Python 的
   Unicode 口径（`list_page.wll` 已按 PY_STRIP 修正，但 `search_index.wll` 侧仍在修，
   见 D1）⇒ 不让它污染本轮结论。
6. **每篇最多一个脚注**：Python 的 `process_footnotes` 用 `set` 收集 key，
   两篇以上时**输出顺序跨进程不确定** ⇒ 夹具会漂。一个脚注时无所谓顺序。
7. **文件一律 LF、UTF-8、无 BOM**：Python 的 `read_text()` 会把 CRLF 归一成 LF，
   而 WLWL 的 `READ_FILE` 不转（tp/README 坑 23）⇒ 语料若含 CRLF，两侧读到的
   正文长度就不同。语料由本模块以 `newline=""` 写出，两侧读到的都是 LF。
8. **`$` 可以随便用，`${` 也行**：`gen_build.py` / `gen_test_build.py` 的 `wl()` 会把
   `$` 转义成 `\\$`（WLWL 字面量里 `$` 是插值，README 坑 32）。
9. ⚠ **行内代码（`` `…` ``）里不要出现 `<` `>` `"` `&`**：`md_inline.wll` 目前
   **不转义**行内代码的内容，而 mistune（`escape=True`）会转义。本机实测（2026-11-02）：
   | 输入 | mistune | `tp/lib/md_inline.wll` |
   |---|---|---|
   | ``a `x<y&z"q` b`` | `<code>x&lt;y&amp;z&quot;q</code>` | `<code>x<y&z"q</code>` |
   | ``x `a & b` y`` | `<code>a &amp; b</code>` | `<code>a & b</code>` |

   这是 `md_inline.wll` 的**未登记缺口**（不是本卡的编排问题，也不在本人可改范围）。
   ⇒ **2026-11-02 已在 md_inline.wll 修好**，语料已把它放回来（见 `_body` 里的
   「转义与编码边界」那一段）；下面两个 dict 保留为**修复记录 + 复现命令**。

## 覆盖清单（卡 S2-构建 要求逐条对应）

| 要求 | 落在哪 |
|---|---|
| 至少 12 篇 + 2 独立页 | 14 篇（13 published + 1 draft）+ 2 独立页 |
| 草稿 | `2026-03-02-draft-wip`（最新日期，若未被过滤会排第一） |
| 多标签多分类 | 3 个分类（含 CJK 名）、多篇 2~3 标签 |
| 脚注 | 4 篇带 `[^n]` |
| 多级标题 | `##` / `###` / `####`（`####` 不进 TOC ⇒ 钉住 2~3 级过滤） |
| 双链 | 3 篇互相 `[[标题]]`，另有 1 条指向不存在的标题（走 slug 回退） |
| 中文标题 | 大部分标题含 CJK |
| 超长标题 | 1 篇 100+ 字符（触发列表页 `title[:80]`）、1 个独立页 30+ 字符（触发导航 `title[:20]`） |
| 分页 | 13 published ⇒ `page_size=10` ⇒ 2 页（第 2 页 3 篇） |
| 无标签无分类 | 1 篇（`tags=""` / `category=""`） |
"""

SITE_URL = 'https://tiny.example.com'

# 已知缺口（不是本卡的编排问题）：md_inline.wll 不转义行内代码的内容。
# 语料刻意避开它（见模块 docstring 的约束 9）；缺口本身登记在此，供 lib 侧修复后回归。
KNOWN_GAP_INLINE_CODE = {
    'status': 'FIXED 2026-11-02（md_inline 的 restore_code 改用 MD_ESCAPE）',
    'owner': 'tp/lib/md_inline.wll',
    'repro': [
        {'src': 'a `x<y&z"q` b',
         'mistune': '<p>a <code>x&lt;y&amp;z&quot;q</code> b</p>',
         'wlwl': '<p>a <code>x<y&z"q</code> b</p>'},
        {'src': 'x `a & b` y',
         'mistune': '<p>x <code>a &amp; b</code> y</p>',
         'wlwl': '<p>x <code>a & b</code> y</p>'},
    ],
    'impact': '只在行内代码里出现 < > " & 时可见；正文其它位置（段落 / 链接 href / 标题）'
              '两侧一致。',
}

# 已知缺口 2（同一模块）：md_inline.wll 不 percent-encode 链接目标里的非 ASCII，
# mistune 会（`/article/中文.html` → `/article/%E4%B8%AD%E6%96%87.html`）。
# ⇒ 语料曾用 ASCII 标题避开它；2026-11-02 已修，`_body` 里放了 CJK 目标链接。
KNOWN_GAP_LINK_PERCENT = {
    'status': 'FIXED 2026-11-02（新增 URL_QUOTE，对齐 mistune.util.escape_url）',
    'owner': 'tp/lib/md_inline.wll',
    'repro': [
        {'src': 'x [a](/article/中文.html) y',
         'mistune': '<p>x <a href="/article/%E4%B8%AD%E6%96%87.html">a</a> y</p>',
         'wlwl': '<p>x <a href="/article/中文.html">a</a> y</p>'},
    ],
    'impact': '只影响非 ASCII 的链接目标；ASCII 目标（含 query 里的 &）两侧一致。',
}

# 站点根下的固定布局（与 tinypage 的 Config 属性一致）
ARTICLE_DIR = 'pages/article'
STANDALONE_DIR = 'pages/standalone'
THEME_DIR = 'themes/default'

# 语料里「旧 html」正文的占位 —— 真正的正文在同名 .md 里（get_raw_content 优先读 .md）。
# 唯一会**留下来**的是草稿：它不进 list_articles ⇒ 永远不会被重新生成。
PLACEHOLDER_BODY = '<p>旧正文占位：真实正文在同名 .md 里。</p>'

THEME_CSS = """/* 语料主题 —— 只求确定性，不求好看 */
:root { --fg: #222; --bg: #fff; }
body { color: var(--fg); background: var(--bg); margin: 0; }
.post-title { font-size: 1.5rem; }
"""

THEME_DARK_CSS = """/* 语料暗色主题（只用于让 has_dark 为真） */
body { color: #eee; background: #111; }
"""


# ── 正文片段 ────────────────────────────────────────────────────────────
def _body(heading, paras, footnote=None, wikilink=None):
    """拼一篇正文：H2 + 段落 + 可选 H3/H4 + 脚注 + 双链。"""
    out = ['## ' + heading, '']
    for p in paras:
        out.append(p)
        out.append('')
    out.append('### 小节：格式')
    out.append('')
    out.append('这一节用来钉住行内语法：**粗体**、*斜体*、`行内代码`，'
               '以及一个[外链](https://example.org/a?b=1&c=2)。')
    out.append('')
    # ⚠ 2026-11-02：这两处曾因 md_inline 的缺陷被语料**避开**，现已修好并放回。
    #   · 行内代码里的 `<` `&` `"` 必须被转义
    #   · 链接目标的 CJK 必须 percent-encode
    #   · 单引号**不**转义（mistune 口径）
    out.append('转义与编码边界：`x<y&z"q` 与 `it\'s`，'
               '以及一个[中文链接](/article/中文.html)。')
    out.append('')
    if wikilink:
        out.append('延伸阅读：' + wikilink + '。')
        out.append('')
    out.append('#### 四级标题（不进 TOC）')
    out.append('')
    out.append('四级标题落在 `build_toc_html(2, 3)` 的过滤范围之外。')
    out.append('')
    out.append('> 引用块：一行也要能渲染成 blockquote。')
    out.append('')
    out.append('- 列表项甲')
    out.append('- 列表项乙')
    out.append('- 列表项丙')
    out.append('')
    if footnote:
        out.append('正文里引用一次脚注[^1]。')
        out.append('')
        out.append('[^1]: ' + footnote)
        out.append('')
    return '\n'.join(out)


# ── 14 篇文章的元数据（顺序即 spec 里的书写顺序，不影响产物）────────────
# 字段与 `_meta_header(title, date, slug, tags, summary, category, status)` 同名。
LONG_TITLE = ('一个被刻意写得很长的文章标题用来钉住列表页的八十码点截断以及'
              '导航栏的二十码点截断确保超长标题不会把布局撑破也不会在截断处产生'
              '半个字符或多余的省略号这是原实现的行为我们照抄不误')

ARTICLES = [
    dict(
        file='2026-01-05-site-launch.html',
        title='发布：站点上线', date='2026-01-05 09:30', slug='site-launch',
        tags='公告,静态站点,Tech', summary='站点第一次上线时的说明。',
        category='Tech', status='published',
        body=_body('我们上线了', [
            '这是站点上线后的第一篇说明，正文放在同名的 `.md` 文件里。',
            '正文经过 `PROCESS_FOOTNOTES` → `EXTRACT_HEADINGS` → '
            '`PARSE_BIDIRECTIONAL_LINKS` → `RENDER_MD` → `ADD_HEADING_IDS` 五步。',
        ], footnote='编排顺序不可调换：脚注必须先于标题提取。'),
    ),
    dict(
        file='2026-01-09-markdown-notes.html',
        title='Markdown 笔记：脚注与标题层级', date='2026-01-09 14:05',
        slug='markdown-notes', tags='Markdown,笔记',
        summary='脚注与标题层级的边界情况。', category='Notes',
        status='published',
        body=_body('脚注与标题', [
            '标题提取在脚注处理**之后**：`[^1]:` 定义行已经不在文本里了，'
            '否则它会被当成普通段落。',
        ], footnote='脚注定义行里的 `#` 不会被当成标题。',
            wikilink='[[双向链接与数字花园]]'),
    ),
    dict(
        file='2026-01-12-wikilink-garden.html',
        title='双向链接与数字花园', date='2026-01-12 08:00',
        slug='wikilink-garden', tags='双链,笔记,Markdown',
        summary='双向链接的两个出口：命中的标题与未命中的标题。',
        category='Tech', status='published',
        body=_body('双向链接', [
            '命中的双链解析成文章页的 URL，未命中的回退到「按标题 slug 拼出来的」URL。',
        ], wikilink='回链：[[发布：站点上线]]；不存在的：[[no-such-page]]'),
    ),
    dict(
        file='2026-01-16-long-title.html',
        title=LONG_TITLE, date='2026-01-16 11:11', slug='long-title',
        tags='测试,长标题', summary='超长标题的截断行为。', category='Notes',
        status='published',
        body=_body('超长标题', [
            '列表页用 `title[:80]`、导航用 `title[:20]`、页面标题不截断。',
        ]),
    ),
    dict(
        file='2026-01-20-css-grid.html',
        title='CSS Grid 布局速查', date='2026-01-20 20:20', slug='css-grid',
        tags='CSS,前端', summary='Grid 的两条心智模型。', category='Tech',
        status='published',
        body=_body('Grid', [
            '轨道与区域是两套正交的模型。',
        ]),
    ),
    dict(
        file='2026-01-24-life-notes.html',
        title='生活片段：三件小事', date='2026-01-24 21:40', slug='life-notes',
        tags='随笔', summary='三件不值得单独写的小事。', category='生活',
        status='published',
        body=_body('三件小事', [
            '冬天的太阳、修好的椅子、没读完的书。',
        ]),
    ),
    dict(
        file='2026-02-01-no-tags.html',
        title='无标签无分类的文章', date='2026-02-01 07:00', slug='no-tags',
        tags='', summary='既没有标签也没有分类。', category='',
        status='published',
        body=_body('什么都没有', [
            '标签为空串时不出标签行；分类为空串时不进任何分类页，'
            '也不进 sitemap 的分类段。',
        ]),
    ),
    dict(
        file='2026-02-04-footnotes-deep.html',
        title='脚注的边界情况', date='2026-02-04 12:00', slug='footnotes-deep',
        tags='Markdown,笔记', summary='脚注定义出现在正文中间的情况。',
        category='Notes', status='published',
        body=_body('脚注边界', [
            '定义行被摘掉之后，剩下的文本才是 Markdown 的输入。',
        ], footnote='这条脚注的文字里含 `&` 与 `<`，两侧都必须逐字节一致。'),
    ),
    dict(
        file='2026-02-08-search-design.html',
        title='站内搜索设计', date='2026-02-08 15:15', slug='search-design',
        tags='搜索,前端', summary='索引只含摘要不含正文。', category='Tech',
        status='published',
        body=_body('搜索索引', [
            '`search-index.json` 的每条记录只有 title / summary / url / date / '
            'tags / category 六个键。',
        ]),
    ),
    dict(
        file='2026-02-12-theme-dark.html',
        title='暗色主题与配色', date='2026-02-12 18:45', slug='theme-dark',
        tags='CSS,主题,前端', summary='暗色主题靠一份额外的 CSS。',
        category='Tech', status='published',
        body=_body('暗色', [
            '`theme.dark.css` 存在 ⇒ `has_dark` 为真 ⇒ 页面里多出 '
            '`color-scheme` meta、形态脚本与主题切换按钮。',
        ]),
    ),
    dict(
        file='2026-02-16-writing-habit.html',
        title='写作习惯：每天两百字', date='2026-02-16 06:30',
        slug='writing-habit', tags='随笔,习惯', summary='两百字的下限。',
        category='生活', status='published',
        body=_body('两百字', [
            '写不出来的时候也写两百字，写完再决定要不要留下。',
        ]),
    ),
    dict(
        file='2026-02-20-robots.html',
        title='robots 与站点地图', date='2026-02-20 10:10', slug='robots',
        tags='SEO', summary='robots.txt 的 Sitemap 行不回落 localhost。',
        category='Notes', status='published',
        body=_body('抓取协议', [
            'Sitemap 那一行用的是 site_url 或空串，**不**回落 localhost。',
        ]),
    ),
    dict(
        file='2026-02-24-pagination.html',
        title='分页：第二页的上一页指向哪', date='2026-02-24 09:00',
        slug='pagination', tags='前端,SEO,测试',
        summary='第 2 页的 `prev_url` 是 `/`。', category='Tech',
        status='published',
        body=_body('分页', [
            '13 篇 + `page_size=10` ⇒ 两页；第 2 页的上一页链接是 `/`（不是 '
            '`/list/1.html`）。',
        ], wikilink='[[站内搜索设计]]'),
    ),
    dict(
        file='2026-03-02-draft-wip.html',
        title='未完成的草稿（不该出现在任何列表里）', date='2026-03-02 23:59',
        slug='draft-wip', tags='测试,草稿', summary='这是一篇草稿。',
        category='Tech', status='draft',
        body=_body('草稿', [
            '如果编排层漏了草稿过滤，它会以最新日期出现在列表首页第一项。',
        ]),
    ),
]

# ── 2 个独立页 ────────────────────────────────────────────────────────
# ⚠ 真 Python 的 `_extract_body_from_html` 会剥标签并把所有空白压成单空格
#   ⇒ 独立页正文实际是**一行**文本，块级 Markdown 语法在它身上本来就不会生效。
STANDALONES = [
    dict(
        file='about.html',
        title='关于本站',
        summary='这个站点是干什么的。',
        body='关于本站。这里是一份用于端到端对照的合成语料，不是真实站点。',
    ),
    dict(
        file='colophon-long-title.html',
        title='版权与致谢以及一份特意写长了的独立页标题用来钉住导航里的二十码点截断',
        summary='致谢与版权说明。',
        body='致谢。构建编排层的对齐工作参考了真 Python 的生成顺序，'
             '因此这份语料的产物可以逐字节比较。',
    ),
]


def _meta_header(a):
    """`content._meta_header` 的等价物（语料文件里那 7 行注释）。"""
    from html import escape as _esc
    keys = ('title', 'date', 'slug', 'tags', 'summary', 'category', 'status')
    return ''.join('<!-- %s: %s -->\n' % (k, _esc(a[k], quote=True).strip())
                   for k in keys)


def _article_html(a):
    """语料里的文章 html：7 行元数据 + 一段占位正文（真实正文在同名 .md）。"""
    return (_meta_header(a) +
            '<!DOCTYPE html>\n<html><body>\n'
            '<div class="post-content">' + PLACEHOLDER_BODY + '</div>\n'
            '</body></html>\n')


def _standalone_html(p):
    return ('<!-- title: %s -->\n<!-- summary: %s -->\n' %
            (p['title'], p['summary']) +
            '<!DOCTYPE html>\n<html><body>\n'
            '<div class="post-content">' + p['body'] + '</div>\n'
            '</body></html>\n')


def config():
    """传给 `BUILD(opts)["config"]` 的 DICT —— 键名与 `tinypage/config.py` 的 `Config` 同名。

    只列与**页面产物**有关的键；`Config` 的其余字段（端口、AI、密码）不参与渲染。
    ⚠ `root_dir` / `theme_dir` **不在这里**：它们是**编排层**按 `root` 推导出来的
    （`root_dir = <out>`、`theme_dir = <root>/themes/<theme_name>`），
    与 Python 侧 `Config.root_dir` / `Config.theme_dir` 的属性口径一致。
    """
    return {
        'site_title': '合成语料站',
        'site_description': '用于构建编排层端到端对照的站点',
        'site_url': SITE_URL,
        'site_author': '布布',
        'footer_text': 'Powered by TinyPage',
        'lang': 'zh-CN',
        'theme_name': 'default',
        'page_size': 10,
        'max_file_size': 10 * 1024 * 1024,
        'max_title_length': 200,
        'max_content_length': 50000,
        'enable_pwa': True,
        'enable_dark_mode': True,
        'enable_search': True,
        'enable_rss': True,
        'enable_sitemap': True,
        'enable_view_transitions': True,
        'pwa_short_name': '合成语料站',
        'pwa_theme_color': '#2c3e50',
        'pwa_bg_color': '#ffffff',
    }


def spec():
    """完整语料：`{config, files}`。`files` 的键是**相对站点根**的 POSIX 路径。

    值一律是**字面内容**（UTF-8 / LF / 无 BOM）—— 两个生成器都按字节写盘。
    """
    files = {}
    for a in ARTICLES:
        html = ARTICLE_DIR + '/' + a['file']
        files[html] = _article_html(a)
        files[html[:-len('.html')] + '.md'] = a['body']
    for p in STANDALONES:
        files[STANDALONE_DIR + '/' + p['file']] = _standalone_html(p)
    files[THEME_DIR + '/theme.css'] = THEME_CSS
    files[THEME_DIR + '/theme.dark.css'] = THEME_DARK_CSS
    return {'config': config(), 'files': dict(sorted(files.items()))}


def build_tree(root):
    """把 spec 写到 `root`（POSIX 相对路径 → 真实目录）。返回实际写出的路径列表。"""
    import os
    from pathlib import Path
    root = Path(root)
    written = []
    for rel, text in spec()['files'].items():
        p = root.joinpath(*rel.split('/'))
        p.parent.mkdir(parents=True, exist_ok=True)
        # newline="" ⇒ 不做换行转换（坑 23：两侧读到的都必须是 LF）
        with open(p, 'w', encoding='utf-8', newline='') as f:
            f.write(text)
        written.append(p)
    return written


# 供两个生成器断言用（写错语料时尽早炸，而不是留到逐字节对照时才红）
assert len(ARTICLES) >= 12, len(ARTICLES)
assert sum(1 for a in ARTICLES if a['status'] == 'draft') == 1
assert len(STANDALONES) == 2
assert len({a['date'] for a in ARTICLES}) == len(ARTICLES), '日期必须互不相同'
assert len({a['file'] for a in ARTICLES}) == len(ARTICLES)
