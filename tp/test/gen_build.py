"""生成 `tp/bin/build.wll` —— **构建编排层**（S2 收尾的核心）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**这一层为什么存在**：S2 的 5 个产物模块（article_page / list_page / feeds /
search_index / theme …）各自都对得上真 Python，但**没有任何东西把它们接起来**。
本模块补的就是那个「组装」环节：读目录 → 解析元数据 → 排序 → 逐篇渲染 → 逐类产页 →
写盘 → 回报统计。

**对齐目标（真 Python 源码树）**：
```
BUILD(opts) == cli.py:96-144 的 build 主流程 + generator.py:628 generate_static_pages
               + content.py:543 regenerate_all_articles
```

## 编排顺序（照抄，不可调换）

```
list_articles(article_dir)          content.py:153  ← 草稿在这里被过滤掉（include_drafts=False）
list_standalones(standalone_dir)    content.py:674
        │
        ├─ 每篇文章：get_raw_content  content.py:493
        │     .md 存在 ⇒ 读它；否则 DECODE_CONTENT(html)；再否则 summary
        │         ↓ 五步管线（content.py:283-305，**顺序不可调换**）
        │     ① PROCESS_FOOTNOTES ② EXTRACT_HEADINGS ③ PARSE_BIDIRECTIONAL_LINKS
        │     ④ RENDER_MD         ⑤ ADD_HEADING_IDS
        │     （⑥ highlight_code_blocks 业主已裁决改前端 ⇒ 不做）
        │     相关文章 / 反向链接  content.py:200 / 375
        │         ↓
        │     ARTICLE_PAGE(…)，写回 <article_dir>/<file>（元数据头 + 整页）
        │
        ├─ 列表页 p=1..pages        generator.py:658   ← index.html / list/{n}.html
        ├─ 分类页（已过滤、已排序）  generator.py:675
        ├─ 独立页                  generator.py:695   ← 抽 post-content、渲染、写回同名文件
        ├─ search.html + search-index.json   generator.py:719  ← **已过滤**列表
        ├─ rss.xml                 generator.py:729  ← **已过滤**列表（再按 is_published 过一遍）
        ├─ sitemap.xml             generator.py:734  ← 见下面「草稿口径」
        └─ robots.txt              generator.py:739
```

## 草稿口径（本卡最容易搞错的一条）

| 消费者 | 喂什么 | 依据 |
|---|---|---|
| 文章页 / 列表页 / 分类页 / 搜索页 | **已过滤** | `list_articles(include_drafts=False)`，`content.py:189` |
| `SEARCH_INDEX()` | **已过滤** | `cli.py:139` 传的就是过滤后的列表 |
| `RSS()` | **已过滤**（再按 `is_published` 筛一遍） | `generator.py:730` |
| `SITEMAP()` | **已过滤** | `generator.py:736` 收到的是 `cli.py:141` 那份**已过滤**列表 |

⚠ **这里与计划书的一条断言相反**：计划写「`generator.py:736` 传的是未过滤
`articles` ⇒ 草稿在 sitemap 里」。那句话只看 `generate_sitemap` 的**函数体内**；
往上追一层：`generate_static_pages(articles, …)` 的 `articles` 来自
`cli.py:139 list_articles(cfg.article_dir, cfg.max_file_size)`（`include_drafts`
默认 `False`），`cli.py:189` / `server.py:74` / `admin/actions.py` 的 8 处调用**全都**如此
⇒ 真实现里草稿**不会**进 sitemap。本机实测（`gen_build_baseline.py` 的
`_check_draft_absent` 就是这条的守卫）：14 篇语料里唯一那篇草稿在
`index.html` / `rss.xml` / `search-index.json` / `sitemap.xml` / 分类页里**全都不出现**。
⇒ 本实现按**实测行为**对齐（否则 sitemap.xml 会永久差一个 `<url>`）。

## ⚠ 顶层绑定是「跨模块共享」的 —— 本文件所有顶层名字都带 `TPB_` 前缀

实测（2026-11-02，两个探针文件）：**模块顶层的 `LET` 写进的是同一张全局表**，
后绑定的赢 —— 即使那个名字是**被 import 的模块自己的私有名字**。

```
probe_x.wll:      LET(HELPER, FUN((n), (+(n, 1))));
                  LET(CALLER, FUN((n), (STR(HELPER(n)))))     // 期望 6
probe_entry3.wll: IMPORT("./probe_x.wll", ["CALLER"]);
                  LET(HELPER, FUN((n), (STR(*(n, 100)))));
                  PRINT(CALLER(5))                             // 实际 "entry:500"
```

本卡就撞在这上面：`feeds.wll` 内部有一个 `ISO_DATE(art)`（从 `date_obj` 取
ISO 串），而本文件原先也叫 `ISO_DATE(d)`（从日期串拼）。**后者的绑定覆盖了前者**
⇒ `RSS()` 内部拿文章 DICT 去调 `SUB(d, 0, 10)` ⇒ `E0030: SUB: expected STRING as
first arg, got dict`，而诊断指的位置恰好是本文件那个 `ISO_DATE` 的**定义行**
（这条读数反过来证实了「全局共享」这个结论）。

⇒ 铁律：**入口/编排层不要用裸通用名**（`AS_STR` / `TAG_LIST` / `ISO_DATE` /
`PY_STRIP` 这些 `tp/lib` 里全都有私有同名实现）。本文件一律 `TPB_` 前缀。
⚠ 这也意味着**不能靠「lib 内部实现」当黑盒** —— 重名会让黑盒里换掉一个零件。

## 与 Python 的边界（本模块**不**重写积木）

页面骨架 / 上下文 / 转义 / 排序 / 主题加载 / Markdown / 脚注 / TOC / 双链 / 搜索索引 /
RSS 全在 `tp/lib/*.wll` 里 —— 本模块只**调**它们。本模块**自己实现**的只有 Python 里
同样属于「编排」的四段：`build_article_title_map`（bidirectional_links.py:104）、
`build_backlink_index`（content.py:375）、`build_backlinks_html`
（bidirectional_links.py:67）、`find_related_articles`（content.py:200）、
`_extract_body_from_html`（content.py:53）。

## 已登记的已知差异 / 未覆盖分支

- **D-NL**：Python 的 `write_text()` 在 Windows 上把 `\\n` 翻成 `\\r\\n`；本模块写 LF。
- **D7**：主题 CSS 不追加 Pygments（`theme.wll` 同款）。
- **未覆盖**：`parse_meta` 在 `summary` 为空时的自动摘要；`get_raw_content` 的
  **懒迁移**（写 `.md`）与「从渲染页 post-content 里恢复正文」两级回退 ——
  语料每篇都有 `.md`，本模块只实现 `.md → DECODE_CONTENT → summary` 三步。
- **日期合法性**：Python 用 `strptime(date[:16], "%Y-%m-%d %H:%M")`（`2 月 31 日` 会失败）；
  本模块用正则判「形状 + 各段取值范围」，**不做**月长 / 闰年校验。
- **`incremental`**：接受但忽略（走全量）。真 Python 的 `--incremental` 只是少写几个
  文件、不产生新产物形态，与本卡的「一次完整构建逐字节对齐」无关。

用法：python gen_build.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'bin', 'build.wll')

# 顶层绑定一律加前缀（见 docstring「顶层绑定是跨模块共享的」）
PREFIXED = (
    'AS_DICT', 'AS_ARR', 'AS_STR', 'AS_INT', 'AS_BOOL',
    'CFG_DEFAULTS', 'CFG_OF',
    'PY_WS', 'WS_LEAD_RE', 'WS_TRAIL_RE', 'WS_RUN_RE', 'PY_STRIP',
    'READ_OR', 'FILE_SIZE', 'IS_DRAFT', 'UNIQ', 'COUNT_IN',
    'DATE_RE', 'VALID_DATE', 'ISO_DATE',
    'ARTICLE_REC', 'LIST_ARTICLES', 'PAGE_NAME_RE', 'LIST_STANDALONES',
    'DECODE_TEXT', 'RAW_OF', 'PIPELINE',
    'ARTICLE_MAP', 'BACKLINK_INDEX', 'BACKLINKS_HTML',
    'TAG_LIST', 'RELATED',
    'PC_OPEN', 'TAG_RE', 'STRIP_TAGS', 'COLLAPSE_WS', 'EXTRACT_BODY',
    'SHARED_OPTS', 'ARTICLE_OPTS',
    'SP',
)
_RENAME_RE = re.compile(r'\b(' + '|'.join(sorted(PREFIXED, key=len, reverse=True)) + r')\b')


def main():
    src = []
    raw = []

    def A(line):
        raw.append(line)

    # ══════════════════════════════════════════════════════════════════
    # 文件头
    # ══════════════════════════════════════════════════════════════════
    A('// tp/bin/build.wll —— 构建编排层（入口脚本 + 可被测试调用的 BUILD）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_build.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树）：')
    A('//   BUILD(opts) == cli.py:96-144 的 build 主流程')
    A('//                + generator.py:628 generate_static_pages')
    A('//                + content.py:543 regenerate_all_articles')
    A('//')
    A('// opts 键：')
    A('//   root        STRING   站点根目录（其下有 pages/）')
    A('//   config      DICT     键名同 tinypage/config.py 的 Config（可缺省）')
    A('//   incremental BOOLEAN  默认 FALSE；**接受但忽略**（走全量，见尾注）')
    A('//   out         STRING   产物根，默认 <root>/pages')
    A('// 返回：["articles": INT, "written": INT, "ok": BOOLEAN, "failed": INT, ...]')
    A('//')
    A('// 五步渲染管线（content.py:283-305，**顺序不可调换**）：')
    A('//   PROCESS_FOOTNOTES → EXTRACT_HEADINGS → PARSE_BIDIRECTIONAL_LINKS')
    A('//   → RENDER_MD → ADD_HEADING_IDS（代码高亮改前端，不做）')
    A('//')
    A('// ⚠ 草稿口径：只在编排层过滤**一次**，sitemap 也吃已过滤列表')
    A('//   （与真实现实测一致；计划书那条断言已被证伪，见 gen_build.py）。')
    A('//')
    A('// ⚠ **顶层绑定是跨模块共享的**（实测：后绑定覆盖被 import 模块的私有名）')
    A('//   ⇒ 本文件所有顶层名字都带 `TPB_` 前缀，绝不与 tp/lib 的同名私有实现撞车。')
    A('//   踩过的实例：本文件的「日期 → ISO 串」助手（现名 TPB_ISO_DATE）与 feeds.wll')
    A('//   内部一个**同名不同语义**的助手撞车（那边收的是文章 DICT、取 date_obj），')
    A('//   后者被本文件的绑定覆盖 ⇒ RSS() 拿 DICT 去 SUB ⇒ E0030，')
    A('//   而诊断恰好指到本文件那个助手的定义行 —— 这条读数反过来证实了「全局共享」。')
    A('//')
    A('// ⚠ 脚本模式：`wlwl run tp/bin/build.wll` ⇒ 默认参数跑一次。')
    A('//   判据用 **ARGS()**（不是 SCRIPT_PATH）：模块顶层执行期 SCRIPT_PATH() 返回')
    A('//   **正在加载的那个模块**（自己），import 与直接运行无法区分；')
    A('//   而 ARGS() 在 import 期是 `[]`、在入口脚本期含脚本路径。')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/build_baseline.json')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # IMPORT
    # ══════════════════════════════════════════════════════════════════
    A('IMPORT("wlwl:std.str", ["CAT", "INDEX_OF"]);')
    A('IMPORT("wlwl:std.text", ["TO_LOWER"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_TEST", "RE_REPLACE"]);')
    A('IMPORT("wlwl:std.math", ["MIN", "MAX"]);')
    A('IMPORT("wlwl:std.encode", ["UTF8_DECODE"]);')
    A('IMPORT("wlwl:std.env", ["ARGS"]);')
    A('IMPORT("wlwl:std.fs", ["READ_FILE", "WRITE_FILE_ATOMIC", "MKDIRS", "LIST_DIR",'
      ' "EXISTS", "PATH_JOIN", "PATH_BASE", "PATH_EXT", "FILE_META"]);')
    A('')
    A('IMPORT("./../lib/esc.wll", ["ESCAPE_HTML"]);')
    A('IMPORT("./../lib/article_store.wll",'
      ' ["VALIDATE_FILENAME", "SOURCE_PATH", "DECODE_CONTENT"]);')
    A('IMPORT("./../lib/frontmatter.wll", ["PARSE_META", "META_HEADER"]);')
    A('IMPORT("./../lib/footnotes.wll", ["PROCESS_FOOTNOTES"]);')
    A('IMPORT("./../lib/toc.wll",'
      ' ["EXTRACT_HEADINGS", "BUILD_TOC_HTML", "ADD_HEADING_IDS"]);')
    A('IMPORT("./../lib/wikilink.wll",'
      ' ["PARSE_BIDIRECTIONAL_LINKS", "EXTRACT_BIDIRECTIONAL_LINKS"]);')
    A('IMPORT("./../lib/md.wll", ["RENDER_MD"]);')
    A('IMPORT("./../lib/sort_util.wll",'
      ' ["SORT_STRINGS", "SORT_BY_DATE", "SORT_BY_TITLE_OR_FILE", "SORT_BY_NUM_DESC"]);')
    A('IMPORT("./../lib/theme.wll", ["LOAD_THEME_CSS"]);')
    A('IMPORT("./../lib/article_page.wll", ["ARTICLE_PAGE", "STANDALONE_PAGE"]);')
    A('IMPORT("./../lib/list_page.wll", ["LIST_PAGE", "CATEGORY_PAGE", "SEARCH_PAGE"]);')
    A('IMPORT("./../lib/feeds.wll", ["RSS", "SITEMAP", "ROBOTS"]);')
    A('IMPORT("./../lib/search_index.wll", ["SEARCH_INDEX"]);')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # 值类型兜底
    # ══════════════════════════════════════════════════════════════════
    A('// ── 值类型兜底 ────────────────────────────────────────────────────')
    A('// ⚠ AT_K(NULL, k, d) 是**运行期 E0030**（默认值不兜 NULL 基值，坑 35）')
    A('//   ⇒ 每次取 opts / config 之前先把它夹成 DICT。')
    A('LET(AS_DICT, FUN((v), (IF(==(TYPE(v), "DICT"), v, DICT()))));')
    A('LET(AS_ARR, FUN((v), (IF(==(TYPE(v), "ARRAY"), v, []))));')
    A('LET(AS_STR, FUN((v), (IF(==(TYPE(v), "STRING"), v, ""))));')
    A('LET(AS_INT, FUN((v), (IF(==(TYPE(v), "INTEGER"), v, 0))));')
    A('LET(AS_BOOL, FUN((v, d), (IF(==(TYPE(v), "BOOLEAN"), v, d))));')
    A('')

    # ── Config 缺省值 ─────────────────────────────────────────────────
    A('// ── Config 的缺省值（逐字段照抄 tinypage/config.py:12-68）────────────')
    A('// 为什么本模块要**自己**补齐：lib 的页面函数用 `AT_K(cfg, k, <默认>)` 取配置，')
    A('//   而 `page_common.wll` 的默认值是 `""`/`FALSE` —— 与 Python 的 `Config()`')
    A('//   （site_title="TinyPage"、enable_search=True…）**不同**。')
    A('//   ⇒ 编排层必须递一份**完整** config，否则 enable_* 会集体变 FALSE。')
    A('LET(CFG_DEFAULTS, FUN((), (')
    A('     ["site_title": "TinyPage",')
    A('      "site_description": "A modern static blog",')
    A('      "site_url": "",')
    A('      "site_author": "",')
    A('      "footer_text": "Powered by TinyPage",')
    A('      "lang": "zh-CN",')
    A('      "theme_name": "default",')
    A('      "page_size": 10,')
    A('      "max_file_size": 10485760,')
    A('      "max_title_length": 200,')
    A('      "max_content_length": 50000,')
    A('      "enable_pwa": TRUE,')
    A('      "enable_dark_mode": TRUE,')
    A('      "enable_search": TRUE,')
    A('      "enable_rss": TRUE,')
    A('      "enable_sitemap": TRUE,')
    A('      "enable_view_transitions": TRUE,')
    A('      "pwa_short_name": "TinyPage",')
    A('      "pwa_theme_color": "#2c3e50",')
    A('      "pwa_bg_color": "#ffffff"]')
    A(')));')
    A('')
    A('// 用户 config 覆盖缺省值（== Config.merge：**逐键覆盖**，不管值真假）')
    A('// ⚠ 必须在 BUILD **之前**绑定：函数体里的名字在**调用期**解析。')
    A('LET(CFG_OF, FUN((opts), (')
    A('     LET(o, AS_DICT(opts));')
    A('     LET(uv, AS_DICT(AT_K(o, "config", DICT())));')
    A('     LET MUT(c, CFG_DEFAULTS());')
    A('     FOR(k, KEYS(uv), (')
    A('          IF(HAS(uv, k), (')
    A('               SET(c, INDEX_SET(c, k, AT_K(uv, k, NULL)))')
    A('          ), NULL)')
    A('     ));')
    A('     c')
    A(')));')
    A('')

    # ── PY_STRIP ─────────────────────────────────────────────────────
    A('// ── Python `str.strip()`（Unicode 空白口径）────────────────────────')
    A('// ⚠ 内建 TRIM **只剥 ASCII 空白**（坑 41）：NBSP / 全角空格原样返回。')
    A('//   `tag_list` / `category.strip()` 用的都是 Python 的 str.strip()。')
    A('// ⚠ UTF8_DECODE 的实参是**字节**（0-255），不是码点（坑 42）。')
    A('LET(PY_WS, FUN((), (')
    A('    UTF8_DECODE([9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 194, 133, 194, 160,')
    A('                  225, 154, 128, 226, 128, 128, 226, 128, 129, 226, 128, 130,')
    A('                  226, 128, 131, 226, 128, 132, 226, 128, 133, 226, 128, 134,')
    A('                  226, 128, 135, 226, 128, 136, 226, 128, 137, 226, 128, 138,')
    A('                  226, 128, 168, 226, 128, 169, 226, 128, 175, 226, 129, 159,')
    A('                  227, 128, 128])')
    A(')));')
    A('LET(WS_LEAD_RE, RE(CAT("^[", PY_WS(), "]+")));')
    A('// ⚠ 结尾锚 `$` 在 WLWL 字面量里是插值 ⇒ 必须写 `\\\\$`（坑 32）。')
    A('LET(WS_TRAIL_RE, RE(CAT("[", PY_WS(), "]+\\\\$")));')
    A('LET(WS_RUN_RE, RE(CAT("[", PY_WS(), "]+")));')
    A('LET(PY_STRIP, FUN((s), (')
    A('    RE_REPLACE(WS_TRAIL_RE, RE_REPLACE(WS_LEAD_RE, s, ""), "")')
    A(')));')
    A('')

    # ── 小工具 ────────────────────────────────────────────────────────
    A('// ── 小工具 ────────────────────────────────────────────────────────')
    A('// 读文件，失败给兜底值（⚠ `LET(r, READ_FILE(p))` 绑定**不算消费** ERR，坑 25）')
    A('LET(READ_OR, FUN((p, fb), (IF(IS_ERR(READ_FILE(p)), fb, READ_FILE(p)))));')
    A('// 文件大小；取不到给 -1（即放过 `max_file_size` 过滤）')
    A('LET(FILE_SIZE, FUN((p), (')
    A('     IF(IS_ERR(FILE_META(p)), -1, AS_INT(AT_K(FILE_META(p), "size", 0)))')
    A(')));')
    A('LET(IS_DRAFT, FUN((rec), (')
    A('     ==(TO_LOWER(AS_STR(AT_K(rec, "status", "published"))), "draft")')
    A(')));')
    A('LET(UNIQ, FUN((xs), (')
    A('     LET MUT(out, []);')
    A('     FOR(x, xs, (IF(CONTAINS(out, x), NULL, (SET(out, +(out, [x]))))));')
    A('     out')
    A(')));')
    A('LET(COUNT_IN, FUN((a, b), (')
    A('     // a 已去重；返回 a 里有多少项出现在 b 里（= 交集大小）')
    A('     LET MUT(n, 0);')
    A('     FOR(x, a, (IF(CONTAINS(b, x), (SET(n, +(n, 1))), NULL)));')
    A('     n')
    A(')));')
    A('')

    # ── 日期 ─────────────────────────────────────────────────────────
    A('// ── 日期合法性（content.py:183-187 的 strptime 守卫）──────────────────')
    A('// ⚠ Python 是 `strptime(meta.date[:16], "%Y-%m-%d %H:%M")`，抛异常就**跳过这篇文章**。')
    A('//   这里用正则判「形状 + 各段取值范围」；**不做**月长 / 闰年校验（见 docstring）。')
    A('LET(DATE_RE, RE("^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])'
      ' ([01][0-9]|2[0-3]):[0-5][0-9]$"));')
    A('LET(VALID_DATE, FUN((d), (')
    A('     // 取前 16 码点再整串匹配（RE_TEST 是**整串锚定**，坑 15 / 36）')
    A('     IF(<(LEN(d), 16), FALSE, RE_TEST(DATE_RE, SUB(d, 0, 16)))')
    A(')));')
    A('// ArticleMeta.iso_date == date_obj.isoformat()（秒补 :00）')
    A('LET(ISO_DATE, FUN((d), (CAT(SUB(d, 0, 10), "T", SUB(d, 11, 5), ":00"))));')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # 读目录
    # ══════════════════════════════════════════════════════════════════
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 读目录（content.py:153 list_articles / :674 list_standalones）')
    A('// ══════════════════════════════════════════════════════════════════')
    A('// ⚠ `LIST_DIR` 返回**完整路径**（含目录自身条目）、已排序、正斜杠；')
    A('//   对「不存在」「传入文件」都返 ERR（坑 37）⇒ 结果只能**内联**用。')
    A('//   「跳过不是文件的条目」靠扩展名判（Python 是 `entry.is_file()`）。')
    A('LET(ARTICLE_REC, FUN((meta, name, date), (')
    A('     // ArticleMeta 的派生字段：file / date_obj（RSS 走 date_obj.isoformat）')
    A('     LET MUT(r, meta);')
    A('     SET(r, INDEX_SET(r, "file", name));')
    A('     SET(r, INDEX_SET(r, "date_obj", ["iso": ISO_DATE(date)]));')
    A('     r')
    A(')));')
    A('')
    A('LET(LIST_ARTICLES, FUN((dir, max_size, with_drafts), (')
    A('     // 逐条 == content.py:171-196：')
    A('     //   .html 后缀 + validate_filename + 大小 + 日期可解析 + 草稿过滤')
    A('     LET MUT(out, []);')
    A('     FOR(e, LIST_DIR(dir), (')
    A('          LET(name, PATH_BASE(e));')
    A('          IF(!=(PATH_EXT(name), "html"), NULL, (')
    A('               IF(!VALIDATE_FILENAME(name), NULL, (')
    A('                    IF(>(FILE_SIZE(e), max_size), NULL, (')
    A('                         LET(meta, PARSE_META(READ_OR(e, "")));')
    A('                         LET(date, AS_STR(AT_K(meta, "date", "")));')
    A('                         IF(!VALID_DATE(date), NULL, (')
    A('                              IF(&&(!with_drafts, IS_DRAFT(meta)), NULL, (')
    A('                                   SET(out, +(out, [ARTICLE_REC(meta, name, date)]))')
    A('                              ))')
    A('                         ))')
    A('                    ))')
    A('               ))')
    A('          ))')
    A('     ));')
    A('     // ⚠ 稳定排序 + 语料日期互不相同 ⇒ 与 Python 的 iterdir 顺序无关')
    A('     SORT_BY_DATE(out)')
    A(')));')
    A('')
    A('// 独立页文件名白名单 == content.py:662 SAFE_PAGE_FILENAME')
    A('// ⚠ CJK 用**字面** `一-龥`（坑 20：`\\u4e00` 在 WLWL 正则里不生效）')
    A('LET(PAGE_NAME_RE, RE("^[a-zA-Z0-9一-龥_-]+[.]html$"));')
    A('LET(LIST_STANDALONES, FUN((dir, max_size), (')
    A('     LET MUT(out, []);')
    A('     FOR(e, LIST_DIR(dir), (')
    A('          LET(name, PATH_BASE(e));')
    A('          IF(!RE_TEST(PAGE_NAME_RE, name), NULL, (')
    A('               IF(>(FILE_SIZE(e), max_size), NULL, (')
    A('                    LET(meta, PARSE_META(READ_OR(e, "")));')
    A('                    LET MUT(r, meta);')
    A('                    SET(r, INDEX_SET(r, "file", name));')
    A('                    // slug = 去掉 ".html" 的干名（Python: entry.stem）')
    A('                    SET(r, INDEX_SET(r, "slug", SUB(name, 0, -(LEN(name), 5))));')
    A('                    SET(out, +(out, [r]))')
    A('               ))')
    A('          ))')
    A('     ));')
    A('     // == content.py:698 pages.sort(key=lambda x: x.title or x.file)')
    A('     SORT_BY_TITLE_OR_FILE(out)')
    A(')));')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # 原文 + 渲染管线
    # ══════════════════════════════════════════════════════════════════
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 原文（content.py:493 get_raw_content，简化到三步）')
    A('// ══════════════════════════════════════════════════════════════════')
    A('LET(DECODE_TEXT, FUN((text), (')
    A('     // DECODE_CONTENT 返回 STRING 或 NULL（没有内嵌正文）')
    A('     LET(d, DECODE_CONTENT(text));')
    A('     IF(==(TYPE(d), "NULL"), "", d)')
    A(')));')
    A('LET(RAW_OF, FUN((html_path, summary), (')
    A('     // ① 兄弟 .md 优先 ② 否则从 html 里解内嵌正文 ③ 都空 ⇒ summary')
    A('     // ⚠ Python 还有「从渲染页 post-content 里恢复并写回 .md」的懒迁移；')
    A('     //   语料每篇都有 .md ⇒ 那条分支不覆盖（见 docstring）。')
    A('     LET(md, SOURCE_PATH(html_path));')
    A('     LET MUT(raw, "");')
    A('     IF(EXISTS(md), (')
    A('          SET(raw, READ_OR(md, ""))')
    A('     ), (')
    A('          SET(raw, DECODE_TEXT(READ_OR(html_path, "")))')
    A('     ));')
    A('     IF(==(raw, ""), summary, raw)')
    A(')));')
    A('')
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 五步渲染管线（content.py:584-600）—— **顺序不可调换**')
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 脚注先摘定义行（否则 `[^1]:` 会被当成段落/标题）；标题提取在脚注之后；')
    A('// ADD_HEADING_IDS 必须在 RENDER_MD **之后**（要给渲染出来的 <hN> 加 id）。')
    A('LET(PIPELINE, FUN((raw, amap), (')
    A('     LET(fnres, PROCESS_FOOTNOTES(raw));')
    A('     LET(processed, fnres[0]);')
    A('     LET(footnotes_html, fnres[1]);')
    A('     LET(headings, EXTRACT_HEADINGS(processed));')
    A('     // == content.py:589 build_toc_html(headings) ⇒ 默认 2/3 级')
    A('     LET(toc_html, BUILD_TOC_HTML(headings, 2, 3));')
    A('     LET(bl, PARSE_BIDIRECTIONAL_LINKS(processed, amap));')
    A('     LET(linked, bl[0]);')
    A('     LET(body, RENDER_MD(linked));')
    A('     LET(html, ADD_HEADING_IDS(body, headings));')
    A('     [html, toc_html, footnotes_html]')
    A(')));')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # 三处编排逻辑
    # ══════════════════════════════════════════════════════════════════
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 三处 Python 侧的「编排」逻辑（不在任何 tp/lib 模块里）')
    A('// ══════════════════════════════════════════════════════════════════')
    A('// ① 标题 → URL 映射 == bidirectional_links.py:104 build_article_title_map')
    A('//    键是 title.lower()（后写覆盖先写，与 dict 赋值一致）')
    A('LET(ARTICLE_MAP, FUN((arts), (')
    A('     LET MUT(m, DICT());')
    A('     FOR(a, arts, (')
    A('          LET(t, AS_STR(AT_K(a, "title", "")));')
    A('          IF(==(t, ""), NULL, (')
    A('               SET(m, INDEX_SET(m, TO_LOWER(t),')
    A('                    CAT("/article/", AS_STR(AT_K(a, "file", "")))))')
    A('          ))')
    A('     ));')
    A('     m')
    A(')));')
    A('')
    A('// ② 反向链接索引 == content.py:375 build_backlink_index')
    A('//    索引值是**扁平对**：[来源file, 来源title, …]（一对 2 项）')
    A('//    ⚠ Python 还比 `target.slug == slugify(linked_title)` 这一支；语料的')
    A('//      slug 恒等于 slugify(title) 且 slug 互不相同 ⇒ 两支等价于「标题小写相等」')
    A('//      （证明见 docstring 与报告）。')
    A('LET(BACKLINK_INDEX, FUN((arts), (')
    A('     LET MUT(idx, DICT());')
    A('     LET(add, FUN((target_file, af, atitle), (')
    A('          LET(cur, AS_ARR(AT_K(idx, target_file, [])));')
    A('          IF(CONTAINS(cur, af), NULL, (')
    A('               SET(idx, INDEX_SET(idx, target_file, +(cur, [af, atitle])))')
    A('          ))')
    A('     )));')
    A('     FOR(a, arts, (')
    A('          IF(IS_DRAFT(a), NULL, (')
    A('               LET(af, AS_STR(AT_K(a, "file", "")));')
    A('               LET(atitle, AS_STR(AT_K(a, "title", "")));')
    A('               FOR(t, EXTRACT_BIDIRECTIONAL_LINKS(AS_STR(AT_K(a, "raw", ""))), (')
    A('                    LET(tl, TO_LOWER(t));')
    A('                    FOR(b, arts, (')
    A('                         IF(IS_DRAFT(b), NULL, (')
    A('                              IF(==(TO_LOWER(AS_STR(AT_K(b, "title", ""))), tl), (')
    A('                                   add(AS_STR(AT_K(b, "file", "")), af, atitle)')
    A('                              ), NULL)')
    A('                         ))')
    A('                    ))')
    A('               ))')
    A('          ))')
    A('     ));')
    A('     idx')
    A(')));')
    A('')
    A('// ③ 反向链接 HTML == bidirectional_links.py:67 build_backlinks_html')
    A('//    模板首尾换行、条目之间 "\\n    " —— 逐字节照抄')
    A('LET(BACKLINKS_HTML, FUN((idx, file), (')
    A('     LET(entries, AS_ARR(AT_K(idx, file, [])));')
    A('     IF(<(LEN(entries), 2), "", (')
    A('          LET MUT(links, "");')
    A('          LET MUT(i, 0);')
    A('          WHILE(<(i, LEN(entries)), (')
    A('               IF(>(i, 0), (SET(links, +(links, "\\n    "))), NULL);')
    A('               SET(links, CAT(links, "<li><a href=\\"/article/", entries[i],')
    A('                    "\\">", ESCAPE_HTML(entries[+(i, 1)]), "</a></li>"));')
    A('               SET(i, +(i, 2))')
    A('          ));')
    A('          CAT("\\n<section class=\\"backlinks\\">\\n  <h2>反向链接</h2>\\n  <ul>\\n    ",')
    A('               links, "\\n  </ul>\\n</section>\\n")')
    A('     ))')
    A(')));')
    A('')
    A('// ④ 相关文章 == content.py:200 find_related_articles（Jaccard，降序稳定，取前 5）')
    A('//    ⚠ 用 `FLOAT(inter) / FLOAT(union)` ⇒ 与 Python 的 `len/len` 同为 IEEE 双精度；')
    A('//      再交给 SORT_BY_NUM_DESC（稳定、降序）⇒ 与 sort(key, reverse=True) 同序。')
    A('LET(TAG_LIST, FUN((tags), (')
    A('     // == ArticleMeta.tag_list：split(",") → strip → 丢空')
    A('     LET MUT(out, []);')
    A('     IF(==(tags, ""), NULL, (')
    A('          FOR(t0, SPLIT(tags, ","), (')
    A('               LET(t, PY_STRIP(t0));')
    A('               IF(==(t, ""), NULL, (SET(out, +(out, [t]))))')
    A('          ))')
    A('     ));')
    A('     out')
    A(')));')
    A('LET(RELATED, FUN((cur, arts, limit), (')
    A('     LET(cset, UNIQ(TAG_LIST(AS_STR(AT_K(cur, "tags", "")))));')
    A('     IF(==(LEN(cset), 0), [], (')
    A('          LET MUT(items, []);')
    A('          LET(cf, AS_STR(AT_K(cur, "file", "")));')
    A('          FOR(a, arts, (')
    A('               IF(==(AS_STR(AT_K(a, "file", "")), cf), NULL, (')
    A('                    IF(IS_DRAFT(a), NULL, (')
    A('                         LET(tl, UNIQ(TAG_LIST(AS_STR(AT_K(a, "tags", "")))));')
    A('                         LET(inter, COUNT_IN(cset, tl));')
    A('                         IF(==(inter, 0), NULL, (')
    A('                              LET(uni, -(+(LEN(cset), LEN(tl)), inter));')
    A('                              SET(items, +(items, [[a, /(FLOAT(inter), FLOAT(uni))]]))')
    A('                         ))')
    A('                    ))')
    A('               ))')
    A('          ));')
    A('          LET(sorted, SORT_BY_NUM_DESC(items));')
    A('          LET MUT(res, []);')
    A('          LET MUT(i, 0);')
    A('          WHILE(&&(<(i, limit), <(i, LEN(sorted))), (')
    A('               SET(res, +(res, [sorted[i][0]]));')
    A('               SET(i, +(i, 1))')
    A('          ));')
    A('          res')
    A('     ))')
    A(')));')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # 独立页正文抽取
    # ══════════════════════════════════════════════════════════════════
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 独立页正文抽取 == content.py:53 _extract_body_from_html')
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 取 post-content div 的内部 → 剥标签 → 空白压成单空格 → strip')
    A('// ⚠ Python 用的是 `<div class="post-content">(.*?)</div>` + DOTALL（非贪婪）')
    A('//   ⇒ 等价于「从这个开标签之后到**第一个** `</div>`」。')
    A('LET(PC_OPEN, "<div class=\\"post-content\\">");')
    A('LET(TAG_RE, RE("[<][^>]+[>]"));')
    A('LET(STRIP_TAGS, FUN((s), (RE_REPLACE(TAG_RE, s, ""))));')
    A('LET(COLLAPSE_WS, FUN((s), (PY_STRIP(RE_REPLACE(WS_RUN_RE, s, " ")))));')
    A('LET(EXTRACT_BODY, FUN((html), (')
    A('     LET(start, INDEX_OF(html, PC_OPEN));')
    A('     LET MUT(chunk, "");')
    A('     IF(<(start, 0), (')
    A('          // 没有 post-content ⇒ Python 退回「整页剥标签」')
    A('          SET(chunk, html)')
    A('     ), (')
    A('          LET(off, +(start, LEN(PC_OPEN)));')
    A('          SET(chunk, SUB(html, off, -(LEN(html), off)));')
    A('          LET(end_i, INDEX_OF(chunk, "</div>"));')
    A('          IF(>=(end_i, 0), (SET(chunk, SUB(chunk, 0, end_i))), NULL)')
    A('     ));')
    A('     COLLAPSE_WS(STRIP_TAGS(chunk))')
    A(')));')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # 页面 opts 组装
    # ══════════════════════════════════════════════════════════════════
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 页面 opts（键名与 Python 的具名参数同名；lib 侧可缺省）')
    A('// ══════════════════════════════════════════════════════════════════')
    A('// 三个页面类型共用：主题三件套 + 配置 + 独立页导航')
    A('LET(SHARED_OPTS, FUN((ctx), (')
    A('     LET MUT(o, DICT());')
    A('     SET(o, INDEX_SET(o, "config", AT_K(ctx, "config", DICT())));')
    A('     SET(o, INDEX_SET(o, "theme_css", AT_K(ctx, "theme_css", "")));')
    A('     SET(o, INDEX_SET(o, "dark_css", AT_K(ctx, "dark_css", "")));')
    A('     SET(o, INDEX_SET(o, "has_dark", AT_K(ctx, "has_dark", FALSE)));')
    A('     SET(o, INDEX_SET(o, "standalones", AS_ARR(AT_K(ctx, "standalones", []))));')
    A('     o')
    A(')));')
    A('')
    A('// == content.py:618-636 里 generate_article_html(...) 的实参')
    A('LET(ARTICLE_OPTS, FUN((a, pipe, bl_html, rel, ctx), (')
    A('     LET MUT(o, SHARED_OPTS(ctx));')
    A('     SET(o, INDEX_SET(o, "title", AS_STR(AT_K(a, "title", ""))));')
    A('     SET(o, INDEX_SET(o, "date", AS_STR(AT_K(a, "date", ""))));')
    A('     SET(o, INDEX_SET(o, "slug", AS_STR(AT_K(a, "slug", ""))));')
    A('     SET(o, INDEX_SET(o, "content", pipe[0]));')
    A('     SET(o, INDEX_SET(o, "toc_html", pipe[1]));')
    A('     SET(o, INDEX_SET(o, "footnotes_html", pipe[2]));')
    A('     SET(o, INDEX_SET(o, "tags", AS_STR(AT_K(a, "tags", ""))));')
    A('     SET(o, INDEX_SET(o, "summary", AS_STR(AT_K(a, "summary", ""))));')
    A('     SET(o, INDEX_SET(o, "category", AS_STR(AT_K(a, "category", ""))));')
    A('     SET(o, INDEX_SET(o, "status", AS_STR(AT_K(a, "status", "published"))));')
    A('     SET(o, INDEX_SET(o, "backlinks_html", bl_html));')
    A('     SET(o, INDEX_SET(o, "related_articles", rel));')
    A('     o')
    A(')));')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # BUILD
    # ══════════════════════════════════════════════════════════════════
    A('// ══════════════════════════════════════════════════════════════════')
    A('// BUILD —— 一次完整构建')
    A('// ══════════════════════════════════════════════════════════════════')
    A('LET(BUILD, FUN((opts), (')
    A('     LET(o, AS_DICT(opts));')
    A('     // ── 路径 ────────────────────────────────────────────────────')
    A('     LET(root0, AS_STR(AT_K(o, "root", "")));')
    A('     LET(root, IF(==(root0, ""), ".", root0));')
    A('     LET(out0, AS_STR(AT_K(o, "out", "")));')
    A('     LET(out_dir, IF(==(out0, ""), PATH_JOIN(root, "pages"), out0));')
    A('     LET(article_dir, PATH_JOIN(out_dir, "article"));')
    A('     LET(list_dir, PATH_JOIN(out_dir, "list"));')
    A('     LET(st_dir, PATH_JOIN(out_dir, "standalone"));')
    A('     LET(cat_dir, PATH_JOIN(out_dir, "category"));')
    A('')
    A('     // ── 配置（补齐 Config 缺省值 + 推导 root_dir / theme_dir）──────')
    A('     LET(base_cfg, CFG_OF(o));')
    A('     LET(theme_dir, PATH_JOIN(root, "themes",')
    A('          AS_STR(AT_K(base_cfg, "theme_name", "default"))));')
    A('     LET MUT(cfg, base_cfg);')
    A('     SET(cfg, INDEX_SET(cfg, "root_dir", out_dir));')
    A('     SET(cfg, INDEX_SET(cfg, "theme_dir", theme_dir));')
    A('     LET(max_size, AS_INT(AT_K(cfg, "max_file_size", 10485760)));')
    A('     LET(page_size, AS_INT(AT_K(cfg, "page_size", 10)));')
    A('     LET MUT(page_size2, page_size);')
    A('     IF(<(page_size2, 1), (SET(page_size2, 1)), NULL);')
    A('')
    A('     // ── 文章目录不存在 ⇒ 与 cli.py:107-110 同口径：直接失败 ──────')
    A('     IF(!EXISTS(article_dir), (')
    A('          RETURN(["articles": 0, "written": 0, "ok": FALSE,')
    A('                  "error": CAT("article dir missing: ", article_dir)])')
    A('     ), NULL);')
    A('')
    A('     // ── 主题（generator.py:638 load_theme_css(cfg.theme_dir)）──────')
    A('     LET(theme, LOAD_THEME_CSS(theme_dir));')
    A('     LET(ctx0, ["config": cfg,')
    A('                "theme_css": AS_STR(AT_K(theme, "css", "")),')
    A('                "dark_css": AS_STR(AT_K(theme, "dark_css", "")),')
    A('                "has_dark": AS_BOOL(AT_K(theme, "has_dark", FALSE), FALSE)]);')
    A('')
    A('     // ── 读目录（草稿在这里就被过滤掉）────────────────────────────')
    A('     LET(arts_raw, LIST_ARTICLES(article_dir, max_size, FALSE));')
    A('     LET(sts, LIST_STANDALONES(st_dir, max_size));')
    A('     LET MUT(ctx, ctx0);')
    A('     SET(ctx, INDEX_SET(ctx, "standalones", sts));')
    A('')
    A('     // ── 每篇补上原文（反向链接索引与渲染共用同一份）──────────────')
    A('     LET MUT(arts, []);')
    A('     FOR(a, arts_raw, (')
    A('          LET MUT(r, a);')
    A('          SET(r, INDEX_SET(r, "raw", RAW_OF(PATH_JOIN(article_dir,')
    A('               AS_STR(AT_K(a, "file", ""))), AS_STR(AT_K(a, "summary", "")))));')
    A('          SET(arts, +(arts, [r]))')
    A('     ));')
    A('     LET(total, LEN(arts));')
    A('')
    A('     // ── 标题映射 + 反向链接索引（两者都是全局的，建一次）──────────')
    A('     LET(amap, ARTICLE_MAP(arts));')
    A('     LET(bidx, BACKLINK_INDEX(arts));')
    A('')
    A('     // ── 写盘计数器（闭包可写外层 LET MUT，坑 12 已实测）──────────')
    A('     // ── 高亮资源注入（D-HL，业主裁决：允许产物多出高亮标签）──────────')
    A('     //   Python 侧是服务端 Pygments 注入 CSS；本实现改**前端** highlight.js，')
    A('     //   故构建后往每个 .html 注入两行资源引用。基准生成器对 Python 的产物做')
    A('     //   **同一后处理** ⇒ 40/40 的比对仍然有意义（差异被隔离成这一个步骤）。')
    A('     //   URL 用根路径：Python 的 StaticApp 把 static_inject/* 挂在 "/文件名"。')
    A('     LET(HL_LINK, "<link rel=\\"stylesheet\\" href=\\"/highlight-theme.css\\">\\n");')
    A('     LET(HL_SCRIPT,')
    A('      "<script src=\\"/highlight.min.js\\"></script>\\n<script>hljs.highlightAll();</script>\\n");')
    A('     LET(INSERT_AT, FUN((s, at, text), (')
    A('          CAT(SUB(s, 0, at), text, SUB(s, at, -(LEN(s), at)))')
    A('     )));')
    A('     LET(INJECT_HL, FUN((s), (')
    A('          // 在 </head> 前插 <link>、在 </body> 前插 <script>；找不到锚点就原样返回')
    A('          LET(h, INDEX_OF(s, "</head>"));')
    A('          LET(s1, IF(>=(h, 0), INSERT_AT(s, h, HL_LINK), s));')
    A('          LET(b, INDEX_OF(s1, "</body>"));')
    A('          IF(>=(b, 0), INSERT_AT(s1, b, HL_SCRIPT), s1)')
    A('     )));')
    A('')

    A('     LET MUT(written, 0);')
    A('     LET MUT(failed, 0);')
    A('     // ⚠ 只有 .html 注入高亮资源；.xml/.json/.txt 原样写')
    A('     LET(WRITE_OUT, FUN((path, content), (')
    A('          LET(body, IF(==(PATH_EXT(path), "html"), INJECT_HL(content), content));')
    A('          IF(IS_ERR(WRITE_FILE_ATOMIC(path, body)), (')
    A('               SET(failed, +(failed, 1))')
    A('          ), (')
    A('               SET(written, +(written, 1))')
    A('          ))')
    A('     )));')
    A('     LET(MKDIR_OK, FUN((p), (IF(IS_ERR(MKDIRS(p)), NULL, NULL))));')
    A('')
    A('     // ══ ① 文章页（content.py:543 regenerate_all_articles）══════════')
    A('     FOR(a, arts, (')
    A('          LET(file, AS_STR(AT_K(a, "file", "")));')
    A('          LET(pipe, PIPELINE(AS_STR(AT_K(a, "raw", "")), amap));')
    A('          LET(bl, BACKLINKS_HTML(bidx, file));')
    A('          LET(rel, RELATED(a, arts, 5));')
    A('          LET(op, ARTICLE_OPTS(a, pipe, bl, rel, ctx));')
    A('          // ⚠ `LET(h, ARTICLE_PAGE(op))` 绑定**不算消费** ERR（坑 25）')
    A('          //   ⇒ 先 IS_ERR 判别，再在分支里重新调一次。')
    A('          LET(page, IF(IS_ERR(ARTICLE_PAGE(op)), "", ARTICLE_PAGE(op)));')
    A('          LET(header, META_HEADER(AS_STR(AT_K(a, "title", "")),')
    A('               AS_STR(AT_K(a, "date", "")), AS_STR(AT_K(a, "slug", "")),')
    A('               AS_STR(AT_K(a, "tags", "")), AS_STR(AT_K(a, "summary", "")),')
    A('               AS_STR(AT_K(a, "category", "")),')
    A('               AS_STR(AT_K(a, "status", "published"))));')
    A('          IF(==(page, ""), (SET(failed, +(failed, 1))), (')
    A('               WRITE_OUT(PATH_JOIN(article_dir, file), CAT(header, page))')
    A('          ))')
    A('     ));')
    A('')
    A('     // ══ ② 列表页（generator.py:658-673）══════════════════════════')
    A('     LET(pages_n, MAX(1, /(-(+(total, page_size2), 1), page_size2)));')
    A('     MKDIR_OK(list_dir);')
    A('     LET MUT(p, 1);')
    A('     WHILE(<=(p, pages_n), (')
    A('          LET(start, *(-(p, 1), page_size2));')
    A('          LET(stop, MIN(+(start, page_size2), total));')
    A('          LET(items, SLICE(arts, start, stop));')
    A('          // == generator.py:666 prev_url="/" if p == 2 else f"/list/{p-1}.html"')
    A('          LET(prev_url, IF(==(p, 2), "/", CAT("/list/", STR(-(p, 1)), ".html")));')
    A('          LET MUT(info, DICT());')
    A('          SET(info, INDEX_SET(info, "current", p));')
    A('          SET(info, INDEX_SET(info, "total", pages_n));')
    A('          SET(info, INDEX_SET(info, "has_prev", >(p, 1)));')
    A('          SET(info, INDEX_SET(info, "has_next", <(p, pages_n)));')
    A('          SET(info, INDEX_SET(info, "prev_url", prev_url));')
    A('          SET(info, INDEX_SET(info, "next_url",')
    A('               IF(<(p, pages_n), CAT("/list/", STR(+(p, 1)), ".html"), "")));')
    A('          LET MUT(lo, SHARED_OPTS(ctx));')
    A('          SET(lo, INDEX_SET(lo, "articles", items));')
    A('          SET(lo, INDEX_SET(lo, "page_info", info));')
    A('          LET(html, IF(IS_ERR(LIST_PAGE(lo)), "", LIST_PAGE(lo)));')
    A('          LET(target, IF(==(p, 1),')
    A('               PATH_JOIN(out_dir, "index.html"),')
    A('               PATH_JOIN(list_dir, CAT(STR(p), ".html"))));')
    A('          IF(==(html, ""), (SET(failed, +(failed, 1))),')
    A('               (WRITE_OUT(target, html)));')
    A('          SET(p, +(p, 1))')
    A('     ));')
    A('')
    A('     // ══ ③ 分类页（generator.py:675-692）══════════════════════════')
    A('     LET MUT(cat_map, DICT());')
    A('     FOR(a, arts, (')
    A('          LET(raw_cat, AS_STR(AT_K(a, "category", "")));')
    A('          IF(==(raw_cat, ""), NULL, (')
    A('               LET(cat, PY_STRIP(raw_cat));')
    A('               IF(==(cat, ""), NULL, (')
    A('                    SET(cat_map, INDEX_SET(cat_map, cat,')
    A('                         +(AS_ARR(AT_K(cat_map, cat, [])), [a])))')
    A('               ))')
    A('          ))')
    A('     ));')
    A('     // == sorted(set(categories))：KEYS 是插入序，再 SORT_STRINGS 成码点序')
    A('     LET(cats, SORT_STRINGS(KEYS(cat_map)));')
    A('     IF(>(LEN(cats), 0), (MKDIR_OK(cat_dir)), NULL);')
    A('     FOR(cat, cats, (')
    A('          LET MUT(co, SHARED_OPTS(ctx));')
    A('          SET(co, INDEX_SET(co, "category", cat));')
    A('          SET(co, INDEX_SET(co, "articles", AS_ARR(AT_K(cat_map, cat, []))));')
    A('          LET(html, IF(IS_ERR(CATEGORY_PAGE(co)), "", CATEGORY_PAGE(co)));')
    A('          IF(==(html, ""), (SET(failed, +(failed, 1))), (')
    A('               WRITE_OUT(PATH_JOIN(cat_dir, CAT(cat, ".html")), html)')
    A('          ))')
    A('     ));')
    A('')
    A('     // ══ ④ 独立页（generator.py:695-716）══════════════════════════')
    A('     IF(>(LEN(sts), 0), (MKDIR_OK(st_dir)), NULL);')
    A('     FOR(st, sts, (')
    A('          LET(file, AS_STR(AT_K(st, "file", "")));')
    A('          LET(src, PATH_JOIN(st_dir, file));')
    A('          // Python: 只处理**存在的**文件')
    A('          IF(!EXISTS(src), NULL, (')
    A('               LET(body, EXTRACT_BODY(READ_OR(src, "")));')
    A('               LET(title, AS_STR(AT_K(st, "title", "")));')
    A('               LET MUT(so, SHARED_OPTS(ctx));')
    A('               // == generator.py:707 title=page.title or page.file')
    A('               SET(so, INDEX_SET(so, "title", IF(==(title, ""), file, title)));')
    A('               SET(so, INDEX_SET(so, "summary",')
    A('                    AS_STR(AT_K(st, "summary", ""))));')
    A('               // == generator.py:708  `_render_md(body) if body else ""`')
    A('               SET(so, INDEX_SET(so, "content",')
    A('                    IF(==(body, ""), "", RENDER_MD(body))));')
    A('               LET(html, IF(IS_ERR(STANDALONE_PAGE(so)), "",')
    A('                    STANDALONE_PAGE(so)));')
    A('               IF(==(html, ""), (SET(failed, +(failed, 1))), (')
    A('                    WRITE_OUT(src, html)')
    A('               ))')
    A('          ))')
    A('     ));')
    A('')
    A('     // ══ ⑤ 搜索页 + 搜索索引（generator.py:719-726）═════════════════')
    A('     IF(AS_BOOL(AT_K(cfg, "enable_search", TRUE), TRUE), (')
    A('          LET(so, SHARED_OPTS(ctx));')
    A('          LET(html, IF(IS_ERR(SEARCH_PAGE(so)), "", SEARCH_PAGE(so)));')
    A('          IF(==(html, ""), (SET(failed, +(failed, 1))), (')
    A('               WRITE_OUT(PATH_JOIN(out_dir, "search.html"), html)')
    A('          ));')
    A('          // ⚠ 喂**已过滤**列表（cli.py:139 的口径）')
    A('          WRITE_OUT(PATH_JOIN(out_dir, "search-index.json"),')
    A('               SEARCH_INDEX(["articles": arts, "standalones": sts]))')
    A('     ), NULL);')
    A('')
    A('     // ══ ⑥ RSS（generator.py:729-731）═════════════════════════════')
    A('     IF(AS_BOOL(AT_K(cfg, "enable_rss", TRUE), TRUE), (')
    A('          // == `published = [a for a in articles if a.is_published]`')
    A('          LET MUT(pub, []);')
    A('          FOR(a, arts, (IF(IS_DRAFT(a), NULL, (SET(pub, +(pub, [a]))))));')
    A('          WRITE_OUT(PATH_JOIN(out_dir, "rss.xml"),')
    A('               RSS(["articles": pub, "config": cfg]))')
    A('     ), NULL);')
    A('')
    A('     // ══ ⑦ sitemap（generator.py:734-737）═════════════════════════')
    A('     IF(AS_BOOL(AT_K(cfg, "enable_sitemap", TRUE), TRUE), (')
    A('          // ⚠ 与 RSS/搜索索引一样是**已过滤**列表 —— 见 gen_build.py docstring')
    A('          WRITE_OUT(PATH_JOIN(out_dir, "sitemap.xml"),')
    A('               SITEMAP(["articles": arts, "config": cfg,')
    A('                        "standalones": sts, "categories": cats]))')
    A('     ), NULL);')
    A('')
    A('     // ══ ⑧ robots.txt（generator.py:739-744）═══════════════════════')
    A('     WRITE_OUT(PATH_JOIN(out_dir, "robots.txt"),')
    A('          ROBOTS(["site_url": AS_STR(AT_K(cfg, "site_url", ""))]));')
    A('')
    A('     // ── 统计回报 ──────────────────────────────────────────────')
    A('     ["articles": total,')
    A('      "written": written,')
    A('      "ok": ==(failed, 0),')
    A('      "failed": failed,')
    A('      "pages": pages_n,')
    A('      "categories": LEN(cats),')
    A('      "standalones": LEN(sts)]')
    A(')));')
    A('')

    # ══════════════════════════════════════════════════════════════════
    # 导出 + 脚本模式
    # ══════════════════════════════════════════════════════════════════
    A('EXPORT(["BUILD"]);')
    A('')
    A('// ── 脚本模式：`wlwl run tp/bin/build.wll` ⇒ 默认参数跑一次 ───────────')
    A('// ⚠ 本文件被 IMPORT 时**不得**自我执行（test_build.wll 就 import 它）。')
    A('//   判据用 ARGS()：')
    A('//     · import 期（模块顶层执行）ARGS() == []          → 不跑')
    A('//     · 入口脚本期        ARGS() == [exe, "run", <脚本>] → 跑')
    A('//   ⚠ **不能**用 SCRIPT_PATH()：模块顶层执行期它返回**正在加载的模块**自己，')
    A('//     两种情形下都是 build.wll ⇒ 区分不出来（实测 2026-11-02）。')
    A('LET(SP, FUN((want), (')
    A('     LET MUT(hit, FALSE);')
    A('     FOR(a, ARGS(), (')
    A('          IF(==(PATH_BASE(a), want), (SET(hit, TRUE)), NULL)')
    A('     ));')
    A('     hit')
    A(')));')
    A('IF(SP("build.wll"), (')
    A('     LET(res, BUILD(["root": ".", "config": DICT()]));')
    A('     PRINT("build: articles=", AT_K(res, "articles", 0),')
    A('           " written=", AT_K(res, "written", 0),')
    A('           " ok=", AT_K(res, "ok", FALSE),')
    A('           " pages=", AT_K(res, "pages", 0),')
    A('           " categories=", AT_K(res, "categories", 0))')
    A('), NULL);')
    A('')
    A('// ── 尾注：`incremental` 接受但忽略 ───────────────────────────────────')
    A('// 真 Python 的 `--incremental`（cli.py:112-136）走 core/incremental.py 的')
    A('// mtime 比价，只重生成「改过的」文章；它**不产生**任何新产物形态，只是少写')
    A('// 几个文件。本卡的判据是「一次完整构建的产物逐字节对齐」⇒ 本层按全量处理，')
    A('// 并把这条事实登记在报告里。')

    # 顶层绑定统一加前缀（见 docstring：跨模块同名会互相覆盖）
    for line in raw:
        src.append(_RENAME_RE.sub(lambda m: 'TPB_' + m.group(1), line))

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
