"""生成 tp/lib/feeds.wll —— 订阅源与站点文件（RSS / sitemap / robots.txt）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。
   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。

**导出三个函数，都收一个 DICT**（WLWL 没有关键字参数与默认参数）：

| 导出 | 对齐的 Python 实现 | 位置 |
|---|---|---|
| `RSS(opts)`     | `generate_rss(articles, config)` | generator.py:542 |
| `SITEMAP(opts)` | `generate_sitemap(articles, config, standalones, categories)` | generator.py:571 |
| `ROBOTS(opts)`  | `generate_static_pages` 里写 robots.txt 的那 3 行（**无独立函数**） | generator.py:739-744 |

逐字节对照基准：`tp/test/fixtures/feeds_baseline.json`
（由 `tp/test/gen_feeds_baseline.py` 用**真 Python**生成；robots 那段是真跑
`generate_static_pages` 读回文件，不是复刻）。

---

## 分层事实（卡片措辞与现状不一致处，已按**实际实现**对齐）

**F1 草稿过滤在调用方，不在 `generate_rss` 里。**

```python
# generator.py:729-731
published = [a for a in articles if a.is_published]
write_text(generate_rss(published, cfg))
```

`generate_rss` 自己只做 `articles[:20]`。⇒ `RSS(opts)` **不过滤草稿**；
「排除草稿」是流水线的责任。谁要排除，就在调用前按 `is_published` 过滤
（`status.lower() != "draft"`）。基准里 `draft_raw` / `draft_filtered` 两条用例
把两个层次分别钉死。

**F2 sitemap 用的是未过滤的 `articles`（generator.py:736）**

⇒ 真实实现里草稿**会**出现在 sitemap 里。`SITEMAP(opts)` 照做，不改（改了与
Python 逐字节对照就红）。这条已登记为「卡片 vs 现状」差异项。

**F3 `robots.txt` 的 `Sitemap:` 行不回落 localhost**

`cfg.site_url or ''` ⇒ 空值得到 `Sitemap: /sitemap.xml`；
`localhost:8080` 的回落只在 rss(545) / sitemap(579) 里。
且这里**没有** `rstrip("/")` ⇒ `https://ex.com/` 会拼出 `//sitemap.xml`。

---

## 三处 WLWL 侧的口径（Python 有、WLWL 没有的东西）

1. **`config` 缺键 ⇒ 取 Python 的 `Config()` 默认值**（`site_title="TinyPage"`、
   `site_description="A modern static blog"`、`lang="zh-CN"`、`site_url=""`）。
   Python 的 `generate_rss` 只接受 `Config` 实例，没有「缺键」的概念 ⇒ 这是
   **最接近的等价物**；基准用例 `rss/default_config`（空 config DICT）钉这条。
2. **`date_obj` 是 `NULL` 或 `DICT{"iso": <datetime.isoformat()>}`**。
   `ArticleMeta.iso_date` 只用到 `isoformat()`（models.py:32-37）⇒ 逐字节等价。
   `date_obj` 为 `NULL` 时走 `date.replace(" ", "T")`（**全部**空格，str.replace 无 count）。
3. **`iso_date` / `is_published` 这类派生属性自己算**（`ISO_DATE()`），
   不指望 DICT 里带。

## 复用

· XML 转义复用 `tp/lib/esc.wll` 的 `ESCAPE_HTML`（== Python `html.escape(quote=True)`；
  ⚠ 内建 `HTML_ESCAPE` 出 `&#39;`，Python 出 `&#x27;` —— 必须用 esc.wll 那个）。
· **不**需要排序：`generate_rss` / `generate_sitemap` 都不排序（顺序完全由调用方给），
  ⇒ 本模块**不** import `sort_util.wll`（引进来反而是错的口径）。
· 只有 rss 的 title/summary 与 channel 的 title/description 走转义；
  **link / guid / loc / language 一律原样插值**（照 Python 的 f-string，别自作聪明）。

用法：python gen_feeds.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'feeds.wll')


def wl(s):
    """Python 字符串 → WLWL 字符串字面量（转义白名单内的那些）。"""
    out = (s.replace('\\', '\\\\')
            .replace('"', '\\"')
            .replace('\n', '\\n')
            .replace('\r', '\\r')
            .replace('\t', '\\t'))
    return '"' + out + '"'


def cat(*parts):
    """WLWL 的多段拼接：`CAT(a, b, c)`（`+` 是二元的且不做隐式转串）。"""
    return 'CAT(' + ', '.join(parts) + ')'


# ── Python 模板的字面量片段（逐字取自 generator.py）────────────────────
# generator.py:559-568
RSS_HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<rss version="2.0">\n'
            '  <channel>\n'
            '    <title>')
RSS_T1 = '</title>\n    <link>'
RSS_T2 = '</link>\n    <description>'
RSS_T3 = '</description>\n    <language>'
RSS_T4 = '</language>\n    '
RSS_TAIL = '\n  </channel>\n</rss>'

# generator.py:550-557（注意 items 以 "\n" 开头，模板里的 4 个空格在它前面）
ITEM_HEAD = '\n    <item>\n      <title>'
ITEM_T1 = '</title>\n      <link>'
ITEM_T2 = '</link>\n      <guid>'
ITEM_T3 = '</guid>\n      <pubDate>'
ITEM_T4 = '</pubDate>\n      <description>'
ITEM_TAIL = '</description>\n    </item>'

# generator.py:593-596
SITEMAP_HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
SITEMAP_TAIL = '\n</urlset>'
URL_ONE = '  <url>\n    <loc>'
URL_TAIL = '</loc>\n  </url>'

# generator.py:740-744（robots = f"""User-agent: *\nAllow: /\nSitemap: {…}/sitemap.xml\n"""）
# ⚠ Sitemap 行用 cfg.site_url or ''，**不回落** localhost；也**没有** rstrip("/")。
ROBOTS_HEAD = 'User-agent: *\nAllow: /\nSitemap: '
ROBOTS_TAIL = '/sitemap.xml\n'

# Config() 的默认值（Python 的 config.py:17/18/19/22）
DEF_TITLE = 'TinyPage'
DEF_DESC = 'A modern static blog'
DEF_LANG = 'zh-CN'
FALLBACK_URL = 'http://localhost:8080'


def main():
    src = []
    A = src.append
    A('// tp/lib/feeds.wll —— 订阅源与站点文件（RSS / sitemap / robots.txt）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_feeds.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树 tinypage/generator.py）：')
    A('//   RSS(opts)     == generator.py:542  generate_rss(articles, config)')
    A('//   SITEMAP(opts) == generator.py:571  generate_sitemap(articles, config,')
    A('//                                        standalones, categories)')
    A('//   ROBOTS(opts)  == generator.py:739-744  generate_static_pages 里写')
    A('//                    robots.txt 的那 3 行（**无独立函数**）')
    A('//')
    A('// ── 分层事实（卡片措辞与现状不一致处，按**实际实现**对齐）──────────────')
    A('// F1 草稿过滤**不在** generate_rss 里，在调用方 generator.py:730：')
    A('//      published = [a for a in articles if a.is_published]')
    A('//    ⇒ RSS() **不过滤**草稿（generate_rss 自己只做 articles[:20]）。')
    A('//    「排除草稿」是流水线责任：调用前按 is_published 过滤。')
    A('// F2 sitemap 用的是**未过滤**的 articles（generator.py:736）')
    A('//    ⇒ 真实实现里草稿**会**出现在 sitemap 里；本模块照做不改（登记为差异项）。')
    A('// F3 robots.txt 的 Sitemap: 行用 cfg.site_url or \'\'，**不回落** localhost，')
    A('//    也**没有** rstrip("/") ⇒ \'https://ex.com/\' 会拼出 \'//sitemap.xml\'。')
    A('//')
    A('// ── WLWL 侧的三处口径 ────────────────────────────────────────────')
    A('// · config 缺键 ⇒ 取 Python Config() 的默认值（site_title/site_description/lang）。')
    A('// · date_obj 是 NULL 或 DICT{"iso": <datetime.isoformat()>}（WLWL 无 datetime；')
    A('//   ArticleMeta.iso_date 只用到 isoformat() ⇒ 逐字节等价）。')
    A('// · 只有 title/summary/channel title+description 走转义；link/guid/loc/language')
    A('//   一律**原样**插值（照 Python 的 f-string）。')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/feeds_baseline.json')
    A('//   （由 tp/test/gen_feeds_baseline.py 用真 Python 生成；robots 那段是真跑')
    A('//     generate_static_pages 读回文件，不是复刻。）')
    A('')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_FIND_ALL", "RE_REPLACE"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('')

    # ── RSTRIP_SLASH ─────────────────────────────────────────────
    src += fn('RSTRIP_SLASH', 's', [
        '// 去掉结尾所有 "/"（对齐 Python 的 s.rstrip("/")）',
        '// ⚠ page_common.wll 里有一份私有同名实现，但它**未导出**（EXPORT 只含三个',
        '//   公开函数）⇒ 这里自带一份，不改别人的文件。',
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

    # ── ISO_DATE ────────────────────────────────────────────────
    # models.py:32-37
    #   @property
    #   def iso_date(self) -> str:
    #       if self.date_obj:
    #           return self.date_obj.isoformat()
    #       return self.date.replace(" ", "T") if " " in self.date else self.date
    src += fn('ISO_DATE', 'art', [
        '// 对齐 ArticleMeta.iso_date（models.py:32）',
        'LET(dobj, AT_K(art, "date_obj", NULL))',
        'LET(d, AT_K(art, "date", ""))',
        '// date 含空格 ⇒ **全部**空格换成 T（str.replace 无 count 参数）',
        'LET(fallback, IF(==(LEN(RE_FIND_ALL(RE(" "), d)), 0), d, '
        'RE_REPLACE(RE(" "), d, "T")))',
        '// date_obj：NULL ⇒ 走 date；DICT{"iso": …} ⇒ 用 isoformat；STRING ⇒ 直接当 iso',
        '// ⚠ IF 是惰性求值的（实测），所以这里的 AT_K(dobj, …) 不会在 dobj 为 NULL 时执行',
        'IF(==(TYPE(dobj), "STRING"), dobj, '
        'IF(==(TYPE(dobj), "DICT"), '
        'IF(==(AT_K(dobj, "iso", ""), ""), fallback, AT_K(dobj, "iso", "")), '
        'fallback))',
    ], '// ISO 8601 日期串（对齐 ArticleMeta.iso_date）')

    # ── PUSH_URL ────────────────────────────────────────────────
    # Python 是 list + "\n".join(...) ⇒ 这里用「非空就补前导 \n」的累积，逐字节等价。
    src += fn('PUSH_URL', 'acc, u', [
        '// 追加一条 <url>（对齐 Python 的 urls.append + "\\n".join）',
        'LET(one, ' + cat(wl(URL_ONE), 'u', wl(URL_TAIL)) + ')',
        'IF(==(acc, ""), one, ' + cat('acc', wl('\n'), 'one') + ')',
    ], '// 追加一条 sitemap <url> 条目')

    # ── RSS ─────────────────────────────────────────────────────
    src += fn('RSS', 'opts', [
        '// opts 键：articles（ARRAY[DICT]）/ config（DICT）',
        'LET(o, IF(==(TYPE(opts), "NULL"), DICT(), opts))',
        'LET(arts, AT_K(o, "articles", []))',
        'LET(cfg, AT_K(o, "config", DICT()))',
        '// generator.py:545 —— site_url = cfg.site_url or "http://localhost:8080"',
        '// ⚠ Python 的 `or` 对空串也回落；WLWL 没有 or 的真值语义 ⇒ 显式比空串',
        'LET(raw_url, AT_K(cfg, "site_url", ""))',
        'LET(site_url, IF(==(raw_url, ""), ' + wl(FALLBACK_URL) + ', raw_url))',
        'LET(base, RSTRIP_SLASH(site_url))',
        '// generator.py:547 —— items 只取前 20 条（截断在 generate_rss **内部**）',
        '// ⚠ 这里**不**过滤草稿：那一步在调用方 generator.py:730（见文件头 F1）',
        'LET(n, LEN(arts))',
        'LET(cap, IF(>(n, 20), 20, n))',
        'LET MUT(items, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, cap)', [
            'LET(a, AT(arts, i, DICT()))',
            '// generator.py:548 —— link 走 rstrip("/")',
            'LET(link, ' + cat('base', wl('/article/'), 'AT_K(a, "file", "")') + ')',
            '// generator.py:550-557 —— 每条 item 的固定缩进与换行（逐字节）',
            'SET(items, ' + cat(
                'items',
                wl(ITEM_HEAD),
                'ESCAPE_HTML(AT_K(a, "title", ""))',
                wl(ITEM_T1),
                'link',
                wl(ITEM_T2),
                'link',
                wl(ITEM_T3),
                'ISO_DATE(a)',
                wl(ITEM_T4),
                'ESCAPE_HTML(AT_K(a, "summary", ""))',
                wl(ITEM_TAIL)) + ')',
            'SET(i, +(i, 1))',
        ]),
        '// generator.py:559-568 —— 模板里 {items} 前有 4 个空格，items 以 "\\n" 开头',
        '// ⇒ items 为空时那一行是「4 个空格 + 换行」（行尾空白，必须留着）',
        cat(
            wl(RSS_HEAD),
            'ESCAPE_HTML(AT_K(cfg, "site_title", ' + wl(DEF_TITLE) + '))',
            wl(RSS_T1),
            'site_url',
            wl(RSS_T2),
            'ESCAPE_HTML(AT_K(cfg, "site_description", ' + wl(DEF_DESC) + '))',
            wl(RSS_T3),
            'AT_K(cfg, "lang", ' + wl(DEF_LANG) + ')',
            wl(RSS_T4),
            'items',
            wl(RSS_TAIL)),
    ], '// RSS 2.0 feed（对齐 generator.py:542）')

    # ── SITEMAP ─────────────────────────────────────────────────
    src += fn('SITEMAP', 'opts', [
        '// opts 键：articles / config / standalones / categories',
        'LET(o, IF(==(TYPE(opts), "NULL"), DICT(), opts))',
        'LET(arts, AT_K(o, "articles", []))',
        'LET(cfg, AT_K(o, "config", DICT()))',
        'LET(sts, AT_K(o, "standalones", []))',
        'LET(cats, AT_K(o, "categories", []))',
        '// generator.py:579 —— 回落同 RSS',
        'LET(raw_url, AT_K(cfg, "site_url", ""))',
        'LET(site_url, IF(==(raw_url, ""), ' + wl(FALLBACK_URL) + ', raw_url))',
        'LET(base, RSTRIP_SLASH(site_url))',
        '// 顺序照 Python（generator.py:580-588）：根 → articles → standalones → categories',
        '// ⚠ articles 是**未过滤**的（generator.py:736）⇒ 草稿也在（见文件头 F2）',
        '// ⚠ loc 是原样插值，**不做** XML 转义（Python 直接 f-string）',
        'LET MUT(entries, PUSH_URL("", ' + cat('base', wl('/')) + '))',
        'LET(na, LEN(arts))',
        'LET MUT(ia, 0)',
        C('WHILE', '<(ia, na)', [
            'SET(entries, PUSH_URL(entries, ' + cat(
                'base', wl('/article/'),
                'AT_K(AT(arts, ia, DICT()), "file", "")') + '))',
            'SET(ia, +(ia, 1))',
        ]),
        'LET(ns, LEN(sts))',
        'LET MUT(isx, 0)',
        C('WHILE', '<(isx, ns)', [
            'SET(entries, PUSH_URL(entries, ' + cat(
                'base', wl('/standalone/'),
                'AT_K(AT(sts, isx, DICT()), "file", "")') + '))',
            'SET(isx, +(isx, 1))',
        ]),
        'LET(nc, LEN(cats))',
        'LET MUT(ic, 0)',
        C('WHILE', '<(ic, nc)', [
            'SET(entries, PUSH_URL(entries, ' + cat(
                'base', wl('/category/'), 'AT(cats, ic, "")', wl('.html')) + '))',
            'SET(ic, +(ic, 1))',
        ]),
        '// generator.py:593-596 —— url_entries 非空（根 URL 恒有）',
        cat(wl(SITEMAP_HEAD), 'entries', wl(SITEMAP_TAIL)),
    ], '// XML sitemap（对齐 generator.py:571）')

    # ── ROBOTS ──────────────────────────────────────────────────
    src += fn('ROBOTS', 'opts', [
        '// opts 键：site_url（**直接**给，不是 config DICT）',
        'LET(site_url, AT_K(IF(==(TYPE(opts), "NULL"), DICT(), opts), "site_url", ""))',
        '// generator.py:740-744 —— 固定 3 行 + 结尾换行；**不回落** localhost',
        '// 也**没有** rstrip("/")（"https://ex.com/" ⇒ "//sitemap.xml"）',
        cat(wl(ROBOTS_HEAD), 'site_url', wl(ROBOTS_TAIL)),
    ], '// robots.txt（对齐 generator.py:739-744）')

    A('EXPORT(["RSS", "SITEMAP", "ROBOTS"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
