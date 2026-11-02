"""生成 tp/test/fixtures/feeds_baseline.json —— 订阅源与站点文件的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标**（全部**直接 import 真 Python 实现**，不重写规则）：

| 基准段 | 对齐的 Python 函数 | 位置 |
|---|---|---|
| `rss` | `tinypage.generator.generate_rss(articles, config)` | generator.py:542 |
| `sitemap` | `tinypage.generator.generate_sitemap(articles, config, standalones, categories)` | generator.py:571 |
| `robots` | `generate_static_pages` 里写 `robots.txt` 的那段（**无独立函数**） | generator.py:739-744 |

**`robots` 是「真跑」而不是复刻**：`_generate_robots()` 在临时目录里真的调
`generate_static_pages([], cfg, None)`，然后读回 `robots.txt` 的字节
（`root_dir` 指向 `mkdtemp()`，不碰仓库）。复刻 f-string 只能证明「我抄对了字面量」，
真跑能同时证明「那段确实被执行、且不受其它配置影响」。

---

## 三条必须先读的分层事实（读源码 + 实测，卡片措辞与现状**不一致**处已登记）

### F1 草稿过滤**不在** `generate_rss` 里，在**调用方**

```python
# generator.py:729-731
if cfg.enable_rss:
    published = [a for a in articles if a.is_published]
    (cfg.root_dir / "rss.xml").write_text(generate_rss(published, cfg), ...)
```

⇒ `generate_rss` 本身**不做任何过滤**，只做 `articles[:20]` 截断。
⇒ WLWL 的 `RSS(opts)` 对齐的是 **`generate_rss`**，所以**也不过滤**；
   「排除草稿」是**流水线**行为，基准里用两条对照用例表达：
   · `draft_raw`：原样喂进去（含草稿）⇒ 草稿**在**输出里（与 Python 逐字节一致）；
   · `draft_filtered`：喂调用方**过滤后**的列表 ⇒ 草稿**不在**输出里。

### F2 sitemap 用的是**未过滤**的 `articles`

```python
# generator.py:734-737
if cfg.enable_sitemap:
    (cfg.root_dir / "sitemap.xml").write_text(
        generate_sitemap(articles, cfg, standalones, categories), ...)
```

⇒ 真实实现里**草稿会出现在 sitemap 里**。这不是 WLWL 侧的偏差，是上游现状。
卡片的反向守卫「草稿不得出现在 sitemap」与现状冲突 ⇒ 本基准按
**真实实现**记录（用例 `draft_included`），并把它登记为「卡片 vs 现状」的差异项，
不擅自把 sitemap 改成过滤（那会与 Python 逐字节对照红）。

### F3 `robots.txt` 的 `Sitemap:` 行**不回落** localhost

```python
# generator.py:740-744
robots = f\"\"\"User-agent: *
Allow: /
Sitemap: {cfg.site_url or ''}/sitemap.xml
\"\"\"
```

⇒ 空 `site_url` 得到 `Sitemap: /sitemap.xml`（`localhost:8080` 的回落只在
`generate_rss`(545) / `generate_sitemap`(579) 里）。用例 `empty_url` + `trailing_slash`
（后者的 `//sitemap.xml` 证明这里**没有** `rstrip("/")`）把这条钉死。

---

**ArticleMeta → DICT 的字段口径**（WLWL 侧没有 dataclass / datetime）：
`title` / `date` / `slug` / `tags` / `summary` / `category` / `status` / `file` /
`date_obj`。`date_obj` 在 WLWL 侧是 `NULL` 或 `DICT{"iso": <datetime.isoformat()>}`
（`ArticleMeta.iso_date` 只用到 `isoformat()`，故这个替换是逐字节等价的；
`models.py:32`）。派生属性（`iso_date` / `is_draft` / `is_published` / `tag_list` /
`url`）在 WLWL 侧自己算。

用法：python gen_feeds_baseline.py
"""
import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from tinypage.config import Config                      # noqa: E402
from tinypage.generator import (                        # noqa: E402
    generate_rss,
    generate_sitemap,
    generate_static_pages,
)
from tinypage.models import ArticleMeta                 # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'feeds_baseline.json')


# ── ArticleMeta 的 JSON 形态 ↔ 真对象 ────────────────────────────────
# 只放 WLWL 侧会读的字段；`date_obj` 用 isoformat 字符串表示（见模块 docstring）。
ARTICLE_KEYS = ('title', 'date', 'summary', 'status', 'file', 'date_obj')


def mk_art(spec):
    """JSON 形态 → 真 ArticleMeta（date_obj 由 isoformat 字符串还原）。"""
    iso = spec.get('date_obj')
    return ArticleMeta(
        title=spec['title'],
        date=spec['date'],
        slug='',
        tags='',
        summary=spec['summary'],
        category='',
        status=spec['status'],
        file=spec['file'],
        date_obj=datetime.fromisoformat(iso) if iso else None,
    )


def mk_cfg(d):
    """JSON 形态 → 真 Config（只允许基准里出现的那几个键）。"""
    return Config(**d)


def art(title, date, summary, status, file, date_obj=None):
    return {
        'title': title,
        'date': date,
        'summary': summary,
        'status': status,
        'file': file,
        'date_obj': date_obj,
    }


# ── 文章与配置夹具 ────────────────────────────────────────────────
A_PUB1 = art('Hello & <World>', '2024-01-02 03:04:05',
             'summary "one" & more', 'published', 'hello.html')
A_PUB2 = art("Second 'quoted'", '2024-02-03', '', 'published', 'second.html')
A_DRAFT = art('Draft post', '2024-03-04 05:06:07', 'not yet', 'draft', 'draft.html')
A_OBJ = art('With date_obj', '2020-01-01 00:00:00', 'iso wins', 'published',
            'obj.html', date_obj='2024-05-06T07:08:09')
A_SPECIAL = art('A & B < C > D " E \' F', '2024-06-07',
                's & <t> "q" \'a\'', 'published', 'special.html')
# status 大小写：models.py:47 用 status.lower()，但 rss/sitemap 不读 status ⇒
# 这里只作为「原样传递」的证据存在。
A_UPPER = art('Upper status', '2024-07-08', 'u', 'DRAFT', 'upper.html')

CFG_URL = {
    'site_url': 'https://ex.com',
    'site_title': 'My & Co <blog>',
    'site_description': 'desc "x" & y',
    'lang': 'zh-CN',
}
CFG_EMPTY_URL = {
    'site_url': '',
    'site_title': 'TinyPage',
    'site_description': 'A modern static blog',
    'lang': 'en',
}
CFG_SLASH = {
    'site_url': 'https://ex.com/',
    'site_title': 'Slash',
    'site_description': 'trailing slash',
    'lang': 'zh-CN',
}


def cap20_articles():
    """25 篇（>20）—— 用来钉 `articles[:20]` 的截断在 `generate_rss` 内部。"""
    out = []
    for i in range(1, 26):
        out.append(art('Post %d' % i, '2024-01-02', 'summary %d' % i,
                       'published', 'p%d.html' % i))
    return out


STANDALONE = art('About', '', 'about page', 'published', 'about.html')


# ── robots.txt：真跑 generate_static_pages 取字节 ─────────────────────
def _generate_robots(site_url):
    """在临时目录里真跑 `generate_static_pages`，读回 robots.txt。

    ⚠ 这条**不是复刻**：它证明 generator.py:739-744 那段真的被执行，
      且内容只由 `cfg.site_url` 决定（其它配置取默认值即可）。
    `enable_search=False` 只是为了少写文件（search 页与 robots 无关）。
    """
    tmp = Path(tempfile.mkdtemp(prefix='tp_feeds_robots_'))
    root = tmp / 'public'
    root.mkdir(parents=True, exist_ok=True)
    cfg = Config(root_dir=root, site_url=site_url, enable_search=False)
    generate_static_pages([], cfg, None)
    return (root / 'robots.txt').read_text(encoding='utf-8')


def main():
    cases = {'rss': {}, 'sitemap': {}, 'robots': {}}

    def add_rss(name, articles, cfg, note=None):
        want = generate_rss([mk_art(a) for a in articles], mk_cfg(cfg))
        cases['rss'][name] = {
            'articles': articles,
            'config': cfg,
            'want': want,
        }
        if note:
            cases['rss'][name]['note'] = note

    def add_sitemap(name, articles, cfg, standalones=None, categories=None,
                    note=None):
        want = generate_sitemap(
            [mk_art(a) for a in articles],
            mk_cfg(cfg),
            [mk_art(a) for a in (standalones or [])] or None,
            list(categories or []) or None,
        )
        cases['sitemap'][name] = {
            'articles': articles,
            'config': cfg,
            'standalones': standalones or [],
            'categories': categories or [],
            'want': want,
        }
        if note:
            cases['sitemap'][name]['note'] = note

    # ── RSS ───────────────────────────────────────────────────────
    add_rss('basic', [A_PUB1, A_PUB2], CFG_URL)
    add_rss('empty', [], CFG_URL,
            note='空列表 ⇒ items 为空串；模板里 {items} 前那 4 个空格仍在（行尾空白，'
                 '逐字节必须一致）')
    add_rss('cap20', cap20_articles(), CFG_URL,
            note='25 篇 ⇒ generate_rss 内部 articles[:20] 截断到 20 条')
    add_rss('special_chars', [A_SPECIAL], CFG_URL,
            note='标题/摘要/站点标题/描述都含 & < > " \' ⇒ 必须走 html.escape(quote=True)')
    add_rss('empty_site_url', [A_PUB1], CFG_EMPTY_URL,
            note='generator.py:545 回落 "http://localhost:8080"（channel link 用回落值）')
    add_rss('trailing_slash', [A_PUB1], CFG_SLASH,
            note='item link 走 rstrip("/")，但 channel <link> 用**原值**（带尾斜杠）')
    add_rss('date_space', [A_PUB1], CFG_URL,
            note='iso_date：date 含空格 ⇒ 全部空格替换成 T（str.replace）')
    add_rss('date_obj', [A_OBJ], CFG_URL,
            note='date_obj 存在 ⇒ 用 datetime.isoformat()，忽略 date')
    add_rss('default_config', [A_PUB1], {},
            note='空 config ⇒ 取 Config() 的默认值（site_title/site_description/lang）')
    add_rss('draft_raw', [A_PUB1, A_DRAFT, A_PUB2], CFG_URL,
            note='F1：原样喂进去 ⇒ generate_rss 不过滤，草稿在输出里（与 Python 一致）')
    add_rss('draft_filtered', [A_PUB1, A_PUB2], CFG_URL,
            note='F1：这是**调用方** generator.py:730 过滤后的输入 ⇒ 草稿不在输出里')
    add_rss('upper_status', [A_UPPER], CFG_URL,
            note='status 原样传递；rss 不读 status（大小写不影响输出）')

    # ── SITEMAP ───────────────────────────────────────────────────
    add_sitemap('basic', [A_PUB1, A_PUB2], CFG_URL)
    add_sitemap('with_standalones', [A_PUB1], CFG_URL, [STANDALONE])
    add_sitemap('with_categories', [A_PUB1], CFG_URL,
                categories=['杂谈', 'tech & stuff'],
                note='loc **不做** XML 转义（Python 直接 f-string 插值）⇒ `&` 原样出现')
    add_sitemap('all', [A_PUB1, A_PUB2], CFG_URL, [STANDALONE],
                ['杂谈', 'tech'])
    add_sitemap('empty_site_url', [A_PUB1], CFG_EMPTY_URL,
                note='generator.py:579 回落 localhost:8080')
    add_sitemap('trailing_slash', [A_PUB1], CFG_SLASH)
    add_sitemap('empty_articles', [], CFG_URL,
                note='只剩根 URL 一条')
    add_sitemap('draft_included', [A_PUB1, A_DRAFT], CFG_URL,
                note='F2：generator.py:736 传的是**未过滤**的 articles ⇒ 草稿在 sitemap 里')

    # ── ROBOTS（真跑）──────────────────────────────────────────────
    for name, url, note in [
        ('with_url', 'https://ex.com', None),
        ('empty_url', '',
         'F3：不回落 localhost ⇒ `Sitemap: /sitemap.xml`'),
        ('trailing_slash', 'https://ex.com/',
         'F3：**没有** rstrip ⇒ `//sitemap.xml`（证明这里不是 rss/sitemap 的口径）'),
    ]:
        entry = {'site_url': url, 'want': _generate_robots(url)}
        if note:
            entry['note'] = note
        cases['robots'][name] = entry

    base = {
        'source': {
            'rss': 'tinypage/generator.py:542 generate_rss(articles, config)',
            'sitemap': 'tinypage/generator.py:571 '
                       'generate_sitemap(articles, config, standalones, categories)',
            'robots': 'tinypage/generator.py:739-744 '
                      '（generate_static_pages 内部，真跑取字节）',
            'draft_filter_site': 'tinypage/generator.py:730 '
                                 '(published = [a for a in articles if a.is_published])',
            'sitemap_unfiltered_site': 'tinypage/generator.py:736 (articles 未过滤)',
            'iso_date': 'tinypage/models.py:32 ArticleMeta.iso_date',
            'article_dict_keys': list(ARTICLE_KEYS),
        },
        'cases': cases,
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(base, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    n = sum(len(v) for v in cases.values())
    print('wrote %s (%d cases: %d rss / %d sitemap / %d robots)' % (
        OUT, n, len(cases['rss']), len(cases['sitemap']), len(cases['robots'])))


if __name__ == '__main__':
    main()
