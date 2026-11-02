"""生成 tp/test/fixtures/search_index_baseline.json —— 搜索索引的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标**（**直接 import 真 Python 实现**，不重写规则）：

| 基准段 | 对齐的 Python 函数 | 位置 |
|---|---|---|
| `search_index` | `tinypage.generator.generate_search_index` | generator.py:599 |

**为什么期望值一律调真函数**：`json.dumps` 的分隔符/转义/键序是**字节级**契约，
照着"规则"手抄一遍基准，抄错的地方就没人能发现了。

**本卡最关键的字节口径（本机实测）**：

  · Python 侧：`json.dumps(data, ensure_ascii=False)`
    ⇒ **插入序** + 分隔符 `", "` / `": "` + 紧凑（**不是** `indent=2`）。
  · WLWL 侧：`std.json::STRINGIFY` 对**容器**是**紧凑分隔符 + 键名字典序**
    （实测 `{"a":2,"z":1}`），与 Python 的插入序不同 ⇒ **不能整体序列化**。
  · WLWL 侧：`STRINGIFY` 对**单个字符串**与 Python 的转义**逐字一致**（实测）：
    `"`→`\\"`、`\\`→`\\\\`、`\\n`/`\\t`/`\\r`/`\\b`/`\\f` 同名、
      控制字符走 `\\u00XX`（实测 `\\x01`→`"\\u0001"`、`\\x1f`→`"\\u001f"`、
      `\\x0b`→`"\\u000b"`）、`\\x7f` 与 `/` 与中文/emoji **原样保留**。
    ⇒ 所以 `tp/lib/search_index.wll` 采取「**骨架手工拼装 + 标量走 STRINGIFY**」，
      可以做到与 Python **逐字节**相同（不是"登记差异"）。

**草稿：不过滤（与 Python 的函数一一对应）**

  `generate_search_index` **本身不过滤草稿**（generator.py:604-624 是对 `articles`
  的无条件推导式），它拿到什么就序列化什么；排除发生在**调用方的上一层**：
  `cli.py:139 list_articles(cfg.article_dir, cfg.max_file_size)` 的
  `include_drafts` 默认 `False`（content.py:187-189）。
  同族的 `generate_rss` 也一样（不过滤，`generator.py:730` 调用方过滤）。
  ⇒ 本项目约定「一个 WLWL 模块 = 一个 Python 函数」⇒ `SEARCH_INDEX` **不过滤**，
    `want` 就是真 Python 对**同一份原样列表**的输出（`python == want`，无差异）。
  ⇒ 反向守卫 `guard/drafts_pass_through` 钉住这条：草稿**会**出现在产物里。

**已知差异（唯一一条，`_meta.known_differences` D1，实测）**

  tags 的 strip 只剥 **ASCII** 空白：实测 WLWL `TRIM("\u3000a\u3000")` 原样返回，
  而 Python 的 `" \u3000 a \u3000 ".strip()` 剥 U+3000/NBSP。⇒ 仅当 tags 里含
  U+3000 / U+00A0 这类非 ASCII 空白时两边不同；夹具的 `tags_edges` 只覆盖 ASCII
  空白，**这条缺口没被用例钉住**（诚实地记在 `_meta` 里，不制造一个假绿用例）。

**用例输入形态**：`articles` / `standalones` 是**ArticleMeta 构造参数**的字典列表
（键名与 dataclass 字段同名：`title` / `date` / `slug` / `tags` / `summary` /
`category` / `status` / `file`）。⚠ 键可以缺省 —— 缺省即用 dataclass 默认值，
测的是「WLWL 侧缺键时的回落与 Python 默认值一致」。
⚠ 也允许出现**多余键**（如 `content`）—— Python 侧会被直接忽略，
用来钉反向守卫「正文不得进索引」。

用法：python gen_search_index_baseline.py
"""
import dataclasses
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.generator import generate_search_index  # noqa: E402
from tinypage.models import ArticleMeta  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'search_index_baseline.json')

FIELD_NAMES = {f.name for f in dataclasses.fields(ArticleMeta)}

# ── 反向守卫用的哨兵串 ────────────────────────────────────────────────
# 这些串只出现在**输入**里，产物里出现即失败（见 gen_test_search_index.py）
DRAFT_TITLE_UPPER = '大写草稿标题-DRAFT-UPPER'
DRAFT_TITLE_LOWER = '小写草稿标题-DRAFT-LOWER'
CONTENT_MARKER = 'CONTENT-MUST-NOT-APPEAR-IN-INDEX'


def art(**kw):
    """一个 ArticleMeta 构造参数。"""
    return kw


# ── 用例 ──────────────────────────────────────────────────────────────
# 每个用例：(名字, articles, standalones, note)
#   note 非空 ⇒ 登记为已知差异（本文件会校验 note 非空的用例 python != want）
CASES = [
    # ① 空列表
    ('empty', [], None, None),
    ('empty_with_standalones_key', [], [], None),

    # ② 单篇
    ('single', [
        art(title='Hello World', date='2024-03-01 10:00', slug='hello-world',
            tags='python, web', summary='第一篇摘要', category='Tech',
            status='published', file='2024-03-01-hello-world.html'),
    ], None, None),

    # ③ 多篇（分类/标签/日期都不同，覆盖排序无关但字段齐全）
    ('multi', [
        art(title='Alpha', date='2024-03-03 09:00', slug='alpha',
            tags='a, b, c', summary='A 摘要', category='Tech',
            status='published', file='2024-03-03-alpha.html'),
        art(title='Beta', date='2024-03-02 09:00', slug='beta',
            tags='', summary='', category='',
            status='published', file='2024-03-02-beta.html'),
        art(title='Gamma', date='2024-03-01 09:00', slug='gamma',
            tags='单标签', summary='中文摘要', category='生活',
            status='published', file='2024-03-01-gamma.html'),
    ], None, None),

    # ④ 含草稿 ⇒ 草稿**原样进产物**（本模块不过滤，见 docstring）
    ('drafts_included', [
        art(title='已发布文章', date='2024-04-03 08:00', slug='pub',
            tags='x', summary='可见', category='Tech',
            status='published', file='2024-04-03-pub.html'),
        # ⚠ status 大小写混排：ArticleMeta.is_draft 是 status.lower() == "draft"，
        #   但 generate_search_index **根本不看 status** ⇒ 两种写法都照样进产物
        art(title=DRAFT_TITLE_UPPER, date='2024-04-02 08:00', slug='d1',
            tags='draft, hidden', summary='草稿一', category='Tech',
            status='Draft', file='2024-04-02-d1.html'),
        art(title=DRAFT_TITLE_LOWER, date='2024-04-01 08:00', slug='d2',
            tags='draft', summary='草稿二', category='',
            status='draft', file='2024-04-01-d2.html'),
    ], None,
     '草稿不排除：generate_search_index 不过滤草稿（generator.py:604-624），'
     '排除在生产链路的调用方（cli.py:139 的 list_articles(include_drafts=False)，'
     '过滤点在 content.py:187-189）。本模块照抄函数现状、原样遍历。'),

    # ⑤ 全是草稿 ⇒ 全部进产物（不是空数组）
    ('all_drafts', [
        art(title=DRAFT_TITLE_UPPER + '-2', date='2024-05-02 08:00',
            slug='d1', tags='draft', summary='s', category='',
            status='draft', file='2024-05-02-d1.html'),
        art(title=DRAFT_TITLE_LOWER + '-2', date='2024-05-01 08:00',
            slug='d2', tags='', summary='', category='',
            status='DRAFT', file='2024-05-01-d2.html'),
    ], None,
     '草稿不排除（全部草稿也照样逐条进产物，不是 "[]"）；'
     '排除在生产链路的调用方 cli.py:139 完成。'),

    # ⑥ 有 standalones
    ('with_standalones', [
        art(title='文章一', date='2024-06-02 07:00', slug='a1', tags='t',
            summary='摘要一', category='Tech', status='published',
            file='2024-06-02-a1.html'),
        art(title='文章二', date='2024-06-01 07:00', slug='a2', tags='',
            summary='', category='', status='published',
            file='2024-06-01-a2.html'),
    ], [
        # standalone 的 date/tags/category 被**硬编码**为空（generator.py:617-624），
        # 即使 meta 里有值也不出现在产物里 ⇒ 这里故意塞了值来钉这条
        art(title='关于页', date='2024-01-01 00:00', slug='',
            tags='ignored, tags', summary='关于本站', category='ignored',
            status='published', file='about.html'),
        art(title='', summary='', file='links.html'),
    ], None),

    # ⑦ 只有 standalones（无 articles）
    ('standalones_only', [], [
        art(title='独立页 A', summary='sa 摘要', file='a.html'),
    ], None),

    # ⑧ JSON 转义：引号 / 反斜杠 / 换行 / tab / 中文 / emoji
    ('escaping', [
        art(title='引号"与反斜杠\\与换行\n第二行',
            date='2024-07-01 06:00', slug='esc', tags='a "quoted" tag, b\\c',
            summary='摘要里的\t制表符 与 "双引号"',
            category='分类"带引号"', status='published',
            file='2024-07-01-esc.html'),
        art(title='emoji 🚀 与中文', date='2024-07-02 06:00', slug='u',
            tags='🚀, 中文', summary='换行\n与回车\r\n结束', category='',
            status='published', file='2024-07-02-u.html'),
    ], None, None),

    # ⑨ tags 的切分边界（Python 的 tag_list）
    ('tags_edges', [
        art(title='t1', tags='', file='t1.html'),
        art(title='t2', tags=' , , ', file='t2.html'),
        art(title='t3', tags='a', file='t3.html'),
        art(title='t4', tags=' a , b ', file='t4.html'),
        art(title='t5', tags='a,b,', file='t5.html'),
        art(title='t6', tags='\t tab \t', file='t6.html'),
        # 内部逗号不切（只有分隔用的逗号才切）
        art(title='t7', tags='a , b ,c', file='t7.html'),
    ], None, None),

    # ⑩ 缺 status 键 ⇒ 回落 published（双向：dataclass 默认 vs WLWL 的 AT_K 默认）
    ('no_status_key', [
        art(title='无 status 键', date='2024-08-01 05:00', slug='n',
            tags='x', summary='s', category='c', file='2024-08-01-n.html'),
    ], None, None),

    # ⑪ 输入里有正文 ⇒ 必须不出现在产物里（反向守卫的输入侧）
    ('extra_fields_ignored', [
        art(title='带正文的文章', date='2024-09-01 04:00', slug='e',
            tags='x', summary='s', category='c', status='published',
            file='2024-09-01-e.html', content=CONTENT_MARKER),
    ], None, None),
]


def build_meta(spec):
    """字典 → 真 ArticleMeta。

    ⚠ `ArticleMeta` 是 dataclass，**多余键会 TypeError** ⇒ 只挑字段名。
    这正是「输入里的 `content` 等多余键在 Python 侧根本不存在」的由来：
    WLWL 侧收到的是字典、可能带多余键 ⇒ 必须与之等价地忽略它们。
    """
    return ArticleMeta(**{k: v for k, v in spec.items() if k in FIELD_NAMES})


def main():
    cases = {}
    for name, arts, pages, note in CASES:
        mates = [build_meta(a) for a in arts]
        pages_meta = None if pages is None else [build_meta(p) for p in pages]

        # 与 Python 的函数**同一份原样列表** ⇒ 无草稿过滤、无任何加工。
        # ⚠ 想要「不含草稿的索引」，Python 侧的写法是先把已发布子集挑出来再调用
        #   （生产链路就是这么做的：cli.py:139），本模块把这件事留给调用方。
        want = generate_search_index(mates, pages_meta)

        entry = {
            'articles': arts,
            'standalones': pages,
            'want': want,
        }
        if note:
            entry['note'] = note
        cases[name] = entry

    base = {
        '_meta': {
            'module': 'tp/lib/search_index.wll',
            'export': 'SEARCH_INDEX(opts)',
            'target': 'tinypage/generator.py:599 generate_search_index',
            'python_eval': 'generate_search_index(articles, standalones)',
            'separators': 'json.dumps 默认（", " / ": "），无 indent',
            'ensure_ascii': False,
            'key_order': '插入序 title, summary, url, date, tags, category',
            'standalone_url_prefix': '/standalone/',
            'article_url_prefix': '/article/',
            'draft_filtering': '本模块不过滤草稿（= generate_search_index 的现状，'
                               '分层：一个 WLWL 模块 = 一个 Python 函数）；'
                               '排除在生产链路的调用方 cli.py:139 '
                               '(list_articles(include_drafts=False)，'
                               '过滤点 content.py:187-189) 完成。'
                               '反向守卫 guard/drafts_pass_through 钉住这条。',
            'known_differences': [
                {
                    'id': 'D1',
                    'what': 'tags 的 strip 只剥 ASCII 空白（Python 剥 Unicode 空白）',
                    'evidence': '实测 WLWL TRIM("\\u3000a\\u3000") 原样返回（len 仍为 3、'
                                '!= "a"）；TRIM(NBSP+"b"+NBSP) 同样不动。'
                                'Python 的 "\\u3000a\\u3000".strip() == "a"、'
                                '"\\xa0b\\xa0".strip() == "b"（两者 isspace() 均为 True）。'
                                '实测 2026-11-02（探针 s24trim.wll / pytrim.py）。',
                    'impact': '仅当 tags 串里含 U+3000（全角空格）/ U+00A0（NBSP）等'
                              '非 ASCII 空白时，本模块与 Python 的 tag 值不同。'
                              '夹具的 tags_edges 只覆盖 ASCII 空白（空格 / \\t），'
                              '所以测试全绿 —— 这条缺口**没有**被夹具钉住。',
                    'fix_if_needed': '按 tp/lib/article_page.wll 的 PY_WS() 写法，'
                                     '用 RE_REPLACE 在两侧剥 Unicode 空白集合'
                                     '（README 陷阱 #41 已登记同一事实）。'
                                     '本卡未改：父会话明确要求保留现有 tags 行为。',
                },
            ],
        },
        'cases': cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(base, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    n = sum(len(c['articles']) + len(c['standalones'] or []) for c in cases.values())
    print(f'wrote {OUT} ({len(cases)} cases, {n} input records)')


if __name__ == '__main__':
    main()
