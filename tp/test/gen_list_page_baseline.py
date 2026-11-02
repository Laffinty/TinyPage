"""生成 tp/test/fixtures/list_page_baseline.json —— 列表/分类/搜索页的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标**（全部**直接 import 真 Python 实现**，不重写任何 HTML 规则）：

| 基准段 | 对齐的 Python 函数 | 位置 |
|---|---|---|
| `LIST_PAGE` | `tinypage.generator.generate_list_page` | generator.py:298 |
| `CATEGORY_PAGE` | `tinypage.generator.generate_category_page` | generator.py:484 |
| `SEARCH_PAGE` | `tinypage.generator.generate_search_page` | generator.py:389 |

期望值 = 真函数的返回值（**逐字节**），WLLW 侧的 `tp/lib/list_page.wll` 必须与它
完全一致。夹具里出现的每个字符串（标题里的 `<script>`、`$5`、只有空格的 tags …）
都是为了钉住某一条具体的 Python 语义，见各 case 的 `note`。

**两条刻意的取舍**（写在这里，免得读夹具的人以为漏了）：
  ① `theme_css` / `dark_css` 一律**显式**传非空值 ⇒ Python 的
     `_build_common_context` 不会走 `load_theme_css(cfg.theme_dir)` 分支
     （那个分支要读文件系统；WLWL 侧的 `COMMON_CONTEXT` 只在 `config` 带
     `theme_dir` 键时才走）⇒ 两边都**不碰文件系统**，夹具与机器无关。
  ② `config` 只序列化**卡片 S2-4 列出的 17 个键**，**不含** `theme_dir`
     （Python 侧是 `Path`，且按 ① 用不到）。
  ③ `ArticleMeta` 只序列化这三个页面函数**真正会读到**的字段：
     `title` / `date` / `tags` / `summary` / `category` / `file`
     （`slug` / `status` / `date_obj` 在这三个函数里没有被用到；
     `url` 与 `tag_list` 是 Python 的**派生属性**，由 `file` / `tags` 算出）。

**分页语义**：`generate_list_page` **不**计算分页 —— `page_info` 由调用方
（`generate_static_pages`，generator.py:658）构造。故「第 2 页的 `prev_url`
指向 `/`」这条表现在夹具里以 `list_page2_prev_root` 固定下来（值是 `"/"`），
而 `page_size` 默认 10 的语义同样属于调用方，本模块不读 `page_size`。

用法：python gen_list_page_baseline.py
"""
import json
import os
import sys
from dataclasses import replace

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.config import Config  # noqa: E402
from tinypage.models import ArticleMeta, PageInfo  # noqa: E402
from tinypage.generator import (  # noqa: E402
    generate_list_page, generate_category_page, generate_search_page,
)

OUT = os.path.join(HERE, 'fixtures', 'list_page_baseline.json')

# ── Config 的 17 个键（卡片 S2-4 的口径；值与 tinypage/config.py 的默认值一致）──
BASE_CONFIG = {
    'site_title': 'TinyPage',
    'site_description': 'A modern static blog',
    'site_url': '',
    'site_author': '',
    'footer_text': 'Powered by TinyPage',
    'lang': 'zh-CN',
    'theme_name': 'default',
    'page_size': 10,
    'enable_pwa': True,
    'enable_dark_mode': True,
    'enable_search': True,
    'enable_rss': True,
    'enable_sitemap': True,
    'enable_view_transitions': True,
    'pwa_short_name': 'TinyPage',
    'pwa_theme_color': '#2c3e50',
    'pwa_bg_color': '#ffffff',
}

THEME_CSS = 'body{color:#222}'
DARK_CSS = 'body{background:#111;color:#eee}'


def make_config(**over):
    """构造**真** Config 对象（先取默认，再按夹具覆写）。

    ⚠ `Config` 是 `@dataclass(frozen=True)` ⇒ **不能** `setattr`，
      只能用 `dataclasses.replace` 派生一个新实例。
    """
    values = dict(BASE_CONFIG)
    values.update(over)
    return replace(Config(), **values)


def make_article(**over):
    """构造**真** ArticleMeta（未给的字段留 dataclass 默认值）。"""
    return ArticleMeta(**over)


def base_opts(**over):
    """三个页面函数共用的 opts 骨架。"""
    opts = {
        'config': dict(BASE_CONFIG),
        'theme_css': THEME_CSS,
        'dark_css': '',
        'has_dark': False,
        'standalones': [],
    }
    opts.update(over)
    return opts


def art(title='', date='2026-01-02', tags='', summary='', category='', file='a.html'):
    return {
        'title': title, 'date': date, 'tags': tags,
        'summary': summary, 'category': category, 'file': file,
    }


def page_info(current=1, total=1, has_prev=False, has_next=False,
              prev_url='', next_url=''):
    return {
        'current': current, 'total': total,
        'has_prev': has_prev, 'has_next': has_next,
        'prev_url': prev_url, 'next_url': next_url,
    }


def build_cases():
    cases = []

    # ── 列表页 ────────────────────────────────────────────────────
    three = [
        make_article(title='Hello World', date='2026-01-02', tags='python, wll',
                     summary='first summary', category='Tech',
                     file='2026-01-02-hello.html'),
        make_article(title='Second Post', date='2026-01-01', tags='',
                     summary='second summary', category='',
                     file='2026-01-01-second.html'),
    ]
    cases.append({
        'name': 'list_single_page',
        'fn': 'LIST_PAGE',
        'note': '单页（total=1）：无分页 nav，两条文章；一条带 tags+category、一条都不带。',
        'opts': base_opts(
            articles=[art(**a) for a in [
                dict(title='Hello World', date='2026-01-02', tags='python, wll',
                     summary='first summary', category='Tech',
                     file='2026-01-02-hello.html'),
                dict(title='Second Post', date='2026-01-01',
                     summary='second summary', file='2026-01-01-second.html'),
            ]],
            page_info=page_info()),
        'want': generate_list_page(
            three, PageInfo(), make_config(), THEME_CSS, '', False, []),
    })

    p2_items = [
        make_article(title='Page Two A', date='2025-12-31', tags='x',
                     summary='a', file='2025-12-31-a.html'),
        make_article(title='Page Two B', date='2025-12-30',
                     summary='b', category='Life', file='2025-12-30-b.html'),
    ]
    p2 = PageInfo(current=2, total=3, has_prev=True, has_next=True,
                  prev_url='/', next_url='/list/3.html')
    cases.append({
        'name': 'list_page2_prev_root',
        'fn': 'LIST_PAGE',
        'note': '第 2 页 / 共 3 页：prev_url 必须是 "/"（不是 "/list/1.html"）；'
                '当前页码用 <span class="current">。',
        'opts': base_opts(
            articles=[art(**a) for a in [
                dict(title='Page Two A', date='2025-12-31', tags='x',
                     summary='a', file='2025-12-31-a.html'),
                dict(title='Page Two B', date='2025-12-30',
                     summary='b', category='Life', file='2025-12-30-b.html'),
            ]],
            page_info=page_info(current=2, total=3, has_prev=True, has_next=True,
                                prev_url='/', next_url='/list/3.html')),
        'want': generate_list_page(
            p2_items, p2, make_config(), THEME_CSS, '', False, []),
    })

    p3_items = [make_article(title='Last', date='2025-12-29', summary='z',
                             file='2025-12-29-last.html')]
    p3 = PageInfo(current=3, total=3, has_prev=True, has_next=False,
                  prev_url='/list/2.html', next_url='')
    cases.append({
        'name': 'list_page3_next_empty',
        'fn': 'LIST_PAGE',
        'note': '末页：只有 prev 链接，没有 next；next_url 为空串。',
        'opts': base_opts(
            articles=[art(title='Last', date='2025-12-29', summary='z',
                          file='2025-12-29-last.html')],
            page_info=page_info(current=3, total=3, has_prev=True,
                                prev_url='/list/2.html')),
        'want': generate_list_page(
            p3_items, p3, make_config(), THEME_CSS, '', False, []),
    })

    cases.append({
        'name': 'list_empty',
        'fn': 'LIST_PAGE',
        'note': '空列表：items 为空串 ⇒ <div class="posts"> 内只有空白；total=1 ⇒ 无分页 nav。',
        'opts': base_opts(articles=[], page_info=page_info()),
        'want': generate_list_page(
            [], PageInfo(), make_config(), THEME_CSS, '', False, []),
    })

    esc_items = [
        make_article(title='<script>alert(1)</script>',
                     date='2026-02-01 10:00', tags='<b>, "q" ,&amp;',
                     summary='<p>段落</p> & <em>x</em>',
                     category='A&B<script>', file='2026-02-01-esc.html'),
    ]
    cases.append({
        'name': 'list_escape',
        'fn': 'LIST_PAGE',
        'note': '反向守卫的基准：标题/摘要/tags/分类里的 HTML 必须被 escape。'
                '⚠ 摘要是**先 escape 再**去掉字面 "<p>"/"</p>"（Python 行序如此）'
                '⇒ escape 后已无 "<p>" ⇒ 那条 replace 实际是空操作，但仍要复刻。',
        'opts': base_opts(
            articles=[art(title='<script>alert(1)</script>',
                          date='2026-02-01 10:00', tags='<b>, "q" ,&amp;',
                          summary='<p>段落</p> & <em>x</em>',
                          category='A&B<script>', file='2026-02-01-esc.html')],
            page_info=page_info()),
        'want': generate_list_page(
            esc_items, PageInfo(), make_config(), THEME_CSS, '', False, []),
    })

    dollar_items = [make_article(title='Price $5 and ${x}',
                                 date='2026-02-02', summary='cost $9',
                                 file='2026-02-02-dollar.html')]
    cases.append({
        'name': 'list_dollar',
        'fn': 'LIST_PAGE',
        'note': '插值守卫：标题/摘要里的 `$` 必须**原样**输出。'
                'WLWL 字符串字面量里 `$` 是插值 ⇒ 夹具生成器必须转义成 `\\$`。',
        'opts': base_opts(
            articles=[art(title='Price $5 and ${x}', date='2026-02-02',
                          summary='cost $9', file='2026-02-02-dollar.html')],
            page_info=page_info()),
        'want': generate_list_page(
            dollar_items, PageInfo(), make_config(), THEME_CSS, '', False, []),
    })

    long_title = 'T' * 100
    long_items = [make_article(title=long_title, date='2026-02-03',
                               summary='s', file='2026-02-03-long.html')]
    cases.append({
        'name': 'list_long_title',
        'fn': 'LIST_PAGE',
        'note': '标题按 Python 的 art.title[:80] 截断（100 个 T ⇒ 只剩 80 个）。',
        'opts': base_opts(
            articles=[art(title=long_title, date='2026-02-03', summary='s',
                          file='2026-02-03-long.html')],
            page_info=page_info()),
        'want': generate_list_page(
            long_items, PageInfo(), make_config(), THEME_CSS, '', False, []),
    })

    tags_space_items = [make_article(title='Spaces', date='2026-02-04',
                                     tags=' ,  , ', summary='s',
                                     file='2026-02-04-sp.html')]
    cases.append({
        'name': 'list_tags_spaces_only',
        'fn': 'LIST_PAGE',
        'note': '⚠ 刁钻点：tags 是 " ,  , " ⇒ `if art.tags:` **真**（原串非空）'
                '但 tag_list 过滤后为空 ⇒ 输出 `<div class="post-tags"></div>`'
                '（空的 div），**不是**不输出 div。',
        'opts': base_opts(
            articles=[art(title='Spaces', date='2026-02-04', tags=' ,  , ',
                          summary='s', file='2026-02-04-sp.html')],
            page_info=page_info()),
        'want': generate_list_page(
            tags_space_items, PageInfo(), make_config(), THEME_CSS, '', False, []),
    })

    dark_arts = [make_article(title='Dark', date='2026-02-05', tags='wll',
                              summary='s', category='Tech',
                              file='2026-02-05-dark.html')]
    stands = [
        make_article(title='About', file='about.html'),
        make_article(title='A very long standalone title here', file='proj.html'),
    ]
    cases.append({
        'name': 'list_dark_standalones',
        'fn': 'LIST_PAGE',
        'note': 'has_dark=True + dark_css 非空 + 两个独立页 ⇒ 暗色 meta/脚本/按钮与'
                '导航里的独立页链接都出现；其中一个标题超过 20 码点（nav 里截断）。',
        'opts': base_opts(
            articles=[art(title='Dark', date='2026-02-05', tags='wll',
                          summary='s', category='Tech', file='2026-02-05-dark.html')],
            page_info=page_info(),
            theme_css=THEME_CSS, dark_css=DARK_CSS, has_dark=True,
            standalones=[{'title': 'About', 'file': 'about.html'},
                         {'title': 'A very long standalone title here',
                          'file': 'proj.html'}]),
        'want': generate_list_page(
            dark_arts, PageInfo(), make_config(), THEME_CSS, DARK_CSS, True, stands),
    })

    # ── 分类页 ────────────────────────────────────────────────────
    cat_arts = [
        make_article(title='One', date='2026-03-01', tags='a,b',
                     summary='s1', category='Tech', file='2026-03-01-one.html'),
        make_article(title='Two', date='2026-02-28', summary='s2',
                     category='Tech', file='2026-02-28-two.html'),
    ]
    cases.append({
        'name': 'category_normal',
        'fn': 'CATEGORY_PAGE',
        'note': '分类页与列表页的预览块有**两处**结构差异：① 没有 category-badge 行；'
                '② 没有标签（post-tags）行 —— 本例第一条文章带 tags="a,b"，'
                '正是用来钉住「分类页不出标签区」。另：分类页没有分页。',
        'opts': base_opts(
            category='Tech',
            articles=[art(title='One', date='2026-03-01', tags='a,b',
                          summary='s1', category='Tech', file='2026-03-01-one.html'),
                      art(title='Two', date='2026-02-28', summary='s2',
                          category='Tech', file='2026-02-28-two.html')]),
        'want': generate_category_page(
            'Tech', cat_arts, make_config(), THEME_CSS, '', False, []),
    })

    cases.append({
        'name': 'category_empty',
        'fn': 'CATEGORY_PAGE',
        'note': '空分类：`共 0 篇文章`，items 为空串。',
        'opts': base_opts(category='Empty', articles=[]),
        'want': generate_category_page(
            'Empty', [], make_config(), THEME_CSS, '', False, []),
    })

    cat_esc_arts = [make_article(title='<i>x</i>', date='2026-03-02',
                                 summary='<p>s</p>', category='A&B',
                                 file='2026-03-02-esc.html')]
    cases.append({
        'name': 'category_escape',
        'fn': 'CATEGORY_PAGE',
        'note': '反向守卫的基准：分类名 `<A&B<script>>` 在 h1 / <title> / '
                'meta description 三处都必须 escape（其中 description 会被 '
                'escape **两次** —— Python 先把 safe_category 传进去，'
                'render_skeleton 再 escape 一遍）。',
        'opts': base_opts(
            category='<A&B<script>>',
            articles=[art(title='<i>x</i>', date='2026-03-02',
                          summary='<p>s</p>', category='A&B',
                          file='2026-03-02-esc.html')]),
        'want': generate_category_page(
            '<A&B<script>>', cat_esc_arts, make_config(), THEME_CSS, '', False, []),
    })

    # ── 搜索页 ────────────────────────────────────────────────────
    cases.append({
        'name': 'search_default',
        'fn': 'SEARCH_PAGE',
        'note': 'enable_search=True：nav 里有「搜索」并带 aria-current（current_path '
                '是 "/search.html"）、body 末尾有 search.js。',
        'opts': base_opts(),
        'want': generate_search_page(make_config(), THEME_CSS, '', False, []),
    })

    cases.append({
        'name': 'search_disabled',
        'fn': 'SEARCH_PAGE',
        'note': 'enable_search=False：nav 里**没有**「搜索」、也没有 '
                '`<script src="/search.js">` —— 这是搜索页最主要的可观察差异。',
        'opts': base_opts(config=dict(BASE_CONFIG, enable_search=False)),
        'want': generate_search_page(
            make_config(enable_search=False), THEME_CSS, '', False, []),
    })

    cases.append({
        'name': 'search_vt_meta_dropped',
        'fn': 'SEARCH_PAGE',
        'note': '⚠ 搜索页把 vt_meta 显式传成 ""（generator.py:421），'
                '**即使** enable_view_transitions=True ⇒ 输出里没有 '
                'view-transition meta。这是与列表/分类页的一个真实差异。',
        'opts': base_opts(config=dict(BASE_CONFIG, enable_view_transitions=True)),
        'want': generate_search_page(
            make_config(enable_view_transitions=True), THEME_CSS, '', False, []),
    })

    return cases


def main():
    cases = build_cases()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump({
            'generated_by': 'tp/test/gen_list_page_baseline.py',
            'note': '期望值全部来自真 Python：tinypage.generator.generate_list_page / '
                    'generate_category_page / generate_search_page。'
                    '已知差异 D1（**故意不放进夹具**）：tags 的 t.strip() —— Python 的 '
                    'str.strip() 剥 Unicode 空白（NBSP U+00A0 / 全角空格 U+3000），'
                    'WLWL 的 TRIM 实测只剥 ASCII 空白 ⇒ 含这类空白的 tags 两边不同；'
                    '放进来会让本夹具变红，故只登记不测。',
            'cases': cases,
        }, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write('\n')
    print(f'wrote {OUT} ({len(cases)} cases)')


if __name__ == '__main__':
    main()
