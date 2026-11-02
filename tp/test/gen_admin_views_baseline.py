"""生成 tp/test/fixtures/admin_views_baseline.json —— admin 视图层的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标（全部直接 import 真 Python 实现，不照抄规则）**：

| 基准组 | 对齐的 Python 实现 |
|---|---|
| `dashboard` | `tinypage.admin.views.dashboard_view`（views.py:14） |
| `article_form` | `tinypage.admin.views.article_form_view`（views.py:90） |
| `page_form` | `tinypage.admin.views.page_form_view`（views.py:162） |
| `pages_dashboard` | `tinypage.admin.views.pages_dashboard_view`（views.py:213） |
| `theme_selector` | `tinypage.admin.views.theme_selector_view`（views.py:239） |
| `login` | `tinypage.admin.views.login_view`（views.py:275） |
| `ai_panel` | `tinypage.admin.views._build_ai_panel`（views.py:291） |
| `nav_html` | `tinypage.admin.templates.build_nav_html`（templates.py:35） |

⚠ **不许**把 `views.py` 的拼装规则在这里重写一遍当基准 —— 那样只是「我的第二种
读法」，与 WLWL 实现同错就失去对照意义。这里一律**调用真函数**。

**数据从哪来**：绝对不读真站点目录。`views` 的**取数**函数
（`list_articles` / `list_standalones` / `get_raw_content` / `list_themes`）在
`views.py` 里是**模块级名字**（`from ..content import list_articles`）⇒ 这里把它们
替换成**固定的假数据**，再用**真的视图函数**渲染。这样：
  · 视图层的拼装逻辑（本卡要复刻的部分）是**真 Python** 跑出来的；
  · 输入是纯数据 ⇒ 夹具里**没有机器相关路径、没有随机值**。
`Config` 仍是**真** `tinypage.config.Config`（只是给了固定的 root_dir/page_size/…），
它在渲染里只贡献 `page_size` / `max_*_length` / `ai_*` 这几个**标量**。

**随机源全部钉死**：
  · CSRF token 一律传**固定串**（两条：普通 + 含 `& < > " '` 的施虐串）。
  · `article_form_view` 的新建分支用 `datetime.now()` ⇒ 这里把
    `views.datetime` 换成**定值假类**（Python 侧 `from datetime import datetime`
    是模块级名字，替换后 `datetime.now()` 返回 2026-01-02 03:04）。
  · 主题列表由固定 manifest 数据给出（不扫 `themes/` 目录）。

**三处与 Python 的契约差异（本模块自己的约定，见 gen_admin_views.py 文件头）**：
  ① `page` 由传输层解析后传入（`views.py:16-20` 的 `parse_qs` + `int()` 属
     `http_util.wll`）；非法/越界口径仍是 `max(1, …)`。
     已知差异：Python 的 `int()` 还接受 `" 2 "` / `"+2"`，WLWL 侧只认 `^[0-9]+$`。
  ② `article_form_view` 的 `now` 改为显式入参（`datetime.now()` 不可测）。
  ③ `is_edit` 且取不到元数据 ⇒ 返回 `<p>… not found</p>`：Python 侧由
     `path.is_file()` 判定（views.py:100/172），本模块由「`article`/`page` 不是
     DICT」判定。这两个用例的 `python` 仍是**真函数**在「文件不存在」时的输出，
     与 `want` 相同 ⇒ 记在 `map_note`（输入改映射，输出不变），不是已知差异。

**漂移守卫**：`gen_admin_views.TEMPLATES` 已与磁盘逐字比对；本文件再核对
`escape_attr == escape_html`（`views.py` 里两个转义函数混用，若上游把它们拆开
（真的开始转义别的字符），这里立刻炸）。

用法：python gen_admin_views_baseline.py
"""
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, HERE)

from tinypage.config import Config  # noqa: E402
from tinypage.models import ArticleMeta  # noqa: E402
from tinypage.security import escape_attr, escape_html  # noqa: E402
from tinypage.admin import views as V  # noqa: E402
from tinypage.admin import templates as T  # noqa: E402
import tinypage.content as CONTENT  # noqa: E402
import tinypage.core.template as CORE_TPL  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'admin_views_baseline.json')

# ── 固定输入 ─────────────────────────────────────────────────────
CSRF = 'tok-fixed-0123456789'
CSRF_TORTURE = 'tok<&>"\'x/y'
NOW = '2026-01-02 03:04'

# 视图参数里会用到、但夹具**不该**出现的机器相关路径 —— 生成期反向守卫
_DRIVE_RE = re.compile(r'(?<![A-Za-z])[A-Za-z]:\\')


def art(title='', file='2026-01-02-x.html', date='2026-01-02 03:04',
        category='', tags='', status='published', slug='x'):
    """构造真的 ArticleMeta（tag_list / is_draft / is_published 都是真 property）。"""
    return ArticleMeta(title=title, date=date, slug=slug, tags=tags,
                       category=category, status=status, file=file)


ARTS = [
    art('第一篇文章', '2026-01-02-first.html', '2026-01-02 03:04', '生活',
        '标签A, 标签B'),
    art('Second Post', '2026-01-03-second.html', '2026-01-03 04:05', 'tech',
        'alpha,beta'),
    art('草稿文章', '2026-01-04-draft.html', '2026-01-04 05:06', '', '', 'draft'),
    art('<b>HTML & "q" & \'a\'</b>', '2026-01-05-esc.html', '2026-01-05 06:07',
        '<cat>', 'a<b, c&d'),
    art('很长的标题' * 30, '2026-01-06-long.html', '2026-01-06 07:08'),
    art('', '2026-01-07-empty.html', '2026-01-07 08:09', '空白', ''),
]

PAGES = [
    art('关于我们', 'about.html', slug='about'),
    art('', 'contact.html', slug='contact'),
    art('<i>X</i> & Y', 'x-y.html', slug='x-y'),
]

THEMES = [
    {'name': 'default', 'display_name': '默认主题',
     'description': '简洁 & 快速 <v1>', 'layouts': ['blog']},
    {'name': 'magazine', 'display_name': '杂志风',
     'description': '', 'layouts': ['blog', 'list', 'detail']},
    {'name': 'bare-layouts', 'display_name': '无布局',
     'description': '空 layouts', 'layouts': []},
    {'name': 'no-display-name', 'description': '缺 display_name',
     'layouts': ['blog']},
    {'name': 'empty-display-name', 'display_name': '',
     'description': '空 display_name', 'layouts': ['blog']},
]

NAV_ITEMS = [
    ['/', '仪表盘', 'dashboard'],
    ['/new', '新建文章', 'article'],
    ['/new-page', '新建页面', 'page'],
    ['/pages', '管理页面', 'pages'],
    ['/theme', '主题', 'theme'],
]

NAV_ITEMS_ODD = [
    ['/x?a=1&b=2', '<未&转义>', 'unknown-icon'],
    ['/theme', '主题', 'theme'],
    ['/', '', 'dashboard'],
]

Q = lambda qs: {'QUERY_STRING': qs}  # noqa: E731


def art_opts(a):
    """ArticleMeta → WLWL 侧 article DICT（只用视图真的读到的字段）。"""
    return {
        'title': a.title,
        'file': a.file,
        'date': a.date,
        'category': a.category,
        'tag_list': a.tag_list,
        'is_draft': a.is_draft,
    }


def art_form_opts(a):
    d = art_opts(a)
    d['tags'] = a.tags
    d['is_published'] = a.is_published
    d['slug'] = a.slug
    return d


def page_opts(p):
    return {'title': p.title, 'file': p.file, 'slug': p.slug}


def cfg_opts(cfg, with_lengths=False):
    d = {
        'page_size': cfg.page_size,
        'ai_enabled': cfg.ai_enabled,
        'ai_api_key': cfg.ai_api_key,
    }
    if with_lengths:
        d['max_title_length'] = cfg.max_title_length
        d['max_content_length'] = cfg.max_content_length
    return d


def stub(arts=None, pages=None, themes=None, raw=''):
    """把 views 的**取数**函数换成固定假数据（视图函数本身仍是真的）。"""
    V.list_articles = lambda *a, **k: list(arts or [])
    V.list_standalones = lambda *a, **k: list(pages or [])
    V.get_raw_content = lambda *a, **k: raw
    CORE_TPL.list_themes = lambda *a, **k: list(themes or [])
    CONTENT.validate_page_filename = lambda name: True


class _FrozenDT:
    """datetime.now() 的定值替身（只实现 views.py 用到的那一面）。"""

    @staticmethod
    def now():
        return datetime(2026, 1, 2, 3, 4)


def build(tmp):
    """返回 {group: {case: {input, python, want, note|map_note}}}。"""
    cfg_small = Config(root_dir=Path(tmp), page_size=2, ai_enabled=True,
                       ai_api_key='k-123')
    cfg_wide = Config(root_dir=Path(tmp), page_size=10, ai_enabled=False,
                      ai_api_key='')
    cfg_keyless = Config(root_dir=Path(tmp), page_size=10, ai_enabled=True,
                         ai_api_key='')
    cfg_one = Config(root_dir=Path(tmp), page_size=1, ai_enabled=True,
                     ai_api_key='k-123')

    cases = {k: {} for k in ('dashboard', 'article_form', 'page_form',
                             'pages_dashboard', 'theme_selector', 'login',
                             'ai_panel', 'nav_html')}

    def rec(group, name, opts, html, note=None, map_note=None):
        cases[group][name] = {
            'input': {'opts': opts},
            'python': html,
            'want': html,
            'note': note,
            'map_note': map_note,
        }

    # ── dashboard ────────────────────────────────────────────────
    def dash(name, arts, pages, cfg, qs, page_opt, csrf=CSRF, note=None):
        stub(arts=arts, pages=pages)
        html = V.dashboard_view(Q(qs), cfg, csrf)
        rec('dashboard', name, {
            'csrf_token': csrf,
            'articles': [art_opts(a) for a in arts],
            'standalones': [page_opts(p) for p in pages],
            'page': page_opt,
            'cfg': cfg_opts(cfg),
        }, html, note=note)

    dash('d00/minimal', ARTS[:1], [], cfg_wide, '', 1)
    dash('d01/page2', ARTS, PAGES, cfg_small, 'page=2', '2')
    dash('d02/last_page', ARTS, PAGES, cfg_small, 'page=3', 3)
    dash('d03/beyond_last', ARTS, PAGES, cfg_small, 'page=9', '9')
    dash('d04/page_non_numeric', ARTS, PAGES, cfg_small, 'page=abc', 'abc',
         note=None)
    dash('d05/page_zero', ARTS, PAGES, cfg_small, 'page=0', '0')
    dash('d06/page_negative', ARTS, PAGES, cfg_small, 'page=-5', '-5')
    dash('d07/empty_articles', [], PAGES, cfg_small, '', 1)
    dash('d08/csrf_torture', ARTS[:2], PAGES[:1], cfg_one, '', 1,
         csrf=CSRF_TORTURE)
    dash('d09/ai_off_no_translate', ARTS, PAGES, cfg_wide, '', 1)
    dash('d10/ai_on_no_key', ARTS, PAGES, cfg_keyless, '', 1)

    # ── article_form ─────────────────────────────────────────────
    # 新建分支需要「文件系统」上的假文章（views.py:99-105 会 is_file 一次）
    adir = Path(tmp) / 'article'
    adir.mkdir(parents=True, exist_ok=True)
    sdir = Path(tmp) / 'standalone'
    sdir.mkdir(parents=True, exist_ok=True)
    for name in ('2026-01-02-first.html', '2026-01-04-draft.html',
                 '2026-01-05-esc.html'):
        (adir / name).write_text('', encoding='utf-8')
    (sdir / 'about.html').write_text('', encoding='utf-8')
    (sdir / 'x-y.html').write_text('', encoding='utf-8')

    RAW = '# 标题\n\n正文 & <tag> "q" \'a\'\n\n- 列表\n'
    RAW_PAGE = '页面正文\n\n第二段 & <b>\n'

    orig_dt = V.datetime
    V.datetime = _FrozenDT
    try:
        def af(name, cfg, is_edit, qs, target, arts, content, csrf=CSRF,
               note=None, map_note=None):
            """article_form 的一个用例：Python 与 opts 由**同一份输入**推导。

            ⚠ 之前把 opts 手写一遍、Python 另 stub 一遍 ⇒ 两次不同步（a02 漏传
              arts、a04 用了普通 csrf）⇒ 夹具与实际调用不一致。现在只有一个来源。
            """
            stub(arts=arts, pages=PAGES, raw=content)
            html = V.article_form_view(Q(qs), cfg, csrf_token=csrf,
                                       is_edit=is_edit)
            rec('article_form', name, {
                'csrf_token': csrf,
                'is_edit': is_edit,
                'now': NOW,
                'articles': [art_opts(a) for a in arts],
                # 非编辑分支正文恒为空（views.py:129），所以这里也传 ""
                'content': content if is_edit else '',
                'article': art_form_opts(target) if target is not None else None,
                'cfg': cfg_opts(cfg, True),
            }, html, note=note, map_note=map_note)

        af('a00/new', cfg_wide, False, '', None, ARTS, '')
        af('a01/new_ai_on', cfg_small, False, '', None, ARTS, '')
        af('a02/new_no_categories', cfg_wide, False, '', None, [], '')
        af('a03/edit_published', cfg_wide, True, 'file=2026-01-02-first.html',
           ARTS[0], ARTS, RAW)
        af('a04/edit_draft_esc', cfg_small, True, 'file=2026-01-05-esc.html',
           ARTS[3], ARTS, RAW, csrf=CSRF_TORTURE)
        # not-found：Python 侧由 is_file 判定，WLWL 侧由 article 不是 DICT 判定
        af('a05/edit_not_found', cfg_wide, True, 'file=2026-01-09-gone.html',
           None, ARTS, '',
           map_note='Python 侧由 views.py:100-101 的 is_file() 判定 not-found；'
                    '本模块以「article 不是 DICT」承载同一分支，输出文案相同。')

        # ── page_form ───────────────────────────────────────────
        def pf(name, cfg, is_edit, qs, target, content, csrf=CSRF,
               note=None, map_note=None):
            stub(arts=ARTS, pages=PAGES, raw=content)
            html = V.page_form_view(Q(qs), cfg, csrf_token=csrf,
                                    is_edit=is_edit)
            rec('page_form', name, {
                'csrf_token': csrf,
                'is_edit': is_edit,
                'page': page_opts(target) if target is not None else None,
                'content': content if is_edit else '',
                'cfg': cfg_opts(cfg, True),
            }, html, note=note, map_note=map_note)

        pf('p00/new', cfg_wide, False, '', None, '')
        pf('p01/new_ai_on', cfg_small, False, '', None, '')
        pf('p02/edit', cfg_small, True, 'file=about.html', PAGES[0], RAW_PAGE)
        pf('p03/edit_esc', cfg_wide, True, 'file=x-y.html', PAGES[2], RAW_PAGE,
           csrf=CSRF_TORTURE)
        pf('p04/edit_not_found', cfg_wide, True, 'file=gone.html', None, '',
           map_note='Python 侧由 views.py:172-173 的 is_file() 判定 not-found；'
                    '本模块以「page 不是 DICT」承载同一分支，输出文案相同。')
    finally:
        V.datetime = orig_dt

    # ── pages_dashboard ─────────────────────────────────────────
    def pd(name, pages, csrf=CSRF):
        stub(pages=pages)
        html = V.pages_dashboard_view(Q(''), Config(root_dir=Path(tmp)), csrf)
        rec('pages_dashboard', name, {
            'csrf_token': csrf,
            'pages': [page_opts(p) for p in pages],
        }, html)

    pd('g00/empty', [])
    pd('g01/three', PAGES)
    pd('g02/csrf_torture', PAGES[:1], CSRF_TORTURE)

    # ── theme_selector ──────────────────────────────────────────
    def th(name, themes, current, csrf=CSRF):
        stub(themes=themes)
        cfg = Config(root_dir=Path(tmp), theme_name=current)
        html = V.theme_selector_view(Q(''), cfg, csrf)
        rec('theme_selector', name, {
            'csrf_token': csrf,
            'themes': themes,
            'current_theme': current,
        }, html)

    th('t00/empty', [], 'default')
    th('t01/five', THEMES, 'default')
    th('t02/no_match', THEMES, 'nope')
    th('t03/csrf_torture', THEMES[:2], 'magazine', CSRF_TORTURE)

    # ── login ───────────────────────────────────────────────────
    def lg(name, qs, error, locked, csrf=CSRF):
        html = V.login_view(Q(qs), csrf)
        rec('login', name, {
            'csrf_token': csrf, 'error': error, 'locked': locked,
        }, html)

    lg('l00/plain', '', '', '')
    lg('l01/error', 'error=1', '1', '')
    lg('l02/locked', 'locked=1', '', '1')
    lg('l03/both_locked_wins', 'error=1&locked=1', '1', '1')
    lg('l04/csrf_torture', '', '', '', CSRF_TORTURE)

    # ── ai_panel（直接调 _build_ai_panel）────────────────────────
    def ai(name, cfg, suggest, csrf=CSRF):
        html = V._build_ai_panel(cfg, csrf, suggest_tags=suggest)
        rec('ai_panel', name, {
            'cfg': cfg_opts(cfg), 'csrf_token': csrf, 'suggest_tags': suggest,
        }, html)

    ai('n00/off', cfg_wide, True)
    ai('n01/on_tags', cfg_small, True)
    ai('n02/on_no_tags', cfg_small, False)
    ai('n03/on_no_key', cfg_keyless, True)

    # ── nav_html ────────────────────────────────────────────────
    def nv(name, items, current):
        html = T.build_nav_html([tuple(i) for i in items], current)
        rec('nav_html', name, {
            'nav_items': items, 'current_path': current,
        }, html)

    nv('v00/dashboard_active', NAV_ITEMS, '/')
    nv('v01/theme_active', NAV_ITEMS, '/theme')
    nv('v02/no_match', NAV_ITEMS, '/nope')
    nv('v03/odd_items', NAV_ITEMS_ODD, '/theme')
    nv('v04/empty', [], '/')

    return cases


def assert_no_machine_paths(doc, tmpdir):
    """反向守卫：夹具里不得出现机器相关路径（含临时目录前缀）。"""
    needles = [tmpdir, tmpdir.replace('\\', '/'), os.path.expanduser('~')]

    def walk(v, path):
        if isinstance(v, str):
            for n in needles:
                if n and n in v:
                    raise SystemExit(
                        '夹具 %s 里出现了机器相关路径 %r' % (path, n))
            m = _DRIVE_RE.search(v)
            if m:
                raise SystemExit(
                    '夹具 %s 里出现了盘符路径 %r' % (path, m.group(0)))
        elif isinstance(v, dict):
            for k, vv in v.items():
                walk(vv, path + '.' + str(k))
        elif isinstance(v, list):
            for i, vv in enumerate(v):
                walk(vv, '%s[%d]' % (path, i))

    walk(doc, '$')


def main():
    # ── 漂移守卫①：两个转义函数等价 ─────────────────────────────
    SAMPLE = ('& < > " \' / \\ \n \t 中文 &amp; &#39; \x00\ufffd '
              'a"b\'c<d>e&f')
    if escape_attr(SAMPLE) != escape_html(SAMPLE):
        raise SystemExit(
            'escape_attr 与 escape_html 不再等价！views.py 里两者混用 ⇒ '
            'gen_admin_views.py 的 AV_ATTR 必须改成独立实现。\n'
            '  attr=%r\n  html=%r'
            % (escape_attr(SAMPLE), escape_html(SAMPLE)))

    # ── 漂移守卫②：模板副本与磁盘一致（复用主生成器的核对）──────
    import gen_admin_views as G
    G.check_templates()

    tmp = tempfile.mkdtemp(prefix='tpav_')
    try:
        cases = build(tmp)
        doc = {'_meta': {}, 'cases': cases}
        assert_no_machine_paths(cases, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ── 自检：python == want ⇔ 无 note；map_note 不许和 note 同时出现 ──
    total = 0
    for group, entries in cases.items():
        if not entries:
            raise SystemExit('%s 组没有用例' % group)
        for name, e in entries.items():
            total += 1
            same = e['python'] == e['want']
            if same and e['note']:
                raise SystemExit(
                    '%s/%s: note 存在但 python==want（应删 note）' % (group, name))
            if not same and not e['note']:
                raise SystemExit(
                    '%s/%s: python!=want 但缺 note（必须登记已知差异）'
                    % (group, name))
            if e['note'] and e['map_note']:
                raise SystemExit(
                    '%s/%s: note 与 map_note 不能同时出现' % (group, name))

    doc['_meta'] = {
        'generated_by': 'tp/test/gen_admin_views_baseline.py',
        'python_functions': {
            'dashboard': 'tinypage.admin.views.dashboard_view (views.py:14)',
            'article_form': 'tinypage.admin.views.article_form_view (views.py:90)',
            'page_form': 'tinypage.admin.views.page_form_view (views.py:162)',
            'pages_dashboard':
                'tinypage.admin.views.pages_dashboard_view (views.py:213)',
            'theme_selector':
                'tinypage.admin.views.theme_selector_view (views.py:239)',
            'login': 'tinypage.admin.views.login_view (views.py:275)',
            'ai_panel': 'tinypage.admin.views._build_ai_panel (views.py:291)',
            'nav_html': 'tinypage.admin.templates.build_nav_html (templates.py:35)',
        },
        'fixed_inputs': {
            'csrf_token': CSRF,
            'csrf_token_torture': CSRF_TORTURE,
            'now': NOW,
            'note': 'CSRF 与 now 都是定值 ⇒ 重跑生成器不得有漂移（无随机值）。',
        },
        'no_machine_paths': '生成期遍历全文档，命中临时目录前缀/盘符路径即中止。',
        'contract_deviations': [
            'page 由传输层解析（views.py:16-20 的 parse_qs+int 属 http_util.wll）；'
            '非法/越界口径仍是 max(1, …)。已知差异：Python 的 int() 还接受 '
            '" 2 " / "+2"，WLWL 侧只认 ^[0-9]+$。',
            'article_form_view 的 now 改为显式入参（datetime.now() 不可测）。',
            'is_edit 且取不到元数据 ⇒ <p>… not found</p>：Python 由 '
            'path.is_file() 判定，本模块由「article/page 不是 DICT」判定；'
            '这类用例记 map_note（输入改映射，输出相同）。',
        ],
        'case_count': total,
        'known_difference_count': sum(
            1 for es in cases.values() for e in es.values() if e['note']),
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    print('wrote %s (%d cases, %d known differences)'
          % (OUT, total, doc['_meta']['known_difference_count']))


if __name__ == '__main__':
    main()
