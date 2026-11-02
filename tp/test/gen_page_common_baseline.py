"""生成 tp/test/fixtures/page_common_baseline.json —— 页面公共上下文的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标**（全部**直接 import 真 Python**，不重写规则）：
  | 基准段 | 对齐的 Python 函数 | 位置 |
  |---|---|---|
  | `json_ld` | `tinypage.generator.build_json_ld` | generator.py:18 |
  | `nav_links` | `tinypage.generator._nav_links` | generator.py:66 |
  | `common_context` | `tinypage.generator._build_common_context` | generator.py:79 |

**为什么单独做一份基准**：这三个函数被 article / standalone / list / category / search
五个页面函数共用（`tp/lib/page_common.wll` 是它们的 WLWL 版）。页面级测试只能间接覆盖，
一旦这里错了，五个页面会一起红且难定位 ⇒ 单独钉死。

**已知口径**：
  · `JSON_LD` 在 `site_url` 为空时返回 `""` —— 这对应 Python 侧
    `generator.py:207` 的 `if cfg.site_url:` 门控（`build_json_ld` 本身没有门控）。
  · `common_context` 的 `theme_dir` 回落分支**不在本基准里**：它等价于
    「调 `LOAD_THEME_CSS` 并把三个值填进去」，而 `LOAD_THEME_CSS` 已在
    `theme_baseline.json` 里逐字节钉过。这里只用**显式 theme_css** 的路径。

用法：python gen_page_common_baseline.py
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.config import Config  # noqa: E402
from tinypage.generator import (  # noqa: E402
    build_json_ld, _nav_links, _build_common_context,
)
from tinypage.models import ArticleMeta  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'page_common_baseline.json')

CTX_FIELDS = [
    'site_title', 'dark_mode_meta', 'dark_mode_script', 'pwa_meta',
    'pwa_manifest', 'vt_meta', 'search_script', 'nav', 'theme_toggle',
]


def cfg_dict(**over):
    """把 Config 的**默认值**取成 DICT，再覆盖指定键。

    ⚠ 只取本模块用得到的键；WLWL 侧的 config 就是这样一个 DICT。
    """
    base = {
        'site_title': Config().site_title,
        'site_description': Config().site_description,
        'site_url': Config().site_url,
        'site_author': Config().site_author,
        'footer_text': Config().footer_text,
        'lang': Config().lang,
        'theme_name': Config().theme_name,
        'page_size': Config().page_size,
        'enable_pwa': Config().enable_pwa,
        'enable_dark_mode': Config().enable_dark_mode,
        'enable_search': Config().enable_search,
        'enable_rss': Config().enable_rss,
        'enable_sitemap': Config().enable_sitemap,
        'enable_view_transitions': Config().enable_view_transitions,
        'pwa_short_name': Config().pwa_short_name,
        'pwa_theme_color': Config().pwa_theme_color,
        'pwa_bg_color': Config().pwa_bg_color,
    }
    base.update(over)
    return base


def make_config(**over):
    """用同样一组值造真 Config（保证两边看的是同一份配置）。"""
    d = cfg_dict(**over)
    return Config(**d)


def main():
    cases = {'json_ld': {}, 'nav_links': {}, 'common_context': {}}

    # ── json_ld ─────────────────────────────────────────────────────
    def add_json(name, note=None, **kw):
        want = build_json_ld(**kw) if kw.get('site_url') else ''
        cases['json_ld'][name] = {
            'input': dict(kw),
            'python': build_json_ld(**kw),
            'want': want,
            'note': note,
        }

    add_json(
        'j01_with_tags',
        title='标题 & "引号"', description='描述', date='2026-01-02T10:00',
        slug='2026-01-01-x', tags=['wlwl', '静态站点'],
        site_url='https://example.com/', author='',
    )
    add_json(
        'j02_no_tags_author',
        title='T', description='D', date='2026-01-02T10:00', slug='s',
        tags=[], site_url='https://example.com', author='张三',
    )
    add_json(
        'j03_empty_site_url',
        note='`site_url` 为空 ⇒ 整段不输出（对齐 generator.py:207 的 `if cfg.site_url:` 门控）',
        title='T', description='D', date='2026-01-02T10:00', slug='s',
        tags=['a'], site_url='', author='',
    )
    add_json(
        'j04_trailing_slashes',
        note='`site_url` 结尾多个 `/` 都要被 rstrip 掉',
        title='T', description='D', date='2026-01-02T10:00', slug='s',
        tags=[], site_url='https://example.com///', author='',
    )
    add_json(
        'j05_special_chars',
        title='a\\b"c', description='换行\n制表\t结束', date='2026-01-02T10:00',
        slug='x', tags=['t"1'], site_url='https://e.com', author='o\\p',
    )

    # ── nav_links ───────────────────────────────────────────────────
    def add_nav(name, cfg_over, standalones, current_path, note=None):
        cfg = make_config(**cfg_over)
        metas = [ArticleMeta(title=t, file=f) for t, f in standalones]
        got = _nav_links(cfg, metas, current_path)
        cases['nav_links'][name] = {
            'input': {
                'cfg': cfg_dict(**cfg_over),
                'standalones': [{'title': t, 'file': f} for t, f in standalones],
                'current_path': current_path,
            },
            'python': got,
            'want': got,
            'note': note,
        }

    add_nav('n01_no_standalones', {}, [], '')
    add_nav('n02_with_standalones', {}, [('关于', 'about.html'), ('联系', 'contact.html')], '')
    add_nav('n03_active_standalone', {},
            [('关于', 'about.html'), ('联系', 'contact.html')], '/standalone/about.html')
    add_nav('n04_active_search', {},
            [('关于', 'about.html')], '/search.html')
    add_nav('n05_search_disabled', {'enable_search': False}, [('关于', 'about.html')], '')
    # n06 需要超长标题 —— 单独构造
    long_title = '一二三四五六七八九十一二三四五六七八九十多出来的部分'
    cfg = make_config()
    metas = [ArticleMeta(title=long_title, file='long.html')]
    got = _nav_links(cfg, metas, '')
    cases['nav_links']['n06_title_truncated'] = {
        'input': {
            'cfg': cfg_dict(),
            'standalones': [{'title': long_title, 'file': 'long.html'}],
            'current_path': '',
        },
        'python': got,
        'want': got,
        'note': '标题取 `title[:20]`；超长要截断到 20 个码点',
    }
    add_nav('n07_empty_title_falls_back', {}, [('', 'no-title.html')], '',
            note='`title[:20] or file` —— 空标题**也**回落文件名（Python 的 or 对空串为假）')

    # ── common_context ──────────────────────────────────────────────
    def add_ctx(name, cfg_over, theme_css, dark_css, has_dark, standalones,
                current_path, note=None):
        cfg = make_config(**cfg_over)
        metas = [ArticleMeta(title=t, file=f) for t, f in standalones]
        ctx = _build_common_context(
            config=cfg, theme_css=theme_css, dark_css=dark_css,
            has_dark=has_dark, standalones=metas, current_path=current_path,
        )
        want = {k: ctx[k] for k in CTX_FIELDS}
        cases['common_context'][name] = {
            'input': {
                'config': cfg_dict(**cfg_over),
                'theme_css': theme_css,
                'dark_css': dark_css,
                'has_dark': has_dark,
                'standalones': [{'title': t, 'file': f} for t, f in standalones],
                'current_path': current_path,
            },
            'python': want,
            'want': dict(want),
            'note': note,
        }

    add_ctx('c01_all_on', {'site_title': 'Tiny & Page'},
            'CSS{1}', 'DARK{2}', True, [('关于', 'about.html')], '/standalone/about.html')
    add_ctx('c02_all_off',
            {'enable_pwa': False, 'enable_search': False,
             'enable_view_transitions': False},
            'CSS', '', False, [], '')
    add_ctx('c03_dark_off_has_css', {}, 'CSS', 'DARKCSS', False, [], '',
            note='`has_dark` 为假 ⇒ dark_mode_meta / dark_mode_script / theme_toggle 都是空串'
                 '（即使 dark_css 非空也不输出那三块）')

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    payload = {
        '_meta': {
            'generated_by': 'tp/test/gen_page_common_baseline.py',
            'aligned_to': {
                'json_ld': 'tinypage/generator.py:18 build_json_ld',
                'nav_links': 'tinypage/generator.py:66 _nav_links',
                'common_context': 'tinypage/generator.py:79 _build_common_context',
            },
            'note': 'json_ld 的 site_url 为空时 want 记空串（对齐 generator.py:207 的调用方门控）',
        },
        'cases': cases,
    }
    with io.open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write('\n')

    n = sum(len(v) for v in cases.values())
    print('wrote %s (%d cases)' % (OUT, n))


if __name__ == '__main__':
    main()
