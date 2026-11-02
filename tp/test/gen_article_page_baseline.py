"""生成 tp/test/fixtures/article_page_baseline.json —— 文章页/独立页的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标（一律**直接 import 真 Python 实现**，不照抄规则）**：

| 基准段 | 对齐的 Python 实现 |
|---|---|
| `article` | `tinypage.generator.generate_article_html`（generator.py:154） |
| `standalone` | `tinypage.generator.generate_standalone_html`（generator.py:429） |

⚠ **不许**把 HTML 拼装规则在这里重写一遍当基准 —— 照抄的基准只是「我的第二种读法」，
  与 WLWL 实现同错就失去对照意义。这里一律调用真函数。

**`input` 的形态 = WLWL 侧 `ARTICLE_PAGE(opts)` / `STANDALONE_PAGE(opts)` 的那个 DICT**：
  键名与 Python 的具名参数同名；`config` 是**普通 dict**（本文件翻成 `Config(**d)`），
  `standalones` / `related_articles` 是**元素为 dict 的数组**（本文件翻成 `ArticleMeta(**d)`）。
  这样基准里的 input 与测试喂给 WLWL 的 opts **逐键同源**，不会各写一份。

**为什么每个用例都显式给 `theme_css`**：
  Python 的 `_build_common_context` 在 `theme_css` 为空时会**去读主题目录**
  （`load_theme_css`，还会拼上 Pygments 的 CSS）—— 那是**环境相关**的输入，
  WLWL 侧无法逐字节复刻（且 README 坑 23：CRLF 归一化口径不同）。
  ⇒ 本基准的用例**一律传非空 `theme_css`**；生成期用断言钉住这条，
    免得有人加了一个空 CSS 的用例、把「环境差异」混进「实现差异」。

**已知差异**：本模块预期 `python == want`、`note` 全为 `null`。
  若实测撞到 WLWL 无法复刻的形态，**在本文件里显式改写 `want` 并写 `note`**，
  不要放宽断言。

用法：python gen_article_page_baseline.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.config import Config  # noqa: E402
from tinypage.generator import (  # noqa: E402
    generate_article_html,
    generate_standalone_html,
)
from tinypage.models import ArticleMeta  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'article_page_baseline.json')

CSS = 'body{margin:0;font-family:sans-serif}'
DARK_CSS = '@media (prefers-color-scheme: dark){body{background:#111;color:#eee}}'

# 独立页（导航里出现的固定页）
PAGES = [
    {'title': '关于', 'file': 'about.html'},
    {'title': '项目列表 - 归档与说明', 'file': 'projects.html'},
]

# 相关文章（ArticleMeta；`url` 由 `file` 派生 ⇒ `/article/<file>`）
RELATED = [
    {'title': '第二篇', 'date': '2026-01-03 10:00', 'file': '2026-01-03-second.html'},
    {'title': 'A & B <i>x</i>', 'date': '2026-01-04 11:00',
     'file': '2026-01-04-special.html'},
]

# ── 文章页用例 ────────────────────────────────────────────────────
# 每个用例的 key 就是 WLWL 侧 opts 的键；缺省的键 ⇒ Python 的默认值。
ARTICLE_CASES = [
    # 最小：只有四个必填项 + 显式 theme_css（site_url 为空 ⇒ 无 og / JSON-LD / share）
    ('a00_minimal', {
        'title': 'Hello', 'date': '2026-01-02 03:04', 'slug': 'hello',
        'content': '<p>body</p>', 'theme_css': CSS,
    }),
    # 完整：tags / category / toc / footnotes / backlinks / related / standalones
    #       + site_url（⇒ og + JSON-LD + share）+ 暗色
    ('a01_full', {
        'title': '完整用例', 'date': '2026-01-02 03:04', 'slug': 'full',
        'content': '<p>正文</p>\n<h2 id="x">小节</h2>',
        'tags': 'wlwl, 静态站点 ,tiny',
        'summary': '一段摘要',
        'category': '技术',
        'status': 'published',
        'config': {'site_url': 'https://example.com', 'site_author': '布布'},
        'theme_css': CSS, 'dark_css': DARK_CSS, 'has_dark': True,
        'standalones': PAGES,
        'toc_html': '<nav class="toc"><a href="#x">小节</a></nav>',
        'footnotes_html': '<section class="footnotes"><p>脚注</p></section>',
        'backlinks_html': '<section class="backlinks"><a href="/a">引用</a></section>',
        'related_articles': RELATED,
    }),
    # 草稿状态（小写 "draft"）
    ('a02_draft', {
        'title': '草稿', 'date': '2026-01-02 03:04', 'slug': 'draft',
        'content': '<p>d</p>', 'status': 'draft', 'theme_css': CSS,
    }),
    # ⚠ Python 是 `status.lower() == "draft"` ⇒ 大写同样命中
    ('a03_status_upper', {
        'title': '草稿大写', 'date': '2026-01-02 03:04', 'slug': 'draft2',
        'content': '<p>d</p>', 'status': 'DRAFT', 'theme_css': CSS,
    }),
    # 无 category
    ('a04_no_category', {
        'title': '无分类', 'date': '2026-01-02 03:04', 'slug': 'nocat',
        'content': '<p>n</p>', 'tags': 'a,b', 'theme_css': CSS,
    }),
    # 无 tags（⇒ 无 .post-tags，JSON-LD 也无 keywords）
    ('a05_no_tags', {
        'title': '无标签', 'date': '2026-01-02 03:04', 'slug': 'notag',
        'content': '<p>n</p>', 'category': '杂项',
        'config': {'site_url': 'https://example.com'},
        'theme_css': CSS,
    }),
    # tags 全是空白 ⇒ Python 的 `if tag_items:` 拦住 ⇒ 无 .post-tags
    ('a06_tags_blank', {
        'title': '空标签', 'date': '2026-01-02 03:04', 'slug': 'blanktag',
        'content': '<p>b</p>', 'tags': ' , ,, ', 'theme_css': CSS,
    }),
    # 特殊字符：title / date / summary / tags / category 都要 escape
    ('a07_escape', {
        'title': 'A & B <b>"x"</b> \'q\'',
        'date': '2026-01-02 03:04 "t"',
        'slug': 'esc',
        'content': '<p>c</p>',
        'tags': '<x>, a&b, "q"',
        'summary': 'S & <T> "Q" \'R\'',
        'category': 'C&D <x> "y"',
        'config': {'site_url': 'https://example.com/?a=1&b=2', 'site_author': 'A & B'},
        'theme_css': CSS,
    }),
    # site_url 以 "/" 结尾 ⇒ og:url 走 rstrip，share 的 url **不** rstrip（双斜杠）
    ('a08_site_url_trailing_slash', {
        'title': '结尾斜杠', 'date': '2026-01-02 03:04', 'slug': 'slash',
        'content': '<p>s</p>', 'tags': 'x',
        'config': {'site_url': 'https://example.com/'},
        'theme_css': CSS,
    }),
    # CJK 全链路
    ('a09_cjk', {
        'title': '中文标题·测试', 'date': '2026-02-03 09:08', 'slug': 'cjk',
        'content': '<p>中文正文</p>', 'tags': '中文, 标签',
        'summary': '摘要中文', 'category': '分类中文',
        'config': {'site_url': 'https://例子.测试'},
        'theme_css': CSS, 'dark_css': DARK_CSS, 'has_dark': True,
        'standalones': PAGES,
    }),
    # content 里的 `<script>` / `$` / `${}` 必须**原样**嵌入（content 不 escape）
    ('a10_content_specials', {
        'title': '正文注入', 'date': '2026-01-02 03:04', 'slug': 'inject',
        'content': "<script>alert('x')</script>\n<p>${title} 与 $slug 与 $$ 与 \\n</p>",
        'theme_css': CSS,
    }),
    # 全空
    ('a11_empty_all', {
        'title': '', 'date': '', 'slug': '', 'content': '',
        'theme_css': CSS,
    }),
    # tags 里夹**Unicode 空白**（U+3000 / U+00A0）—— Python 的 strip() 会去掉，
    # 而 WLWL 内建 TRIM **只去 ASCII 空白**（实测）⇒ 钉住这条差异是否已抹平
    ('a12_tags_unicode_ws', {
        'title': 'Unicode 空白', 'date': '2026-01-02 03:04', 'slug': 'uws',
        'content': '<p>u</p>',
        'tags': '\u3000甲\u3000, \u00a0乙\u00a0 ,\t丙\t',
        'theme_css': CSS,
    }),
    # 功能开关全关（PWA / 搜索 / 视图过渡）
    ('a13_features_off', {
        'title': '开关全关', 'date': '2026-01-02 03:04', 'slug': 'off',
        'content': '<p>o</p>',
        'config': {
            'enable_pwa': False, 'enable_search': False,
            'enable_view_transitions': False,
        },
        'theme_css': CSS,
    }),
    # 部分 config：只给 site_url ⇒ 其余键必须回落到 Config 的默认值
    ('a14_partial_config', {
        'title': '部分配置', 'date': '2026-01-02 03:04', 'slug': 'partial',
        'content': '<p>p</p>',
        'config': {'site_url': 'https://p.example'},
        'theme_css': CSS,
    }),
    # related_articles 是空数组（Python 侧 falsy ⇒ 无 related 段）
    ('a15_related_empty', {
        'title': '空相关', 'date': '2026-01-02 03:04', 'slug': 'rel0',
        'content': '<p>r</p>', 'related_articles': [], 'theme_css': CSS,
    }),
    # 无暗色（has_dark=false 且 dark_css 为空）
    ('a16_no_dark', {
        'title': '无暗色', 'date': '2026-01-02 03:04', 'slug': 'nodark',
        'content': '<p>n</p>', 'config': {'site_url': 'https://example.com'},
        'theme_css': CSS, 'dark_css': '', 'has_dark': False,
        'related_articles': RELATED,
    }),
    # 自定义 lang / footer_text（走 render_skeleton 的二次 escape）
    ('a17_lang_footer', {
        'title': '页脚 & 语言', 'date': '2026-01-02 03:04', 'slug': 'lang',
        'content': '<p>l</p>',
        'config': {'lang': 'en', 'footer_text': 'F & <b>x</b> "q"'},
        'theme_css': CSS,
    }),
    # ⚠ dark_css 非空但 has_dark=false：Python 的 render_skeleton 只按 **dark_css**
    #   决定是否输出暗色 <style> 块，而切换按钮 / color-scheme meta 只按 **has_dark**
    #   ⇒ 这一档会出现「有暗色样式、没有切换按钮」的耦合形态，别「顺手修正」
    ('a18_dark_css_without_flag', {
        'title': '有暗色样式但没有开关', 'date': '2026-01-02 03:04', 'slug': 'dcss',
        'content': '<p>d</p>', 'config': {'site_url': 'https://example.com'},
        'theme_css': CSS, 'dark_css': DARK_CSS, 'has_dark': False,
        'standalones': PAGES,
    }),
]

# ── 独立页用例 ────────────────────────────────────────────────────
STANDALONE_CASES = [
    # 最小（无 summary / 无 site_url）
    ('s00_minimal', {
        'title': 'About', 'content': '<p>about</p>', 'theme_css': CSS,
    }),
    # 完整：summary + site_url（⇒ og）+ 暗色 + standalones 导航
    ('s01_full', {
        'title': '关于本站', 'content': '<p>说明</p>',
        'summary': '本站说明 & <x>',
        'config': {'site_url': 'https://example.com'},
        'theme_css': CSS, 'dark_css': DARK_CSS, 'has_dark': True,
        'standalones': PAGES,
    }),
    # 空 summary
    ('s02_empty_summary', {
        'title': 'Empty', 'content': '<p>e</p>', 'summary': '',
        'config': {'site_url': 'https://example.com'},
        'theme_css': CSS,
    }),
    # 特殊字符 + 空标题
    ('s03_escape', {
        'title': 'A & B <i>"x"</i>', 'content': '<p>c & d</p>',
        'summary': 'S & <T>', 'config': {'site_url': 'https://example.com/?a&b'},
        'theme_css': CSS,
    }),
    # content 的注入形态必须原样嵌入
    ('s04_content_specials', {
        'title': '注入', 'content': "<script>alert('x')</script>\n<p>${title}</p>",
        'theme_css': CSS,
    }),
    # 无 site_url 但有暗色
    ('s05_no_url_dark', {
        'title': '无 URL', 'content': '<p>n</p>', 'summary': 's',
        'theme_css': CSS, 'dark_css': DARK_CSS, 'has_dark': True,
        'standalones': PAGES,
    }),
    # 功能全关
    ('s06_features_off', {
        'title': '开关全关', 'content': '<p>o</p>',
        'config': {
            'site_url': 'https://o.example',
            'enable_pwa': False, 'enable_search': False,
            'enable_view_transitions': False,
        },
        'theme_css': CSS,
    }),
]


def _article_meta(d):
    """opts 里的元素 dict → ArticleMeta（只允许 ArticleMeta 的字段）。"""
    return ArticleMeta(**d)


def call_article(spec):
    """用**真 Python** 生成文章页。"""
    kw = dict(spec)
    cfg = kw.pop('config', None)
    st = kw.pop('standalones', None)
    rel = kw.pop('related_articles', None)
    kw['config'] = Config(**(cfg or {}))
    if st is not None:
        kw['standalones'] = [_article_meta(p) for p in st]
    if rel is not None:
        kw['related_articles'] = [_article_meta(p) for p in rel]
    return generate_article_html(**kw)


def call_standalone(spec):
    """用**真 Python** 生成独立页。"""
    kw = dict(spec)
    cfg = kw.pop('config', None)
    st = kw.pop('standalones', None)
    kw['config'] = Config(**(cfg or {}))
    if st is not None:
        kw['standalones'] = [_article_meta(p) for p in st]
    return generate_standalone_html(**kw)


def main():
    cases = {'article': {}, 'standalone': {}}

    for group, specs, caller in [
            ('article', ARTICLE_CASES, call_article),
            ('standalone', STANDALONE_CASES, call_standalone),
    ]:
        for name, spec in specs:
            # ⚠ 空 theme_css 会让 Python 去读主题目录（环境相关）⇒ 一律禁止
            assert spec.get('theme_css'), (
                '%s: 用例必须显式给非空 theme_css（否则 Python 会读主题目录，'
                '基准不可复现）' % name)
            py = caller(spec)
            cases[group][name] = {
                'input': spec,
                'python': py,
                'want': py,
                'note': None,
            }

    # ── 自检：python 与 want 一致 ⇔ 无 note ────────────────────────
    for group, entries in cases.items():
        for name, entry in entries.items():
            same = entry['python'] == entry['want']
            if same and entry['note']:
                raise SystemExit(
                    '%s/%s: note 存在但 python==want（应删 note）' % (group, name))
            if not same and not entry['note']:
                raise SystemExit(
                    '%s/%s: python!=want 但缺 note（必须登记已知差异）'
                    % (group, name))

    doc = {
        '_meta': {
            'generated_by': 'tp/test/gen_article_page_baseline.py',
            'python_functions': {
                'article': 'tinypage.generator.generate_article_html (generator.py:154)',
                'standalone':
                    'tinypage.generator.generate_standalone_html (generator.py:429)',
            },
            'input_shape':
                '与 WLWL 侧 opts 逐键同源：config 为 dict（翻成 Config(**d)），'
                'standalones / related_articles 为元素是 dict 的数组（翻成 ArticleMeta(**d)）',
            'theme_css_boundary':
                '每个用例都显式传非空 theme_css —— 空串会让 Python 去读主题目录'
                '（load_theme_css + Pygments），那是环境相关输入，不进逐字节对照',
            'known_difference_count': sum(
                1 for entries in cases.values() for e in entries.values()
                if e['note']),
        },
        'cases': cases,
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    total = sum(len(e) for e in cases.values())
    print('wrote %s (%d cases, %d known differences)'
          % (OUT, total, doc['_meta']['known_difference_count']))


if __name__ == '__main__':
    main()
