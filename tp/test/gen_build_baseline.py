"""生成 `tp/test/fixtures/build_baseline.json` —— 构建编排层（`tp/bin/build.wll`）的对照基准。

⚠ 输出的夹具由本文件生成，不要手改。重跑：`python tp\\test\\gen_build_baseline.py`

**它到底做了什么**（与 S2 其它基准同一套做法）：

1. 用 `site_corpus.spec()` 在**临时目录**里造一份确定性语料；
2. `chdir` 到那个临时根，调**真 Python** 的
   `list_articles` + `list_standalones` + `generator.generate_static_pages` 跑一遍
   （与 `cli.py:139-141` 的 `build` 完全同一串调用）；
3. 把**每个产物**记成 `相对路径 → {sha256, chars, bytes}`；
4. **整套跑两遍**（两个不同的临时目录）并要求两次产物逐字节相同 ——
   这一步是防「`iterdir()` 顺序 / `set` 迭代顺序」这类不确定性的硬门槛：
   夹具一旦漂，CI 第 3 步（重生成后 `git diff` 为空）就会红。

**夹具里绝不含绝对路径**：`expected` 的键是相对 `pages/` 的 POSIX 路径，
语料本体以 `spec.files` 的形式整份内联（`test_build.wll` 用它重建同一棵树）。

## 三条**已知差异**（登记在此，不制造「会随环境漂移的 python 值」）

**D-NL 行尾**：Python 的 `Path.write_text()` / `open(..., "w")` 用 `newline=None`
⇒ 在 Windows 上把 `\\n` 翻成 `\\r\\n`，而 WLWL 的 `WRITE_FILE_ATOMIC` 原样写 `\\n`。
本夹具登记的是 **LF 归一化后**的内容（`read_text()` 会把 `\\r\\n` 读回 `\\n`，
所以「登记值」就是两侧的逻辑内容）。⇒ 在 Windows 上直接 `cmp` 磁盘字节会看到
CRLF/LF 差异，这不是渲染差异。仓库本身也是「生成器一律写 LF」（.gitattributes 固化了
`*.wll` / `*.py` / 夹具的行尾），⇒ **LF 是正确的一侧**。

**D7 Pygments**：`generator.load_theme_css` 会在 `base_css` 后追加
`"\\n/* Pygments syntax highlighting */\\n" + pygments_css`；业主已裁决
**代码高亮改前端**（`theme.wll` 的 D7 同款）⇒ 本文件在跑 Python 前把
`parsers.syntax.has_syntax_highlighting` 打成 `False`（等价于「没装 Pygments」），
让基准与 WLWL 侧的 `LOAD_THEME_CSS` 同一口径。若不这么做，每个页面的 `<style>`
都会多出整段 Pygments 样式表 —— 与编排逻辑无关，却会让每一行都红。

**`.tinypage/backlinks.json` 不入账**：它是 `build_backlink_index` 写的**缓存**，
内容含 `st_mtime`（不可复现），不是站点产物 ⇒ 两个生成器都跳过它
（`EXCLUDE_DIRS`）。WLWL 侧**不写**这个缓存。

## 反向守卫（本文件自己把关，失败直接 SystemExit）

- 两次独立运行的产物必须逐字节相同（见上）；
- 草稿 html 必须**保持语料原样**（它不进 `list_articles` ⇒ 不会被重新生成）；
- 草稿**不得**出现在 `index.html` / `rss.xml` / `search-index.json` / `sitemap.xml` /
  分类页里（**这是本卡「草稿过滤只在编排层做」的可执行判据**）。

用法：python gen_build_baseline.py
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
OUT = os.path.join(HERE, 'fixtures', 'build_baseline.json')

sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

import site_corpus  # noqa: E402

# 站点产物根（== Config.root_dir）
PAGES = 'pages'

# 不算站点产物的目录（缓存 / 编辑器垃圾）
EXCLUDE_DIRS = ('.tinypage',)

DRAFT_FILE = '2026-03-02-draft-wip.html'


def _run_python_build(root):
    """在 `root` 里跑一次真 Python 的全量构建，返回写出的文件集合（相对 pages/）。"""
    import tinypage.generator as gen
    import tinypage.parsers.syntax as syntax
    from tinypage.config import Config
    from tinypage.content import list_articles, list_standalones

    cfg_fields = dict(site_corpus.config())
    cfg_fields['root_dir'] = (Path(root) / PAGES).resolve()

    stats = {}

    # ── D7：把「有没有 Pygments」钉成 False（见文件头）─────────────────
    orig_has = syntax.has_syntax_highlighting
    syntax.has_syntax_highlighting = lambda: False
    try:
        cwd = os.getcwd()
        os.chdir(root)          # Config.theme_dir 是 CWD 相对的 Path("themes")/<name>
        try:
            cfg = Config(**cfg_fields)
            if not cfg.theme_dir.is_dir():
                raise SystemExit('主题目录没按预期解析到：%r' % (cfg.theme_dir,))
            articles = list_articles(cfg.article_dir, cfg.max_file_size)
            standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
            stats['articles'] = len(articles)
            stats['standalones'] = len(standalones)
            stats['list_pages'] = max(
                1, (len(articles) + cfg.page_size - 1) // cfg.page_size)
            stats['categories'] = len(
                sorted({a.category.strip() for a in articles if a.category.strip()}))
            gen.generate_static_pages(articles, cfg, standalones)
        finally:
            os.chdir(cwd)
    finally:
        syntax.has_syntax_highlighting = orig_has
    return stats


def _collect(root):
    """把 `pages/` 下的产物读成 `相对路径 → {sha256, chars, bytes}`（LF 归一化）。"""
    base = Path(root) / PAGES
    out = {}
    for p in sorted(base.rglob('*')):
        if not p.is_file():
            continue
        rel = p.relative_to(base).as_posix()
        if rel.split('/')[0] in EXCLUDE_DIRS:
            continue
        # read_text 会把 CRLF / 孤立 CR 归一成 LF（坑 23 / 40）
        text = p.read_text(encoding='utf-8')
        raw = text.encode('utf-8')
        out[rel] = {
            'sha256': hashlib.sha256(raw).hexdigest(),
            'chars': len(text),
            'bytes': len(raw),
        }
    return out


def _build_once(root):
    site_corpus.build_tree(root)
    stats = _run_python_build(root)
    files = _collect(root)
    stats['files'] = files
    return stats


def _check_draft_absent(root, files):
    """反向守卫：草稿不得进任何列表类产物，且草稿 html 必须保持原样。"""
    draft_html = (Path(root) / PAGES / 'article' / DRAFT_FILE)
    if not draft_html.is_file():
        raise SystemExit('草稿文件不见了：%s' % draft_html)
    corpus = site_corpus.spec()['files']
    want = corpus['pages/article/' + DRAFT_FILE]
    got = draft_html.read_text(encoding='utf-8')
    if got != want:
        raise SystemExit(
            '草稿 html 被重新生成了（应当原样保留）：\n  期望 %r\n  实际 %r'
            % (want[:80], got[:80]))

    needle = [DRAFT_FILE, '草稿']
    # 这些产物里**不得**出现草稿的文件名或「草稿」二字
    targets = ['index.html', 'list/2.html', 'rss.xml', 'search-index.json',
               'sitemap.xml', 'search.html']
    for rel in targets:
        p = Path(root) / PAGES / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding='utf-8')
        if DRAFT_FILE in text:
            raise SystemExit('草稿文件 %s 出现在了 %s 里' % (DRAFT_FILE, rel))
    # 「草稿」二字只应出现在草稿自己的文章页 / 正文里（本语料没有其它来源）
    for rel in files:
        if rel.startswith('article/'):
            continue
        p = Path(root) / PAGES / rel
        text = p.read_text(encoding='utf-8')
        if '草稿' in text:
            raise SystemExit('「草稿」二字出现在了 %s 里' % rel)
    del needle


def main():
    runs = []
    roots = []
    try:
        for i in range(2):
            root = tempfile.mkdtemp(prefix='tp-build-base-%d-' % i)
            roots.append(root)
            runs.append(_build_once(root))

        first, second = runs
        if first['files'] != second['files']:
            a, b = set(first['files']), set(second['files'])
            raise SystemExit(
                '两次独立构建的产物不一致 ⇒ 语料不确定（文件差异：%r / 内容差异：%r）'
                % (sorted(a ^ b),
                   sorted(k for k in a & b
                          if first['files'][k] != second['files'][k])))
        if first['articles'] != second['articles'] or \
                first['list_pages'] != second['list_pages']:
            raise SystemExit('两次独立构建的统计量不一致：%r vs %r' % (first, second))

        _check_draft_absent(roots[0], first['files'])

        # 编排层应当写出的文件数 = 全部产物 − 语料带来的 .md − 未被重生成的草稿 html
        written = [rel for rel in first['files']
                   if not rel.endswith('.md') and rel != 'article/' + DRAFT_FILE]
        fixture = {
            '_meta': {
                'generated_by': 'tp/test/gen_build_baseline.py',
                'python': 'tinypage.generator.generate_static_pages'
                          ' (== cli.py:139-141 的 build)',
                'compared_by': 'tp/test/test_build.wll（由 gen_test_build.py 生成）',
                'spec_source': 'tp/test/site_corpus.py（本夹具已内联 spec，'
                               '测试不再 import 它）',
                'paths': 'expected 的键是相对 pages/ 的 POSIX 路径；'
                         '夹具内**不含任何绝对路径**',
                'known_differences': {
                    'D-NL': 'Python 的 write_text/open(newline=None) 在 Windows 上把'
                            ' \\n 翻成 \\r\\n，WLWL 的 WRITE_FILE_ATOMIC 原样写 \\n。'
                            '夹具登记的是 read_text() 之后的 LF 内容 ⇒ 磁盘字节在'
                            ' Windows 上会有 CRLF/LF 差异，与渲染无关。',
                    'D7': 'generator.load_theme_css 会追加 Pygments 样式表；'
                          '本基准把 has_syntax_highlighting 打成 False'
                          '（业主裁决：代码高亮改前端）⇒ 与 WLWL 的 LOAD_THEME_CSS 同口径。',
                    'cache': '.tinypage/backlinks.json 是含 st_mtime 的缓存、不可复现'
                             '⇒ 不入账；WLWL 侧不写它。',
                    'md': '语料自带的 *.md 正文不入账（两侧内容相同，'
                          '但 WLWL 侧不重写源文件）。',
                    'md_inline_code_escape':
                        'md_inline.wll 不转义行内代码的内容（mistune 会）。'
                        '语料刻意避开（见 site_corpus.KNOWN_GAP_INLINE_CODE），'
                        '⇒ 该缺口不影响本夹具的任何一条哈希。',
                    'md_inline_link_percent':
                        'md_inline.wll 不对链接目标里的非 ASCII 做 percent-encoding'
                        '（mistune 会）。语料的未命中双链用 ASCII 标题'
                        '（见 site_corpus.KNOWN_GAP_LINK_PERCENT）。',
                },
                'counts': {k: first[k] for k in
                           ('articles', 'standalones', 'list_pages', 'categories')},
                'written_expected': len(written),
                'files_expected': len(first['files']),
            },
            'spec': site_corpus.spec(),
            'expected': dict(sorted(first['files'].items())),
        }
        with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(fixture, f, ensure_ascii=False, indent=1, sort_keys=False)
            f.write('\n')

        print('wrote %s' % OUT)
        print('  articles=%d  standalones=%d  list_pages=%d  categories=%d'
              % (first['articles'], first['standalones'], first['list_pages'],
                 first['categories']))
        print('  files=%d  written_expected=%d'
              % (len(first['files']), len(written)))
        for rel in sorted(first['files']):
            print('    %-46s %s  %d chars' % (rel, first['files'][rel]['sha256'][:16],
                                              first['files'][rel]['chars']))
    finally:
        for r in roots:
            shutil.rmtree(r, ignore_errors=True)


if __name__ == '__main__':
    main()
