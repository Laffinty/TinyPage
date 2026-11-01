"""生成 tp/test/fixtures/toc_baseline.json —— TOC 的真 Python 基准。

对齐目标：`tinypage/parsers/toc.py` 的四个函数 ——
slugify_heading / extract_headings / build_toc_html / add_heading_ids。
**直接 import 真 Python 实现**（不是照抄语义），序列化成 JSON 供
gen_test_toc.py 生成逐字节对照断言。

用法：python gen_toc_baseline.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.parsers.toc import (  # noqa: E402
    add_heading_ids,
    build_toc_html,
    extract_headings,
    slugify_heading,
)

OUT = os.path.join(HERE, 'fixtures', 'toc_baseline.json')

# slugify_heading 用例：(name, src)
SLUG_CASES = [
    ('punct_ascii', 'Hello, World!'),
    ('cjk_only', '中文标题'),
    ('ws_edges', '  Leading and trailing  '),
    ('ws_collapse', 'Multiple   spaces\tand tabs'),
    ('already', 'already-slugged'),
    ('underscore_amp', 'Under_scores & symbols!'),
    ('dashes_only', '---'),
    ('bangs_only', '!!!'),
    ('mixed_cjk_ascii', 'Mixed汉字 and ASCII 123'),
    ('dash_collapse', 'a--b---c'),
    ('dash_edges', '-leading-trailing-'),
    ('upper', 'UPPERCASE'),
]

# extract_headings 用例：(name, md_text)
EXTRACT_CASES = [
    ('levels', '# Title\n## Sub A\n### Deep\n## Sub B\n'),
    ('dup_three', '## Usage\n## Usage\n## Usage\n'),
    ('dup_diff_text', '## Hello World!\n## Hello World\n'),
    ('cjk_dup', '## 第一章\n## 第一章\n## 中文 标题\n'),
    ('noise_lines', '#NoSpace\n#\n##\nNot a heading\n ## Indented heading\n####### seven\n###### six\n'),
    ('inline_md', '## Using `code` and **bold**\n## [Link](http://x.y/?a=1&b=2)\n'),
    ('empty', ''),
    ('tab_sep', '##\tTab title\n'),
]

# build_toc_html 用例：(name, md_text, min_level, max_level)
TOC_CASES = [
    ('h2h3', '# Top\n## Sub A\n### Deep\n#### Deeper\n## Sub B\n', 2, 3),
    ('full_1_6', '# Top\n## A\n### B\n#### C\n##### D\n###### E\n', 1, 6),
    ('all_filtered', '# Only one\n# Only two\n', 2, 3),
    ('escapes', '## Use <tag> & "quotes" \'single\'\n', 2, 3),
    ('deep_indent', '## Level Two\n#### Level Four\n', 2, 4),
    ('h3_only', '## Two\n### Three\n## Two B\n', 3, 3),
]

# add_heading_ids 用例：(name, html_content, md_for_headings)
ADDIDS_CASES = [
    ('basic', '<h1>Title</h1>\n<h2>Sub</h2>\n<p>body</p>\n', '# Title\n## Sub\n'),
    ('attrs_after_id', '<h2 class="hl">Sub</h2>\n', '## Sub\n'),
    ('existing_id', '<h1 id="keep">Title</h1>\n', '# Title\n'),
    ('multiline_content', '<h2>line one\nline two</h2>\n', '## line one\n'),
    ('no_match', '<h2>Mystery</h2>\n', '## Other\n'),
    ('substring_content', '<h2>Intro Section</h2>\n', '## Intro\n'),
    ('empty_content', '<h1></h1>\n', '# Title\n'),
    ('dup_override', '<h2>Same</h2>\n', '## Same\n## Same\n'),
]


def hdicts(md_text):
    """extract_headings 的 dataclass 结果 → 可序列化的 dict 列表。"""
    return [{'level': h.level, 'text': h.text, 'id': h.id}
            for h in extract_headings(md_text)]


def main():
    base = {'slug': [], 'extract': [], 'toc': [], 'addids': []}

    for name, src in SLUG_CASES:
        base['slug'].append({'name': name, 'src': src, 'want': slugify_heading(src)})

    for name, md in EXTRACT_CASES:
        base['extract'].append({'name': name, 'md': md, 'want': hdicts(md)})

    for name, md, mn, mx in TOC_CASES:
        want = build_toc_html(extract_headings(md), mn, mx)
        base['toc'].append({'name': name, 'md': md, 'min': mn, 'max': mx, 'want': want})

    for name, html, md in ADDIDS_CASES:
        want = add_heading_ids(html, extract_headings(md))
        base['addids'].append({'name': name, 'html': html, 'md': md, 'want': want})

    total = sum(len(v) for v in base.values())
    if total < 15:
        raise SystemExit(f'baseline too small: {total} cases (< 15)')

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(base, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    print(f'wrote {OUT} ({total} cases: '
          f'{len(base["slug"])} slug + {len(base["extract"])} extract + '
          f'{len(base["toc"])} toc + {len(base["addids"])} addids)')


if __name__ == '__main__':
    main()
