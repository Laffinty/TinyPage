"""生成 mistune 的基准输出，供 WLWL 实现逐字节对照。

用法：python gen_mistune_baseline.py
产物：tp/test/fixtures/mistune_baseline.json
"""
import json
import os

import mistune

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')

md = mistune.create_markdown(escape=True)

CASES = {
    'heading_h1': '# Title\n',
    'heading_h6': '###### Six\n',
    'para_single': 'Just one paragraph.\n',
    'para_multi_line': 'Line one\nLine two\nLine three\n',
    'para_blank_sep': 'First para.\n\nSecond para.\n',
    'inline_bold': 'a **b** c\n',
    'inline_italic': 'a *b* c\n',
    'inline_code': 'a `b` c\n',
    'inline_link': '[t](https://a.b/c)\n',
    'inline_link_relative': '[t](/x/y)\n',
    'inline_escape_html': '<script>alert(1)</script>\n',
    'ul': '- one\n- two\n',
    'ul_plus': '+ one\n+ two\n',
    'ol': '1. one\n2. two\n',
    'ol_paren': '1) one\n2) two\n',
    'code_fence_lang': '```python\nx = 1\n```\n',
    'code_fence_nolang': '```\nplain\n```\n',
    'blockquote': '> quoted\n',
    'hr': '---\n',
    'hr_star': '***\n',
    'heading_with_inline': '## Sub *it*\n',
    'list_with_inline': '- a **b**\n- c `d`\n',
    'empty': '',
    'only_blank': '\n\n\n',
    'text_no_trailing_nl': 'no newline at end',
}


def main():
    os.makedirs(FIXTURES, exist_ok=True)
    out = {}
    for name, src in CASES.items():
        out[name] = {'src': src, 'html': md(src)}
    path = os.path.join(FIXTURES, 'mistune_baseline.json')
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(out, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f'wrote {path} ({len(out)} cases)')
    for name in sorted(out):
        print(f'  {name}: {out[name]["html"]!r}')


if __name__ == '__main__':
    main()
