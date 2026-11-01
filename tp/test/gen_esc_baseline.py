"""生成 tp/test/fixtures/esc_baseline.json —— HTML 转义的真 Python 基准。

对齐目标：`tinypage.security.escape_html` == `html.escape(s, quote=True)`。
（`escape_attr` 与它等价：escape 已把 `"` 转成 `&quot;`，再 replace 无事可做。）

用法：python gen_esc_baseline.py
"""
import html
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'fixtures', 'esc_baseline.json')

CASES = [
    # 基本四个字符
    '<a>"b"&c',
    "<a>'b'&c",
    '&<>"\'',
    # 中文与 ASCII 混排
    '普通中文 & <script>',
    # 控制字符（html.escape 不动 tab/换行）
    'tab\there "x"',
    'line1\nline2',
    # 空串
    '',
    # 只有单引号 —— 关键：Python 出 &#x27;，WLWL 内建出 &#39;
    "'",
    "it's a 'test'",
    # 已含实体字面量 —— 守卫：不得被二次转义或误替换
    '&#39;',
    '&amp;#39;',
    '&lt;',
    # markdown 常见文本
    '**bold** & `code`',
    '[link](http://x.y/?a=1&b=2)',
    # 反斜杠与特殊符号
    'C:\\path\\to\\file',
    'a = b < c > d',
    # 已转义过一次的输入（幂等性检查：escape 不是幂等的，此处锁真实行为）
    '&amp;',
]


def main():
    base = {}
    for i, s in enumerate(CASES):
        name = 'case_%02d' % i
        base[name] = {
            'src': s,
            'html': html.escape(s, quote=True),
        }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(base, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    print(f'wrote {OUT} ({len(base)} cases)')


if __name__ == '__main__':
    main()
