"""生成 tp/lib/esc.wll —— HTML 转义共享工具。

⚠ 输出的 .wll 由本文件生成，不要手改。

**为什么单独一个模块**：S1-4 的 frontmatter / toc / footnotes 三个模块都要
输出「对齐 Python `html.escape(quote=True)`」的 HTML，必须只有一份实现。

**实测差异（2026-11-01）**：WLWL 内建 `HTML_ESCAPE` 把 `'` 转成 `&#39;`，
Python 转成 `&#x27;` —— 语义等价但**逐字节不同**，对照测试会红。
⇒ 后处理把 `&#39;` 换成 `&#x27;`。
  安全性：`HTML_ESCAPE` 已先把 `&` 转成 `&amp;`，所以结果里的 `&#39;`
  必然是它自己生成的单引号；输入里的字面 `&#39;` 会变成 `&amp;#39;`
  （子串里没有 `&#39;`，因为 `&` 后面跟的是 `a`）⇒ 不会被误替换。

对齐目标：`tinypage.security.escape_html` == `html.escape(s, quote=True)`。
基准：tp/test/fixtures/esc_baseline.json（由 gen_esc_baseline.py 用真 Python 生成）

用法：python gen_esc.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'esc.wll')


def main():
    src = []
    A = src.append
    A('// tp/lib/esc.wll —— HTML 转义共享工具')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_esc.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标：Python html.escape(s, quote=True)')
    A('//   （== tinypage.security.escape_html）')
    A('// 逐字节对照基准：tp/test/fixtures/esc_baseline.json')
    A('//')
    A('// 为什么必须后处理：WLWL 内建 HTML_ESCAPE 把 \' 转成 &#39;，')
    A('// Python 转成 &#x27; —— 语义等价但逐字节不同 ⇒ 用 RE_REPLACE 换过去。')
    A('// 安全性：HTML_ESCAPE 已把 & 转成 &amp; ⇒ 输出里的 &#39; 必然是它自己')
    A('// 生成的单引号；输入的字面 &#39; 变成 &amp;#39;（& 后跟 a）不会被误伤。')
    A('')
    A('IMPORT("wlwl:std.sanitize", ["HTML_ESCAPE"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_REPLACE"]);')
    A('')

    src += fn('ESCAPE_HTML', 's', [
        '// 对齐 Python html.escape(s, quote=True)：',
        '// & < > \" \' → &amp; &lt; &quot; &#x27;（内建已做前四个，\' 要换写法）',
        'RE_REPLACE(RE("&#39;"), HTML_ESCAPE(s), "&#x27;")',
    ], '// HTML 转义（逐字节对齐 Python html.escape(quote=True)）')

    A('EXPORT(["ESCAPE_HTML"]);')
    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
