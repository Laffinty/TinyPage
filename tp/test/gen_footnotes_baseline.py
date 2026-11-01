"""生成 tp/test/fixtures/footnotes_baseline.json —— 脚注模块的真 Python 基准。

对齐目标：`tinypage.parsers.footnotes` 的四个函数（**直接 import 真 Python 实现**，
不是手抄期望值）：
    parse_footnotes / render_footnote_refs / build_footnotes_html / process_footnotes

⚠ **顺序差异的刻意处理**（重要）：
  Python 的 `parse_footnotes` 用 `set` 收集 key ⇒ 返回的 footnotes 列表顺序
  **跨进程不确定**（父进程实测 5 次运行给出 4 种不同顺序）——逐字节对照
  根本无法依赖它。本脚本序列化前把 footnotes 按**定义出现顺序**（插入序）
  重排：用与实现同款的 DEF 模式在原始文本里找首次出现顺序，重建 set 丢掉的
  插入序。这是**刻意的确定性选择**；WLWL 实现同样取定义出现顺序（见
  gen_footnotes.py 注释）⇒ 两边逐字节可比。
  `process_footnotes` 返回的 html 同样吃 set 顺序 ⇒ 基准里的 html 用
  **重排后的 footnotes** 重新调真 `build_footnotes_html` 产出（仍是真 Python，
  只是把顺序钉死成定义出现序）。

用法：python gen_footnotes_baseline.py
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.parsers.footnotes import (  # noqa: E402
    parse_footnotes,
    render_footnote_refs,
    build_footnotes_html,
    process_footnotes,
)

OUT = os.path.join(HERE, 'fixtures', 'footnotes_baseline.json')

# 与实现里 FOOTNOTE_DEF_PATTERN 逐字相同，仅用于重建「定义出现顺序」
DEF_PATTERN = re.compile(r"\[\^([^\]]+)\]:\s*(.+)$", re.MULTILINE)

CASES = {
    # ── A（parse）/ D（process）主路径 ──────────────────────
    'basic': '段落一[^1]，补充说明[^2]。\n\n[^1]: 第一个脚注\n[^2]: 第二个脚注\n',
    'single_ref': '正文[^note]结尾。\n\n[^note]: 单个脚注\n',
    'multi_ref_same_key': '同一个键[^k]出现两次[^k]。\n\n[^k]: 重复引用\n',
    'ref_no_def': '引用没有定义[^ghost]，保持原样。\n',
    'def_no_ref': '[^lonely]: 孤独定义\n前面没有引用。\n',
    'cjk_key': '中文键[^键值]测试。\n\n[^键值]: 中文键的脚注\n',
    'colon_in_key': '键含冒号[^a:b]。\n\n[^a:b]: 值\n',
    # C：BUILD_FOOTNOTES_HTML 的 escape_html 路径（含 < > & " '）
    'html_in_text': '脚注含 HTML[^h]。\n\n[^h]: <b>粗</b> & "引号" <tag> \'q\'\n',
    # A：\s* 吃掉冒号后空白 + (.+) 的两端由 strip 收拾
    'def_value_stripped': '[^s]:   两端空格   \n正文。\n',
    # C/D：无脚注 ⇒ html 为 ""
    'no_footnotes': '普通段落，无脚注。\n',
    'adjacent_refs': 'a[^1]b[^2]c\n\n[^1]: one\n[^2]: two\n',
    'mixed_defs_and_refs': '句[^a]尾。\n[^a]: 一行定义\n第二行保留\n[^b]: 后一个\n',
    # ── 反向守卫（期望值同样由真 Python 产出） ──────────────
    # A：定义值只取到行尾，第二行保留在正文
    'guard_newline_def': 'before [^x]: first line\nsecond line\nafter',
    # A：重复定义 ⇒ 值取第一个，但**两行**都被删除
    'guard_dup_def': 'dup [^d]: first\nalso [^d]: second\nend\n',
    # A：DEF 无行首锚定 ⇒ 行中间的定义也被识别删除
    'guard_midline_def': 'def at mid [^z]: value',
    # B：空定义 `[^e]:`（冒号后无内容）⇒ DEF 匹配不到、引用也不得转 <sup>
    'guard_empty_def_eol': 'no content [^e]:',
    # B：直接调 render（未先 parse）⇒ [^a]: 定义形态被 (?!:) 跳过
    'direct_render_skip_defs': 'x[^a]: v and ref[^b]',
}


def def_first_order(text):
    """按定义**首次出现**顺序重建 key 列表（set 丢掉的插入序）。"""
    seen = []
    for m in DEF_PATTERN.finditer(text):
        k = m.group(1)
        if k not in seen:
            seen.append(k)
    return seen


def ordered_footnotes(src):
    """parse_footnotes 的结果，按定义出现顺序重排（确定性选择，见模块注释）。"""
    cleaned, foots = parse_footnotes(src)
    order = def_first_order(src)
    by_key = {f.key: f for f in foots}
    # 防御：两边 key 集合必须一致（set 与插入序只差顺序）
    assert set(by_key) == set(order), (sorted(by_key), sorted(order))
    return cleaned, [by_key[k] for k in order]


def main():
    base = {}
    for name in sorted(CASES):
        src = CASES[name]
        cleaned, foots = ordered_footnotes(src)
        processed_text, _ = process_footnotes(src)
        base[name] = {
            'src': src,
            'cleaned': cleaned,
            # ⚠ 这里已是**定义出现顺序**（见模块注释），不是 Python 的 set 顺序
            'footnotes': [{'key': f.key, 'text': f.text} for f in foots],
            'refs': processed_text,          # render(parse 后的 cleaned)
            'render_raw': render_footnote_refs(src),  # 直接 render（未 parse）
            'html': build_footnotes_html(foots),      # 真 Python + 重排后的顺序
        }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(base, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    print(f'wrote {OUT} ({len(base)} cases)')


if __name__ == '__main__':
    main()
