r"""生成 tp/test/fixtures/wikilink_baseline.json —— wikilink 的真 Python 基准。

对齐目标：`tinypage/parsers/bidirectional_links.py`
  - `parse_bidirectional_links(text, article_map)` → (processed_text, found_links)
  - `extract_bidirectional_links(text)`             → [title, ...]

⚠ 必须**直接 import 真 Python 实现**（不是照抄规则重写一遍），
  否则基准只是「我的第二种读法」，逐字节对照失去意义。

article_map 形态：Python `dict[str_lower_title, (slug, url)]`；
JSON 里二元组序列化成 `[slug, url]`（WLWL 侧同形，值是两元素数组）。

⚠ **已知差异（2026-11-01 实测，wlwl v0.12.1）**：`WIKILINK_TARGET`（复用自
  md_inline.wll）与 Python `slugify_for_link` 只剩**一类**不一致，受影响用例
  在 JSON 里带 `known_divergence` 注记，测试侧钉住 WLWL 实测值并单独标注：
  ① ~~尾部 `-` 未裁剪~~ —— **已修复（2026-11-02）**：`trim_dashes` 第二个条件
     原为 `>(start, end)`（恒假 ⇒ 尾部循环一次都不执行），已改为 `<(start, end)`
     并重生成 md 系列产物；`Hello, World!` 现与 Python 逐字节一致，已从
     KNOWN_DIVERGENCE 移除、回归权威值断言。
  ② **非 ASCII 非 CJK 字母被丢弃**（预期内的 `\w` 语义差）：
     Python `\w` 含 é/西里尔/假名，WLWL 白名单只有 ASCII+CJK ⇒ 落到 untitled。
     例：`café` → Python `café` / WLWL `caf`（尾 `-` 已随 trim_dashes 修复一并裁掉）；`ひら가な` → Python `ひらがな` /
     WLWL `untitled`。
  差异②归 md_inline.wll 的既定对齐口径（ASCII+CJK），本模块不改它，只如实登记。

用法：python gen_wikilink_baseline.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.parsers.bidirectional_links import (  # noqa: E402
    extract_bidirectional_links,
    parse_bidirectional_links,
)

OUT = os.path.join(HERE, 'fixtures', 'wikilink_baseline.json')

# 每条用例：(src, article_map)
# 覆盖：无别名 / 带别名 / CJK / 命中 map / 未命中 map / 多链接 / 相邻链接 /
#       正文夹杂 / strip / 空 map / 无链接 / 多竖线 / 特殊字符 slug
CASES = [
    # 无别名
    ('见 [[Page]] 一文。', {}),
    # 带别名
    ('[[Page|显示名]]', {}),
    # CJK 标题（slug 保留 CJK）
    ('[[中文标题]]', {}),
    # 命中 map（键是小写标题，值 [slug, url]）
    ('[[Another]]', {'another': ('another', '/article/other.html')}),
    # 未命中 map ⇒ 回退 /article/{slug}.html
    ('[[Missing Page]]', {'another': ('another', '/article/other.html')}),
    # 多个链接
    ('[[a]] 和 [[b|B]] 结束', {}),
    # 相邻链接（不得互相吞并）
    ('[[a]][[b]]', {}),
    # 正文夹杂（前后都有中文）
    ('# 标题\n\n正文 [[Foo]]，见 [[Bar|条]]。\n', {}),
    # 标题两侧空白被 strip
    ('[[ a ]]', {}),
    # 别名两侧空白被 strip（title 也 strip）
    ('[[ a | b ]]', {}),
    # 标点 → slug 折叠
    ('[[Hello, World!]]', {}),
    # 命中 map + 带别名
    ('[[Another|去看看]]', {'another': ('another', '/article/other.html')}),
    # 大写标题：查 map 用 title.lower()
    ('[[MyPage]]', {'mypage': ('custom', '/custom/x.html')}),
    # CJK 标题命中 map
    ('[[你好|hi]]', {'你好': ('你好', '/article/nihao.html')}),
    # 多竖线：group(2) 吃掉第二个 | 之后的内容
    ('[[a|b|c]]', {}),
    # 完全没有 wikilink（原样返回）
    ('没有任何链接的普通段落。', {}),
    # 特殊字符 slug（对齐 slugify：非 \\w → -，折叠，去首尾 -）
    ('[[C++ / R&D]]', {}),
    # 不配对 / 竖线开头 ⇒ 正则不匹配，原样返回
    ('前 [[|b]] 后 [[x 前', {}),
    # tab 两侧空白（strip 语义对齐）
    ('[[\tTab\t]]', {}),
    # 标题末尾空别名形态：[[x| ]]  display 的 [^\]]+ 至少 1 字符 ⇒ " "
    ('[[x| ]] end', {}),
    # ── 已知差异类（见文件头注记②）────────────────────────────
    ('[[café]]', {}),        # 非 ASCII 非 CJK 字母：Python 保留，WLWL 换 -
    ('[[ひらがな]]', {}),    # 假名同上（\u4e00-\u9fa5 之外）⇒ WLWL 落 untitled
]

# 受已知差异影响的用例（key = src）：JSON 里加 known_divergence 注记。
# Python 侧输出仍是权威基准；WLWL 侧差异在 gen_test_wikilink.py 里钉实测值。
KNOWN_DIVERGENCE = {
    # ② \w 语义差（预期内，md_inline 的对齐口径是 ASCII+CJK）
    #    （原 ① trim_dashes 尾部裁剪已于 2026-11-02 修复，Hello, World! 回归权威值）
    '[[café]]':
        '非 ASCII 非 CJK 字母：Python slug café，WLWL slug caf',
    '[[ひらがな]]':
        '假名在 \\u4e00-\\u9fa5 之外：Python slug ひらがな，WLWL slug untitled',
}


def main():
    base = {}
    for i, (src, amap) in enumerate(CASES):
        name = 'case_%02d' % i
        py_map = {k: tuple(v) for k, v in amap.items()}
        processed, found = parse_bidirectional_links(src, py_map)
        extracted = extract_bidirectional_links(src)
        entry = {
            'src': src,
            # 二元组 → [slug, url]（与 WLWL 侧 DICT 值同形）
            'map': {k: list(v) for k, v in amap.items()},
            'processed': processed,
            'found': [{'title': t, 'display': d, 'url': u} for (t, d, u) in found],
            'extracted': extracted,
        }
        if src in KNOWN_DIVERGENCE:
            entry['known_divergence'] = KNOWN_DIVERGENCE[src]
        base[name] = entry
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(base, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    print(f'wrote {OUT} ({len(base)} cases)')


if __name__ == '__main__':
    main()
