r"""生成 tp/lib/wikilink.wll —— 双向链接（[[标题]]）解析模块。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律生成器产出）。

对齐目标：`tinypage/parsers/bidirectional_links.py`
  - PARSE_BIDIRECTIONAL_LINKS(text, article_map)
      == parse_bidirectional_links(text, article_map)
  - EXTRACT_BIDIRECTIONAL_LINKS(text)
      == extract_bidirectional_links(text)

三条关键设计（全部有实测依据）：

1. **正则逐字节照抄 Python 原模式**
   `\\[\\[([^\\]|]+)(?:\\|([^\\]]+))?\\]\\]`（WLWL 字符串里反斜杠要**双写**，
   因为 .wll 的转义白名单只认 `\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`）。
   实测 `RE_FIND_ALL` 返回 ARRAY of DICT（`matched/start/end/groups`），
   `groups` 恒为 3 项、缺席的可选捕获组是 `NULL`；`start/end` 是**原串码点下标**
   ⇒ 直接按 `[pos, start)` 切片拼接，等价于 Python 的一次性 `re.sub`。

2. **URL 解析复用 `WIKILINK_TARGET`（不重写 slugify）**
   `WIKILINK_TARGET(title, map)` 命中 map 时返回**映射值本身**。本模块的
   article_map 值是二元组同形的两元素数组 `[slug, url]` ⇒ 命中时拿到 ARRAY，
   取 `target[1]` 当 URL；未命中 / map 为 NULL 时它返回 STRING（回退
   `/article/{slug}.html`），原样用。用 `TYPE(target) == "ARRAY"` 分流。

3. **extract 也 strip —— 与任务简报的说法不同，以真源码为准**
   简报称 `extract_bidirectional_links` 不做 strip，但当前
   `tinypage/parsers/bidirectional_links.py:98` 是 `title = match.group(1).strip()`
   且 `if title:` 跳过空串。基准由真 Python 生成 ⇒ **以源码为准：两处都 strip**，
   空白串标题被丢弃。差异已在交付报告中登记。

⚠ `title.lower()`（Python）↔ `TO_LOWER`（std.text，完整 Unicode 小写），
   两边同语义；slugify 的字符集差异（`\w` vs ASCII+CJK 白名单）由
   `md_inline.wll` 的 `WIKILINK_TARGET` 承担，本模块不碰。

基准：tp/test/fixtures/wikilink_baseline.json（由 gen_wikilink_baseline.py 用真 Python 生成）

用法：python gen_wikilink.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'wikilink.wll')

# 与 Python BIDIRECTIONAL_LINK_PATTERN 完全同款（原始串里的反斜杠在 .wll 中双写）
BIDI_RE = r'RE("\\[\\[([^\\]|]+)(?:\\|([^\\]]+))?\\]\\]")'


def main():
    src = []
    A = src.append
    A('// tp/lib/wikilink.wll —— 双向链接 [[标题]] 解析')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_wikilink.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标：tinypage/parsers/bidirectional_links.py')
    A('//   PARSE_BIDIRECTIONAL_LINKS(text, article_map) == parse_bidirectional_links')
    A('//   EXTRACT_BIDIRECTIONAL_LINKS(text)             == extract_bidirectional_links')
    A('// 逐字节对照基准：tp/test/fixtures/wikilink_baseline.json')
    A('//')
    A('// 三条实测依据（2026-11-01 探针）：')
    A('//   ① RE_FIND_ALL 返回 ARRAY of DICT（matched/start/end/groups），')
    A('//      groups 恒 3 项、缺席的可选捕获组 = NULL；start/end 是原串**码点**下标')
    A('//      ⇒ 按 [pos, start) 切片拼接 == Python re.sub 的一次性全部替换。')
    A('//   ② WIKILINK_TARGET 命中 map 返回映射值本身 —— 本模块 map 值是')
    A('//      [slug, url] 二元组同形数组 ⇒ TYPE(target)=="ARRAY" 时取 target[1]。')
    A('//      slugify 规则整体复用 md_inline.wll（已对齐 security.py::slugify），')
    A('//      本模块**不重写** slug。')
    A('//   ③ title.lower() ↔ TO_LOWER（std.text，完整 Unicode 小写），同语义。')
    A('')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_FIND_ALL"]);')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("./md_inline.wll", ["WIKILINK_TARGET"]);')
    A('')
    A('// 与 Python re.compile(r"\\[\\[([^\\]|]+)(?:\\|([^\\]]+))?\\]\\]") 同款')
    A(f'LET(BIDI_LINK_RE, {BIDI_RE});')
    A('')

    # ── A. 解析 + 替换 ───────────────────────────────────────
    src += fn('PARSE_BIDIRECTIONAL_LINKS', 'text, article_map', [
        '// 对齐 parse_bidirectional_links：返回 [processed_text, found_links]',
        '// found_links 每项 {title, display, url}，保持出现顺序',
        'LET(matches, RE_FIND_ALL(BIDI_LINK_RE, text))',
        'LET MUT(out, "")',
        'LET MUT(found, [])',
        'LET MUT(pos, 0)',
        C('FOR', 'm, matches', [
            'LET(groups, AT_K(m, "groups", []))',
            # ⚠ 两处 strip 都在取值之后：title = group(1).strip()，
            #   display = group(2).strip()（缺省时 display = 已 strip 的 title）
            'LET(raw_title, groups[1])',
            'LET(raw_disp, groups[2])',
            'LET(title, TRIM(raw_title))',
            'LET(display, IF(==(TYPE(raw_disp), "NULL"), title, TRIM(raw_disp)))',
            # URL：命中 map ⇒ [slug, url] 数组取 [1]；未命中 ⇒ 回退串
            'LET(target, WIKILINK_TARGET(title, article_map))',
            'LET(url, IF(==(TYPE(target), "ARRAY"), target[1], target))',
            C('SET', 'out',
              'CAT(out, SUB(text, pos, -(AT_K(m, "start", 0), pos)), '
              '"[", display, "](", url, ")")'),
            C('SET', 'pos', 'AT_K(m, "end", 0)'),
            # ⚠ 字典字面量的 Key 是**表达式**：裸标识符会被当变量求值（E0020），
            #   键必须写成字符串字面量
            C('SET', 'found',
              '+(found, [["title": title, "display": display, "url": url]])'),
        ]),
        # 末尾补齐最后一个匹配之后的正文（无匹配时 pos==0 ⇒ 原样返回整段）
        C('IF', '<(pos, LEN(text))',
          [C('SET', 'out', 'CAT(out, SUB(text, pos, -(LEN(text), pos)))')],
          'NULL'),
        '[out, found]',
    ], '// 解析 [[标题]] / [[标题|显示]] → [processed_text, found_links]')

    # ── B. 仅提取标题 ────────────────────────────────────────
    src += fn('EXTRACT_BIDIRECTIONAL_LINKS', 'text', [
        '// 对齐 extract_bidirectional_links：',
        '// ⚠ 简报说这里「未 strip」，但真源码 bidirectional_links.py:98 是',
        '//   `title = match.group(1).strip()` + `if title:` ⇒ **同样 strip**，',
        '//   且 strip 后为空的标题被丢弃。以真源码为准（基准由真 Python 生成）。',
        'LET(matches, RE_FIND_ALL(BIDI_LINK_RE, text))',
        'LET MUT(out, [])',
        C('FOR', 'm, matches', [
            'LET(groups, AT_K(m, "groups", []))',
            'LET(title, TRIM(groups[1]))',
            C('IF', '==(title, "")',
              'NULL',
              [C('SET', 'out', '+(out, [title])')]),
        ]),
        'out',
    ], '// 提取全部链接标题（原文顺序，strip 后）')

    A('EXPORT(["PARSE_BIDIRECTIONAL_LINKS", "EXTRACT_BIDIRECTIONAL_LINKS"]);')
    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
