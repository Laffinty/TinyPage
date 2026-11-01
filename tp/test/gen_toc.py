"""生成 tp/lib/toc.wll —— 文章目录（TOC）模块。

⚠ 输出的 .wll 由本文件生成，不要手改。

对齐目标：`tinypage/parsers/toc.py` 的四个函数（逐字节）：
  SLUGIFY_HEADING(text)                   == slugify_heading
  EXTRACT_HEADINGS(md_text)               == extract_headings（返回 ARRAY of DICT）
  BUILD_TOC_HTML(headings, min, max)      == build_toc_html
  ADD_HEADING_IDS(html_content, headings) == add_heading_ids
基准：tp/test/fixtures/toc_baseline.json（由 gen_toc_baseline.py import 真 Python 生成）

⚠ 三条实测得来的要点（2026-11-01，wlwl v0.12.1 REPL 实测）：
  ① wlwl 正则**无反向引用**（`\1` → E0030）⇒ ADD_HEADING_IDS 不用正则，改为
     INDEX_OF 逐位手工扫描，与 Python
     re.sub(r"<(h[1-6])([^>]*)>(.+?)</\\1>", flags=re.DOTALL)
     的「左最早、content ≥1 字符、同级闭合、消费后从匹配尾继续」逐位对齐。
  ② wlwl 正则把 `\\u4e00` 当成**字面** `u4e00`
     （实测：RE_TEST(RE("\\u4e00"), "中") = FALSE、RE_TEST(RE("a\\u4e00b"), "au4e00b") = TRUE）
     ⇒ 字符类用**字面** `一-龥`（U+4E00..U+9FA5，实测 RE_REPLACE
     RE("[^a-zA-Z0-9一-龥\\s]"), "中文, hi! 你好", "") = "中文 hi 你好"，与 Python 一致）。
  ③ wlwl 的 `\\s` 是 ASCII-only（Python `\\s` 含 Unicode 空白 \\u3000 / \\xa0 等）
     ⇒ 标题行/slug 含 Unicode 空白时与 Python 有差异（基准用例均避开，见模块头注释）。

用法：python gen_toc.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, FUN_DEF, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'toc.wll')

# BUILD_TOC_HTML 的模板串（逐字节对齐 Python f-string）：
#   "\n<nav ...>\n  <details open>\n    <summary>目录</summary>\n    <ul>\n      "
#   + items + "\n    </ul>\n  </details>\n</nav>"
# 以 \n 开头、</nav> 后**无**换行。全部转义都是 WLWL 白名单内的 \n 与 \"。
TOC_TPL = (r'CAT("\n<nav class=\"toc\" aria-label=\"文章目录\">\n  <details open>'
           r'\n    <summary>目录</summary>\n    <ul>\n      ", items, '
           r'"\n    </ul>\n  </details>\n</nav>")')


def main():
    src = []
    A = src.append
    A('// tp/lib/toc.wll —— 文章目录（TOC）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_toc.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标：tinypage/parsers/toc.py 的四个函数（逐字节对照）：')
    A('//   SLUGIFY_HEADING(text)                   == slugify_heading')
    A('//   EXTRACT_HEADINGS(md_text)               == extract_headings（返回 ARRAY of DICT）')
    A('//   BUILD_TOC_HTML(headings, min, max)      == build_toc_html')
    A('//   ADD_HEADING_IDS(html_content, headings) == add_heading_ids')
    A('// 逐字节对照基准：tp/test/fixtures/toc_baseline.json')
    A('//   （由 tp/test/gen_toc_baseline.py import 真 Python 生成）')
    A('//')
    A('// ⚠ 已知差异（基准用例均避开）：')
    A('//   · wlwl 的 \\s 是 ASCII-only，Python 的 \\s 含 Unicode 空白（\\u3000、\\xa0 等）')
    A('//     ⇒ 标题行/slug 里出现 Unicode 空白时两边结果可能不同。')
    A('//   · ADD_HEADING_IDS 的 map 键（标题文本）必须非空（CONTAINS_SUB 空串 → E0030）；')
    A('//     EXTRACT_HEADINGS 产出的 text 恒非空，安全。')
    A('//')
    A('// 导出：')
    A('//   SLUGIFY_HEADING(text) -> STRING')
    A('//   EXTRACT_HEADINGS(md_text) -> ARRAY of ["level":INT, "text":STR, "id":STR]')
    A('//   BUILD_TOC_HTML(headings, min_level, max_level) -> STRING')
    A('//   ADD_HEADING_IDS(html_content, headings) -> STRING')
    A('')
    A('IMPORT("wlwl:std.str", ["SPLIT_LINES", "INDEX_OF", "CONTAINS_SUB", "CAT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_SEARCH", "RE_REPLACE"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('')

    # ── 辅助 ────────────────────────────────────────────────
    src += fn('indent_sp', 'n', [
        '// "  " * n（Python 同名语义；负数/0 ⇒ 空串）',
        'LET MUT(i, 0)',
        'LET MUT(acc, "")',
        C('WHILE', '<(i, n)', [
            'SET(acc, CAT(acc, "  "))',
            'SET(i, +(i, 1))',
        ]),
        'acc',
    ], '// 两空格重复 n 次（TOC 缩进）')

    src += fn('is_lvl_digit', 'ch', [
        '// ch 为空串 ⇒ FALSE（LENGTH 守卫防 SUB 越界取空）',
        '&&(>(LEN(ch), 0), &&(>=(ch, "1"), <=(ch, "6")))',
    ], '// 是否是 1~6 的层级数字字符')

    # ── A. SLUGIFY_HEADING ──────────────────────────────────
    src += fn('SLUGIFY_HEADING', 'text', [
        '// 对齐 Python slugify_heading —— 顺序必须照搬：',
        '// ① 删非法字符（保留 ASCII 字母数字 / 汉字 / 空白）',
        '// ② 空白序列转 "-" 且整体小写',
        '// ③ 连续 "-" 压成一个',
        '// ④ 去首尾 "-"',
        '// ⑤ 结果为空 ⇒ "heading"',
        '// ⚠ 字符类用字面 一-龥：wlwl 正则不认 \\u4e00（实测当字面 u4e00）',
        r'LET(s1, RE_REPLACE(RE("[^a-zA-Z0-9一-龥\\s]"), text, ""))',
        r'LET(s2, RE_REPLACE(RE("\\s+"), LOWER(s1), "-"))',
        'LET(s3, RE_REPLACE(RE("-+"), s2, "-"))',
        'LET(s4, RE_REPLACE(RE("^-+"), s3, ""))',
        'LET(s5, RE_REPLACE(RE("-+$"), s4, ""))',
        'IF(==(s5, ""), "heading", s5)',
    ], '// slug：对齐 Python slugify_heading')

    # ── B. EXTRACT_HEADINGS ─────────────────────────────────
    src += fn('EXTRACT_HEADINGS', 'md_text', [
        '// 对齐 Python extract_headings：每行先 TRIM 再匹配 ^(#{1,6})\\s+(.+)$；',
        '// 去重计数按 base_slug 分组（DICT），第 n 次出现的 id 为 base-n。',
        'LET(lines, SPLIT_LINES(md_text))',
        'LET MUT(out, [])',
        'LET MUT(slug_counts, DICT())',
        C('FOR', 'line, lines', [
            'LET(t, TRIM(line))',
            r'LET(m, RE_SEARCH(RE("^(#{1,6})\\s+(.+)$"), t))',
            C('IF', '==(TYPE(m), "NULL")', 'NULL', [
                'LET(g, AT_K(m, "groups", []))',
                'LET(txt, TRIM(g[2]))',
                'LET(lvl, LEN(g[1]))',
                'LET(base, SLUGIFY_HEADING(txt))',
                'LET(cnt, +(AT_K(slug_counts, base, 0), 1))',
                'SET(slug_counts, INDEX_SET(slug_counts, base, cnt))',
                'SET(out, +(out, [["level": lvl, "text": txt, "id": '
                'IF(>(cnt, 1), CAT(base, "-", STR(cnt)), base)]]))',
            ]),
        ]),
        'out',
    ], '// 提取全部 ATX 标题（对齐 Python extract_headings）')

    # ── C. BUILD_TOC_HTML ───────────────────────────────────
    src += fn('BUILD_TOC_HTML', 'headings, min_level, max_level', [
        '// 对齐 Python build_toc_html：过滤 min~max；过滤后为空 ⇒ ""（不是空模板）；',
        '// 模板首尾换行逐字节精确（以 \\n 开头，</nav> 后无换行）。',
        'LET MUT(items, "")',
        'LET MUT(hit, FALSE)',
        C('FOR', 'h, headings', [
            'LET(lv, AT_K(h, "level", 0))',
            C('IF', '&&(>=(lv, min_level), <=(lv, max_level))', [
                'SET(hit, TRUE)',
                'SET(items, CAT(items, indent_sp(-(lv, min_level)), '
                '"<li><a href=\\"#", AT_K(h, "id", ""), "\\">", '
                'ESCAPE_HTML(AT_K(h, "text", "")), "</a></li>"))',
            ], 'NULL'),
        ]),
        C('IF', 'hit', [TOC_TPL], '""'),
    ], '// 生成目录 HTML（对齐 Python build_toc_html）')

    # ── D. ADD_HEADING_IDS ──────────────────────────────────
    src += fn('ADD_HEADING_IDS', 'html_content, headings', [
        '// 对齐 Python add_heading_ids：map 按出现顺序（同名后者覆盖值、键位保留首次）；',
        '// ⚠ wlwl 正则无反向引用（</\\1> → E0030）⇒ 手工扫描：',
        '//   对每个 "<h"+1..6 起手的开标签，INDEX_OF 找**同级**闭合标签；',
        '//   闭合须自 end+1 起（Python 的 .+? 至少吃 1 字符）、content 可含换行；',
        '//   失败则前进 1 字符重试、成功则从闭合尾继续 —— 与 Python',
        '//   re.sub(r"<(h[1-6])([^>]*)>(.+?)</\\1>", DOTALL) 的左最早语义逐位对齐。',
        'LET MUT(map, DICT())',
        C('FOR', 'h, headings', [
            'SET(map, INDEX_SET(map, AT_K(h, "text", ""), AT_K(h, "id", "")))',
        ]),
        FUN_DEF('repl_heading', 'raw, tag, attrs, content', [
            '// 已有 id= 原样（含 data-id= 这种子串命中，与 Python "id=" in attrs 同口径）',
            'IF(CONTAINS_SUB(attrs, "id="), (RETURN(raw)), NULL)',
            'LET MUT(found, "")',
            C('FOR', 'k, map', [
                C('IF', '==(found, "")', [
                    C('IF', 'CONTAINS_SUB(content, k)', [
                        'SET(found, AT_K(map, k, ""))',
                    ], 'NULL'),
                ], 'NULL'),
            ]),
            C('IF', '==(found, "")', [
                'RETURN(raw)',
            ], 'NULL'),
            'CAT("<", tag, " id=\\"", found, "\\"", attrs, ">", content, "</", tag, ">")',
        ]),
        'LET MUT(out, "")',
        'LET MUT(pos, 0)',
        'LET MUT(q, 0)',
        'LET MUT(run, TRUE)',
        C('WHILE', 'run', [
            'LET(p, INDEX_OF(html_content, "<", q))',
            C('IF', '<(p, 0)', [
                'SET(run, FALSE)',
            ], [
                'LET(t1, SUB(html_content, p, 2))',
                'LET(t2, SUB(html_content, +(p, 2), 1))',
                C('IF', 'NOT(&&(==(t1, "<h"), is_lvl_digit(t2)))', [
                    'SET(q, +(p, 1))',
                ], [
                    'LET(e, INDEX_OF(html_content, ">", +(p, 3)))',
                    C('IF', '<(e, 0)', [
                        'SET(q, +(p, 1))',
                    ], [
                        '// tag = "h"+digit（Python 组 1 = h[1-6] 整体，闭合标签是 </h1>）',
                        'LET(tag, SUB(html_content, +(p, 1), 2))',
                        'LET(attrs, SUB(html_content, +(p, 3), -(e, +(p, 3))))',
                        'LET(end, +(e, 1))',
                        'LET(close, CAT("</", tag, ">"))',
                        'LET(c, INDEX_OF(html_content, close, +(end, 1)))',
                        C('IF', '<(c, 0)', [
                            'SET(q, +(p, 1))',
                        ], [
                            'SET(out, CAT(out, SUB(html_content, pos, -(p, pos))))',
                            'SET(out, CAT(out, repl_heading('
                            'SUB(html_content, p, -(+(c, LEN(close)), p)), '
                            'tag, attrs, SUB(html_content, end, -(c, end)))))',
                            'SET(pos, +(c, LEN(close)))',
                            'SET(q, pos)',
                        ]),
                    ]),
                ]),
            ]),
        ]),
        'CAT(out, SUB(html_content, pos, -(LEN(html_content), pos)))',
    ], '// 给已渲染 HTML 的标题加 id（对齐 Python add_heading_ids）')

    A('EXPORT(["SLUGIFY_HEADING", "EXTRACT_HEADINGS", "BUILD_TOC_HTML", "ADD_HEADING_IDS"]);')
    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
