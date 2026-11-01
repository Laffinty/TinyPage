"""生成 tp/lib/md_inline.wll。

⚠ 本文件是 `tp/test/gen_md_inline.py` 的**旧版内嵌渲染器**的迁移目标：
渲染器已抽到 `wllgen.py`，本文件改为 import 它。
迁移的验收标准：**生成的 md_inline.wll 逐字节不变**（CI 的 no-drift 步骤会验证）。

用法：python gen_md_inline.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'md_inline.wll')


def main():
    src = []
    A = src.append
    A('// tp/lib/md_inline.wll —— Markdown 行内解析')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_md_inline.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器。理由：WLWL 的括号诊断只说「expected \')\' got X」，')
    A('//   不告诉你缺了几层；生成器保证括号必然平衡。')
    A('//')
    A('// 职责：把一段行内 Markdown 转成 HTML。')
    A('//   `code`                   → <code>')
    A('//   **bold**                 → <strong>')
    A('//   *italic*                 → <em>')
    A('//   [text](url)              → <a>（带协议白名单）')
    A('//   [[Wiki]] / [[Wiki|显示]] → <a class="wikilink">')
    A('//')
    A('// ⚠ 为什么手写定界符扫描：WLWL 的 `std.regex` **拒绝反向引用**（E0030），')
    A('//   因为它必须保持线性时间 ⇒ `(\\*\\*|__)(.+?)\\1` 这种「配对定界符」的模式')
    A('//   在 WLWL 里不存在。本模块用手工扫描实现配对。')
    A('//')
    A('// ⚠ 转义顺序：**先 HTML 转义，再做行内替换**。与 TinyPage 的 mistune')
    A('//   `escape=True` 语义一致（源码里的原始 HTML 一律转义，不透传）。')
    A('//')
    A('// ⚠ 链接协议白名单：与 tinypage/security.py::validate_url_protocol 同语义。')
    A('//')
    A('// ⚠ 四条实测得来的 WLWL 陷阱（本模块已按它们写）：')
    A('//   ① `CAT` 把每个 part 用 `STR` 渲染 ⇒ 数组拼接必须用 `+(a, b)`，')
    A('//      不能用 `CAT`（`CAT([], ["x"])` 得到字符串 `"[x]"`）。')
    A('//   ② `WHILE` 的值是 NULL ⇒ 想要循环后的值，表达式必须写在 WHILE **外面**。')
    A('//   ③ 顶层语句必须以 `;` 结尾，缺了报 E0013 且位置指向**下一条**语句。')
    A('//   ④ 没有中缀算术：`a + b` 是硬 E0011，必须写 `+(a, b)`。')
    A('//')
    A('// 导出：')
    A('//   INLINE(text)                       -> STRING   渲染行内 Markdown')
    A('//   INLINE_WITH_MAP(text, article_map) -> STRING  同上，但解析 wikilink 目标')
    A('//   IS_SAFE_URL(url)                   -> BOOLEAN  协议白名单判定')
    A('//   WIKILINK_TARGET(link_text, map)    -> STRING  wikilink 的目标 URL')
    A('')
    A('IMPORT("wlwl:std.sanitize", ["HTML_ESCAPE"]);')
    A('IMPORT("wlwl:std.str", ["INDEX_OF", "CAT"]);')
    A('IMPORT("wlwl:std.text", ["TO_LOWER"]);')
    A('')

    # ── 协议白名单 ─────────────────────────────────────────
    A('// ── 协议白名单（对齐 tinypage/security.py）────────────────────')
    A('LET(SAFE_PROTOCOLS, ["http", "https", "ftp", "ftps", "mailto", "tel", "sip", "sips",')
    A('                      "news", "nntp", "telnet", "irc", "ircs", "gopher", "wais"]);')
    A('')
    A('LET(DANGEROUS_PROTOCOLS, ["javascript", "data", "vbscript", "file", "about", "chrome",')
    A('                           "chrome-extension", "ms-help", "ms-windows-store", "ms-settings",')
    A('                           "jar", "rmi", "jndi", "ldap", "dns"]);')
    A('')

    src += fn('has_prefix', 's, prefix', [
        'LET(n, LEN(prefix))',
        'IF(<(LEN(s), n), FALSE, ==(SUB(s, 0, n), prefix))',
    ], '// 前缀匹配（区分大小写）')

    src += fn('in_list', 'items, needle', [
        'LET MUT(i, 0)',
        'LET MUT(found, FALSE)',
        C('WHILE', '<(i, LEN(items))', [
            C('IF', '==(items[i], needle)', [C('SET', 'found', 'TRUE')], 'NULL'),
            C('SET', 'i', '+(i, 1)'),
        ]),
        'found',
    ], '// 线性查找')

    src += fn('proto_of', 'u', [
        'LET(colon, INDEX_OF(u, ":"))',
        'IF(<(colon, 0), "", SUB(u, 0, colon))',
    ], '// 协议前缀（含冒号），无冒号时返回 ""')

    src += fn('IS_SAFE_URL', 'url', [
        'IF(==(TYPE(url), "NULL"), (RETURN(FALSE)), NULL)',
        'LET(u, TO_LOWER(TRIM(url)))',
        'IF(==(u, ""), (RETURN(FALSE)), NULL)',
        'IF(has_prefix(u, "//"), (RETURN(TRUE)), NULL)',
        'LET(p, proto_of(u))',
        'IF(==(p, ""), (RETURN(TRUE)), NULL)',
        'IF(in_list(DANGEROUS_PROTOCOLS, p), (RETURN(FALSE)), NULL)',
        'in_list(SAFE_PROTOCOLS, p)',
    ], '// 协议白名单判定（对齐 validate_url_protocol）')

    # ── 字符串工具 ─────────────────────────────────────────
    A('// ── 字符串切片小工具 ────────────────────────────────────────')
    src += fn('replace_span', 's, a, b, replacement', [
        'LET(prefix, SUB(s, 0, a))',
        'LET(suffix, SUB(s, b, -(LEN(s), b)))',
        'CAT(prefix, replacement, suffix)',
    ], '// 把 s 的 [a, b) 区间替换成 replacement')

    src += fn('find_pair', 's, delim', [
        'LET(dlen, LEN(delim))',
        'LET(a, INDEX_OF(s, delim))',
        'IF(<(a, 0), (RETURN([-1, -1])), NULL)',
        'LET(b, INDEX_OF(s, delim, +(a, dlen)))',
        'IF(<(b, 0), (RETURN([-1, -1])), NULL)',
        '[a, b]',
    ], '// 找第一对配对定界符：[start, end]；找不到返回 [-1, -1]')

    src += fn('replace_pairs', 's, delim, open_tag, close_tag', [
        'LET MUT(out, s)',
        'LET MUT(guard, 0)',
        C('WHILE', '<(guard, 1000)', [
            'LET(pair, find_pair(out, delim))',
            'LET(a, pair[0])',
            'LET(b, pair[1])',
            'LET(dlen, LEN(delim))',
            'LET(inner, IF(<(a, 0), "", SUB(out, +(a, dlen), -(b, +(a, dlen)))))',
            C('IF', '==(inner, "")',
              [C('SET', 'guard', '1000')],
              [C('LET', 'rep, CAT(open_tag, inner, close_tag)'),
               C('SET', 'out, replace_span(out, a, +(b, dlen), rep)'),
               C('SET', 'guard', '+(guard, 1)')]),
        ]),
        'out',
    ], '// 替换所有配对的定界符；未配对的原样保留')

    # ── 行内代码 ───────────────────────────────────────────
    A('// ── 行内代码（优先级最高）────────────────────────────────────')
    A('// ⚠ 占位符用 `\\0`（NUL）—— WLWL 的字符串转义白名单只有')
    A('//   `\\" \\\\ / \\n \\r \\t \\b \\f \\0 \\$`，**没有** `\\u`。')
    A('LET(CODE_PH, "\\0CODE");')
    A('')

    src += fn('extract_code', 's', [
        'LET MUT(out, s)',
        'LET MUT(codes, [])',
        'LET MUT(pos, 0)',
        'LET MUT(guard, 0)',
        C('WHILE', '<(guard, 10000)', [
            'LET(tick, INDEX_OF(out, "`", pos))',
            'LET(tick2, IF(<(tick, 0), -1, INDEX_OF(out, "`", +(tick, 1))))',
            C('IF', '<(tick2, 0)',
              [C('SET', 'guard', '10000')],
              [C('LET', 'content, SUB(out, +(tick, 1), -(tick2, +(tick, 1)))'),
               C('SET', 'codes', '+(codes, [content])'),
               C('SET', 'out', 'CAT(SUB(out, 0, tick), CODE_PH, SUB(out, +(tick2, 1), -(LEN(out), +(tick2, 1))))'),
               C('SET', 'pos', '+(tick, LEN(CODE_PH))'),
               C('SET', 'guard', '+(guard, 1)')]),
        ]),
        'LET(pair, [out, codes])',
        'pair',
    ], '// 抽出 `code` 段落，返回 [剩余文本, 代码内容数组]')

    src += fn('restore_code', 's, codes', [
        'LET MUT(out, s)',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, LEN(codes))', [
            'LET(at, INDEX_OF(out, CODE_PH))',
            C('IF', '>=(at, 0)',
              [C('LET', 'rep', 'CAT("<code>", codes[i], "</code>")'),
               C('SET', 'out', 'replace_span(out, at, +(at, LEN(CODE_PH)), rep)')],
              'NULL'),
            C('SET', 'i', '+(i, 1)'),
        ]),
        'out',
    ], '// 把占位符还原成 <code>...</code>（占位符与 extract_code 插入的是同一个 CODE_PH）')

    # ── wikilink ───────────────────────────────────────────
    A('// ── wikilink ────────────────────────────────────────────────')
    src += fn('collapse_dashes', 's', [
        'LET MUT(out, "")',
        'LET MUT(prev_dash, FALSE)',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, LEN(s))', [
            'LET(c, SUB(s, i, 1))',
            C('IF', '==(c, "-")',
              [C('IF', 'prev_dash',
                 'NULL',
                 [C('SET', 'out', 'CAT(out, c)'),
                  C('SET', 'prev_dash', 'TRUE')])],
              [C('SET', 'out', 'CAT(out, c)'),
               C('SET', 'prev_dash', 'FALSE')]),
            C('SET', 'i', '+(i, 1)'),
        ]),
        'out',
    ], '// 把连续多个 "-" 折叠成一个（对齐 re.sub(r"-{2,}", "-", s)）')

    src += fn('trim_dashes', 's', [
        'LET MUT(start, 0)',
        'LET MUT(end, LEN(s))',
        C('WHILE', '&&(<(start, end), ==(SUB(s, start, 1), "-"))',
          [C('SET', 'start', '+(start, 1)')]),
        C('WHILE', '&&(<(start, end), ==(SUB(s, -(end, 1), 1), "-"))',
          [C('SET', 'end', '-(end, 1)')]),
        'IF(<=(start, end), SUB(s, start, -(end, start)), "")',
    ], '// 去掉首尾的 "-"（对齐 .strip("-")）')

    src += fn('slug_of', 'title', [
        'LET(low, TO_LOWER(title))',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, LEN(low))', [
            'LET(c, SUB(low, i, 1))',
            'LET(is_ascii, ||(&&(>=(c, "a"), <=(c, "z")), &&(>=(c, "0"), <=(c, "9"))))',
            'LET(is_cjk, &&(>=(c, "一"), <=(c, "龥")))',
            'LET(keep, ||(||(is_ascii, is_cjk), ==(c, "_")))',
            C('IF', 'keep',
              [C('SET', 'out', 'CAT(out, c)')],
              [C('SET', 'out', 'CAT(out, "-")')]),
            C('SET', 'i', '+(i, 1)'),
        ]),
        'LET(collapsed, collapse_dashes(out))',
        'LET(trimmed, trim_dashes(collapsed))',
        'IF(==(trimmed, ""), "untitled", trimmed)',
    ], '// 标题 → URL slug（对齐 security.py::slugify：保留 CJK，非法字符换 -，折叠连续 -，去首尾 -）')

    src += fn('WIKILINK_TARGET', 'link_text, article_map', [
        C('IF', '==(TYPE(article_map), "NULL")',
          '(RETURN(CAT("/article/", slug_of(link_text), ".html")))',
          'NULL'),
        'LET(hit, AT_K(article_map, TO_LOWER(link_text), NULL))',
        C('IF', '==(TYPE(hit), "NULL")',
          '(RETURN(CAT("/article/", slug_of(link_text), ".html")))',
          'hit'),
    ], '// wikilink 目标：命中 article_map 用映射值，否则回退 /article/{slug}.html')

    src += fn('replace_wikilinks', 's, article_map', [
        'LET MUT(out, s)',
        'LET MUT(guard, 0)',
        C('WHILE', '<(guard, 1000)', [
            'LET(open, INDEX_OF(out, "[["))',
            'LET(close, IF(<(open, 0), -1, INDEX_OF(out, "]]", +(open, 2))))',
            'LET(inner, IF(<(close, 0), "", SUB(out, +(open, 2), -(close, +(open, 2)))))',
            'LET(bar, IF(<(close, 0), -1, INDEX_OF(inner, "|")))',
            'LET(title, IF(<(bar, 0), inner, SUB(inner, 0, bar)))',
            'LET(label, IF(<(bar, 0), title, SUB(inner, +(bar, 1), -(LEN(inner), +(bar, 1)))))',
            'LET(target, WIKILINK_TARGET(title, article_map))',
            'LET(rep, CAT("<a class=\\"wikilink\\" href=\\"", target, "\\">", label, "</a>"))',
            C('IF', '<(close, 0)',
              [C('SET', 'guard', '1000')],
              [C('SET', 'out', 'replace_span(out, open, +(close, 2), rep)'),
               C('SET', 'guard', '+(guard, 1)')]),
        ]),
        'out',
    ], '// 替换 [[标题]] / [[标题|显示]]')

    # ── Markdown 链接 ──────────────────────────────────────
    A('// ── Markdown 链接 [text](url) ───────────────────────────────')
    A('// 协议不合法的 URL **不生成 <a>**，但保留原文本（对齐 Python 降级路径）。')
    src += fn('replace_links', 's', [
        'LET MUT(out, s)',
        'LET MUT(guard, 0)',
        C('WHILE', '<(guard, 1000)', [
            'LET(open, INDEX_OF(out, "["))',
            'LET(close, IF(<(open, 0), -1, INDEX_OF(out, "]", +(open, 1))))',
            'LET(after, IF(<(close, 0), "", SUB(out, +(close, 1), 1)))',
            'LET(paren, IF(==(after, "("), INDEX_OF(out, ")", +(close, 2)), -1))',
            'LET(text, SUB(out, +(open, 1), -(close, +(open, 1))))',
            'LET(url, SUB(out, +(close, 2), -(paren, +(close, 2))))',
            C('LET', 'rep', [
                C('IF', 'IS_SAFE_URL(url)',
                  # ⚠ 逐字节对齐 mistune 3.2.1：不加 rel 属性
                  'CAT("<a href=\\"", url, "\\">", text, "</a>")',
                  'CAT("[", text, "](", url, ")")'),
            ]),
            C('IF', '<(paren, 0)',
              [C('SET', 'guard', '1000')],
              [C('SET', 'out', 'replace_span(out, open, +(paren, 1), rep)'),
               C('SET', 'guard', '+(guard, 1)')]),
        ]),
        'out',
    ], '// 替换 [text](url)')

    # ── 主入口 ─────────────────────────────────────────────
    A('// ── 主入口 ──────────────────────────────────────────────────')
    src += fn('INLINE_WITH_MAP', 'text, article_map', [
        'IF(==(TYPE(text), "NULL"), (RETURN("")), NULL)',
        'LET(ec, extract_code(text))',
        'LET(s0, ec[0])',
        'LET(codes, ec[1])',
        'LET(s1, HTML_ESCAPE(s0))',
        'LET(s2, replace_wikilinks(s1, article_map))',
        'LET(s3, replace_links(s2))',
        'LET(s4, replace_pairs(s3, "**", "<strong>", "</strong>"))',
        'LET(s5, replace_pairs(s4, "*", "<em>", "</em>"))',
        'restore_code(s5, codes)',
    ], '// 渲染行内 Markdown')

    A('LET(INLINE, FUN((text), INLINE_WITH_MAP(text, NULL)));')
    A('')
    A('EXPORT(["INLINE", "INLINE_WITH_MAP", "IS_SAFE_URL", "WIKILINK_TARGET"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
