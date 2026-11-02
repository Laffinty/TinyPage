"""生成 tp/test/test_list_page.wll —— 列表/分类/搜索页的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的页面输出**逐字节对照**。
基准：tp/test/fixtures/list_page_baseline.json
    （由 tp/test/gen_list_page_baseline.py 用真 Python 生成）。

**本生成器同时承担两条静态反向守卫**（在生成期执行 ⇒ CI 的「重跑生成器」这一步
就会红）—— 作用域只到**本卡的产物** `tp/lib/list_page.wll`，不扫整个 `tp/lib`：
本轮有 3 个并行 agent 在写别的 `tp/lib/*.wll`，扫全目录会踩别人的中间态。
  ① 不得出现内建 `SORT` / `SORT_BY`（二次复杂度，见 tp/README.md 坑 10）。
     匹配用**整词** `\\bSORT\\b` / `\\bSORT_BY\\b`：`SORT_BY_DATE` 这类名字里
     `_` 是词字符 ⇒ 不构成词边界 ⇒ 不会误报（论证见 gen_test_sort_util.py）。
     匹配前先剥 `//` 注释（注释里提到 SORT 不算违规）。
  ② 不得直接 import 内建 `HTML_ESCAPE` —— 必须复用 `esc.wll::ESCAPE_HTML`
     （内建与 Python 的 `html.escape` 在 `'` 上**逐字节不同**，见坑 19）。
     同理不得自己写 `html.escape` 的替代品：本文件只允许 `ESCAPE_HTML(` 出现。

**运行时反向守卫**（在 `wlwl run` 里执行）：
  · 标题里的 `<script>alert(1)</script>` **不得原样**出现在输出里；
  · 分类名里的 `<A&B<script>>` 同上（h1 / title / meta 三处）；
  · `$` 必须原样输出（WLWL 的字符串插值不得泄漏到产物里）；
  · `enable_search=False` 的搜索页里不得出现 `/search.js` 与「搜索」导航项。

⚠ `RUN_TESTS()` 的失败**不影响退出码**（规范明载）⇒ 本文件末尾自己把关：有失败
就 `PANIC`（退出码非 0）。

用法：python gen_test_list_page.py
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402
from paren_check import strip_comments  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, '..', 'lib')
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_list_page.wll')

TARGET = os.path.join(LIB, 'list_page.wll')

# 内建 SORT / SORT_BY 的整词匹配（论证见 gen_test_sort_util.py 的 docstring）
FORBIDDEN_SORT = re.compile(r'\bSORT\b|\bSORT_BY\b')

# 直接使用内建 HTML_ESCAPE（必须走 esc.wll::ESCAPE_HTML）
FORBIDDEN_ESCAPE = re.compile(r'\bHTML_ESCAPE\b')


def guard_static():
    """静态反向守卫：作用于 tp/lib/list_page.wll（本卡独占的产物）。"""
    with open(TARGET, encoding='utf-8') as f:
        raw = f.read()
    code, _ = strip_comments(raw)

    problems = []
    for i, line in enumerate(code.split('\n'), 1):
        if FORBIDDEN_SORT.search(line):
            problems.append('list_page.wll:%d: %s' % (i, line.strip()[:100]))
    if problems:
        raise SystemExit(
            'list_page 静态守卫失败：tp/lib/list_page.wll 出现内建 SORT / SORT_BY 引用\n  '
            + '\n  '.join(problems)
            + '\n  （本卡不排序；若将来要排序，必须用 sort_util.wll 的实现 —— '
              '内建 SORT 是二次复杂度）')

    problems = []
    for i, line in enumerate(code.split('\n'), 1):
        if FORBIDDEN_ESCAPE.search(line):
            problems.append('list_page.wll:%d: %s' % (i, line.strip()[:100]))
    if problems:
        raise SystemExit(
            'list_page 静态守卫失败：出现了内建 HTML_ESCAPE 的直接引用\n  '
            + '\n  '.join(problems)
            + '\n  （必须复用 esc.wll::ESCAPE_HTML：内建把 \' 出成 &#39;，'
              'Python 出 &#x27;，逐字节不同 —— tp/README.md 坑 19）')


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 白名单 `\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`；`$` **必须**转义
      （WLWL 字面量里 `${...}` / `$name` 是插值 —— 见 tp/README.md 坑 32）。
    """
    out = []
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\0':
            out.append('\\0')
        elif ch == '$':
            out.append('\\$')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def wl_value(v):
    """Python 值（str / bool / None / int / list / dict）→ WLWL 字面量表达式。

    ⚠ 字典**字面量** `["k": v]` 会触发 wllgen 的逗号表达式守卫 ⇒ 一律 INDEX_SET 逐层套。
    """
    if isinstance(v, str):
        return wl_string(v)
    if isinstance(v, bool):
        # ⚠ 必须在 int 之前判（Python 的 bool 是 int 的子类）
        return 'TRUE' if v else 'FALSE'
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return '[' + ', '.join(wl_value(x) for x in v) + ']'
    if isinstance(v, dict):
        expr = 'DICT()'
        for k in v:
            expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl_string(k), wl_value(v[k]))
        return expr
    raise TypeError('bad fixture value: %r' % (v,))


# 每个页面函数对应的 WLWL 名字
FN_NAME = {
    'LIST_PAGE': 'LIST_PAGE',
    'CATEGORY_PAGE': 'CATEGORY_PAGE',
    'SEARCH_PAGE': 'SEARCH_PAGE',
}


def main():
    guard_static()

    with open(os.path.join(FIXTURES, 'list_page_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']

    src = []
    A = src.append
    A('// tp/test/test_list_page.wll —— 列表/分类/搜索页的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_list_page.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的页面输出逐字节对照。')
    A('// 基准：tp/test/fixtures/list_page_baseline.json')
    A('//   （由 tp/test/gen_list_page_baseline.py 调真函数生成：')
    A('//     generate_list_page / generate_category_page / generate_search_page）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件末尾自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["CONTAINS_SUB"]);')
    A('IMPORT("./../lib/list_page.wll", '
      '["CATEGORY_PAGE", "LIST_PAGE", "SEARCH_PAGE"]);')
    A('')

    A('// ── 用例数据（期望值逐字节来自基准）─────────────────────────────')
    for case in cases:
        name = case['name']
        fn = FN_NAME[case['fn']]
        A('// %s —— %s' % (name, case['note'].replace('\n', ' ')))
        A('LET(o_%s, %s);' % (name, wl_value(case['opts'])))
        # ⚠ 先判 IS_ERR 再取值：这三个函数会把 RENDER_SKELETON 的 ERR 原样透出，
        #   而 `LET(x, <ERR>)` 绑定不算消费 ERR（坑 25）⇒ 用 IS_ERR 直接判。
        A('LET(iserr_%s, IS_ERR(%s(o_%s)));' % (name, fn, name))
        A('LET(out_%s, IF(iserr_%s, "", %s(o_%s)));' % (name, name, fn, name))
        A('LET(want_%s, %s);' % (name, wl_string(case['want'])))
        A('')

    A('// ── 逐字节对照 ────────────────────────────────────────────────')
    for case in cases:
        name = case['name']
        A('TEST("list_page/%s", FUN((),' % name)
        A('    (ASSERT_EQ(out_%s, want_%s));' % (name, name))
        A('    TRUE));')
    A('')

    A('// ── 运行时反向守卫 ────────────────────────────────────────────')
    A('// ① 标题里的 <script> 必须被 escape —— 不得原样出现')
    A('TEST("guard/title_script_escaped", FUN((),')
    A('    (ASSERT(!(CONTAINS_SUB(out_list_escape, '
      '"<script>alert(1)</script>")),')
    A('            "raw <script> leaked into list page");')
    A('     ASSERT(CONTAINS_SUB(out_list_escape, '
      '"&lt;script&gt;alert(1)&lt;/script&gt;"),')
    A('            "escaped title form missing"));')
    A('    TRUE));')
    A('// ② 分类名里的 <A&B<script>> 必须被 escape（h1 / <title> / meta 三处）')
    A('TEST("guard/category_escaped", FUN((),')
    A('    (ASSERT(!(CONTAINS_SUB(out_category_escape, "<A&B<script>>")),')
    A('            "raw category leaked into category page");')
    A('     ASSERT(CONTAINS_SUB(out_category_escape, '
      '"&lt;A&amp;B&lt;script&gt;&gt;"),')
    A('            "escaped category form missing"));')
    A('    TRUE));')
    A('// ③ `$` 必须原样输出（WLWL 字面量插值不得泄漏进产物）')
    A('TEST("guard/dollar_literal", FUN((),')
    A('    (ASSERT(CONTAINS_SUB(out_list_dollar, "Price \\$5 and \\${x}"),')
    A('            "dollar text mangled by string interpolation");')
    A('     ASSERT(CONTAINS_SUB(out_list_dollar, "cost \\$9"),')
    A('            "dollar in summary mangled"));')
    A('    TRUE));')
    A('// ④ 分页语义：第 2 页的 prev_url 必须指向 "/"（不是 /list/1.html）')
    A('TEST("guard/page2_prev_root", FUN((),')
    A('    (ASSERT(CONTAINS_SUB(out_list_page2_prev_root, '
      '"<a href=\\"/\\" class=\\"prev\\">"),')
    A('            "page 2 prev link must point at /");')
    A('     ASSERT(!(CONTAINS_SUB(out_list_page2_prev_root, "/list/1.html")),')
    A('            "page 2 must not link to /list/1.html"));')
    A('    TRUE));')
    A('// ⑤ enable_search=False：搜索页不得有 search.js，nav 里也不得有「搜索」')
    A('TEST("guard/search_disabled", FUN((),')
    A('    (ASSERT(!(CONTAINS_SUB(out_search_disabled, "/search.js")),')
    A('            "search script leaked while enable_search=False");')
    A('     ASSERT(!(CONTAINS_SUB(out_search_disabled, ">搜索</a>")),')
    A('            "search nav link leaked while enable_search=False"));')
    A('    TRUE));')
    A('// ⑥ enable_search=True：同一个位置必须有 search.js（与 ⑤ 成对）')
    A('TEST("guard/search_enabled", FUN((),')
    A('    (ASSERT(CONTAINS_SUB(out_search_default, "/search.js"),')
    A('            "search script missing while enable_search=True"));')
    A('    TRUE));')
    A('')

    A('// ── 跑测试 ────────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_list_page: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_list_page: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_list_page: FAILED"); '
      'PANIC("list_page tests failed")), NULL);')
    A('PRINT("test_list_page: OK");')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines, {len(cases)} baseline cases + 6 guards)')


if __name__ == '__main__':
    main()
