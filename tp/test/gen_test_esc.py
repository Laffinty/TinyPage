"""生成 tp/test/test_esc.wll —— HTML 转义的对照测试。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：与**真 Python** `html.escape(s, quote=True)` 逐字节对照。
基准由 `tp/test/gen_esc_baseline.py` 生成到 `tp/test/fixtures/esc_baseline.json`。

用法：python gen_test_esc.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_esc.wll')


def wl_escape(s):
    """把 Python 字符串转成 WLWL 字符串字面量。"""
    out = s.replace('\\', '\\\\').replace('"', '\\"')
    out = out.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return '"' + out + '"'


def main():
    with open(os.path.join(FIXTURES, 'esc_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)

    src = []
    A = src.append
    A('// tp/test/test_esc.wll —— HTML 转义测试（对照真 Python html.escape）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_esc.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** html.escape(s, quote=True) 逐字节对照。')
    A('// 基准：tp/test/fixtures/esc_baseline.json')
    A('//   （由 tp/test/gen_esc_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("./../lib/esc.wll", ["ESCAPE_HTML"]);')
    A('')

    for name in sorted(base):
        case = base[name]
        A(f'// {name}: {case["src"]!r}')
        A(f'LET(src_{name}, {wl_escape(case["src"])});')
        A(f'LET(want_{name}, {wl_escape(case["html"])});')
        A('')

    A('// ── 用例 ──────────────────────────────────────────────')
    for name in sorted(base):
        A(f'TEST("esc/{name}", FUN(() ,')
        A(f'    (ASSERT_EQ(ESCAPE_HTML(src_{name}), want_{name}));')
        A('    TRUE));')
    A('')

    A('// ── 反向守卫 ──────────────────────────────────────────')
    A('// 单引号必须是 &#x27; 而不是内建的 &#39;（与 Python 逐字节对齐）')
    A('TEST("guard/apostrophe_is_x27", FUN(() ,')
    A('    (ASSERT_EQ(ESCAPE_HTML("\'"), "&#x27;"));')
    A('    TRUE));')
    A('')
    A('// 字面 &#39; 不得被误替换成 &#x27;（& 已先转成 &amp; ⇒ 子串不成立）')
    A('TEST("guard/literal_entity_not_mangled", FUN(() ,')
    A('    (ASSERT_EQ(ESCAPE_HTML("&#39;"), "&amp;#39;"));')
    A('    TRUE));')
    A('')

    A('// ── 跑测试 ──────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_esc: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_esc: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_esc: FAILED"); PANIC("esc tests failed")), NULL);')
    A('PRINT("test_esc: OK");')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines, {len(base)} baseline cases + 2 guards)')


if __name__ == '__main__':
    main()
