"""生成 tp/test/test_md.wll —— 块级解析器的对照测试。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：与**真正的 mistune 3.2.1**（TinyPage 现在用的同一版本）逐字节对照。
基准由 `tp/test/gen_mistune_baseline.py` 生成到
`tp/test/fixtures/mistune_baseline.json`；本脚本把它读进来，生成 WLWL 断言。

用法：python gen_test_md.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_md.wll')


def wl_escape(s):
    """把 Python 字符串转成 WLWL 字符串字面量。"""
    out = s.replace('\\', '\\\\').replace('"', '\\"')
    out = out.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return '"' + out + '"'


def main():
    with open(os.path.join(FIXTURES, 'mistune_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)

    src = []
    A = src.append
    A('// tp/test/test_md.wll —— 块级解析器测试（对照 mistune 3.2.1）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_md.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真正的 mistune 3.2.1** 的输出逐字节对照。')
    A('// 基准：tp/test/fixtures/mistune_baseline.json')
    A('//   （由 tp/test/gen_mistune_baseline.py 用真 mistune 生成）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["CONTAINS_SUB"]);')
    A('IMPORT("./../lib/md.wll", ["RENDER_MD"]);')
    A('')

    for name in sorted(base):
        case = base[name]
        A(f'// {name}')
        A(f'LET(src_{name}, {wl_escape(case["src"])});')
        A(f'LET(want_{name}, {wl_escape(case["html"])});')
        A('')

    A('// ── 用例 ──────────────────────────────────────────────')
    for name in sorted(base):
        A(f'TEST("md/{name}", FUN(() ,')
        A(f'    (ASSERT_EQ(RENDER_MD(src_{name}), want_{name}));')
        A('    TRUE));')
    A('')

    A('// ── 反向守卫：代码块内不得解析行内语法 ──────────────────')
    A('// 围栏代码块里的 ** 与 ` 必须是**字面量**（对齐 mistune）')
    A('LET(src_guard_code, "```\\n**not bold** and `not code`\\n```\\n");')
    A('LET(want_guard_code, "<pre><code>**not bold** and `not code`\\n</code></pre>\\n");')
    A('TEST("guard/code_block_keeps_markdown_literal", FUN(() ,')
    A('    (ASSERT_EQ(RENDER_MD(src_guard_code), want_guard_code));')
    A('    TRUE));')
    A('')
    A('// 围栏里的 # 不是标题')
    A('LET(src_guard_hash, "```\\n# not a heading\\n```\\n");')
    A('LET(want_guard_hash, "<pre><code># not a heading\\n</code></pre>\\n");')
    A('TEST("guard/code_block_hash_is_not_heading", FUN(() ,')
    A('    (ASSERT_EQ(RENDER_MD(src_guard_hash), want_guard_hash));')
    A('    TRUE));')
    A('')
    A('// 未闭合围栏必须闭合而不是吞掉剩余全文')
    A('LET(src_guard_open, "```\\nunclosed\\n");')
    A('LET(want_guard_open, "<pre><code>unclosed\\n</code></pre>\\n");')
    A('TEST("guard/unclosed_fence_closes", FUN(() ,')
    A('    (ASSERT_EQ(RENDER_MD(src_guard_open), want_guard_open));')
    A('    TRUE));')
    A('')

    A('// ── 跑测试 ──────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_md: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_md: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_md: FAILED"); PANIC("md tests failed")), NULL);')
    A('PRINT("test_md: OK");')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines, {len(base)} baseline cases + 3 guards)')


if __name__ == '__main__':
    main()
