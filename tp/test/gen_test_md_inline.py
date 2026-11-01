"""生成 tp/test/test_md_inline.wll。

为什么用生成器而不是手写：WLWL 的括号诊断（E0011）只说「expected ')' got X」，
不告诉你缺了几层；手写嵌套 WLWL 时反复数括号极低效且易错。
生成器把括号配对交给 Python，产出**括号必然平衡**的源码。

改测试用例请改本文件的 CASES 列表，不要手改 .wll。
"""
import os

# 本脚本自身所在目录 —— 产物路径由它推导 ⇒ **不硬编码绝对路径**
# （CI 上仓库在别处，硬编码会写到错误位置）
HERE = os.path.dirname(os.path.abspath(__file__))

HEADER = '''// tp/test/test_md_inline.wll —— 行内解析器测试
//
// ⚠ 本文件由 tp/test/gen_test_md_inline.py 生成 —— 请勿手改。
//   改用例请改生成器里的 CASES。
//
// 验收：D:\\wlwl_v0.12.1\\wlwl.exe run tp\\test\\test_md_inline.wll
//       ⇒ 退出码 0，且全部用例 passed
//
// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关：
//   有任何失败 ⇒ PANIC ⇒ 非零退出。
IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "ASSERT_NEQ", "RUN_TESTS"]);
// ⚠ CONTAINS_SUB 在 std.str，**不是全局名** ⇒ 必须 IMPORT（否则 E0020）。
IMPORT("wlwl:std.str", ["CONTAINS_SUB"]);
IMPORT("./../lib/md_inline.wll", ["INLINE", "INLINE_WITH_MAP", "IS_SAFE_URL", "WIKILINK_TARGET"]);
'''

# (用例名, 测试体源码) —— 体是**语句序列**，生成器负责括号
CASES = [
    ('inline/code', [
        'ASSERT_EQ(INLINE("use `x` here"), "use <code>x</code> here")',
    ]),
    ('inline/bold', [
        'ASSERT_EQ(INLINE("a **b** c"), "a <strong>b</strong> c")',
    ]),
    ('inline/italic', [
        'ASSERT_EQ(INLINE("a *b* c"), "a <em>b</em> c")',
    ]),
    ('inline/bold_before_italic', [
        # ** 必须先于 * 处理 ⇒ "**x**" 不得变成 "<em><em>x</em></em>"
        'ASSERT_EQ(INLINE("**x**"), "<strong>x</strong>")',
    ]),
    ('inline/link', [
        # 逐字节对齐 mistune 3.2.1（无 rel 属性）
        'ASSERT_EQ(INLINE("[t](https://a.b/c)"), '
        '"<a href=\\"https://a.b/c\\">t</a>")',
    ]),
    ('inline/wikilink', [
        'ASSERT_EQ(INLINE("[[Page]]"), '
        '"<a class=\\"wikilink\\" href=\\"/article/page.html\\">Page</a>")',
    ]),
    ('inline/wikilink_alias', [
        'ASSERT_EQ(INLINE("[[Page|显示]]"), '
        '"<a class=\\"wikilink\\" href=\\"/article/page.html\\">显示</a>")',
    ]),
    # ── 反向守卫 1：未配对的定界符不得吞掉后续正文 ─────────────
    ('guard/unpaired_bold_keeps_rest', [
        'LET(out, INLINE("**未闭合 后面还有正文"))',
        'ASSERT(CONTAINS_SUB(out, "后面还有正文"))',
        'ASSERT(NOT(CONTAINS_SUB(out, "<strong>")))',
    ]),
    ('guard/unpaired_italic_keeps_rest', [
        'LET(out, INLINE("a *b"))',
        'ASSERT(CONTAINS_SUB(out, "a *b"))',
        'ASSERT(NOT(CONTAINS_SUB(out, "<em>")))',
    ]),
    # ── 反向守卫 2：源码里的 HTML 必须被转义 ───────────────────
    ('guard/script_is_escaped', [
        'LET(out, INLINE("<script>alert(1)</script>"))',
        'ASSERT(NOT(CONTAINS_SUB(out, "<script>")))',
        'ASSERT(CONTAINS_SUB(out, "&lt;script&gt;"))',
    ]),
    ('guard/quotes_are_escaped', [
        'LET(out, INLINE("a \\"b\\" c"))',
        'ASSERT(NOT(CONTAINS_SUB(out, "\\"b\\"")))',
        'ASSERT(CONTAINS_SUB(out, "&quot;"))',
    ]),
    # ── 反向守卫 3：危险协议不得生成 <a href> ─────────────────
    ('guard/javascript_protocol_blocked', [
        'LET(out, INLINE("[x](javascript:alert(1))"))',
        'ASSERT(NOT(CONTAINS_SUB(out, "<a ")))',
    ]),
    ('guard/data_protocol_blocked', [
        'LET(out, INLINE("[x](data:text/html,x)"))',
        'ASSERT(NOT(CONTAINS_SUB(out, "<a ")))',
    ]),
    ('guard/vbscript_protocol_blocked', [
        'LET(out, INLINE("[x](vbscript:msgbox)"))',
        'ASSERT(NOT(CONTAINS_SUB(out, "<a ")))',
    ]),
    # ── 协议白名单判定 ────────────────────────────────────────
    ('url/safe_protocols', [
        'ASSERT(IS_SAFE_URL("https://example.com"))',
        'ASSERT(IS_SAFE_URL("http://example.com"))',
        'ASSERT(IS_SAFE_URL("/relative/path"))',
        'ASSERT(IS_SAFE_URL("mailto:a@b.c"))',
        'ASSERT(IS_SAFE_URL("//protocol-relative"))',
    ]),
    ('url/dangerous_protocols', [
        'ASSERT(NOT(IS_SAFE_URL("javascript:alert(1)")))',
        'ASSERT(NOT(IS_SAFE_URL("JavaScript:alert(1)")))',
        'ASSERT(NOT(IS_SAFE_URL("data:text/html,x")))',
        'ASSERT(NOT(IS_SAFE_URL("file:///etc/passwd")))',
        'ASSERT(NOT(IS_SAFE_URL("vbscript:x")))',
        'ASSERT(NOT(IS_SAFE_URL("")))',
        'ASSERT(NOT(IS_SAFE_URL(NULL)))',
    ]),
    ('url/unknown_protocol_rejected', [
        # 未知协议默认拒绝（对齐 Python 的 SAFE_URL_PROTOCOLS 白名单）
        'ASSERT(NOT(IS_SAFE_URL("weirdscheme://x")))',
    ]),
    # ── wikilink 目标解析 ────────────────────────────────────
    ('wiki/article_map', [
        'LET(m, ["另一篇": "/article/other.html"])',
        'ASSERT_EQ(WIKILINK_TARGET("另一篇", m), "/article/other.html")',
        # 未命中 ⇒ 回退 /article/{slug}.html；slug 保留 CJK（对齐 security.py::slugify）
        'ASSERT_EQ(WIKILINK_TARGET("没找到", m), "/article/没找到.html")',
    ]),
    # ── 行内代码优先级：代码里的 * 不被解释 ────────────────────
    ('inline/code_has_priority', [
        'LET(out, INLINE("`*not italic*`"))',
        'ASSERT(CONTAINS_SUB(out, "<code>*not italic*</code>"))',
        'ASSERT(NOT(CONTAINS_SUB(out, "<em>")))',
    ]),
    # ── 混合场景 ──────────────────────────────────────────────
    ('inline/mixed', [
        'LET(out, INLINE("**粗** 与 *斜* 与 `码` 与 [链](https://x.y)"))',
        'ASSERT(CONTAINS_SUB(out, "<strong>粗</strong>"))',
        'ASSERT(CONTAINS_SUB(out, "<em>斜</em>"))',
        'ASSERT(CONTAINS_SUB(out, "<code>码</code>"))',
        'ASSERT(CONTAINS_SUB(out, "href=\\"https://x.y\\""))',
    ]),
    # ── 幂等：同一输入两次得到同一输出 ────────────────────────
    ('inline/deterministic', [
        'LET(a, INLINE("**a** *b* `c` [d](https://e.f) [[g]]"))',
        'LET(b, INLINE("**a** *b* `c` [d](https://e.f) [[g]]"))',
        'ASSERT_EQ(a, b)',
    ]),
]

FOOTER = '''
LET(records, RUN_TESTS());
PRINT("test_md_inline: ", LEN(records), " test(s) run");

LET MUT(failed, 0);
FOR(rec, records,
    (IF(AT_K(rec, "passed", FALSE),
        PRINT("  PASS ", AT_K(rec, "name", "?")),
        (SET(failed, +(failed, 1));
         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));

PRINT("test_md_inline: failed=", failed);
IF(>(failed, 0), (PRINT_ERR("test_md_inline: FAILED"); PANIC("md_inline tests failed")), NULL);
PRINT("test_md_inline: OK");
'''


def main():
    out = [HEADER]
    for idx, (name, body) in enumerate(CASES):
        out.append(f'// {name}')
        out.append(f'LET(body_{idx}, FUN(() ,')
        out.append('    (' + '; '.join(body) + ');')
        out.append('    TRUE));')
        out.append('')
    # 注册
    out.append('// ── 注册并运行 ────────────────────────────────────────────')
    for idx, (name, _) in enumerate(CASES):
        out.append(f'TEST("{name}", body_{idx});')
    out.append(FOOTER)

    src = '\n'.join(out)
    path = os.path.join(HERE, 'test_md_inline.wll')
    open(path, 'w', encoding='utf-8', newline='\n').write(src)
    print(f'wrote {path} ({len(src)} chars, {len(CASES)} cases)')


if __name__ == '__main__':
    main()
