"""生成 tp/test/test_footnotes.wll —— 脚注模块的对照测试。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：与**真 Python** `tinypage.parsers.footnotes` 逐字节对照。
基准由 `tp/test/gen_footnotes_baseline.py` 生成到
`tp/test/fixtures/footnotes_baseline.json`（直接 import 真实现）。
⚠ Python parse_footnotes 用 set 收集 key ⇒ 顺序跨进程不确定；基准序列化前
已按**定义出现顺序**重排，与 WLWL 实现的确定性插入序一致 —— 两边因此可
逐字节对照（详见基准生成器注释）。

用法：python gen_test_footnotes.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_footnotes.wll')


def wl_escape(s):
    """把 Python 字符串转成 WLWL 字符串字面量。"""
    out = s.replace('\\', '\\\\').replace('"', '\\"')
    out = out.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return '"' + out + '"'


def emit_body(A, idx, name, body, label):
    """发出 LET(body_idx, FUN(...)); + TEST(...) 两段（照 gen_test_md_inline 范式）。"""
    A(f'// {label}')
    A(f'LET(body_{idx}, FUN(() ,')
    A('    (' + '; '.join(body) + ');')
    A('    TRUE));')
    A(f'TEST("{name}", body_{idx});')
    A('')


def main():
    with open(os.path.join(FIXTURES, 'footnotes_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)

    src = []
    A = src.append
    A('// tp/test/test_footnotes.wll —— 脚注模块测试（对照真 Python footnotes.py）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_footnotes.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** tinypage.parsers.footnotes 逐字节对照。')
    A('// 基准：tp/test/fixtures/footnotes_baseline.json')
    A('//   （由 tp/test/gen_footnotes_baseline.py 用真 Python 生成；')
    A('//    footnotes 顺序已按**定义出现顺序**重排 —— Python set 顺序跨进程不确定，')
    A('//    WLWL 实现取确定性插入序，两边因此可逐字节对照。）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("./../lib/footnotes.wll", ["PARSE_FOOTNOTES", "RENDER_FOOTNOTE_REFS", '
      '"BUILD_FOOTNOTES_HTML", "PROCESS_FOOTNOTES"]);')
    A('')

    names = sorted(base)
    for name in names:
        case = base[name]
        A(f'// {name}: {case["src"]!r}')
        A(f'LET(src_{name}, {wl_escape(case["src"])});')
        A(f'LET(want_cleaned_{name}, {wl_escape(case["cleaned"])});')
        A(f'LET(want_refs_{name}, {wl_escape(case["refs"])});')
        A(f'LET(want_raw_{name}, {wl_escape(case["render_raw"])});')
        A(f'LET(want_html_{name}, {wl_escape(case["html"])});')
        A('')

    # ── 用例 ────────────────────────────────────────────────
    idx = 0
    A('// ── 用例（对照真 Python 基准） ─────────────────────────')
    for name in names:
        case = base[name]
        body = [
            f'LET(p, PARSE_FOOTNOTES(src_{name}))',
            f'ASSERT_EQ(p[0], want_cleaned_{name})',
            f'ASSERT_EQ(LEN(p[1]), {len(case["footnotes"])})',
        ]
        for i, fnote in enumerate(case['footnotes']):
            body.append(
                f'ASSERT_EQ(AT_K(p[1][{i}], "key", "?"), {wl_escape(fnote["key"])})')
            body.append(
                f'ASSERT_EQ(AT_K(p[1][{i}], "text", "?"), {wl_escape(fnote["text"])})')
        body += [
            # 直接 render（未先 parse）：定义形态 [^n]: 必须被跳过（无前瞻等价）
            f'ASSERT_EQ(RENDER_FOOTNOTE_REFS(src_{name}), want_raw_{name})',
            f'LET(pr, PROCESS_FOOTNOTES(src_{name}))',
            f'ASSERT_EQ(pr[0], want_refs_{name})',
            f'ASSERT_EQ(pr[1], want_html_{name})',
        ]
        emit_body(A, idx, f'fn/{name}', body, name)
        idx += 1

    # ── 反向守卫 ────────────────────────────────────────────
    A('// ── 反向守卫 ──────────────────────────────────────────')

    # G1：定义含换行 ⇒ 只取第一行，第二行**保留在正文里**
    #     （DEF 的 $ 是行尾、(.+) 不跨行 —— 换行不属于匹配）
    body = [
        'LET(p, PARSE_FOOTNOTES(src_guard_newline_def))',
        'ASSERT_EQ(p[0], want_cleaned_guard_newline_def)',
        'ASSERT_EQ(LEN(p[1]), 1)',
        'ASSERT_EQ(AT_K(p[1][0], "key", "?"), "x")',
        'ASSERT_EQ(AT_K(p[1][0], "text", "?"), "first line")',
    ]
    emit_body(A, idx, 'guard/def_newline_takes_first_line_only', body,
              'G1 定义含换行 ⇒ 只取第一行，第二行保留在正文')
    idx += 1

    # G2：重复定义 ⇒ 值取**第一个**，但**两个**定义行都被删除
    #     （RE_REPLACE 删全部匹配，defs 先出现者赢）
    body = [
        'LET(p, PARSE_FOOTNOTES(src_guard_dup_def))',
        'ASSERT_EQ(p[0], want_cleaned_guard_dup_def)',
        'ASSERT_EQ(LEN(p[1]), 1)',
        'ASSERT_EQ(AT_K(p[1][0], "key", "?"), "d")',
        'ASSERT_EQ(AT_K(p[1][0], "text", "?"), "first")',
    ]
    emit_body(A, idx, 'guard/dup_def_value_first_all_lines_removed', body,
              'G2 重复定义 ⇒ 值取第一个，但两个定义行都被删除')
    idx += 1

    # G3：DEF 无行首锚定 ⇒ 行中间的定义也必须被识别并删除
    body = [
        'LET(p, PARSE_FOOTNOTES(src_guard_midline_def))',
        'ASSERT_EQ(p[0], want_cleaned_guard_midline_def)',
        'ASSERT_EQ(LEN(p[1]), 1)',
        'ASSERT_EQ(AT_K(p[1][0], "key", "?"), "z")',
        'ASSERT_EQ(AT_K(p[1][0], "text", "?"), "value")',
    ]
    emit_body(A, idx, 'guard/midline_def_recognized', body,
              'G3 行中间的定义（无行首锚定）也必须被识别')
    idx += 1

    # G4：空定义 `[^e]:`（冒号后无内容）⇒ DEF 匹配不到 ⇒ 也不得转成 <sup>
    #     （对齐 Python REF 的 (?!:)；RENDER 直接调用同样跳过）
    body = [
        'LET(pr, PROCESS_FOOTNOTES(src_guard_empty_def_eol))',
        'ASSERT_EQ(pr[0], src_guard_empty_def_eol)',
        'ASSERT_EQ(pr[1], "")',
        'ASSERT_EQ(RENDER_FOOTNOTE_REFS(src_guard_empty_def_eol), src_guard_empty_def_eol)',
    ]
    emit_body(A, idx, 'guard/empty_def_not_superscript', body,
              'G4 空定义 [^e]: 不得被转成 <sup>（对齐 (?!:)）')
    idx += 1

    # G5：无脚注 ⇒ BUILD_FOOTNOTES_HTML 返回 ""（不是空骨架 section）
    body = [
        'ASSERT_EQ(BUILD_FOOTNOTES_HTML([]), "")',
        'ASSERT_EQ(PROCESS_FOOTNOTES(src_no_footnotes)[1], "")',
    ]
    emit_body(A, idx, 'guard/no_footnotes_html_empty', body,
              'G5 无脚注 ⇒ BUILD_FOOTNOTES_HTML 返回 ""')
    idx += 1

    # G6：未先 parse 直接 render ⇒ [^n]: 定义形态跳过、[^n] 引用形态替换
    #     （这正是 (?!:) 的等价语义 —— process_footnotes 正常路径上定义已删）
    body = [
        'ASSERT_EQ(RENDER_FOOTNOTE_REFS(src_direct_render_skip_defs), '
        'want_raw_direct_render_skip_defs)',
        'LET(pr, PROCESS_FOOTNOTES(src_direct_render_skip_defs))',
        'ASSERT_EQ(pr[0], want_refs_direct_render_skip_defs)',
    ]
    emit_body(A, idx, 'guard/direct_render_skips_def_colon', body,
              'G6 直接 render：[^a]: 跳过、[^b] 替换（无前瞻等价）')
    idx += 1

    # ── 跑测试 ──────────────────────────────────────────────
    A('// ── 跑测试 ──────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_footnotes: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_footnotes: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_footnotes: FAILED"); '
      'PANIC("footnotes tests failed")), NULL);')
    A('PRINT("test_footnotes: OK");')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines, '
          f'{len(names)} baseline cases + 6 guards)')


if __name__ == '__main__':
    main()
