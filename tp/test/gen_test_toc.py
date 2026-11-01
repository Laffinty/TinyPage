"""生成 tp/test/test_toc.wll —— TOC 模块的对照测试。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：与**真 Python** `tinypage.parsers.toc` 逐字节对照。
基准由 `tp/test/gen_toc_baseline.py` 生成到 `tp/test/fixtures/toc_baseline.json`；
反向守卫的期望值在生成时用真 Python **复核**（手写错会在这里直接炸）。

用法：python gen_test_toc.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_toc.wll')
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.parsers.toc import (  # noqa: E402
    add_heading_ids,
    build_toc_html,
    extract_headings,
    slugify_heading,
)


def wl_escape(s):
    """把 Python 字符串转成 WLWL 字符串字面量。"""
    out = s.replace('\\', '\\\\').replace('"', '\\"')
    out = out.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return '"' + out + '"'


def wl_lit(v):
    """Python 值 → WLWL 字面量（str/int/list/dict）。"""
    if isinstance(v, str):
        return wl_escape(v)
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        if not v:
            return '[]'
        return '[' + ', '.join(wl_lit(x) for x in v) + ']'
    if isinstance(v, dict):
        return '[' + ', '.join(
            f'{wl_escape(k)}: {wl_lit(val)}' for k, val in v.items()) + ']'
    raise TypeError(f'cannot render {v!r}')


def main():
    with open(os.path.join(FIXTURES, 'toc_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)

    total = sum(len(base[k]) for k in ('slug', 'extract', 'toc', 'addids'))
    if total < 15:
        raise SystemExit(f'baseline too small: {total} cases (< 15)')

    # ── 反向守卫的期望值：先用真 Python 复核（防手写错） ──────
    dup_ids = [h.id for h in extract_headings('## Same\n## Same\n')]
    assert dup_ids == ['same', 'same-2'], dup_ids
    filtered = build_toc_html(extract_headings('# Only one\n# Only two\n'), 2, 3)
    assert filtered == '', repr(filtered)
    assert slugify_heading('!!!') == 'heading', slugify_heading('!!!')
    assert slugify_heading('### !!!') == 'heading', slugify_heading('### !!!')
    keep = '<h1 id="keep">Title</h1>\n'
    assert add_heading_ids(keep, extract_headings('# Title\n')) == keep
    assert extract_headings('#NoSpace') == [], extract_headings('#NoSpace')

    src = []
    A = src.append
    A('// tp/test/test_toc.wll —— TOC 模块测试（对照真 Python tinypage.parsers.toc）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_toc.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的输出逐字节对照。')
    A('// 基准：tp/test/fixtures/toc_baseline.json')
    A('//   （由 tp/test/gen_toc_baseline.py 用真 Python 生成）')
    A('// 反向守卫的期望值由 gen_test_toc.py 生成时用真 Python 复核。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT_EQ", "ASSERT_NEQ", "RUN_TESTS"]);')
    A('IMPORT("./../lib/toc.wll", ["SLUGIFY_HEADING", "EXTRACT_HEADINGS", '
      '"BUILD_TOC_HTML", "ADD_HEADING_IDS"]);')
    A('')

    # ── 数据 ────────────────────────────────────────────────
    for case in base['slug']:
        n = case['name']
        A(f'// slug/{n}: {case["src"]!r}')
        A(f'LET(src_slug_{n}, {wl_escape(case["src"])});')
        A(f'LET(want_slug_{n}, {wl_escape(case["want"])});')
        A('')
    for case in base['extract']:
        n = case['name']
        A(f'// extract/{n}: {case["md"]!r}')
        A(f'LET(md_ex_{n}, {wl_escape(case["md"])});')
        A(f'LET(want_ex_{n}, {wl_lit(case["want"])});')
        A('')
    for case in base['toc']:
        n = case['name']
        A(f'// toc/{n}: {case["md"]!r} min={case["min"]} max={case["max"]}')
        A(f'LET(md_toc_{n}, {wl_escape(case["md"])});')
        A(f'LET(want_toc_{n}, {wl_escape(case["want"])});')
        A('')
    for case in base['addids']:
        n = case['name']
        A(f'// addids/{n}: html={case["html"]!r} md={case["md"]!r}')
        A(f'LET(html_ad_{n}, {wl_escape(case["html"])});')
        A(f'LET(md_ad_{n}, {wl_escape(case["md"])});')
        A(f'LET(want_ad_{n}, {wl_escape(case["want"])});')
        A('')

    # ── 用例 ────────────────────────────────────────────────
    A('// ── 基准用例（真 Python 逐字节对照） ──────────────────')
    for case in base['slug']:
        n = case['name']
        A(f'TEST("toc/slug/{n}", FUN(() ,')
        A(f'    (ASSERT_EQ(SLUGIFY_HEADING(src_slug_{n}), want_slug_{n}));')
        A('    TRUE));')
    A('')
    for case in base['extract']:
        n = case['name']
        A(f'TEST("toc/extract/{n}", FUN(() ,')
        A(f'    (ASSERT_EQ(EXTRACT_HEADINGS(md_ex_{n}), want_ex_{n}));')
        A('    TRUE));')
    A('')
    for case in base['toc']:
        n = case['name']
        A(f'TEST("toc/toc/{n}", FUN(() ,')
        A(f'    (ASSERT_EQ(BUILD_TOC_HTML(EXTRACT_HEADINGS(md_toc_{n}), '
          f'{case["min"]}, {case["max"]}), want_toc_{n}));')
        A('    TRUE));')
    A('')
    for case in base['addids']:
        n = case['name']
        A(f'TEST("toc/addids/{n}", FUN(() ,')
        A(f'    (ASSERT_EQ(ADD_HEADING_IDS(html_ad_{n}, '
          f'EXTRACT_HEADINGS(md_ad_{n})), want_ad_{n}));')
        A('    TRUE));')
    A('')

    # ── 反向守卫（期望值已用真 Python 复核，见文件头） ────────
    A('// ── 反向守卫 ──────────────────────────────────────────')
    A('// 两个同名标题 ⇒ id 必须是 x 与 x-2，不得都是 x')
    A('LET(g_md_dup, "## Same\\n## Same\\n");')
    A('TEST("guard/dup_slug_x_then_x2", FUN(() ,')
    A('    (ASSERT_EQ(EXTRACT_HEADINGS(g_md_dup), '
      '[["level": 2, "text": "Same", "id": "same"], '
      '["level": 2, "text": "Same", "id": "same-2"]]));')
    A('    TRUE));')
    A('TEST("guard/dup_ids_differ", FUN(() ,')
    A('    (ASSERT_NEQ(AT_K(EXTRACT_HEADINGS(g_md_dup)[0], "id", ""), '
      'AT_K(EXTRACT_HEADINGS(g_md_dup)[1], "id", "")));')
    A('    TRUE));')
    A('')
    A('// 全部标题都被 min/max 过滤掉 ⇒ TOC 必须是 ""（不是空模板）')
    A('LET(g_md_h1, "# Only one\\n# Only two\\n");')
    A('TEST("guard/all_filtered_empty_toc", FUN(() ,')
    A('    (ASSERT_EQ(BUILD_TOC_HTML(EXTRACT_HEADINGS(g_md_h1), 2, 3), ""));')
    A('    TRUE));')
    A('')
    A('// SLUGIFY_HEADING 结果为空 ⇒ 得 "heading"')
    A('TEST("guard/slug_empty_fallback_heading", FUN(() ,')
    A('    (ASSERT_EQ(SLUGIFY_HEADING("!!!"), "heading"));')
    A('    TRUE));')
    A('TEST("guard/slug_hashes_punct_fallback", FUN(() ,')
    A('    (ASSERT_EQ(SLUGIFY_HEADING("### !!!"), "heading"));')
    A('    TRUE));')
    A('')
    A('// ADD_HEADING_IDS 对已有 id="..." 的标签不得重复添加')
    A('LET(g_html_keep, "<h1 id=\\"keep\\">Title</h1>\\n");')
    A('TEST("guard/existing_id_not_duplicated", FUN(() ,')
    A('    (ASSERT_EQ(ADD_HEADING_IDS(g_html_keep, '
      'EXTRACT_HEADINGS("# Title\\n")), g_html_keep));')
    A('    TRUE));')
    A('')
    A('// #NoSpace（# 后无空白）不得被当成标题')
    A('TEST("guard/hash_no_space_not_heading", FUN(() ,')
    A('    (ASSERT_EQ(EXTRACT_HEADINGS("#NoSpace"), []));')
    A('    TRUE));')
    A('')

    # ── 跑测试 ──────────────────────────────────────────────
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_toc: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_toc: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_toc: FAILED"); PANIC("toc tests failed")), NULL);')
    A('PRINT("test_toc: OK");')

    guards = 6
    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines, '
          f'{total} baseline cases + {guards} guards)')


if __name__ == '__main__':
    main()
