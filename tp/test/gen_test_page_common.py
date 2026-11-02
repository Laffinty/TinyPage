"""生成 tp/test/test_page_common.wll —— 页面公共上下文的逐字节对照测试。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的输出**逐字节对照**。
基准：tp/test/fixtures/page_common_baseline.json（由 gen_page_common_baseline.py 生成）。

**三组的断言形态**：
  · `json_ld`        → `ASSERT_EQ(JSON_LD(opts), want)`（want 是整段 HTML 字符串）
  · `nav_links`      → `ASSERT_EQ(NAV_LINKS(opts), want)`
  · `common_context` → 对 9 个**字符串字段**逐个 `ASSERT_EQ`（DICT 整体不可直接比）

用法：python gen_test_page_common.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_page_common.wll')

CTX_FIELDS = [
    'site_title', 'dark_mode_meta', 'dark_mode_script', 'pwa_meta',
    'pwa_manifest', 'vt_meta', 'search_script', 'nav', 'theme_toggle',
]


def wl_string(s):
    """Python 字符串 → WLWL 字面量（⚠ 字面美元符在 WLWL 里是插值，必须写 \\$）。"""
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
        elif ch == '$':
            out.append('\\$')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def wl_value(v):
    if isinstance(v, str):
        return wl_string(v)
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        s = repr(v)
        return s if ('.' in s or 'e' in s or 'E' in s) else s + '.0'
    if isinstance(v, dict):
        if not v:
            return 'DICT()'
        expr = 'DICT()'
        for k, x in v.items():
            expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl_string(k), wl_value(x))
        return expr
    if isinstance(v, list):
        return '[' + ', '.join(wl_value(x) for x in v) + ']'
    raise TypeError('bad fixture value: %r' % (v,))


def main():
    with open(os.path.join(FIXTURES, 'page_common_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']

    src = []
    A = src.append
    A('// tp/test/test_page_common.wll —— 页面公共上下文的逐字节对照测试')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_page_common.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的输出逐字节对照。')
    A('// 基准：tp/test/fixtures/page_common_baseline.json')
    A('//   （json_ld / nav_links / common_context 三组，全部直接 import 真 Python）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("./../lib/page_common.wll", ["COMMON_CONTEXT", "JSON_LD", "NAV_LINKS"]);')
    A('')

    # ── json_ld ─────────────────────────────────────────────────────
    for name in sorted(cases['json_ld']):
        e = cases['json_ld'][name]
        A('LET(want_%s, %s);' % (name, wl_value(e['want'])))
    A('')
    for name in sorted(cases['json_ld']):
        e = cases['json_ld'][name]
        if e.get('note'):
            A('// %s：%s' % (name, e['note']))
        A('TEST("json_ld/%s", FUN(() ,' % name)
        A('    (ASSERT_EQ(JSON_LD(%s), want_%s));' % (wl_value(e['input']), name))
        A('    TRUE));')
    A('')

    # ── nav_links ───────────────────────────────────────────────────
    for name in sorted(cases['nav_links']):
        e = cases['nav_links'][name]
        A('LET(want_%s, %s);' % (name, wl_value(e['want'])))
    A('')
    for name in sorted(cases['nav_links']):
        e = cases['nav_links'][name]
        if e.get('note'):
            A('// %s：%s' % (name, e['note']))
        A('TEST("nav_links/%s", FUN(() ,' % name)
        A('    (ASSERT_EQ(NAV_LINKS(%s), want_%s));' % (wl_value(e['input']), name))
        A('    TRUE));')
    A('')

    # ── common_context ──────────────────────────────────────────────
    for name in sorted(cases['common_context']):
        e = cases['common_context'][name]
        if e.get('note'):
            A('// %s：%s' % (name, e['note']))
        A('LET(ctx_%s, COMMON_CONTEXT(%s));' % (name, wl_value(e['input'])))
        for fld in CTX_FIELDS:
            A('LET(want_%s_%s, %s);' % (name, fld, wl_value(e['want'][fld])))
        for fld in CTX_FIELDS:
            A('TEST("common_context/%s/%s", FUN(() ,' % (name, fld))
            A('    (ASSERT_EQ(AT_K(ctx_%s, %s, "<missing>"), want_%s_%s));'
              % (name, wl_string(fld), name, fld))
            A('    TRUE));')
    A('')

    # ── 反向守卫 ────────────────────────────────────────────────────
    A('// ── 反向守卫 ──────────────────────────────────────────────────')
    A('// ① site_url 为空 ⇒ 不得输出 JSON-LD')
    A('TEST("guard/json_ld_absent_without_site_url", FUN(() ,')
    A('    (ASSERT_EQ(JSON_LD(INDEX_SET(DICT(), "title", "T")), ""));')
    A('    TRUE));')
    A('// ② 导航栏第一项必须是首页链接（顺序不得颠倒）')
    A('//    ⚠ `LET` 必须放在 TEST 之外 —— 放进 FUN 体里会让括号层级算错（实测 E0011）')
    A('LET(_nav_g_, NAV_LINKS(INDEX_SET(DICT(), "cfg", DICT())));')
    A('TEST("guard/nav_starts_with_home", FUN(() ,')
    A('    (ASSERT_EQ(SUB(_nav_g_, 0, 12), "<a href=\\"/\\">"));')
    A('    TRUE));')
    A('// ③ has_dark 为假 ⇒ theme_toggle 必须是空串（不得残留按钮）')
    A('LET(_ctx_g_, COMMON_CONTEXT(INDEX_SET(INDEX_SET(DICT(), "has_dark", FALSE),')
    A('    "config", DICT())));')
    A('TEST("guard/no_toggle_without_dark", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(_ctx_g_, "theme_toggle", "?"), ""));')
    A('    TRUE));')
    A('')

    # ── 跑测试 ──────────────────────────────────────────────────────
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_page_common: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_page_common: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_page_common: FAILED"); '
      'PANIC("page_common tests failed")), NULL);')
    A('PRINT("test_page_common: OK");')

    chars, lines = write(OUT, src)
    n = sum(len(v) for v in cases.values())
    print('wrote %s (%d chars, %d lines, %d baseline cases)'
          % (OUT, chars, lines, n))


if __name__ == '__main__':
    main()
