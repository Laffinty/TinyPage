"""生成 tp/test/test_frontmatter.wll —— front-matter 的对照测试。

⚠ 输出的 .wll 由本生成器产出，不要手改。

**验收方式**：与**真 Python** 逐字节对照。
基准由 `tp/test/gen_frontmatter_baseline.py` 生成到 `tp/test/fixtures/frontmatter_baseline.json`：
  · meta_value / meta_header  → 直接 import 真函数 `meta_value` / `_meta_header`
  · parse_meta                → 逐字复刻的 `parse_meta_from_text`
                                （真 parse_meta 接收文件路径、会真开文件）

覆盖：≥15 条基准用例（A/B/C 全规则）+ 5 条反向守卫。

用法：python gen_test_frontmatter.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_frontmatter.wll')


def wl_escape(s):
    """把 Python 字符串转成 WLWL 字符串字面量。"""
    out = s.replace('\\', '\\\\').replace('"', '\\"')
    out = out.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return '"' + out + '"'


def wl_dict(d):
    """把 Python dict 转成 WLWL 字典字面量（空字典只有 DICT() 一种写法）。"""
    if not d:
        return 'DICT()'
    parts = ['%s: %s' % (wl_escape(k), wl_escape(d[k])) for k in sorted(d)]
    return '[' + ', '.join(parts) + ']'


def main():
    with open(os.path.join(FIXTURES, 'frontmatter_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    pm = base['parse_meta']
    mv = base['meta_value']
    mh = base['meta_header']

    src = []
    A = src.append
    A('// tp/test/test_frontmatter.wll —— front-matter 测试（对照真 Python）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_frontmatter.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的期望值逐字节对照。')
    A('// 基准：tp/test/fixtures/frontmatter_baseline.json')
    A('//   （gen_frontmatter_baseline.py：meta_value/_meta_header 调真函数；')
    A('//     parse_meta 用与 parse_meta 逐字相同的正则与循环逻辑复刻）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("./../lib/frontmatter.wll", ["PARSE_META", "META_VALUE", "META_HEADER"]);')
    A('')

    # ── 数据绑定 ──────────────────────────────────────────────
    A('// ── parse_meta 基准用例（复刻的 parse_meta_from_text） ──')
    for name in sorted(pm):
        case = pm[name]
        A(f'// {name}: {case["src"]!r}')
        A(f'LET(src_{name}, {wl_escape(case["src"])});')
        A(f'LET(want_{name}, {wl_dict(case["want"])});')
        A('')
    A('// ── meta_value 基准用例（真 meta_value） ────────────────')
    for name in sorted(mv):
        case = mv[name]
        if case['src_type'] == 'int':
            lit = str(case['src'])
        else:
            lit = wl_escape(case['src'])
        A(f'// {name}: {case["src"]!r}')
        A(f'LET(src_{name}, {lit});')
        A(f'LET(want_{name}, {wl_escape(case["want"])});')
        A('')
    A('// ── meta_header 基准用例（真 _meta_header） ─────────────')
    for name in sorted(mh):
        case = mh[name]
        A(f'// {name}: {case["args"]!r}')
        A(f'LET(want_{name}, {wl_escape(case["want"])});')
        A('')

    # ── 用例 ──────────────────────────────────────────────────
    A('// ── parse_meta 用例 ────────────────────────────────────')
    for name in sorted(pm):
        A(f'TEST("fm/parse_meta/{name}", FUN(() ,')
        A(f'    (ASSERT_EQ(PARSE_META(src_{name}), want_{name}));')
        A('    TRUE));')
    A('')
    A('// ── meta_value 用例 ────────────────────────────────────')
    for name in sorted(mv):
        A(f'TEST("fm/meta_value/{name}", FUN(() ,')
        A(f'    (ASSERT_EQ(META_VALUE(src_{name}), want_{name}));')
        A('    TRUE));')
    A('')
    A('// ── meta_header 用例 ───────────────────────────────────')
    for name in sorted(mh):
        args = mh[name]['args']
        call = 'META_HEADER(%s)' % ', '.join(wl_escape(a) for a in args)
        A(f'TEST("fm/meta_header/{name}", FUN(() ,')
        A(f'    (ASSERT_EQ({call}, want_{name}));')
        A('    TRUE));')
    A('')

    # ── 反向守卫 ──────────────────────────────────────────────
    A('// ── 反向守卫 ──────────────────────────────────────────')

    # 守卫①：第 8 行的键不得被读入（前 7 行规则）
    g1 = (
        '<!-- title: t -->\n'
        '<!-- date: d -->\n'
        '<!-- tags: a -->\n'
        '<!-- summary: s -->\n'
        '<!-- category: c -->\n'
        '<!-- status: draft -->\n'
        '<!-- markdown: m -->\n'
        '<!-- slug: toolate -->\n'
    )
    g1_want = {
        'title': 't', 'date': 'd', 'tags': 'a', 'summary': 's',
        'category': 'c', 'status': 'draft', 'markdown': 'm',
    }
    A(f'// 8 行输入：slug 在第 8 行 ⇒ 不得读入（前 7 行规则）')
    A(f'LET(src_g1, {wl_escape(g1)});')
    A(f'LET(want_g1, {wl_dict(g1_want)});')
    A('TEST("fm/guard/line8_not_read", FUN(() ,')
    A('    (ASSERT_EQ(PARSE_META(src_g1), want_g1));')
    A('    (ASSERT_EQ(HAS(PARSE_META(src_g1), "slug"), FALSE));')
    A('    TRUE));')
    A('')

    # 守卫②：白名单外的键不得出现在结果里
    g2 = '<!-- title: t -->\n<!-- bogus: x -->\n<!-- date: d -->\n'
    g2_want = {'title': 't', 'date': 'd', 'status': 'published'}
    A('// 白名单外的 bogus 键静默丢弃')
    A(f'LET(src_g2, {wl_escape(g2)});')
    A(f'LET(want_g2, {wl_dict(g2_want)});')
    A('TEST("fm/guard/non_whitelist_dropped", FUN(() ,')
    A('    (ASSERT_EQ(PARSE_META(src_g2), want_g2));')
    A('    (ASSERT_EQ(HAS(PARSE_META(src_g2), "bogus"), FALSE));')
    A('    TRUE));')
    A('')

    # 守卫③：连续换行压成一个空格（不是三个）
    A('// [\\r\\n]+ 是「一个或多个连续换行符」⇒ "a\\n\\n\\nb" → "a b"')
    A('TEST("fm/guard/newline_collapse", FUN(() ,')
    A('    (ASSERT_EQ(META_VALUE("a\\n\\n\\nb"), "a b"));')
    A('    TRUE));')
    A('')

    # 守卫④：单引号必须出 &#x27;（对齐 Python html.escape）
    A('// 单引号 → &#x27;（不是 WLWL 内建 HTML_ESCAPE 的 &#39;）')
    A('TEST("fm/guard/apostrophe_x27", FUN(() ,')
    A('    (ASSERT_EQ(META_VALUE("it\'s"), "it&#x27;s"));')
    A('    TRUE));')
    A('')

    # 守卫⑤：贪婪匹配 —— 值吃到**最后一个** --> 之前
    A('// (.*) 贪婪：title 的值吃到最后一个 --> 之前 ⇒ "a --> tail"')
    A('TEST("fm/guard/greedy_tail", FUN(() ,')
    A('    (ASSERT_EQ('
      'AT_K(PARSE_META("<!-- title: a --> tail -->\\n"), "title", "?"), '
      '"a --> tail"));')
    A('    TRUE));')
    A('')

    # ── 跑测试 ────────────────────────────────────────────────
    A('// ── 跑测试 ──────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_frontmatter: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_frontmatter: failed=", failed);')
    A('IF(>(failed, 0), '
      '(PRINT_ERR("test_frontmatter: FAILED"); PANIC("frontmatter tests failed")), NULL);')
    A('PRINT("test_frontmatter: OK");')

    chars, lines = write(OUT, src)
    n = len(pm) + len(mv) + len(mh)
    print(f'wrote {OUT} ({chars} chars, {lines} lines, '
          f'{n} baseline cases (pm {len(pm)} / mv {len(mv)} / mh {len(mh)}) + 5 guards)')


if __name__ == '__main__':
    main()
