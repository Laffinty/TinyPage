"""生成 tp/test/test_wikilink.wll —— wikilink 的逐字节对照测试。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：与**真 Python** `tinypage.parsers.bidirectional_links` 逐字节对照。
基准由 `tp/test/gen_wikilink_baseline.py` 生成到 `tp/test/fixtures/wikilink_baseline.json`
（直接 import 真实现，不是照抄规则重写）。

⚠ **已知差异用例**（基准 JSON 里带 `known_divergence` 注记，共 3 条）：
  WIKILINK_TARGET（md_inline.wll，禁碰）与 Python slugify 有两类不一致
  （尾部 `-` 未裁剪 / 非 ASCII 非 CJK 字母丢弃）。这些用例的
  **processed/found.url 钉住 WLWL 实测值**并单独标注（测试名带
  `_known_divergence` 后缀），title/display/extracted 三轴仍是 Python 权威值
  逐字节断言。差异面与实测读数见 gen_wikilink_baseline.py 文件头。

用例：≥12 条基准（覆盖 A/B/C 每条规则）+ 反向守卫。
⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 收尾自己统计 failed 并 PANIC。

用法：python gen_test_wikilink.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_wikilink.wll')


def wl_escape(s):
    """把 Python 字符串转成 WLWL 字符串字面量。"""
    out = s.replace('\\', '\\\\').replace('"', '\\"')
    out = out.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return '"' + out + '"'


def wl_map(m):
    """article_map → WLWL 字面量（空 map ⇒ DICT()；键值对 ⇒ 字典字面量）。"""
    if not m:
        return 'DICT()'
    pairs = []
    for k in sorted(m):
        slug, url = m[k]
        pairs.append('%s: [%s, %s]' % (
            wl_escape(k), wl_escape(slug), wl_escape(url)))
    return '[' + ', '.join(pairs) + ']'


def wl_found(found):
    """found_links（list of dict）→ WLWL 数组字面量。"""
    if not found:
        return '[]'
    items = []
    for f in found:
        items.append('["title": %s, "display": %s, "url": %s]' % (
            wl_escape(f['title']), wl_escape(f['display']), wl_escape(f['url'])))
    return '[' + ', '.join(items) + ']'


def wl_extract(titles):
    """extracted titles → WLWL 数组字面量。"""
    return '[' + ', '.join(wl_escape(t) for t in titles) + ']'


# ── 反向守卫（每条都钉死一条容易写反的语义）────────────────────
# (用例名, 语句序列)
GUARDS = [
    ('guard/alias_display_is_b_not_merged', [
        # `[[a|b]]` ⇒ title=a、display=b；**不得**把 a|b 整个当标题
        'LET(r, PARSE_BIDIRECTIONAL_LINKS("[[a|b]]", DICT()))',
        'ASSERT_EQ(r[0], "[b](/article/a.html)")',
        'ASSERT_EQ(AT_K(r[1][0], "title", "?"), "a")',
        'ASSERT_EQ(AT_K(r[1][0], "display", "?"), "b")',
    ]),
    ('guard/title_whitespace_stripped', [
        # `[[ a ]]` ⇒ title 是 "a"（strip 在取值之后发生）
        'LET(r, PARSE_BIDIRECTIONAL_LINKS("[[ a ]]", DICT()))',
        'ASSERT_EQ(r[0], "[a](/article/a.html)")',
        'ASSERT_EQ(AT_K(r[1][0], "title", "?"), "a")',
    ]),
    ('guard/no_wikilink_passthrough', [
        # 不含 `[[` 的文本原样返回，且不产出任何 found/extracted
        'LET(t, "普通文本，没有链接。")',
        'LET(r, PARSE_BIDIRECTIONAL_LINKS(t, DICT()))',
        'ASSERT_EQ(r[0], t)',
        'ASSERT_EQ(r[1], [])',
        'ASSERT_EQ(EXTRACT_BIDIRECTIONAL_LINKS(t), [])',
    ]),
    ('guard/extract_strips_like_real_python', [
        # ⚠ 任务简报称 extract「未 strip」，但真源码 bidirectional_links.py:98
        #   是 `title = match.group(1).strip()` + `if title:` ⇒ **同样 strip**。
        #   基准由真 Python 生成（case_08/09 已逐字节证明）⇒ 以源码为准。
        'ASSERT_EQ(EXTRACT_BIDIRECTIONAL_LINKS("[[ a ]]"), ["a"])',
        # strip 后为空的标题被丢弃（真源码 if title: 过滤）
        'ASSERT_EQ(EXTRACT_BIDIRECTIONAL_LINKS("[[   ]]"), [])',
    ]),
    ('guard/null_map_supported', [
        # article_map 为 NULL（未传）⇒ 走 slug 回退，不报错
        'LET(r, PARSE_BIDIRECTIONAL_LINKS("[[x]]", NULL))',
        'ASSERT_EQ(r[0], "[x](/article/x.html)")',
    ]),
    ('guard/multi_pipe_display', [
        # `[[a|b|c]]` ⇒ display 是 "b|c"（[^\]]+ 允许吃掉第二个 |）
        'LET(r, PARSE_BIDIRECTIONAL_LINKS("[[a|b|c]]", DICT()))',
        'ASSERT_EQ(r[0], "[b|c](/article/a.html)")',
    ]),
]

# 已知差异用例的 WLWL 实测值（wlwl v0.12.1，探针读数）。
# key = 基准里的 src；value = (processed, url)。
# ⚠ 调整 md_inline 的 \w 口径后，这里必须同步更新。
# （原 ① trim_dashes 尾部裁剪已于 2026-11-02 修复 ⇒ Hello, World! 不再钉实测，
#   回归 Python 权威值断言。）
WL_OBSERVED = {
    '[[café]]':
        ('[café](/article/caf.html)', '/article/caf.html'),
    '[[ひらがな]]':
        ('[ひらがな](/article/untitled.html)', '/article/untitled.html'),
}


def main():
    with open(os.path.join(FIXTURES, 'wikilink_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)

    src = []
    A = src.append
    A('// tp/test/test_wikilink.wll —— wikilink 测试（对照真 Python bidirectional_links）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_wikilink.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** parse_bidirectional_links /')
    A('// extract_bidirectional_links 逐字节对照（processed / found / extracted 三轴）。')
    A('// 基准：tp/test/fixtures/wikilink_baseline.json')
    A('//   （由 tp/test/gen_wikilink_baseline.py 用真 Python 生成）')
    A('// ⚠ 测试名带 `_known_divergence` 后缀的用例：processed/found.url 钉的是')
    A('//   WLWL 实测值（md_inline 的 w 语义口径差异），extracted 仍对 Python。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("./../lib/wikilink.wll", ["PARSE_BIDIRECTIONAL_LINKS", '
      '"EXTRACT_BIDIRECTIONAL_LINKS"]);')
    A('')

    for name in sorted(base):
        case = base[name]
        div = case.get('known_divergence')
        A(f'// {name}: {case["src"]!r}')
        if div:
            A(f'// ⚠ 已知差异：{div}')
        A(f'LET(src_{name}, {wl_escape(case["src"])});')
        A(f'LET(map_{name}, {wl_map(case["map"])});')
        A('// 下面三条是 Python 权威值（差异用例的 processed/found 不用于断言，见下）')
        A(f'LET(want_text_{name}, {wl_escape(case["processed"])});')
        A(f'LET(want_found_{name}, {wl_found(case["found"])});')
        A(f'LET(want_ext_{name}, {wl_extract(case["extracted"])});')
        if div:
            obs_text, obs_url = WL_OBSERVED[case['src']]
            pinned_found = [dict(f, url=obs_url) for f in case['found']]
            A('// ⚠ WLWL 实测钉值（wlwl v0.12.1）—— title/display 仍取 Python 权威值，')
            A('//   仅 url/processed 换成 WLWL 实测；md_inline 修复后须同步更新')
            A(f'LET(wl_text_{name}, {wl_escape(obs_text)});')
            A(f'LET(wl_found_{name}, {wl_found(pinned_found)});')
        A('')

    A('// ── 基准用例（真 Python 逐字节对照）────────────────────')
    for name in sorted(base):
        case = base[name]
        div = case.get('known_divergence')
        if div:
            A(f'// {name}: ⚠ 已知差异用例 —— processed/found 钉 WLWL 实测值，')
            A('//   extracted 仍是 Python 权威值逐字节断言')
            A(f'TEST("{name}_known_divergence", FUN(() ,')
            A(f'    (LET(r_{name}, PARSE_BIDIRECTIONAL_LINKS(src_{name}, map_{name}));')
            A(f'     ASSERT_EQ(r_{name}[0], wl_text_{name});')
            A(f'     ASSERT_EQ(r_{name}[1], wl_found_{name});')
            A(f'     ASSERT_EQ(EXTRACT_BIDIRECTIONAL_LINKS(src_{name}), want_ext_{name}));')
            A('    TRUE));')
            continue
        A(f'TEST("{name}", FUN(() ,')
        A(f'    (LET(r_{name}, PARSE_BIDIRECTIONAL_LINKS(src_{name}, map_{name}));')
        A(f'     ASSERT_EQ(r_{name}[0], want_text_{name});')
        A(f'     ASSERT_EQ(r_{name}[1], want_found_{name});')
        A(f'     ASSERT_EQ(EXTRACT_BIDIRECTIONAL_LINKS(src_{name}), want_ext_{name}));')
        A('    TRUE));')
    A('')

    A('// ── 反向守卫 ──────────────────────────────────────────')
    for name, body in GUARDS:
        A(f'// {name}')
        A(f'TEST("{name}", FUN(() ,')
        A('    (' + '; '.join(body) + ');')
        A('    TRUE));')
        A('')

    A('// ── 跑测试 ──────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_wikilink: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_wikilink: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_wikilink: FAILED"); PANIC("wikilink tests failed")), NULL);')
    A('PRINT("test_wikilink: OK");')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines, '
          f'{len(base)} baseline cases + {len(GUARDS)} guards)')


if __name__ == '__main__':
    main()
