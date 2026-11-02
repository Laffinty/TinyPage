"""生成 tp/test/test_search_index.wll —— 搜索索引的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的结果**逐字节对照**。
基准：tp/test/fixtures/search_index_baseline.json
    （由 tp/test/gen_search_index_baseline.py 用真 Python 生成）。

**用例矩阵**（卡 S2-4 的要求逐条覆盖）：

| 要求 | 用例 |
|---|---|
| 空列表 | `empty` / `empty_with_standalones_key` / `empty_opts_dict` / `null_lists` |
| 单篇 | `single` |
| 多篇 | `multi` |
| 含草稿（验**不**过滤）| `drafts_included`（status 大写/小写两种写法）/ `all_drafts` |
| 有 standalones | `with_standalones` / `standalones_only` |
| 无 standalones | `single` / `multi` / `drafts_included` … |
| 标题/摘要含 `"` / 中文 / 换行（验 JSON 转义）| `escaping`（含反斜杠、tab、emoji、`\\r\\n`）|
| tags 切分边界 | `tags_edges` |
| 缺 `status` 键 | `no_status_key` |
| 输入带多余键（`content`）| `extra_fields_ignored` |

**反向守卫**（卡 S2-4 要求 ≥2 条，这里 6 组）：

  · `guard/output_is_valid_json` —— 产物必须能被 `JSON_VALIDATE` 判为合法 JSON。
  · `guard/no_dangling_separator` —— 不得出现 `,]` / `, }`。
  · `guard/drafts_pass_through` —— **草稿必须出现在产物里**：本模块不过滤草稿，
    这是与 `generate_search_index` 一一对应的结果；将来谁「顺手加个过滤」就会红。
  · `guard/{content_marker,content_key}_absent` —— 正文哨兵
    `CONTENT-MUST-NOT-APPEAR-IN-INDEX` 与 `"content"` 键**都不得**出现在产物里。
  · `guard/record_keys_exact` —— 每条记录恰好 6 个索引字段（不含正文）。
  · `guard/standalone_fields_hardcoded` —— standalone 的 date/tags/category
    即使输入里有值，产物也必须是 `""` / `[]` / `""`。
  · `guard/tags_split_and_trimmed` —— `a , b` 必须切成两个 tag。

**⚠ 草稿与 `want`**：`drafts_included` / `all_drafts` 的 `want` 就是真 Python
对**同一份原样列表**的输出（草稿在结果里）。`generate_search_index` 本身不过滤
草稿，排除在生产链路的调用方（`cli.py:139` 的 `list_articles(include_drafts=False)`，
过滤点 `content.py:187-189`）——本模块照抄函数现状、把过滤留给调用方。

用法：python gen_test_search_index.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, HERE)
sys.path.insert(0, REPO_ROOT)

from wllgen import write  # noqa: E402
from gen_search_index_baseline import (  # noqa: E402
    CONTENT_MARKER, DRAFT_TITLE_LOWER, DRAFT_TITLE_UPPER,
)

FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_search_index.wll')

# 索引字段（必须与 gen_search_index.py 的 FIELDS 一致）
FIELDS = ['title', 'summary', 'url', 'date', 'tags', 'category']


def paren_depth(text):
    """`(`/`)` 净深度（忽略字符串内的括号）。"""
    depth = 0
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        i += 1
    return depth


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 转义白名单只有 `\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`
      ⇒ `$` 必须写 `\\$`（否则是插值，坑 #32）。
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
        elif ch == '$':
            out.append('\\$')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def wl_dict(spec):
    """字典 → `INDEX_SET(INDEX_SET(DICT(), k, v), …)` 表达式。

    ⚠ 字典**字面量** `["k": v]` 会触发 wllgen 的逗号表达式守卫 ⇒ 一律用 INDEX_SET。
    ⚠ 只渲染**给到的**键：`no_status_key` 用例靠"键缺失"测默认值回落。
    """
    expr = 'DICT()'
    for k, v in spec.items():
        if isinstance(v, str):
            val = wl_string(v)
        elif isinstance(v, bool):
            val = 'TRUE' if v else 'FALSE'
        elif v is None:
            val = 'NULL'
        elif isinstance(v, int):
            val = str(v)
        elif isinstance(v, list):
            val = '[' + ', '.join(wl_string(x) for x in v) + ']'
        else:
            raise TypeError('bad fixture value: %r' % (v,))
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl_string(k), val)
    return expr


def main():
    with open(os.path.join(FIXTURES, 'search_index_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']

    src = []
    A = src.append

    def line(text):
        """一条**完整语句/表达式分组**行 —— 当场校验括号自平衡。"""
        d = paren_depth(text)
        if d != 0:
            raise SystemExit('不平衡(%+d)的生成行：%s' % (d, text))
        A(text)

    def assert_true(cond):
        """`(ASSERT(<cond>));` —— TEST body 里的一行。"""
        line('    (ASSERT(%s));' % cond)

    def assert_eq(a, b):
        """`(ASSERT_EQ(<a>, <b>));`"""
        line('    (ASSERT_EQ(%s, %s));' % (a, b))

    def test_open(name):
        A('TEST("%s", FUN(() ,' % name)

    def test_close():
        A('    TRUE));')

    A('// tp/test/test_search_index.wll —— 搜索索引的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_search_index.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的结果逐字节对照。')
    A('// 基准：tp/test/fixtures/search_index_baseline.json')
    A('//   （由 tp/test/gen_search_index_baseline.py 用真 Python 生成）')
    A('//')
    A('// 对齐目标：tinypage/generator.py:599 generate_search_index')
    A('//   ⇒ WLWL 侧 SEARCH_INDEX(opts)')
    A('//')
    A('// ⚠ 草稿：**本模块不过滤**（= generate_search_index 的现状）。')
    A('//   排除在生产链路的调用方 cli.py:139 (list_articles(include_drafts=False)，')
    A('//   过滤点 content.py:187-189)；反向守卫 guard/drafts_pass_through 钉住这条。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('// ⚠ PARSE 失败会产生 E0070 且**无法捕获**（中止整个运行）')
    A('//   ⇒ 只对「先过了 JSON_VALIDATE」的产物做 PARSE。')
    A('IMPORT("wlwl:std.json", ["JSON_VALIDATE", "PARSE"]);')
    A('IMPORT("./../lib/search_index.wll", ["SEARCH_INDEX"]);')
    A('')

    # ── 用例数据 ──────────────────────────────────────────────────
    A('// ── 用例数据（输入与期望值都逐字节来自基准）────────────────────')
    A('// 索引字段：' + ' / '.join(FIELDS))
    A('')
    for name in sorted(cases):
        c = cases[name]
        note = c.get('note')
        A('// %s：%d 篇文章 + %d 个独立页' % (
            name, len(c['articles']), len(c['standalones'] or [])))
        if note:
            A('// 分层说明：%s' % note)
        line('LET(arts_%s, [%s]);' % (
            name, ', '.join(wl_dict(a) for a in c['articles'])))
        if c['standalones'] is not None:
            line('LET(sa_%s, [%s]);' % (
                name, ', '.join(wl_dict(p) for p in c['standalones'])))
            line('LET(opts_%s, INDEX_SET(INDEX_SET(DICT(), "articles", arts_%s), '
                 '"standalones", sa_%s));' % (name, name, name))
        else:
            # standalones 缺省 ⇒ opts 里**没有**这个键（对齐 Python 的 None）
            line('LET(opts_%s, INDEX_SET(DICT(), "articles", arts_%s));'
                 % (name, name))
        line('LET(want_%s, %s);' % (name, wl_string(c['want'])))
        A('')

    # ── 逐字节对照 ────────────────────────────────────────────────
    A('// ── 逐字节对照（真 Python 的 json.dumps 输出）──────────────────')
    for name in sorted(cases):
        test_open('search_index/%s' % name)
        assert_eq('SEARCH_INDEX(opts_%s)' % name, 'want_%s' % name)
        test_close()
    A('')

    # 两个键都缺省 / 显式 NULL
    A('// opts 两个键都缺省 ⇒ 空数组（对齐 Python 的 [] / None）')
    test_open('search_index/empty_opts_dict')
    assert_eq('SEARCH_INDEX(DICT())', '"[]"')
    test_close()
    A('// 显式 NULL（= Python 的 None）⇒ 同样空数组')
    test_open('search_index/null_lists')
    assert_eq('SEARCH_INDEX(INDEX_SET(INDEX_SET(DICT(), "articles", NULL), '
              '"standalones", NULL))', '"[]"')
    test_close()
    A('')

    # ── 结构化断言（先 validate 再 PARSE）──────────────────────────
    A('// ── 结构化断言：先 JSON_VALIDATE 再 PARSE ─────────────────────')
    A('// ⚠ 顺序不可换：PARSE 失败直接 E0070 中止，无法捕获。')
    A('// ⚠ 非法时退回 [] ⇒ 变成一条「条数不符」的 FAIL，而不是中止整个运行。')
    for name in ('drafts_included', 'multi', 'with_standalones'):
        c = cases[name]
        # 记录数 = 全部 articles（草稿也算）+ 全部 standalones
        n_rec = len(c['articles']) + len(c['standalones'] or [])
        line('LET(out_%s, SEARCH_INDEX(opts_%s));' % (name, name))
        line('LET(doc_%s, IF(IS_ERR(JSON_VALIDATE(out_%s)), [], PARSE(out_%s)));'
             % (name, name, name))
        A('// %s ⇒ %d 条记录' % (name, n_rec))
        test_open('structure/%s_record_count' % name)
        assert_eq('LEN(doc_%s)' % name, str(n_rec))
        test_close()
        test_open('structure/%s_record_keys' % name)
        assert_eq('LEN(KEYS(AT(doc_%s, 0, DICT())))' % name, str(len(FIELDS)))
        test_close()
        A('')

    # standalone 的 date/tags/category 硬编码空（输入里故意塞了值）
    A('// with_standalones 的第 3 条记录是 standalone（about.html）：')
    A('// 输入 date="2024-01-01 00:00"、tags="ignored, tags"、category="ignored"，')
    A('// 但产物必须是 "" / [] / ""（generator.py:617-624 硬编码）。')
    line('LET(sa0, AT(doc_with_standalones, 2, DICT()));')
    test_open('guard/standalone_fields_hardcoded')
    assert_eq('AT_K(sa0, "date", "?")', '""')
    assert_eq('LEN(AT_K(sa0, "tags", [1]))', '0')
    assert_eq('AT_K(sa0, "category", "?")', '""')
    assert_eq('AT_K(sa0, "url", "?")', '"/standalone/about.html"')
    test_close()
    A('')

    # ── 反向守卫 ──────────────────────────────────────────────────
    A('// ── 反向守卫（卡 S2-4 要求 ≥2 条）─────────────────────────────')

    A('// ① 产物必须是合法 JSON（空数组与含转义的两个极端都钉住）')
    test_open('guard/output_is_valid_json')
    for opts in ('opts_multi', 'opts_escaping', 'opts_with_standalones',
                 'opts_drafts_included'):
        assert_true('!IS_ERR(JSON_VALIDATE(SEARCH_INDEX(%s)))' % opts)
    assert_true('!IS_ERR(JSON_VALIDATE(SEARCH_INDEX(DICT())))')
    test_close()
    A('')

    A('// ② 不得出现悬挂逗号（记录分隔符写错的典型症状）')
    test_open('guard/no_dangling_separator')
    assert_true('!CONTAINS(SEARCH_INDEX(opts_multi), ",]")')
    assert_true('!CONTAINS(SEARCH_INDEX(opts_multi), ", }")')
    assert_true('CONTAINS(SEARCH_INDEX(opts_with_standalones), "[{")')
    test_close()
    A('')

    A('// ③ 草稿**必须**出现在产物里：本模块不过滤草稿（见 wll 头部说明）。')
    A('//    ⚠ 这条是「将来的自己」的哨兵：谁在 SEARCH_INDEX 里顺手加个草稿过滤，')
    A('//      它就红 —— 因为那会让本模块与 generate_search_index 不再一一对应。')
    line('LET(out_draftpass, SEARCH_INDEX(opts_drafts_included));')
    test_open('guard/drafts_pass_through')
    assert_true('CONTAINS(out_draftpass, %s)' % wl_string(DRAFT_TITLE_UPPER))
    assert_true('CONTAINS(out_draftpass, %s)' % wl_string(DRAFT_TITLE_LOWER))
    # 草稿的 tag 也照样进产物（tags 不做任何 status 相关处理）
    assert_true('CONTAINS(out_draftpass, "\\"hidden\\"")')
    test_close()
    test_open('guard/all_drafts_pass_through')
    assert_true('CONTAINS(SEARCH_INDEX(opts_all_drafts), %s)'
                % wl_string(DRAFT_TITLE_UPPER + '-2'))
    assert_true('CONTAINS(SEARCH_INDEX(opts_all_drafts), %s)'
                % wl_string(DRAFT_TITLE_LOWER + '-2'))
    test_close()
    A('')

    A('// ④ 正文（`content`）不得进索引：哨兵串与键名都不得出现')
    line('LET(out_extra_fields_ignored, SEARCH_INDEX(opts_extra_fields_ignored));')
    test_open('guard/content_marker_absent')
    assert_true('!CONTAINS(out_extra_fields_ignored, %s)' % wl_string(CONTENT_MARKER))
    test_close()
    test_open('guard/content_key_absent')
    assert_true('!CONTAINS(out_extra_fields_ignored, "\\"content\\"")')
    test_close()
    A('')

    A('// ⑤ 记录键恰好是 6 个索引字段（顺序由逐字节对照钉住，这里钉"不多不少"）')
    test_open('guard/record_keys_exact')
    for f in FIELDS:
        assert_true('CONTAINS(out_drafts_included, %s)' % wl_string('"%s": ' % f))
    assert_eq('LEN(KEYS(AT(doc_drafts_included, 0, DICT())))', str(len(FIELDS)))
    test_close()
    A('')

    A('// ⑥ tag 必须按逗号切、各自 strip（不能把 "a , b" 当一个 tag）')
    test_open('guard/tags_split_and_trimmed')
    assert_true('CONTAINS(SEARCH_INDEX(opts_tags_edges), '
                '"\\"tags\\": [\\"a\\", \\"b\\"]")')
    assert_true('!CONTAINS(SEARCH_INDEX(opts_tags_edges), "\\" a , b \\"")')
    test_close()
    A('')

    # ── 跑测试 ────────────────────────────────────────────────────
    A('// ── 跑测试 ────────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_search_index: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_search_index: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_search_index: FAILED"); '
      'PANIC("search_index tests failed")), NULL);')
    A('PRINT("test_search_index: OK");')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines, '
          f'{len(cases)} baseline cases + structure/guards)')


if __name__ == '__main__':
    main()
