"""生成 tp/test/test_article_page.wll —— 文章页/独立页的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的结果**逐字节对照**。
基准：tp/test/fixtures/article_page_baseline.json
    （由 tp/test/gen_article_page_baseline.py 用真 Python 生成）。

**分组与断言形态**：
  | 基准组 | WLWL 调用 | 断言 |
  |---|---|---|
  | article | `ARTICLE_PAGE(opts)` | 非 ERR + 与 want **逐字节**相等 |
  | standalone | `STANDALONE_PAGE(opts)` | 非 ERR + 与 want **逐字节**相等 |

⚠ `RENDER_SKELETON`（⇒ 本模块）返回的是「STRING 或 ERR」，而
`LET(x, <ERR>)` **不算消费** ERR（README 坑 25）⇒ 每个用例先
`IS_ERR(...)` 判别、再在分支里重新调用取字符串（与 gen_test_template.py 同形）。

**反向守卫（卡 S2-4 的要求，每条都钉住「刻意为之」的那一面）**：
  g1 `content` 里的 `<script>` **原样嵌入**（content 是已渲染 HTML，不 escape）
     —— 同一用例里 `title` 的 `<script>` 必须被 escape ⇒ 「谁 escape、谁不 escape」两侧都钉。
  g2 独立页 `content` 里的 `${title}` **不被二次替换**（模板注入守卫；
     值只经 SUBSTITUTE 一遍）。
  g3 `site_url` 为空时，产物里**不得**出现 `application/ld+json` / `og:title` / `share-btn`。
  g4 对照组：`site_url` 非空时这三样**必须**出现（否则 g3 是空断言）。
  g5 mermaid 只在文章页出现（独立页 Python 侧没传）—— 两侧都钉。
  g6 `enable_search=false` 时导航里**不得**出现 `/search.html`。

用法：python gen_test_article_page.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_article_page.wll')


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 转义白名单只有 `\\" \\/ \\n \\r \\t \\b \\f \\0 \\$`（README 坑 7）
      ⇒ 其余控制字符写不进字面量（基准里没有，出现就炸）。
    ⚠ `$` 必须写成 `\\$`，否则会被当插值（坑 32）—— 基准里的 content 就含 `$`。
    """
    out = []
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '$':
            out.append('\\$')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        else:
            if ord(ch) < 32:
                raise ValueError(
                    '控制字符 %r 无法写进 WLWL 字面量（基准里有它就要换构造方式）'
                    % (ch,))
            out.append(ch)
    return '"' + ''.join(out) + '"'


def wl_dict_expr(d):
    """dict → `INDEX_SET(INDEX_SET(DICT(), k, v), …)` 链（**不用**字典字面量）。

    ⚠ 字典字面量会触发 wllgen 的逗号表达式守卫 ⇒ 一律 INDEX_SET。
    ⚠ 键按字典序遍历 ⇒ 产物确定（幂等）。
    """
    expr = 'DICT()'
    for k in sorted(d):
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl_string(k), wl_value(d[k]))
    return expr


def wl_value(v):
    """Python 值（str / bool / None / int / dict / list）→ WLWL 表达式。"""
    if isinstance(v, str):
        return wl_string(v)
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, dict):
        return wl_dict_expr(v)
    if isinstance(v, list):
        return '[' + ', '.join(wl_value(x) for x in v) + ']'
    raise TypeError('bad fixture value: %r' % (v,))


def emit_opts(A, prefix, spec):
    """把基准的 input 逐键灌进一个 DICT（`LET MUT` + `SET`，避免超长单行）。"""
    A('LET MUT(%s, DICT());' % prefix)
    for k in sorted(spec):
        A('SET(%s, INDEX_SET(%s, %s, %s));'
          % (prefix, prefix, wl_string(k), wl_value(spec[k])))


def emit_guard(A, name, conds):
    """一个守卫用例。

    ⚠ 每条断言写成 `(ASSERT(<cond>));` —— 行首那个 `(` 是**分组括号**，
      与范本（gen_test_article_store.py）同形。少了它每行就多出一个 `)`
      （实测：paren_check 报「ends at depth 7」，即整段少 7 个括号）。
    """
    A('TEST("%s", FUN(() ,' % name)
    for c in conds:
        A('    (ASSERT(%s));' % c)
    A('    TRUE));')


def main():
    with open(os.path.join(FIXTURES, 'article_page_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']
    meta = base['_meta']
    if meta.get('known_difference_count'):
        # 有登记差异时，want 与 python 不同 ⇒ 这里必须仍按 want 断言（不是放任）
        print('note: baseline has %d registered known difference(s)'
              % meta['known_difference_count'])

    src = []
    A = src.append
    A('// tp/test/test_article_page.wll —— 文章页/独立页的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_article_page.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的结果逐字节对照。')
    A('// 基准：tp/test/fixtures/article_page_baseline.json')
    A('//   （由 tp/test/gen_article_page_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件末尾自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "CONTAINS_SUB"]);')
    A('IMPORT("./../lib/article_page.wll", ["ARTICLE_PAGE", "STANDALONE_PAGE"]);')
    A('')

    # ── 用例数据 ──────────────────────────────────────────────────
    A('// ── 用例数据（逐键来自基准；与真 Python 的实参同源）────────────────')
    article_ids = sorted(cases['article'])
    standalone_ids = sorted(cases['standalone'])

    for key in article_ids:
        e = cases['article'][key]
        emit_opts(A, 'opt_' + key, e['input'])
        A('LET(want_%s, %s);' % (key, wl_string(e['want'])))
        if e.get('note'):
            A('// ⚠ 已知差异：%s' % e['note'])
    A('')
    for key in standalone_ids:
        e = cases['standalone'][key]
        emit_opts(A, 'opt_' + key, e['input'])
        A('LET(want_%s, %s);' % (key, wl_string(e['want'])))
        if e.get('note'):
            A('// ⚠ 已知差异：%s' % e['note'])
    A('')

    # ── 产出 + ERR 判别 ───────────────────────────────────────────
    A('// ── 产出与 ERR 判别 ───────────────────────────────────────────')
    A('// ⚠ `LET(x, <ERR>)` 绑定不算消费 ERR（README 坑 25）⇒ 先 IS_ERR，再在分支里重算。')
    for key in article_ids:
        A('LET(iserr_%s, IS_ERR(ARTICLE_PAGE(opt_%s)));' % (key, key))
        A('LET(out_%s, IF(iserr_%s, "", ARTICLE_PAGE(opt_%s)));' % (key, key, key))
    for key in standalone_ids:
        A('LET(iserr_%s, IS_ERR(STANDALONE_PAGE(opt_%s)));' % (key, key))
        A('LET(out_%s, IF(iserr_%s, "", STANDALONE_PAGE(opt_%s)));'
          % (key, key, key))
    A('')

    # ── 逐字节对照 ────────────────────────────────────────────────
    A('// ── 逐字节对照 ────────────────────────────────────────────────')
    for key in article_ids:
        A('TEST("article/%s", FUN(() ,' % key)
        A('    (ASSERT(!iserr_%s);' % key)
        A('     ASSERT_EQ(out_%s, want_%s));' % (key, key))
        A('    TRUE));')
    for key in standalone_ids:
        A('TEST("standalone/%s", FUN(() ,' % key)
        A('    (ASSERT(!iserr_%s);' % key)
        A('     ASSERT_EQ(out_%s, want_%s));' % (key, key))
        A('    TRUE));')
    A('')

    # ── 反向守卫 ──────────────────────────────────────────────────
    A('// ── 反向守卫（卡 S2-4 的要求）──────────────────────────────────')
    A('// g1：content 里的 <script> **原样嵌入**（content 是已渲染 HTML、不 escape），')
    A('//     而 title 的 <script> 必须被 escape —— 「谁 escape、谁不 escape」两侧都钉。')
    A('LET MUT(g1, DICT());')
    A('SET(g1, INDEX_SET(g1, "title", "<script>alert(\\"T\\")</script>"));')
    A('SET(g1, INDEX_SET(g1, "date", "2026-01-02 03:04"));')
    A('SET(g1, INDEX_SET(g1, "slug", "g1"));')
    A('SET(g1, INDEX_SET(g1, "content", "<script>alert(\'x\')</script>"));')
    A('LET(out_g1, ARTICLE_PAGE(g1));')
    emit_guard(A, 'guard/content_verbatim', [
        'CONTAINS_SUB(out_g1, "<script>alert(\'x\')</script>")',
        'CONTAINS_SUB(out_g1, "<h1 class=\\"post-title\\">&lt;script&gt;")',
        '!CONTAINS_SUB(out_g1, "<h1 class=\\"post-title\\"><script>")',
    ])
    A('')
    A('// g2：独立页 content 里的 `${title}` 不被二次替换（值只经 SUBSTITUTE 一遍）。')
    A('//     若被二次展开，产物里会只剩标题文本而不见占位符。')
    A('LET MUT(g2, DICT());')
    A('SET(g2, INDEX_SET(g2, "title", "TITLE"));')
    A('SET(g2, INDEX_SET(g2, "content", "<p>\\${title}</p>"));')
    A('LET(out_g2, STANDALONE_PAGE(g2));')
    emit_guard(A, 'guard/content_no_double_substitution', [
        'CONTAINS_SUB(out_g2, "<p>\\${title}</p>")',
    ])
    A('')
    A('// g3：site_url 为空 ⇒ 不得出现 JSON-LD / og / share。')
    A('//     （默认 config 的 site_url 就是 ""）')
    A('LET(out_g3, ARTICLE_PAGE(opt_%s));' % 'a00_minimal')
    emit_guard(A, 'guard/no_jsonld_without_site_url', [
        '!CONTAINS_SUB(out_g3, "application/ld+json")',
        '!CONTAINS_SUB(out_g3, "og:title")',
        '!CONTAINS_SUB(out_g3, "share-btn")',
    ])
    A('')
    A('// g4：对照组 —— site_url 非空时这三样必须出现（否则 g3 是空断言）。')
    A('LET(out_g4, ARTICLE_PAGE(opt_%s));' % 'a05_no_tags')
    emit_guard(A, 'guard/jsonld_present_with_site_url', [
        'CONTAINS_SUB(out_g4, "application/ld+json")',
        'CONTAINS_SUB(out_g4, "og:title")',
        'CONTAINS_SUB(out_g4, "share-btn")',
    ])
    A('')
    A('// g5：mermaid 只在文章页（独立页 Python 侧没传 mermaid_script）。')
    emit_guard(A, 'guard/mermaid_only_on_article', [
        'CONTAINS_SUB(out_g3, "cdn.jsdelivr.net/npm/mermaid@10")',
        '!CONTAINS_SUB(out_g2, "mermaid")',
    ])
    A('')
    A('// g6：enable_search=false ⇒ 导航里不得出现 /search.html。')
    A('LET(out_g6, ARTICLE_PAGE(opt_%s));' % 'a13_features_off')
    emit_guard(A, 'guard/no_search_link_when_disabled', [
        '!CONTAINS_SUB(out_g6, "/search.html")',
    ])
    A('')
    A('// g7：对照组 —— 默认 config（enable_search=true）时导航里必须有 /search.html。')
    emit_guard(A, 'guard/search_link_by_default', [
        'CONTAINS_SUB(out_g3, "/search.html")',
    ])
    A('')

    # ── 跑测试 ────────────────────────────────────────────────────
    A('// ── 跑测试 ────────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_article_page: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_article_page: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_article_page: FAILED"); '
      'PANIC("article_page tests failed")), NULL);')
    A('PRINT("test_article_page: OK");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines, %d article + %d standalone cases)'
          % (OUT, chars, lines, len(article_ids), len(standalone_ids)))


if __name__ == '__main__':
    main()
