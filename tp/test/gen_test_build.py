"""生成 `tp/test/test_build.wll` —— 构建编排层的**端到端逐字节对照** + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**（卡 S2-构建 最重要的一条）：
在 `TEMP_DIR()` 里用与基准**同一份**语料（夹具内联的 `spec.files`）重建一棵树，
调 `BUILD(opts)`，然后**逐文件比 sha256**（并比码点数，让失败信息能定位）。

基准：`tp/test/fixtures/build_baseline.json`（由 `gen_build_baseline.py` 用**真 Python**
的 `generate_static_pages` 生成，同一份语料、同一串调用）。

## 断言分组

| 组 | 钉住什么 |
|---|---|
| `stats/*` | `BUILD` 的返回值：articles / written / pages / categories / standalones / ok |
| `files/*` | **每一个产物**的 sha256 + 码点数（40 个：13 篇文章页、2 页列表、3 个分类页、2 个独立页、search/rss/sitemap/robots/search-index、14 个 `.md`、1 篇未被重生成的草稿） |
| `fileset` | `WALK_DIR` 的结果与基准的**文件清单逐个相等**（多一个少一个都红） |
| `guard/*` | 反向守卫（每条都钉「刻意为之」的那一面） |

## 反向守卫（都要**成对**，否则是空断言）

- `g1` 草稿**不得**出现在 index.html / list/2.html / rss.xml / sitemap.xml /
  search-index.json 里；`g1b` 对照组：**已发布**文章必须出现在同样的产物里。
- `g2` 草稿 html 必须**保持语料原样**（没被重新生成）；`g2b` 已发布文章的 html
  必须**不再**含语料里的占位正文（证明它真的被重写了）。
- `g3` rss.xml 的 `<item>` 恰好 13 条（= 已发布篇数，不是 14）。
- `g4` sitemap.xml 里**不得**有草稿 URL（这是计划书那条断言被证伪处，见 gen_build.py）。
- `g5` `written` 必须等于夹具的 `written_expected`（25）—— 证明每个写盘点都走到了。
- `g6` `BUILD` 不得改写 `.md` 源文件（`WRITE_SOURCE` 在真 Python 里会写，
  WLWL 侧不写；两侧内容相同所以 sha256 相同 ⇒ 这条钉的是「不写也不出错」）。

⚠ `RUN_TESTS()` 的失败**不影响退出码**（规范明载）⇒ 文件末尾自己把关。

用法：python gen_test_build.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_build.wll')

DRAFT = '2026-03-02-draft-wip.html'
DRAFT_MARK = '草稿'


def wl(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 转义白名单只有 `\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`（README 坑 7）。
    ⚠ `$` 必须写 `\\$`（WLWL 字面量里 `${...}` / `$name` 是**插值**，坑 32）。
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
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\0':
            out.append('\\0')
        else:
            if ord(ch) < 32:
                raise ValueError('控制字符 %r 无法写进 WLWL 字面量' % (ch,))
            out.append(ch)
    return '"' + ''.join(out) + '"'


def wl_value(v):
    """Python 值 → WLWL 表达式（只用 INDEX_SET 链，不用字典字面量以外的构造）。"""
    if isinstance(v, str):
        return wl(v)
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, dict):
        expr = 'DICT()'
        for k in sorted(v):
            expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl(k), wl_value(v[k]))
        return expr
    if isinstance(v, list):
        return '[' + ', '.join(wl_value(x) for x in v) + ']'
    raise TypeError('bad value: %r' % (v,))


def emit_test(A, name, conds):
    A('TEST("%s", FUN(() ,' % name)
    for c in conds:
        A('    (ASSERT(%s));' % c)
    A('    TRUE));')


def main():
    with open(os.path.join(FIXTURES, 'build_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)
    spec = base['spec']
    files = spec['files']
    expected = base['expected']
    meta = base['_meta']
    counts = meta['counts']

    rels = sorted(expected)
    index_of = {rel: i for i, rel in enumerate(rels)}

    src = []
    A = src.append
    A('// tp/test/test_build.wll —— 构建编排层端到端逐字节对照 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_build.py 生成 —— 请勿手改。')
    A('//')
    A('// 做法：在 TEMP_DIR() 里用夹具内联的语料重建同一棵树 → BUILD → 逐文件比 sha256。')
    A('// 基准：tp/test/fixtures/build_baseline.json（真 Python generate_static_pages 产出）')
    A('//')
    A('// ⚠ 夹具里没有绝对路径：语料按「相对站点的 POSIX 路径 → 内容」内联，')
    A('//   测试自己把它们拼到 TEMP_DIR() 下（跨机器可复现，CI 上同样是临时目录）。')
    A('')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "TEMP_DIR", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "CONTAINS_SUB"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_FIND_ALL"]);')
    A('IMPORT("wlwl:std.encode", ["SHA256"]);')
    A('IMPORT("wlwl:std.fs", ["READ_FILE", "WRITE_FILE_ATOMIC", "MKDIRS", "PATH_JOIN",'
      ' "WALK_DIR", "FILE_META"]);')
    A('IMPORT("./../bin/build.wll", ["BUILD"]);')
    A('')
    A('// ── 小工具 ────────────────────────────────────────────────────────')
    A('// ⚠ `LET(r, READ_FILE(p))` / `LET(r, WRITE_FILE_ATOMIC(...))` 绑定**不算消费**')
    A('//   ERR（坑 25）⇒ 一律直接放进 IS_ERR(...)。')
    A('LET(PUT_FILE, FUN((p, c), (')
    A('     IF(IS_ERR(WRITE_FILE_ATOMIC(p, c)), (PANIC(CAT("write failed: ", p))), NULL)')
    A(')));')
    A('LET(PUT_DIR, FUN((p), (')
    A('     IF(IS_ERR(MKDIRS(p)), (PANIC(CAT("mkdir failed: ", p))), NULL)')
    A(')));')
    A('LET(READ_OR_SPENT, FUN((p), (')
    A('     IF(IS_ERR(READ_FILE(p)), "", READ_FILE(p))')
    A(')));')
    A('// `WALK_DIR` 的结果**含目录条目**（实测：4 个目录 + 40 个文件 = 44 条）')
    A('// ⇒ 要按「只留文件」过滤，才与基准的文件清单同形。')
    A('LET(TST_IS_DIR, FUN((p), (')
    A('     IF(IS_ERR(FILE_META(p)), TRUE,')
    A('          AT_K(FILE_META(p), "is_dir", TRUE))')
    A(')));')
    A('LET(TST_WALK_FILES, FUN((dir), (')
    A('     LET(all, IF(IS_ERR(WALK_DIR(dir)), [], WALK_DIR(dir)));')
    A('     LET MUT(out, []);')
    A('     FOR(e, all, (')
    A('          IF(TST_IS_DIR(PATH_JOIN(dir, e)), NULL, (SET(out, +(out, [e]))))')
    A('     ));')
    A('     out')
    A(')));')
    A('')

    # ── 造语料 ────────────────────────────────────────────────────────
    A('// ── 造语料（与基准同一份 spec）──────────────────────────────────────')
    A('LET(root, TEMP_DIR());')
    A('LET(out_dir, PATH_JOIN(root, "pages"));')
    # 先建目录（MKDIRS 不自动建父目录这件事在 WRITE_FILE_ATOMIC 上成立，坑 24）
    dirs = sorted({rel.rsplit('/', 1)[0] for rel in files if '/' in rel})
    for d in dirs:
        A('PUT_DIR(PATH_JOIN(root, %s));' % wl(d))
    A('')
    for rel in sorted(files):
        A('PUT_FILE(PATH_JOIN(root, %s), %s);' % (wl(rel), wl(files[rel])))
    A('')

    # ── 调 BUILD ──────────────────────────────────────────────────────
    A('// ── 跑一次完整构建 ──────────────────────────────────────────────────')
    A('LET(res, BUILD(["root": root, "config": %s]));' % wl_value(spec['config']))
    A('LET(res_articles, AT_K(res, "articles", -1));')
    A('LET(res_written, AT_K(res, "written", -1));')
    A('LET(res_ok, AT_K(res, "ok", FALSE));')
    A('LET(res_pages, AT_K(res, "pages", -1));')
    A('LET(res_cats, AT_K(res, "categories", -1));')
    A('LET(res_sts, AT_K(res, "standalones", -1));')
    A('')
    A('// ── 每个产物的实际内容（顶层取，TEST 的 FUN 体里不能放 LET）─────────────')
    for rel in rels:
        i = index_of[rel]
        A('LET(f%d, READ_OR_SPENT(PATH_JOIN(out_dir, %s)));' % (i, wl(rel)))
    A('')

    # ── 清单 ──────────────────────────────────────────────────────────
    A('// ── 实际写出的文件清单（与基准逐个比对；多一个少一个都红）──────────────')
    A('LET(walked, TST_WALK_FILES(out_dir));')
    A('LET(want_list, [')
    for i, rel in enumerate(rels):
        A('     %s%s' % (wl(rel), ',' if i < len(rels) - 1 else ''))
    A(']);')
    A('')

    # ── 关键产物引用（守卫用）─────────────────────────────────────────
    keep = {}
    for r in ['index.html', 'list/2.html', 'rss.xml', 'sitemap.xml',
              'search-index.json', 'search.html', 'article/' + DRAFT]:
        if r in index_of:
            keep[r] = index_of[r]
    A('LET(i_index, f%d);' % keep['index.html'])
    A('LET(i_list2, f%d);' % keep['list/2.html'])
    A('LET(i_rss, f%d);' % keep['rss.xml'])
    A('LET(i_sitemap, f%d);' % keep['sitemap.xml'])
    A('LET(i_sidx, f%d);' % keep['search-index.json'])
    A('LET(i_draft, f%d);' % keep['article/' + DRAFT])
    A('LET(i_pub, f%d);' % index_of['article/2026-02-24-pagination.html'])
    A('LET(n_items, LEN(RE_FIND_ALL(RE("[<]item[>]"), i_rss)));')
    A('')

    # ── 测试 ──────────────────────────────────────────────────────────
    A('// ── 统计量 ────────────────────────────────────────────────────────')
    emit_test(A, 'stats/articles', ['ASSERT_EQ(res_articles, %d)' % counts['articles']])
    emit_test(A, 'stats/standalones', ['ASSERT_EQ(res_sts, %d)' % counts['standalones']])
    emit_test(A, 'stats/pages', ['ASSERT_EQ(res_pages, %d)' % counts['list_pages']])
    emit_test(A, 'stats/categories', ['ASSERT_EQ(res_cats, %d)' % counts['categories']])
    emit_test(A, 'stats/written', ['ASSERT_EQ(res_written, %d)'
                                   % meta['written_expected']])
    emit_test(A, 'stats/ok', ['ASSERT_EQ(res_ok, TRUE)'])
    A('')

    A('// ── 逐文件对照（sha256 + 码点数）──────────────────────────────────────')
    for rel in rels:
        i = index_of[rel]
        emit_test(A, 'files/%s' % rel, [
            'ASSERT_EQ(SHA256(f%d), %s)' % (i, wl(expected[rel]['sha256'])),
            'ASSERT_EQ(LEN(f%d), %d)' % (i, expected[rel]['chars']),
        ])
    A('')

    A('// ── 文件清单 ──────────────────────────────────────────────────────')
    emit_test(A, 'fileset/count', [
        'ASSERT_EQ(LEN(walked), LEN(want_list))',
    ])
    emit_test(A, 'fileset/order_and_names', [
        'ASSERT_EQ(walked, want_list)',
    ])
    A('')

    # ── 反向守卫 ──────────────────────────────────────────────────────
    A('// ── 反向守卫 ──────────────────────────────────────────────────────')
    A('// g1：草稿**不得**出现在任何列表类产物里（编排层过滤的唯一判据）。')
    for nm, var in [('index', 'i_index'), ('list2', 'i_list2'), ('rss', 'i_rss'),
                    ('sitemap', 'i_sitemap'), ('search_index', 'i_sidx')]:
        emit_test(A, 'guard/draft_absent_from_%s' % nm,
                  ['!CONTAINS_SUB(%s, "%s")' % (var, DRAFT),
                   '!CONTAINS_SUB(%s, "%s")' % (var, DRAFT_MARK)])
    A('')
    A('// g1b：对照组 —— 已发布文章**必须**出现在同样的产物里（否则 g1 是空断言）。')
    for nm, var in [('index', 'i_index'), ('rss', 'i_rss'),
                    ('sitemap', 'i_sitemap'), ('search_index', 'i_sidx')]:
        emit_test(A, 'guard/published_present_in_%s' % nm,
                  ['CONTAINS_SUB(%s, "2026-02-24-pagination.html")' % var])
    # 分页对照组要用**第 2 页**才有的文章（第 1 页是最近 10 篇）
    emit_test(A, 'guard/published_present_in_list2',
              ['CONTAINS_SUB(i_list2, "2026-01-05-site-launch.html")',
               '!CONTAINS_SUB(i_list2, "2026-02-24-pagination.html")'])
    A('')
    A('// g2：草稿 html 必须保持语料原样（它不进 list_articles ⇒ 不会被重新生成）。')
    emit_test(A, 'guard/draft_html_untouched', [
        'ASSERT_EQ(SHA256(i_draft), %s)'
        % wl(expected['article/' + DRAFT]['sha256']),
        'CONTAINS_SUB(i_draft, "旧正文占位")',
    ])
    A('')
    A('// g2b：对照组 —— 已发布文章的 html 必须**不再**含语料里的占位正文，')
    A('//      且必须是「整页」（骨架 + 元数据头都在）⇒ 它真的被重新生成过。')
    emit_test(A, 'guard/published_html_regenerated', [
        '!CONTAINS_SUB(i_pub, "旧正文占位")',
        'CONTAINS_SUB(i_pub, "class=\\"post-title\\"")',
        'CONTAINS_SUB(i_pub, "<!-- status: published -->")',
    ])
    A('')
    A('// g3：rss 的 <item> 恰好等于已发布篇数（14 篇语料里 1 篇草稿）。')
    emit_test(A, 'guard/rss_item_count', [
        'ASSERT_EQ(n_items, %d)' % (counts['articles']),
    ])
    A('')
    A('// g4：sitemap 的 <url> 数 == 1（根） + 文章数 + 独立页数 + 分类数。')
    A('LET(n_loc, LEN(RE_FIND_ALL(RE("[<]loc[>]"), i_sitemap)));')
    emit_test(A, 'guard/sitemap_url_count', [
        'ASSERT_EQ(n_loc, %d)' % (1 + counts['articles'] + counts['standalones']
                                  + counts['categories']),
    ])
    A('')
    A('// g5：BUILD 不得改坏 .md 源文件（内容与语料相同即通过）。')
    emit_test(A, 'guard/md_sources_intact', [
        'ASSERT_EQ(SHA256(f%d), %s)'
        % (index_of['article/2026-01-05-site-launch.md'],
           wl(expected['article/2026-01-05-site-launch.md']['sha256'])),
    ])
    A('')

    # ── 跑测试 ────────────────────────────────────────────────────────
    A('// ── 跑测试（RUN_TESTS 的失败不影响退出码 ⇒ 自己把关）──────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_build: ", LEN(records), " test(s) run");')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE), NULL,')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_build: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_build: FAILED"); '
      'PANIC("build tests failed")), NULL);')
    A('PRINT("test_build: OK");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines, %d file assertions)'
          % (OUT, chars, lines, len(rels)))


if __name__ == '__main__':
    main()
