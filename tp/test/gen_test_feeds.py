"""生成 tp/test/test_feeds.wll —— 订阅源与站点文件的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的结果**逐字节对照**。
基准：`tp/test/fixtures/feeds_baseline.json`
（由 `tp/test/gen_feeds_baseline.py` 用真 Python 生成；`robots` 段是真跑
`generate_static_pages` 读回 `robots.txt`，**不是复刻**）。

| 基准组 | WLWL 调用 | 断言 |
|---|---|---|
| `rss` | `RSS(opts)` | `== want`（整串逐字节） |
| `sitemap` | `SITEMAP(opts)` | `== want`（整串逐字节） |
| `robots` | `ROBOTS(INDEX_SET(DICT(), "site_url", …))` | `== want`（整串逐字节） |

**两条分层用例（对应 lib/feeds.wll 文件头的 F1）**：
· `rss/draft_raw` —— 原样喂含草稿的列表 ⇒ 草稿**在**输出里（`generate_rss` 不过滤）；
· `rss/draft_filtered` —— 喂**调用方 `generator.py:730` 过滤后**的列表 ⇒ 草稿**不在**。
两条都要与 Python 逐字节相等，否则说明我们擅自把过滤塞进了错的那一层。

**反向守卫**（7 条）：
1. `guard/rss_no_bare_amp` —— 每个 `&` 都必须是一个合法实体（不得出现裸 `&`）
2. `guard/rss_cap_is_20` —— 25 篇输入只出 20 个 `<item>`
3. `guard/sitemap_no_lastmod_changefreq` —— 不得出现 `<lastmod` / `<changefreq`
4. `guard/robots_no_localhost_fallback` —— 空 site_url **不**回落 localhost
5. `guard/rss_draft_layer` —— 草稿只在 raw 层出现，filtered 层必须消失
6. `guard/sitemap_draft_present_upstream` —— 钉死上游现状（草稿**在** sitemap 里）
7. `guard/null_opts_ok` —— 三个导出函数收到 NULL 不得崩

⚠ `RUN_TESTS()` 的失败**不影响退出码**（规范明载）⇒ 本文件末尾自己把关。

用法：python gen_test_feeds.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_feeds.wll')

# 与 gen_feeds_baseline.py 的 ARTICLE_KEYS 逐字一致
ARTICLE_KEYS = ('title', 'date', 'summary', 'status', 'file', 'date_obj')


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量（只转义白名单内的字符）。"""
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
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def art_expr(a):
    """基准里的文章 DICT → `_ART(...)` 调用（6 参数，见 _ART 定义）。"""
    extra = set(a) - set(ARTICLE_KEYS)
    if extra:
        raise ValueError('article spec has keys the test helper does not '
                         'handle: %r' % sorted(extra))
    return '_ART(%s, %s, %s, %s, %s, %s)' % (
        wl_string(a['title']),
        wl_string(a['date']),
        wl_string(a['summary']),
        wl_string(a['status']),
        wl_string(a['file']),
        wl_string(a['date_obj'] or ''),
    )


def emit_art_array(A, var, articles):
    """把文章列表渲染成 WLWL 数组（PUSH 累积；空列表就是 []）。"""
    A('LET MUT(%s, []);' % var)
    for a in articles:
        A('SET(%s, PUSH(%s, %s));' % (var, var, art_expr(a)))


def emit_str_array(A, var, values):
    A('LET MUT(%s, []);' % var)
    for v in values:
        A('SET(%s, PUSH(%s, %s));' % (var, var, wl_string(v)))


def emit_cfg(A, var, cfg):
    """config DICT：基准里只有字符串值 ⇒ 逐键 INDEX_SET。"""
    A('LET MUT(%s, DICT());' % var)
    for k in sorted(cfg):
        v = cfg[k]
        if not isinstance(v, str):
            raise ValueError('config value must be str: %r=%r' % (k, v))
        A('SET(%s, INDEX_SET(%s, %s, %s));' % (var, var, wl_string(k), wl_string(v)))


def test_block(A, name, got, want, note=None):
    if note:
        A('// ⚠ %s：%s' % (name, note))
    A('TEST(%s, FUN(() ,' % wl_string(name))
    A('    (ASSERT_EQ(%s, %s));' % (got, want))
    A('    TRUE));')


def main():
    with open(os.path.join(FIXTURES, 'feeds_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']

    src = []
    A = src.append
    A('// tp/test/test_feeds.wll —— 订阅源与站点文件的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_feeds.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的结果逐字节对照。')
    A('// 基准：tp/test/fixtures/feeds_baseline.json')
    A('//   （由 tp/test/gen_feeds_baseline.py 用真 Python 生成；robots 段是真跑')
    A('//     generate_static_pages 读回 robots.txt，**不是复刻**。）')
    A('//')
    A('// ⚠ 分层：草稿过滤**不在** generate_rss 里，在调用方 generator.py:730')
    A('//   ⇒ rss/draft_raw（原样）与 rss/draft_filtered（调用方过滤后）两条都要对。')
    A('// ⚠ sitemap 用的是**未过滤**的 articles（generator.py:736）⇒ 草稿在 sitemap 里，')
    A('//   这是上游现状，不是本实现的偏差（见 guard/sitemap_draft_present_upstream）。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件末尾自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_FIND_ALL"]);')
    A('IMPORT("./../lib/feeds.wll", ["RSS", "SITEMAP", "ROBOTS"]);')
    A('')
    A('// ── 工具：把基准的 6 个字段包成 ArticleMeta 的 DICT ────────────────')
    A('//   date_obj："" ⇒ NULL；否则 DICT{"iso": <datetime.isoformat()>}')
    A('//   （iso_date 只用到 isoformat()，故与 Python 逐字节等价；见 lib/feeds.wll）')
    A('LET(_ART, FUN((t, d, s, st, f, iso), (')
    A('      LET MUT(a, DICT());')
    A('      SET(a, INDEX_SET(a, "title", t));')
    A('      SET(a, INDEX_SET(a, "date", d));')
    A('      SET(a, INDEX_SET(a, "slug", ""));')
    A('      SET(a, INDEX_SET(a, "tags", ""));')
    A('      SET(a, INDEX_SET(a, "summary", s));')
    A('      SET(a, INDEX_SET(a, "category", ""));')
    A('      SET(a, INDEX_SET(a, "status", st));')
    A('      SET(a, INDEX_SET(a, "file", f));')
    A('      SET(a, INDEX_SET(a, "date_obj", IF(==(iso, ""), NULL, '
      'INDEX_SET(DICT(), "iso", iso))));')
    A('      a)));')
    A('')

    # ── RSS：数据 ────────────────────────────────────────────────
    A('// ── RSS：输入数据 ────────────────────────────────────────────')
    for name in sorted(cases['rss']):
        e = cases['rss'][name]
        var = 'rss_%s' % name
        emit_art_array(A, 'ar_%s' % var, e['articles'])
        emit_cfg(A, 'cfg_%s' % var, e['config'])
    A('')

    # ── SITEMAP：数据 ────────────────────────────────────────────
    A('// ── SITEMAP：输入数据 ────────────────────────────────────────')
    for name in sorted(cases['sitemap']):
        e = cases['sitemap'][name]
        var = 'sitemap_%s' % name
        emit_art_array(A, 'ar_%s' % var, e['articles'])
        emit_art_array(A, 'st_%s' % var, e['standalones'])
        emit_str_array(A, 'ct_%s' % var, e['categories'])
        emit_cfg(A, 'cfg_%s' % var, e['config'])
    A('')

    # ── RSS：期望值 + 用例 ───────────────────────────────────────
    A('// ── RSS：期望值（真 Python 的字节）─────────────────────────────')
    for name in sorted(cases['rss']):
        e = cases['rss'][name]
        var = 'rss_%s' % name
        A('LET(want_%s, %s);' % (var, wl_string(e['want'])))
    A('')
    A('// ── RSS：用例 ────────────────────────────────────────────────')
    for name in sorted(cases['rss']):
        e = cases['rss'][name]
        var = 'rss_%s' % name
        A('LET MUT(o_%s, DICT());' % var)
        A('SET(o_%s, INDEX_SET(o_%s, "articles", ar_%s));' % (var, var, var))
        A('SET(o_%s, INDEX_SET(o_%s, "config", cfg_%s));' % (var, var, var))
        A('LET(got_%s, RSS(o_%s));' % (var, var))
        test_block(A, 'rss/%s' % name, 'got_%s' % var, 'want_%s' % var,
                   e.get('note'))
        A('')

    # ── SITEMAP：期望值 + 用例 ──────────────────────────────────
    A('// ── SITEMAP：期望值（真 Python 的字节）─────────────────────────')
    for name in sorted(cases['sitemap']):
        e = cases['sitemap'][name]
        var = 'sitemap_%s' % name
        A('LET(want_%s, %s);' % (var, wl_string(e['want'])))
    A('')
    A('// ── SITEMAP：用例 ───────────────────────────────────────────')
    for name in sorted(cases['sitemap']):
        e = cases['sitemap'][name]
        var = 'sitemap_%s' % name
        A('LET MUT(o_%s, DICT());' % var)
        A('SET(o_%s, INDEX_SET(o_%s, "articles", ar_%s));' % (var, var, var))
        A('SET(o_%s, INDEX_SET(o_%s, "standalones", st_%s));' % (var, var, var))
        A('SET(o_%s, INDEX_SET(o_%s, "categories", ct_%s));' % (var, var, var))
        A('SET(o_%s, INDEX_SET(o_%s, "config", cfg_%s));' % (var, var, var))
        A('LET(got_%s, SITEMAP(o_%s));' % (var, var))
        test_block(A, 'sitemap/%s' % name, 'got_%s' % var, 'want_%s' % var,
                   e.get('note'))
        A('')

    # ── ROBOTS：用例 ────────────────────────────────────────────
    A('// ── ROBOTS：用例（robots.txt 无独立函数 ⇒ 基准是真跑 generate_static_pages）')
    for name in sorted(cases['robots']):
        e = cases['robots'][name]
        var = 'robots_%s' % name
        A('LET(got_%s, ROBOTS(INDEX_SET(DICT(), "site_url", %s)));'
          % (var, wl_string(e['site_url'])))
        A('LET(want_%s, %s);' % (var, wl_string(e['want'])))
        test_block(A, 'robots/%s' % name, 'got_%s' % var, 'want_%s' % var,
                   e.get('note'))
        A('')

    # ── 反向守卫 ────────────────────────────────────────────────
    A('// ── 反向守卫 ────────────────────────────────────────────────')
    A('// ① 每个 & 都必须是一个合法实体（XML 里不得出现裸 &）')
    A('//    做法：数 "&" 的总数，与 "&(amp|lt|gt|quot|#x27);" 的匹配数比。')
    A('//    ⚠ 不能用 RE_TEST（整串锚定，判不出"含子串"，见 README 陷阱 #36）')
    A('LET(_amp_all_, LEN(RE_FIND_ALL(RE("&"), got_rss_special_chars)));')
    A('LET(_amp_ent_, LEN(RE_FIND_ALL(RE("&(amp|lt|gt|quot|#x27);"), '
      'got_rss_special_chars)));')
    A('TEST("guard/rss_no_bare_amp", FUN(() ,')
    A('    (ASSERT(>(_amp_all_, 0)));')
    A('    (ASSERT_EQ(_amp_ent_, _amp_all_));')
    A('    TRUE));')
    A('')
    A('// ② 25 篇输入只出 20 个 <item>（截断在 generate_rss 内部）')
    A('TEST("guard/rss_cap_is_20", FUN(() ,')
    A('    (ASSERT_EQ(LEN(ar_rss_cap20), 25));')
    A('    (ASSERT_EQ(LEN(RE_FIND_ALL(RE("<item>"), got_rss_cap20)), 20));')
    A('    TRUE));')
    A('')
    A('// ③ sitemap 不得有 lastmod / changefreq（与现状一致）')
    A('TEST("guard/sitemap_no_lastmod_changefreq", FUN(() ,')
    A('    (ASSERT_EQ(LEN(RE_FIND_ALL(RE("<lastmod"), got_sitemap_all)), 0));')
    A('    (ASSERT_EQ(LEN(RE_FIND_ALL(RE("<changefreq"), got_sitemap_all)), 0));')
    A('    TRUE));')
    A('')
    A('// ④ robots 的 Sitemap: 行**不回落** localhost（F3）')
    A('TEST("guard/robots_no_localhost_fallback", FUN(() ,')
    A('    (ASSERT_EQ(LEN(RE_FIND_ALL(RE("localhost:8080"), '
      'got_robots_empty_url)), 0));')
    A('    (ASSERT_EQ(LEN(RE_FIND_ALL(RE("Sitemap: /sitemap[.]xml"), '
      'got_robots_empty_url)), 1));')
    A('    TRUE));')
    A('')
    A('// ⑤ 草稿的两层：raw 层在、filtered 层不在（F1）')
    A('//    ⚠ 字面量点用 [.]（README 陷阱 #26：RE 里 "\\." 是字面反斜杠+点）')
    A('//    ⚠ raw 层的计数是 **2**（<link> 与 <guid> 各一次，都指向同一 URL）⇒ 判 >0，')
    A('//      别写成 ==1（写死具体次数会把「模板加了一条重复引用」也测成红的）。')
    A('TEST("guard/rss_draft_layer", FUN(() ,')
    A('    (ASSERT(>(LEN(RE_FIND_ALL(RE("draft[.]html"), got_rss_draft_raw)), 0)));')
    A('    (ASSERT_EQ(LEN(RE_FIND_ALL(RE("draft[.]html"), '
      'got_rss_draft_filtered)), 0));')
    A('    TRUE));')
    A('')
    A('// ⑥ 钉死上游现状：sitemap 用的是未过滤的 articles ⇒ 草稿**在** sitemap 里')
    A('//    （卡片的「草稿不得出现在 sitemap」与 generator.py:736 冲突 —— 已登记为')
    A('//      差异项；这里按**真实实现**断言，改动上游时要先改这条）')
    A('TEST("guard/sitemap_draft_present_upstream", FUN(() ,')
    A('    (ASSERT_EQ(LEN(RE_FIND_ALL(RE("draft[.]html"), '
      'got_sitemap_draft_included)), 1));')
    A('    TRUE));')
    A('')
    A('// ⑦ 三个导出函数收到 NULL 不得崩（AT_K(NULL, …) 是 E0030，先判 TYPE）')
    A('TEST("guard/null_opts_ok", FUN(() ,')
    A('    (ASSERT_EQ(TYPE(RSS(NULL)), "STRING"));')
    A('    (ASSERT_EQ(TYPE(SITEMAP(NULL)), "STRING"));')
    A('    (ASSERT_EQ(TYPE(ROBOTS(NULL)), "STRING"));')
    A('    TRUE));')
    A('')

    # ── 跑测试 ──────────────────────────────────────────────────
    A('// ── 跑测试 ──────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_feeds: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_feeds: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_feeds: FAILED"); '
      'PANIC("feeds tests failed")), NULL);')
    A('PRINT("test_feeds: OK");')

    chars, lines = write(OUT, src)
    n = sum(len(v) for v in cases.values()) + 7
    print('wrote %s (%d chars, %d lines, %d baseline cases + 7 guards)'
          % (OUT, chars, lines, n - 7))


if __name__ == '__main__':
    main()
