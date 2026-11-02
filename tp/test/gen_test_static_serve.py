"""生成 tp/test/test_static_serve.wll —— 静态服务内核的脱网测试（卡 S3-1）。

⚠ 输出的 .wll 由本文件生成，不要手改。

**为什么能脱网**：`tp/lib/static_serve.wll` 是纯函数（不碰 socket），
所以测试只需在 `TEMP_DIR()` 里造出产物树，然后直接调 `HANDLE` 比对
`status` / `headers`（含**顺序**）/ `body`。

**基准**：tp/test/fixtures/static_serve_baseline.json
（由 `gen_static_serve_baseline.py` 生成：手写期望值 + 出处行号，
并对 `tinypage/security.py:331` 与 `tinypage/frontend.py:35` 做真 Python 交叉校验）。

**覆盖**（每条用例 4 组断言：status / 头序 / 每个头的值 / body）：
  · 200 正常文件、`/` 与 `/list/` 的目录回落
  · 长缓存命中（.css/.js/.woff/.woff2）与未命中（.html/.txt）
  · 404（不存在 / 隐藏 / 敏感 / 穿越 / 坏 percent 转义）
  · 405（POST / PUT / DELETE）
  · HEAD（body 空但头齐全、Content-Length 是真实长度）
  · 9 项 Permissions-Policy 逐字 + 5 个头的顺序
  · 反向守卫：/.git/config、/../secret.txt、/admin_password.txt 必须 404

**自己把关退出码**：`RUN_TESTS()` 的失败**不影响退出码**（规范明载）
⇒ 末尾必须 `IF(>(failed, 0), PANIC(...), NULL)`。

用法：python gen_test_static_serve.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_static_serve.wll')


def wl_string(s):
    """Python 字符串 → WLWL 字面量。⚠ `${...}` / `$x` 是插值 ⇒ 字面美元符写 \\$。"""
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


def opts_expr(case, root_var='root'):
    """HANDLE 的 opts：root / method / path / query（键序固定，便于阅读）。"""
    return ('INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "root", %s), "method", %s), '
            '"path", %s), "query", %s)'
            % (root_var, wl_string(case['method']), wl_string(case['path']),
               wl_string(case['query'])))


def main():
    with open(os.path.join(FIXTURES, 'static_serve_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)

    cases = base['cases']
    unit = base['unit']
    tree = base['tree']

    src = []
    A = src.append
    A('// tp/test/test_static_serve.wll —— 静态服务内核的脱网测试（卡 S3-1）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_static_serve.py 生成 —— 请勿手改。')
    A('//')
    A('// 被测：tp/lib/static_serve.wll 的 HANDLE / MIME_TYPE / SECURITY_HEADERS。')
    A('// 基准：tp/test/fixtures/static_serve_baseline.json')
    A('//   · 手写期望值 + 出处行号（nginx.conf / security.py / frontend.py）')
    A('//   · 生成期已对 tinypage 的真 Python 做交叉校验（见该 JSON 的 meta.cross_checks）')
    A('//')
    A('// 本文件是**脱网**的：产物树在 TEMP_DIR() 里现造，不碰 socket。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS", "TEMP_DIR"]);')
    A('IMPORT("wlwl:std.fs", ["MKDIRS", "WRITE_FILE", "PATH_JOIN", "PATH_CANONICAL"]);')
    A('IMPORT("wlwl:std.str", ["JOIN", "CAT"]);')
    A('IMPORT("./../lib/static_serve.wll", ["HANDLE", "MIME_TYPE", "SECURITY_HEADERS"]);')
    A('')

    # ── 造产物树 ────────────────────────────────────────────────────
    A('// ── 产物树（结构照 tinypage 的产物布局；内容见夹具 tree.files）──────')
    A('LET(root, PATH_CANONICAL(TEMP_DIR()));')
    A('PRINT("fixture root: ", root);')
    for d in tree['dirs']:
        A('IF(IS_ERR(MKDIRS(PATH_JOIN(root, %s))), PANIC(%s), NULL);'
          % (wl_string(d), wl_string('mkdirs failed: ' + d)))
    for rel, text in tree['files'].items():
        A('IF(IS_ERR(WRITE_FILE(PATH_JOIN(root, %s), %s)), PANIC(%s), NULL);'
          % (wl_string(rel), wl_string(text), wl_string('write failed: ' + rel)))
    A('')

    # ── 逐用例：预计算响应（LET 不能进 TEST 的 FUN 体）──────────────────
    A('// ── 预计算每个用例的响应（⚠ LET 不能放进 TEST 的 FUN 体）────────────')
    for c in cases:
        A('// %s —— %s' % (c['name'], c['note']))
        A('//   出处：%s' % c['source'])
        A('LET(resp_%s, HANDLE(%s));' % (c['name'], opts_expr(c)))
    A('')

    # ── 逐用例：断言 ────────────────────────────────────────────────
    A('// ── 用例断言：status / 头序 / 每个头的值 / body ──────────────────')
    for c in cases:
        hdrs = c['headers']
        names = [k for k, _ in hdrs]
        A('')
        A('// %s' % c['name'])
        A('TEST("handle/%s/status", FUN(() ,' % c['name'])
        A('    (ASSERT_EQ(AT_K(resp_%s, "status", -1), %d));' % (c['name'], c['status']))
        A('    TRUE));')
        A('TEST("handle/%s/header_order", FUN(() ,' % c['name'])
        A('    (ASSERT_EQ(JOIN(KEYS(AT_K(resp_%s, "headers", DICT())), "|"), %s));'
          % (c['name'], wl_string('|'.join(names))))
        A('    TRUE));')
        for k, v in hdrs:
            A('TEST("handle/%s/header/%s", FUN(() ,' % (c['name'], k))
            A('    (ASSERT_EQ(AT_K(AT_K(resp_%s, "headers", DICT()), %s, "<missing>"), %s));'
              % (c['name'], wl_string(k), wl_string(v)))
            A('    TRUE));')
        A('TEST("handle/%s/body", FUN(() ,' % c['name'])
        A('    (ASSERT_EQ(AT_K(resp_%s, "body", "<missing>"), %s));'
          % (c['name'], wl_string(c['body'])))
        A('    TRUE));')

    # ── 反向守卫（显式三条 + 头数）──────────────────────────────────
    A('')
    A('// ── 反向守卫（卡 S3-1 明确要求的三条，单独钉一次）─────────────────')
    for gname, case_name, want in [
        ('git_config', 'hidden_git_config', 404),
        ('traversal', 'traversal_plain', 404),
        ('admin_password', 'sensitive_admin_password', 404),
    ]:
        A('TEST("guard/%s_must_%d", FUN(() ,' % (gname, want))
        A('    (ASSERT_EQ(AT_K(resp_%s, "status", -1), %d));' % (case_name, want))
        A('    TRUE));')
    A('')
    A('// ── 反向守卫：Cache-Control 只发**一个**（发两个就会多出一个键）────────')
    A('LET(resp_keys_200, KEYS(AT_K(resp_article, "headers", DICT())));')
    A('TEST("guard/single_cache_control", FUN(() ,')
    A('    (ASSERT_EQ(LEN(resp_keys_200), 8));')
    A('    TRUE));')
    A('TEST("guard/no_csp_on_public_site", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(AT_K(resp_article, "headers", DICT()), '
      '"Content-Security-Policy", "<absent>"), "<absent>"));')
    A('    TRUE));')

    # ── 单元：SECURITY_HEADERS ──────────────────────────────────────
    sec = unit['security_headers']
    A('')
    A('// ── 单元：SECURITY_HEADERS（顺序 = nginx.conf:9-13 = security.py:331）──')
    A('LET(sh, SECURITY_HEADERS());')
    A('TEST("security/order", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(sh), "|"), %s));'
      % wl_string('|'.join(k for k, _ in sec)))
    A('    TRUE));')
    for k, v in sec:
        A('TEST("security/%s", FUN(() ,' % k)
        A('    (ASSERT_EQ(AT_K(sh, %s, "<missing>"), %s));' % (wl_string(k), wl_string(v)))
        A('    TRUE));')
    A('// ⚠ Permissions-Policy 的项数：`nginx.conf:13` 与 `security.py:338` **都是 8 项**')
    A('//   （accelerometer / camera / geolocation / gyroscope / magnetometer /')
    A('//     microphone / payment / usb）—— 卡 S3-1 写「9 项」是数错，本实现以源码为准；')
    A('//   生成期已断言它与 `get_security_headers()` **逐字相等**。')
    A('//   这里再用逗号数钉一次，防「漏一项 / 多一项」的回归。')
    n_policy_items = len(dict(sec)['Permissions-Policy'].split(','))
    A('TEST("security/permissions_policy_items", FUN(() ,')
    A('    (ASSERT_EQ(LEN(SPLIT(AT_K(sh, "Permissions-Policy", ""), ",")), %d));'
      % n_policy_items)
    A('    TRUE));')
    A('// 反向守卫：公开站**不**发 CSP（security.py:342 是 admin 专用）')
    A('TEST("security/no_csp", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(sh, "Content-Security-Policy", "<absent>"), "<absent>"));')
    A('    TRUE));')

    # ── 单元：MIME_TYPE ─────────────────────────────────────────────
    A('')
    A('// ── 单元：MIME_TYPE（对齐 frontend.py:74；字体按 D-2 取 nginx 值）────')
    for row in unit['mime']:
        p, want = row['path'], row['want']
        safe = p.replace('.', '_').replace('/', '_')
        A('TEST("mime/%s", FUN(() ,' % safe)
        A('    (ASSERT_EQ(MIME_TYPE(INDEX_SET(DICT(), "path", %s)), %s));'
          % (wl_string(p), wl_string(want)))
        A('    TRUE));')

    # ── 跑测试 + 自己把关退出码 ─────────────────────────────────────
    A('')
    A('// ── 跑测试 + 自己把关退出码 ─────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_static_serve: ", LEN(records), " test(s) run");')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"), " :: ", '
      'AT_K(rec, "error", ""))))));')
    A('PRINT("test_static_serve: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_static_serve: FAILED"); '
      'PANIC("static_serve tests failed")), NULL);')
    A('PRINT("test_static_serve: OK");')

    chars, lines = write(OUT, src)
    n_tests = (len(cases) * 11 + len(unit['mime']) + len(sec) + 2 + 3 + 2 + 1)
    print('wrote %s (%d chars, %d lines, ~%d tests)'
          % (OUT, chars, lines, n_tests))


if __name__ == '__main__':
    main()
