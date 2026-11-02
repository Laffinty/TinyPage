"""生成 tp/test/test_security.wll —— 卡 S4-1（会话与 CSRF）+ S4-2（限流与审计）的测试。

⚠ 输出的 .wll 由本文件生成，不要手改。

**基准**：tp/test/fixtures/security_baseline.json
（由 `gen_security_baseline.py` 调真 Python 产出；唯一替换是 HMAC 的字节↔hex
 编码，见 D-S4-1。）

**覆盖**
  · CSRF token：注入 secret/random/now_ms 后**逐字节**等于 Python 期望值；
    长度 72 / 解码 52 / 尾部 ==（形状不变量）；真随机路径只比结构不比随机值。
  · CSRF 校验 34 例：正常、篡改 1 字节、超 1h、边界 3600/60、格式错、
    cookie 不一致 / 首个同名 cookie、Origin/Referer 白名单（含前缀伪造照抄）。
  · Cookie 头：CSRF / 会话 / 清会话，含 Secure 与 Max-Age，逐字对齐。
  · 会话：24h 过期、边界、destroy、from_cookie、上限淘汰（max_sessions=3
    复刻算法）、清空后旧 token 全失效（进程重启替身）。
  · 限流：滑动窗口 5 次放行/第 6 次被限/窗口滑过恢复；登录失败 5 次锁定、
    第 6 次仍被限、300 秒后恢复；max_ips 上限；每步 6 个字段逐值对拍。
  · 审计：JSONL 单行，msg 逐字取自真 Python 日志；未知事件 ⇒ ""。
  · 口令：Argon2id 官方向量 + 自定存储格式 + 错口令必拒；PBKDF2 600k 向量。

⚠ RUN_TESTS() 的失败**不影响退出码** ⇒ 末尾自己 `IF(failed > 0, PANIC)`。

用法：python gen_test_security.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_security.wll')

EXPORTS = ['NEW_CSRF_TOKEN', 'VALIDATE_CSRF_TOKEN', 'CSRF_COOKIE_HEADER',
           'NEW_SESSION_TOKEN', 'SESSION_COOKIE_HEADER',
           'SESSION_CLEAR_COOKIE_HEADER', 'SESSION_CREATE', 'SESSION_VALIDATE',
           'SESSION_DESTROY', 'SESSION_RESET', 'SESSION_COUNT',
           'SESSION_FROM_COOKIE', 'SESSION_CONFIG', 'RATE_LIMIT',
           'RATE_LIMIT_RESET', 'AUDIT_EVENT', 'HASH_PASSWORD', 'VERIFY_PASSWORD']


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


def val_expr(v):
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return wl_string(v)
    if isinstance(v, dict):
        return dict_expr(v)
    if v is None:
        return 'NULL'
    raise TypeError('bad value: %r' % (v,))


def dict_expr(d):
    expr = 'DICT()'
    for k, v in d.items():
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl_string(k), val_expr(v))
    return expr


def test(name, asserts):
    """一条 TEST；asserts 是已渲染的断言语句列表（每条自带分号）。"""
    lines = ['TEST(%s, FUN(() ,' % wl_string(name)]
    for a in asserts:
        lines.append('    (%s);' % a)
    lines.append('    TRUE));')
    return lines


def main():
    with open(os.path.join(FIXTURES, 'security_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)

    src = []
    A = src.append
    A('// tp/test/test_security.wll —— 卡 S4-1（会话与 CSRF）+ S4-2（限流与审计）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_security.py 生成 —— 请勿手改。')
    A('//')
    A('// 被测：tp/lib/security.wll')
    A('// 基准：tp/test/fixtures/security_baseline.json')
    A('//   · 期望值由真 Python（tinypage/security.py）产出')
    A('//   · 唯一替换：HMAC 的 key/data 以 hex 文本参与（D-S4-1）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败不影响退出码（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "JOIN"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_TEST"]);')
    A('IMPORT("./../lib/security.wll", [%s]);'
      % ', '.join('"%s"' % e for e in EXPORTS))
    A('')

    # ── CSRF token ────────────────────────────────────────────────
    csrf = base['csrf']
    A('// ── CSRF token：注入 secret/random/now_ms ⇒ 与 Python 逐字节一致 ──────')
    tok_opts = {'secret': csrf['secret'], 'random_hex': csrf['random_hex'],
                'now_ms': csrf['now_ms']}
    A('LET(tok, NEW_CSRF_TOKEN(%s));' % dict_expr(tok_opts))
    src += test('csrf/token_exact', [
        'ASSERT_EQ(tok, %s)' % wl_string(csrf['token']),
        'ASSERT_EQ(LEN(tok), %d)' % csrf['token_len'],
    ])
    src += test('csrf/token_shape', [
        'ASSERT_EQ(LEN(tok), 72)',
        'ASSERT(ENDS_WITH(tok, "=="))',
        'ASSERT(RE_TEST(RE("^[A-Za-z0-9_-]+==$"), tok))',
    ])
    # 随机路径的结构不变量（不比值）
    A('LET(rt1, NEW_CSRF_TOKEN(DICT()));')
    A('LET(rt2, NEW_CSRF_TOKEN(DICT()));')
    src += test('csrf/random_distinct', [
        'ASSERT(!=(rt1, rt2))',
        'ASSERT_EQ(LEN(rt1), 72)',
        'ASSERT_EQ(LEN(rt2), 72)',
    ])
    A('LET(rt_ok, VALIDATE_CSRF_TOKEN(INDEX_SET(INDEX_SET(DICT(), "token", rt1), '
      '"cookie", CAT("csrf_token=", rt1))));')
    src += test('csrf/random_token_validates', [
        'ASSERT_EQ(rt_ok, TRUE)',
    ])

    # ── CSRF 校验用例 ─────────────────────────────────────────────
    A('')
    A('// ── CSRF 校验：34 例逐条对拍（顺序 = 源码的格式→HMAC→时限→cookie→Origin）──')
    for i, c in enumerate(base['csrf_cases']):
        A('// %s —— %s' % (c['name'], c['note']))
        A('LET(csrf_%d, VALIDATE_CSRF_TOKEN(%s));' % (i, dict_expr(c['opts'])))
        src += test('csrf/%s' % c['name'], [
            'ASSERT_EQ(csrf_%d, %s)' % (i, val_expr(c['want'])),
        ])
    A('')

    # ── 反向守卫（卡片点名的四条 + 前缀伪造）─────────────────────
    A('// ── 反向守卫（卡片点名的四条，单独再钉一次）──────────────────────')
    guards = [
        ('tampered_token_must_reject', 'fail_tamper_sig'),
        ('expired_token_must_reject', 'fail_expired_3601'),
        ('cookie_mismatch_must_reject', 'fail_cookie_mismatch'),
        ('origin_not_whitelisted_must_reject', 'fail_origin_evil'),
    ]
    idx = {c['name']: i for i, c in enumerate(base['csrf_cases'])}
    for gname, cname in guards:
        A('TEST("guard/%s", FUN(() ,' % gname)
        A('    (ASSERT_EQ(csrf_%d, FALSE));' % idx[cname])
        A('    TRUE));')
    A('// 照抄源码的前缀匹配：这条**故意**通过（不是漏洞修复漏项，是行为对齐）')
    A('TEST("guard/origin_prefix_spoof_matches_source", FUN(() ,')
    A('    (ASSERT_EQ(csrf_%d, TRUE));' % idx['ok_origin_prefix_spoof'])
    A('    TRUE));')
    A('')

    # ── Cookie 头 ─────────────────────────────────────────────────
    A('// ── Cookie 头：逐字对齐（含 Secure / Max-Age 的出现与顺序）────────')
    for c in base['cookies']:
        want = c['want']
        var = 'ck_' + c['name']
        A('LET(%s, %s);' % (var, {
            'csrf_plain': 'CSRF_COOKIE_HEADER(%s)' % dict_expr(c['opts']),
            'csrf_secure': 'CSRF_COOKIE_HEADER(%s)' % dict_expr(c['opts']),
            'session_plain': 'SESSION_COOKIE_HEADER(%s)' % dict_expr(c['opts']),
            'session_secure_maxage60': 'SESSION_COOKIE_HEADER(%s)' % dict_expr(c['opts']),
            'session_clear': 'SESSION_CLEAR_COOKIE_HEADER(%s)' % dict_expr(c['opts']),
            'session_clear_secure': 'SESSION_CLEAR_COOKIE_HEADER(%s)' % dict_expr(c['opts']),
        }[c['name']]))
        src += test('cookie/%s' % c['name'], [
            'ASSERT_EQ(LEN(%s), 2)' % var,
            'ASSERT_EQ(AT(%s, 0, ""), %s)' % (var, wl_string(want[0])),
            'ASSERT_EQ(AT(%s, 1, ""), %s)' % (var, wl_string(want[1])),
        ])
    A('')

    # ── 会话 token / 常量 ─────────────────────────────────────────
    st = base['sessions']['token']
    A('// ── 会话 token：32B → urlsafe base64 **去 padding**（43 字符）────────')
    A('LET(sess_tok, NEW_SESSION_TOKEN(%s));'
      % dict_expr({'random_hex': st['random_hex']}))
    src += test('session/token_exact', [
        'ASSERT_EQ(sess_tok, %s)' % wl_string(st['want']),
        'ASSERT_EQ(LEN(sess_tok), %d)' % st['want_len'],
        'ASSERT(RE_TEST(RE("^[A-Za-z0-9_-]+$"), sess_tok))',
    ])

    cfg = base['sessions']['config']
    A('')
    A('// ── 会话常量（源码类属性：24h / 5000 / 300s）────────────────────')
    A('LET(scfg, SESSION_CONFIG(DICT()));')
    src += test('session/config', [
        'ASSERT_EQ(AT_K(scfg, "max_age", -1), %d)' % cfg['max_age'],
        'ASSERT_EQ(AT_K(scfg, "max_tracked", -1), %d)' % cfg['max_tracked'],
        'ASSERT_EQ(AT_K(scfg, "cleanup_interval", -1), %d)' % cfg['cleanup_interval'],
        'ASSERT_EQ(AT_K(scfg, "max_failures", -1), 5)',
        'ASSERT_EQ(AT_K(scfg, "lockout_seconds", -1), 300)',
    ])

    # ── 会话场景 ──────────────────────────────────────────────────
    def emit_session(scenario, prefix, max_sessions=None):
        A('')
        A('// ── 会话场景：%s ────────────────────────────────────────' % prefix)
        A('// %s' % scenario['note'])
        A('SESSION_RESET(DICT());')
        toks = {}
        created = set()
        destroyed = set()
        for i, e in enumerate(scenario['events']):
            var = None
            if e['op'] == 'create':
                opts = {'client_ip': e.get('client_ip', ''), 'now_ms': e['at_ms']}
                if max_sessions is not None:
                    opts['max_sessions'] = max_sessions
                var = 'tok_%s_%s' % (prefix, e['as'])
                A('LET(%s, SESSION_CREATE(%s));' % (var, dict_expr(opts)))
                toks[e['as']] = var
                created.add(e['as'])
                want = scenario['results'][i]
                src.extend(test('session/%s/create/%s' % (prefix, e['as']), [
                    'ASSERT_EQ(LEN(%s), %d)' % (var, want['len']),
                    'ASSERT(RE_TEST(RE("^[A-Za-z0-9_-]+$"), %s))' % var,
                ]))
            elif e['op'] == 'validate':
                ref = e.get('ref', '')
                tokexpr = toks.get(ref, '""')
                var = 'sv_%s_%d' % (prefix, i)
                A('LET(%s, SESSION_VALIDATE(INDEX_SET(INDEX_SET(DICT(), "token", %s), '
                  '"now_ms", %d)));' % (var, tokexpr, e['at_ms']))
                src.extend(test('session/%s/validate/%d' % (prefix, i), [
                    'ASSERT_EQ(%s, %s)' % (var, val_expr(scenario['results'][i])),
                ]))
            elif e['op'] == 'destroy':
                ref = e.get('ref', '')
                tokexpr = toks.get(ref, '""')
                existed = ref in created and ref not in destroyed
                if ref in created:
                    destroyed.add(ref)
                var = 'sd_%s_%d' % (prefix, i)
                A('LET(%s, SESSION_DESTROY(INDEX_SET(DICT(), "token", %s)));'
                  % (var, tokexpr))
                src.extend(test('session/%s/destroy/%d' % (prefix, i), [
                    'ASSERT_EQ(%s, %s)' % (var, 'TRUE' if existed else 'FALSE'),
                ]))
            elif e['op'] == 'from_cookie':
                var = 'sf_%s_%d' % (prefix, i)
                A('LET(%s, SESSION_FROM_COOKIE(INDEX_SET(DICT(), "cookie", %s)));'
                  % (var, wl_string(e['cookie'])))
                src.extend(test('session/%s/from_cookie/%d' % (prefix, i), [
                    'ASSERT_EQ(%s, %s)' % (var, wl_string(scenario['results'][i])),
                ]))
        A('LET(cnt_%s, SESSION_COUNT(DICT()));' % prefix)
        src.extend(test('session/%s/count' % prefix, [
            'ASSERT_EQ(cnt_%s, %d)' % (prefix, scenario['count']),
        ]))
        return toks

    toks_main = emit_session(base['sessions']['scenario_main'], 'main')
    toks_evict = emit_session(base['sessions']['scenario_evict'], 'evict',
                              max_sessions=base['sessions']['scenario_evict']['max_tracked'])

    # 进程重启替身：清空后旧 token 全失效
    A('')
    A('// ── 反向守卫：清空注册表（进程重启替身）后旧 token 全失效──────────')
    A('SESSION_RESET(DICT());')
    for i, ref in enumerate(base['sessions']['scenario_restart']['refs']):
        var = toks_main.get(ref) or toks_evict.get(ref)
        A('LET(rst_%d, SESSION_VALIDATE(INDEX_SET(INDEX_SET(DICT(), "token", %s), '
          '"now_ms", %d)));' % (i, var, base['sessions']['scenario_main']['events'][0]['at_ms']))
        src.extend(test('guard/restart_invalidates_%s' % ref, [
            'ASSERT_EQ(rst_%d, %s)'
            % (i, val_expr(base['sessions']['scenario_restart']['results'][i])),
        ]))

    # ── 限流 ──────────────────────────────────────────────────────
    A('')
    A('// ── 限流 + 登录锁定：每步 6 个字段逐值对拍 ───────────────────────')
    rate = base['rate']
    for sname in ['window', 'auth', 'max_ips']:
        sc = rate[sname]
        cfgd = {'client_ip': '', 'now_ms': 0, 'event': 'request',
                'max_requests': sc['cfg']['max_requests'],
                'window_seconds': sc['cfg']['window_seconds'],
                'max_failures': sc['cfg']['max_failures'],
                'lockout_seconds': sc['cfg']['lockout_seconds']}
        if sc['cfg'].get('max_ips') is not None:
            cfgd['max_ips'] = sc['cfg']['max_ips']
        A('')
        A('// 场景 %s（%d 步）' % (sname, len(sc['events'])))
        A('RATE_LIMIT_RESET(DICT());')
        for i, (e, want) in enumerate(zip(sc['events'], sc['results'])):
            opts = dict(cfgd)
            opts['client_ip'] = e['client_ip']
            opts['now_ms'] = e['at_ms']
            opts['event'] = e['kind']
            var = 'rl_%s_%d' % (sname, i)
            A('LET(%s, RATE_LIMIT(%s));' % (var, dict_expr(opts)))
            for key in ['allowed', 'retry_after', 'locked', 'lockout_remaining',
                        'failures', 'tracked_ips']:
                src.extend(test('rate/%s/%d/%s' % (sname, i, key), [
                    'ASSERT_EQ(AT_K(%s, "%s", "missing"), %s)'
                    % (var, key, val_expr(want[key])),
                ]))

    # 卡片点名的「第 6 次被限」再单独钉一次
    A('')
    A('// ── 反向守卫：5 次放行后第 6 次必须被限（卡片 S4-2 点名）────────')
    A('TEST("guard/sixth_request_blocked", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(rl_window_5, "allowed", "missing"), FALSE));')
    A('    TRUE));')
    A('TEST("guard/locked_after_five_failures", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(rl_auth_5, "locked", "missing"), TRUE));')
    A('    (ASSERT_EQ(AT_K(rl_auth_6, "allowed", "missing"), FALSE));')
    A('    TRUE));')
    A('// 300 秒后恢复（第 8 步）')
    A('TEST("guard/unlocked_after_300s", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(rl_auth_8, "locked", "missing"), FALSE));')
    A('    (ASSERT_EQ(AT_K(rl_auth_8, "allowed", "missing"), TRUE));')
    A('    TRUE));')

    # ── 审计 ──────────────────────────────────────────────────────
    A('')
    A('// ── 审计：单行 JSONL，msg 逐字取自真 Python 日志 ────────────────')
    for i, a in enumerate(base['audit']['cases']):
        var = 'au_%d' % i
        A('// %s —— %s' % (a['name'], a['note']))
        A('LET(%s, AUDIT_EVENT(%s));' % (var, dict_expr(a['opts'])))
        src.extend(test('audit/%s' % a['name'], [
            'ASSERT_EQ(%s, %s)' % (var, wl_string(a['want'])),
            'ASSERT_EQ(LEN(SPLIT(%s, "\\n")), 1)' % var,
        ]))
    src.extend(test('audit/unknown_event_rejected', [
        'ASSERT_EQ(AUDIT_EVENT(%s), "")'
        % dict_expr({'event': base['audit']['unknown']['event']}),
    ]))
    # 显式 level 覆盖
    src.extend(test('audit/level_override', [
        'ASSERT_EQ(AUDIT_EVENT(%s), %s)'
        % (dict_expr({'event': 'CSRF-FAIL', 'level': 'ERROR', 'now_ms': 1700000000000,
                      'msg': '[CSRF-FAIL] x'}),
           wl_string('{"ts":1700000000000,"level":"ERROR","event":"CSRF-FAIL",'
                     '"msg":"[CSRF-FAIL] x","fields":{}}')),
    ]))

    # ── 口令 ──────────────────────────────────────────────────────
    pw = base['password']
    A('')
    A('// ── 口令：Argon2id 官方向量 + 自定存储格式 + 错口令必拒 ───────────')
    v = pw['argon2_spec_vector']
    A('// 标准库·安全册 §11.5 的官方向量（Python 独立复算一致）')
    A('LET(vec, HASH_PASSWORD(%s));' % dict_expr(
        {'password': v['password'], 'salt_hex': v['salt_hex'], 'len': 32}))
    src.extend(test('password/argon2_spec_vector', [
        'ASSERT_EQ(vec, %s)' % wl_string(v['stored']),
    ]))
    a = pw['argon2']
    A('LET(argon, HASH_PASSWORD(%s));' % dict_expr(
        {'password': a['password'], 'salt_hex': a['salt_hex'],
         't_cost': a['t_cost'], 'm_cost': a['m_cost'], 'p_cost': a['p_cost'],
         'len': a['len']}))
    src.extend(test('password/argon2_stored', [
        'ASSERT_EQ(argon, %s)' % wl_string(a['stored']),
    ]))
    A('LET(av_ok, VERIFY_PASSWORD(%s));' % dict_expr(
        {'password': a['password'], 'stored': a['stored']}))
    A('LET(av_bad, VERIFY_PASSWORD(%s));' % dict_expr(
        {'password': 'wrong horse', 'stored': a['stored']}))
    src.extend(test('password/argon2_verify', [
        'ASSERT_EQ(av_ok, TRUE)',
        'ASSERT_EQ(av_bad, FALSE)',
    ]))
    p = pw['pbkdf2']
    A('// PBKDF2：OWASP 下界 600000（官方向量）')
    A('LET(pbk, HASH_PASSWORD(%s));' % dict_expr(
        {'password': p['password'], 'salt_hex': p['salt_hex'],
         'iter': p['iter'], 'len': p['len'], 'algo': 'pbkdf2'}))
    src.extend(test('password/pbkdf2_stored', [
        'ASSERT_EQ(pbk, %s)' % wl_string(p['stored']),
    ]))
    A('LET(pv_ok, VERIFY_PASSWORD(%s));' % dict_expr(
        {'password': p['password'], 'stored': p['stored']}))
    A('LET(pv_bad, VERIFY_PASSWORD(%s));' % dict_expr(
        {'password': 'wrong password', 'stored': p['stored']}))
    src.extend(test('password/pbkdf2_verify', [
        'ASSERT_EQ(pv_ok, TRUE)',
        'ASSERT_EQ(pv_bad, FALSE)',
    ]))
    src.extend(test('password/weak_iter_rejected', [
        'ASSERT_EQ(HASH_PASSWORD(%s), "")' % dict_expr(
            {'password': 'x', 'salt_hex': '73616c74', 'iter': 1000,
             'algo': 'pbkdf2'}),
        'ASSERT_EQ(VERIFY_PASSWORD(%s), FALSE)' % dict_expr(
            {'password': 'x',
             'stored': 'pbkdf2-sha256$1000$32$73616c74$aa'}),
    ]))

    # ── 跑测试 + 自己把关退出码 ─────────────────────────────────────
    A('')
    A('// ── 跑测试 + 自己把关退出码 ─────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_security: ", LEN(records), " test(s) run");')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"), " :: ", '
      'AT_K(rec, "error", ""))))));')
    A('PRINT("test_security: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_security: FAILED"); '
      'PANIC("security tests failed")), NULL);')
    A('PRINT("test_security: OK");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
