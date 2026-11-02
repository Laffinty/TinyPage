"""生成 tp/test/fixtures/security_baseline.json —— 卡 S4-1/S4-2 的期望值基准。

**这不是手写期望值**：所有可执行的部分都调**真 Python**（`tinypage/security.py`）
产出，再落成 JSON；只有「卡片要求但源码没有」的项才手写并注明出处。

⚠ 唯一被替换的是 HMAC 的**字节↔文本编码**（已知差异 D-S4-1）：
  WLWL 的 `HMAC_SHA256` 只收 `STRING` ⇒ 本实现把 key / data 都转小写 hex 文本。
  基准用 `HmacShim` 把 `hmac.new(bytes, bytes, …)` 换成
  `hmac.new(key.hex().encode(), data.hex().encode(), …)` 后**原样跑** Python 的
  `generate_csrf_token` / `validate_csrf_token` ⇒ 控制流、校验顺序、日志文本
  全部来自真源码，只有编码这一步是我们定义的。

⚠ 时间全部虚拟：`time.time` 被打桩成固定值，测试与基准用同一个 `now_ms`，
  CI 不做真实等待。

⚠ 不得出现机器相关路径：本文件只含常量、令牌、消息文本，不含任何绝对路径。

用法：python gen_security_baseline.py
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import sys
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import tinypage.security as S  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'security_baseline.json')

# ── 固定输入 ───────────────────────────────────────────────────────
SECRET_HEX = 'aa' * 32            # 32 字节进程密钥（D-S4-1：以 hex 文本作 HMAC key）
SECRET2_HEX = '5c' * 32
RANDOM_HEX = '000102030405060708090a0b0c0d0e0f'   # 16 字节
T0 = 1700000000000                # 2023-11-14T22:13:20Z，毫秒
CLIENT_IP = '203.0.113.7'


class HmacShim:
    """把 Python 的「原始字节 HMAC」换成「hex 文本 HMAC」（D-S4-1）。"""

    @staticmethod
    def new(key, msg, digestmod=None):
        k = bytes(key).hex().encode('ascii') if isinstance(key, (bytes, bytearray)) \
            else key.encode('utf-8')
        m = bytes(msg).hex().encode('ascii') if isinstance(msg, (bytes, bytearray)) \
            else msg.encode('utf-8')
        return hmac.new(k, m, digestmod or hashlib.sha256)

    compare_digest = staticmethod(hmac.compare_digest)


S._CSRF_SECRET = bytes.fromhex(SECRET_HEX)
S.hmac = HmacShim


class Cap(logging.Handler):
    def __init__(self):
        super().__init__()
        self.rows = []

    def emit(self, rec):
        self.rows.append((rec.levelname, rec.getMessage()))


CAP = Cap()
S.logger.addHandler(CAP)
S.logger.setLevel(logging.DEBUG)


def capture(fn, *a, **kw):
    CAP.rows = []
    val = fn(*a, **kw)
    return val, list(CAP.rows)


def make_token(rb, ts_s):
    with mock.patch('time.time', return_value=float(ts_s)):
        with mock.patch.object(S.secrets, 'token_bytes', return_value=rb):
            return S.generate_csrf_token()


def validate(token, env, now_ms, admin_port=8081, bind_domain=''):
    with mock.patch('time.time', return_value=now_ms / 1000.0):
        return S.validate_csrf_token(env, token, admin_port=admin_port,
                                     bind_domain=bind_domain)


def flip(tok, i):
    alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    return tok[:i] + alpha[(alpha.index(tok[i]) + 1) % 64] + tok[i + 1:]


def audit_line(ts, level, event, msg, fields):
    return json.dumps({'ts': ts, 'level': level, 'event': event, 'msg': msg,
                       'fields': fields}, ensure_ascii=False, separators=(',', ':'))


def lvl(name):
    return {'WARNING': 'WARN', 'ERROR': 'ERROR', 'INFO': 'INFO',
            'DEBUG': 'DEBUG'}.get(name, name)


# ── CSRF 令牌生成 ──────────────────────────────────────────────────
TOK0 = make_token(bytes.fromhex(RANDOM_HEX), T0 // 1000)
TOK_OTHER = make_token(bytes.fromhex('10' * 16), T0 // 1000)
with mock.patch.object(S, '_CSRF_SECRET', bytes.fromhex(SECRET2_HEX)):
    TOK_SECRET2 = make_token(bytes.fromhex(RANDOM_HEX), T0 // 1000)

# D-S4-1 自检：hex 编码的签名**必须**与我手算的一致（否则说明 shim 没生效）
_data = bytes.fromhex(RANDOM_HEX) + (T0 // 1000).to_bytes(4, 'big')
_sig = hmac.new(SECRET_HEX.encode(), _data.hex().encode(), hashlib.sha256).digest()
assert TOK0 == base64.urlsafe_b64encode(_data + _sig).decode('ascii'), \
    'D-S4-1 token 自检失败'
# Python 原版（原始字节 HMAC）的 token 与 ours 不同 ⇒ 登记 token 互不通用
_sig_raw = hmac.new(bytes.fromhex(SECRET_HEX), _data, hashlib.sha256).digest()
TOK_RAW = base64.urlsafe_b64encode(_data + _sig_raw).decode('ascii')
assert TOK_RAW != TOK0

csrf = {
    'secret': SECRET_HEX,
    'random_hex': RANDOM_HEX,
    'now_ms': T0,
    'token': TOK0,
    'token_len': len(TOK0),
    'decoded_len': len(base64.urlsafe_b64decode(TOK0.encode())),
    'timestamp': T0 // 1000,
    'token_python_raw_bytes': TOK_RAW,
    'note': ('D-S4-1：签名覆盖 token_data 的 hex 文本；token 形状（72 字符 / 52 字节 / '
             'ts 在第 17-20 字节）与 Python 一致，但签名值与 Python 原版不同 ⇒ 不互通。'),
}

# ── CSRF 校验用例 ──────────────────────────────────────────────────
CASES = []


def add(name, note, token, env, now_ms, admin_port=8081, bind_domain='',
        source='security.py:53'):
    e = {'REMOTE_ADDR': CLIENT_IP}
    e.update(env)
    want, rows = capture(validate, token, e, now_ms, admin_port, bind_domain)
    log = rows[-1][1] if rows else ''
    CASES.append({
        'name': name,
        'note': note,
        'source': source,
        'opts': {
            'secret': SECRET_HEX,
            'now_ms': now_ms,
            'token': token,
            'cookie': env.get('HTTP_COOKIE', ''),
            'origin': env.get('HTTP_ORIGIN', ''),
            'referer': env.get('HTTP_REFERER', ''),
            'admin_port': admin_port,
            'bind_domain': bind_domain,
        },
        'want': bool(want),
        'log': log,
        'log_level': lvl(rows[-1][0]) if rows else '',
    })


CK = 'csrf_token=' + TOK0

add('ok_ip', '正常：token + cookie + 127.0.0.1 Origin',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'http://127.0.0.1:8081'}, T0)
add('ok_localhost', 'localhost Origin 也在白名单',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'http://localhost:8081'}, T0)
add('ok_no_origin_referer', 'Origin/Referer 都缺 ⇒ 跳过域名检查',
    TOK0, {'HTTP_COOKIE': CK}, T0)
add('ok_null_origin', 'Origin: null ⇒ 跳过（大小写不敏感）',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'null'}, T0)
add('ok_null_origin_upper', 'Origin: NULL ⇒ 跳过',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'NULL'}, T0)
add('ok_extra_cookie', 'Cookie 里还有别的键',
    TOK0, {'HTTP_COOKIE': 'a=1; csrf_token=' + TOK0 + '; b=2'}, T0)
add('ok_cookie_spaces', 'Cookie 段两侧空白被 strip',
    TOK0, {'HTTP_COOKIE': '   csrf_token=' + TOK0 + '   '}, T0)
add('ok_referer', 'Referer 命中白名单',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_REFERER': 'http://127.0.0.1:8081/index.html'}, T0)
add('ok_admin_port_9090', 'admin_port 参与白名单构造',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'http://127.0.0.1:9090'}, T0,
    admin_port=9090)
add('ok_bind_domain_https', 'bind_domain 追加 https 前缀',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'https://blog.example.com'}, T0,
    bind_domain='blog.example.com')
add('ok_bind_domain_http', 'bind_domain 追加 http 前缀',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'http://blog.example.com'}, T0,
    bind_domain='blog.example.com')
add('ok_boundary_3600', '恰好 3600 秒：不判过期（> 才过期）',
    TOK0, {'HTTP_COOKIE': CK}, T0 + 3600 * 1000)
add('ok_future_boundary_60', '时间戳比 now 大 60 秒：不判未来',
    TOK0, {'HTTP_COOKIE': CK}, T0 - 60 * 1000)
add('ok_junk_char', 'Python b64decode 忽略字母表外字符 ⇒ 仍可解',
    TOK0 + '!', {'HTTP_COOKIE': 'csrf_token=' + TOK0 + '!'}, T0)

add('fail_empty', '空 token', '', {'HTTP_COOKIE': CK}, T0)
add('fail_short', '长度 < 32', 'abc', {'HTTP_COOKIE': 'csrf_token=abc'}, T0)
add('fail_non_ascii', '非 ASCII ⇒ Python 编码异常',
    '中' * 40, {'HTTP_COOKIE': 'csrf_token=' + '中' * 40}, T0)
add('fail_onepad', '少一个 = ⇒ 总长 71，非 4 倍数',
    TOK0[:-1], {'HTTP_COOKIE': 'csrf_token=' + TOK0[:-1]}, T0)
add('fail_unpadded', '去掉 == 后 70 字符 ⇒ Python 报 padding 错',
    TOK0.rstrip('='), {'HTTP_COOKIE': 'csrf_token=' + TOK0.rstrip('=')}, T0)
add('fail_tamper_sig', '篡改签名区 1 字节',
    flip(TOK0, 50), {'HTTP_COOKIE': 'csrf_token=' + flip(TOK0, 50)}, T0)
add('fail_tamper_random', '篡改随机区 1 字节',
    flip(TOK0, 3), {'HTTP_COOKIE': 'csrf_token=' + flip(TOK0, 3)}, T0)
add('fail_other_secret', '别的密钥签出的 token',
    TOK_SECRET2, {'HTTP_COOKIE': 'csrf_token=' + TOK_SECRET2}, T0)
add('fail_expired_3601', '超过 1 小时 1 秒',
    TOK0, {'HTTP_COOKIE': CK}, T0 + 3601 * 1000)
add('fail_future_61', '时间戳比 now 大 61 秒',
    TOK0, {'HTTP_COOKIE': CK}, T0 - 61 * 1000)
add('fail_no_cookie', '没有 cookie（双提交缺失）',
    TOK0, {}, T0)
add('fail_cookie_mismatch', 'cookie 里是另一个 token',
    TOK0, {'HTTP_COOKIE': 'csrf_token=' + TOK_OTHER}, T0)
add('fail_cookie_first_wins', '同名 cookie 取第一个（即便是坏的）',
    TOK0, {'HTTP_COOKIE': 'csrf_token=bad; csrf_token=' + TOK0}, T0)
add('fail_origin_evil', 'Origin 不在白名单',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'http://evil.example.com'}, T0)
add('fail_origin_wrong_port', 'Origin 端口不对',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'http://127.0.0.1:9099'}, T0)
add('fail_origin_https_localhost', 'https 不在 http 白名单里',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'https://localhost:8081'}, T0)
add('fail_origin_case', 'startswith 区分大小写',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'http://LOCALHOST:8081'}, T0)
add('ok_origin_prefix_spoof', '源码是**前缀**匹配 ⇒ 8081.evil.com 会通过（照抄，不加固）',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'http://127.0.0.1:8081.evil.com'}, T0)
add('fail_referer_evil', 'Referer 不在白名单',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_REFERER': 'http://evil.example.com/x'}, T0)
add('fail_bind_domain_other', 'bind_domain 之外的域名被拒',
    TOK0, {'HTTP_COOKIE': CK, 'HTTP_ORIGIN': 'https://other.example.com'}, T0,
    bind_domain='blog.example.com')

# ── Cookie 头（逐字节）────────────────────────────────────────────
SESS_BYTES = bytes(range(32))
SESS_TOK = base64.urlsafe_b64encode(SESS_BYTES).decode('ascii').rstrip('=')


class _FakeRand:
    """CPython 3.12+ 的 secrets 走 `_sysrand.randbytes`，不是 os.urandom。"""

    def randbytes(self, n):
        return SESS_BYTES[:n]


with mock.patch.object(S.secrets, '_sysrand', _FakeRand()):
    assert S.generate_session_token() == SESS_TOK, 'token_urlsafe 口径不一致'

COOKIES = []
for name, want, opts in [
    ('csrf_plain', S.get_csrf_cookie_header(token=TOK0, secure=False),
     {'token': TOK0, 'secure': False}),
    ('csrf_secure', S.get_csrf_cookie_header(token=TOK0, secure=True),
     {'token': TOK0, 'secure': True}),
    ('session_plain', S.get_session_cookie_header(token=SESS_TOK, secure=False),
     {'token': SESS_TOK, 'secure': False}),
    ('session_secure_maxage60',
     S.get_session_cookie_header(token=SESS_TOK, secure=True, max_age=60),
     {'token': SESS_TOK, 'secure': True, 'max_age': 60}),
    ('session_clear', S.get_session_clear_cookie_header(secure=False),
     {'secure': False}),
    ('session_clear_secure', S.get_session_clear_cookie_header(secure=True),
     {'secure': True}),
]:
    COOKIES.append({'name': name, 'opts': opts, 'want': list(want),
                    'source': 'security.py:116/139/159'})

# ── 会话 ──────────────────────────────────────────────────────────
# ⚠ 令牌用**符号引用**：Python 的 create_session 自己生成 token，测试侧也用
#   自己 create 出来的 token ⇒ 两边跑同一串操作、比较**行为**，不比较随机值本身。
def run_session(events, max_tracked=None):
    t0 = events[0]['at_ms']
    with mock.patch('time.time', return_value=t0 / 1000.0):
        sm = S.SessionManager()
    if max_tracked is not None:
        sm.MAX_TRACKED_SESSIONS = max_tracked
    toks = {}
    results = []
    for ev in events:
        with mock.patch('time.time', return_value=ev['at_ms'] / 1000.0):
            op = ev['op']
            if op == 'create':
                t = sm.create_session(ev.get('client_ip', ''))
                toks[ev['as']] = t
                r = {'created': True, 'len': len(t)}
            elif op == 'validate':
                r = sm.validate_session(toks.get(ev.get('ref', ''), ''),
                                        ev.get('client_ip', ''))
            elif op == 'destroy':
                sm.destroy_session(toks.get(ev.get('ref', ''), ''))
                r = None
            elif op == 'from_cookie':
                r = sm.get_session_from_environ({'HTTP_COOKIE': ev['cookie']}) or ''
            else:
                raise AssertionError(op)
        results.append(r)
    return results, len(sm._sessions), toks


def ev(op, at_ms, ref=None, as_=None, client_ip='', cookie=None):
    d = {'op': op, 'at_ms': at_ms, 'client_ip': client_ip}
    if ref is not None:
        d['ref'] = ref
    if as_ is not None:
        d['as'] = as_
    if cookie is not None:
        d['cookie'] = cookie
    return d


MISSING = 'never-created'   # 未定义的符号引用（测试侧就发空串）

SESS_EVENTS = [
    ev('create', T0, as_='s1', client_ip='198.51.100.1'),
    ev('validate', T0, ref='s1'),
    ev('validate', T0, ref=MISSING),
    ev('create', T0 + 1000, as_='s2', client_ip='198.51.100.2'),
    ev('validate', T0 + 86400 * 1000, ref='s1'),
    ev('validate', T0 + 86400 * 1000 + 1, ref='s1'),
    ev('validate', T0 + 86400 * 1000 + 1, ref='s2'),
    ev('destroy', T0 + 86400 * 1000 + 2, ref='s2'),
    ev('validate', T0 + 86400 * 1000 + 2, ref='s2'),
    ev('destroy', T0 + 86400 * 1000 + 2, ref=MISSING),
    ev('from_cookie', T0, cookie='x=1; session_id=abc'),
    ev('from_cookie', T0, cookie='x=1'),
]

EVICT_EVENTS = [
    ev('create', T0, as_='e1'),
    ev('create', T0 + 100, as_='e2'),
    ev('create', T0 + 200, as_='e3'),
    ev('create', T0 + 300, as_='e4'),
    ev('validate', T0 + 300, ref='e1'),
    ev('validate', T0 + 300, ref='e2'),
    ev('create', T0 + 400, as_='e5'),
    ev('validate', T0 + 400, ref='e2'),
    ev('validate', T0 + 400, ref='e5'),
]

sess_results, sess_count, main_toks = run_session(SESS_EVENTS)
evict_results, evict_count, evict_toks = run_session(EVICT_EVENTS, max_tracked=3)

# 「进程重启」：新 SessionManager 里旧 token 全失效
with mock.patch('time.time', return_value=(T0 + 500) / 1000.0):
    sm_fresh = S.SessionManager()
    restart_results = [sm_fresh.validate_session(main_toks.get('s2', ''), ''),
                       sm_fresh.validate_session(evict_toks.get('e3', ''), ''),
                       False]


def clean(rs):
    return ['' if r is None else r for r in rs]


SESSIONS = {
    'config': {
        'max_age': S.SessionManager.SESSION_MAX_AGE,
        'max_tracked': S.SessionManager.MAX_TRACKED_SESSIONS,
        'cleanup_interval': S.SessionManager.CLEANUP_INTERVAL,
    },
    'token': {'random_hex': SESS_BYTES.hex(), 'want': SESS_TOK,
              'want_len': len(SESS_TOK)},
    'create_len': 43,
    'scenario_main': {
        'events': SESS_EVENTS,
        'results': clean(sess_results),
        'count': sess_count,
        'note': 'create 的结果是 {created, len}（随机值不比）；destroy 记录 null',
    },
    'scenario_evict': {
        'events': EVICT_EVENTS,
        'results': clean(evict_results),
        'count': evict_count,
        'max_tracked': 3,
        'note': '源码是「最老创建」淘汰（卡片写 LRU，实现照源码）',
    },
    'scenario_restart': {
        'results': clean(restart_results),
        'refs': ['s2', 'e3'],
        'note': '新进程 = 新 SessionManager ⇒ 旧 token 全失效',
    },
}

# ── 限流 + 登录锁定 ───────────────────────────────────────────────
def run_rate(events, cfg):
    t0 = events[0]['at_ms']
    with mock.patch('time.time', return_value=t0 / 1000.0):
        rl = S.RateLimiter(max_requests=cfg['max_requests'],
                           window_seconds=cfg['window_seconds'])
        af = S.AuthFailureTracker(max_failures=cfg['max_failures'],
                                  lockout_seconds=cfg['lockout_seconds'])
    if cfg.get('max_ips') is not None:
        rl.MAX_TRACKED_IPS = cfg['max_ips']
    out = []
    for e in events:
        now_ms = e['at_ms']
        ip = e['client_ip']
        kind = e['kind']
        with mock.patch('time.time', return_value=now_ms / 1000.0):
            if kind == 'request':
                allowed = rl.is_allowed(ip)
                retry = rl.get_retry_after(ip)
            else:
                if kind == 'auth_failure':
                    af.record_failure(ip)
                allowed = None
                retry = None
            locked = af.is_locked_out(ip)
            rem = af.get_lockout_remaining(ip)
            fails = len([t for t in af._failures.get(ip, [])
                         if t > now_ms / 1000.0 - cfg['lockout_seconds']])
            if kind != 'request':
                allowed = not locked
                retry = rem if locked else 0
            tracked = len(rl._requests)
        out.append({'allowed': allowed, 'retry_after': retry, 'locked': locked,
                    'lockout_remaining': rem, 'failures': fails,
                    'tracked_ips': tracked})
    return out


def rev(kind, at_ms, ip):
    return {'kind': kind, 'at_ms': at_ms, 'client_ip': ip}


WINDOW_CFG = {'max_requests': 5, 'window_seconds': 60, 'max_failures': 5,
              'lockout_seconds': 300, 'max_ips': None}
WINDOW_EVENTS = [
    rev('request', T0, '10.1.0.1'),
    rev('request', T0 + 1000, '10.1.0.1'),
    rev('request', T0 + 2000, '10.1.0.1'),
    rev('request', T0 + 3000, '10.1.0.1'),
    rev('request', T0 + 4000, '10.1.0.1'),
    rev('request', T0 + 5000, '10.1.0.1'),          # 第 6 次 ⇒ 被限
    rev('request', T0 + 5000, '10.1.0.2'),          # 别的 IP 不受影响
    rev('request', T0 + 60000, '10.1.0.1'),         # 窗口滑过 t0
    rev('request', T0 + 61000, '10.1.0.1'),
]

AUTH_CFG = {'max_requests': 60, 'window_seconds': 60, 'max_failures': 5,
            'lockout_seconds': 300, 'max_ips': None}
AUTH_EVENTS = [
    rev('auth_check', T0, '10.2.0.1'),
    rev('auth_failure', T0, '10.2.0.1'),
    rev('auth_failure', T0 + 1000, '10.2.0.1'),
    rev('auth_failure', T0 + 2000, '10.2.0.1'),
    rev('auth_failure', T0 + 3000, '10.2.0.1'),
    rev('auth_failure', T0 + 4000, '10.2.0.1'),     # 第 5 次 ⇒ 锁
    rev('auth_check', T0 + 5000, '10.2.0.1'),       # 第 6 次 ⇒ 仍被限
    rev('auth_check', T0 + 299000, '10.2.0.1'),
    rev('auth_check', T0 + 300000, '10.2.0.1'),     # 300 秒后恢复
    rev('auth_check', T0 + 304001, '10.2.0.1'),
    rev('auth_failure', T0 + 304001, '10.2.0.1'),
]

IPS_CFG = {'max_requests': 60, 'window_seconds': 60, 'max_failures': 5,
           'lockout_seconds': 300, 'max_ips': 1}
IPS_EVENTS = [
    rev('request', T0, '10.3.0.1'),
    rev('request', T0 + 1000, '10.3.0.2'),
    rev('request', T0 + 2000, '10.3.0.1'),
]

RATE = {
    'window': {'cfg': WINDOW_CFG, 'events': WINDOW_EVENTS,
               'results': run_rate(WINDOW_EVENTS, WINDOW_CFG)},
    'auth': {'cfg': AUTH_CFG, 'events': AUTH_EVENTS,
             'results': run_rate(AUTH_EVENTS, AUTH_CFG)},
    'max_ips': {'cfg': IPS_CFG, 'events': IPS_EVENTS,
                'results': run_rate(IPS_EVENTS, IPS_CFG)},
}

# ── 审计 ──────────────────────────────────────────────────────────
# 从上面捕获的**真 Python 日志消息**取 msg（CSRF 各失败分支）
by_name = {c['name']: c for c in CASES}
AUDIT = []


def add_audit(name, opts, level, note, source):
    fields = opts.get('fields', {})
    want = audit_line(opts.get('now_ms', T0), level, opts['event'],
                      opts['msg'], fields)
    AUDIT.append({'name': name, 'note': note, 'source': source,
                  'opts': opts, 'want_level': level, 'want': want})


for cname, ev_name in [('fail_origin_evil', 'CSRF-FAIL'),
                       ('fail_cookie_mismatch', 'CSRF-FAIL'),
                       ('fail_expired_3601', 'CSRF-FAIL'),
                       ('fail_tamper_sig', 'CSRF-FAIL'),
                       ('fail_non_ascii', 'CSRF-ERROR')]:
    c = by_name[cname]
    add_audit('csrf_' + cname,
              {'event': ev_name, 'now_ms': c['opts']['now_ms'], 'msg': c['log'],
               'fields': {'client_ip': CLIENT_IP}},
              c['log_level'] or 'WARN',
              'msg 逐字取自真 Python 日志（%s 分支）' % cname,
              'security.py:58-112')

# XSS-BLOCK：真调 validate_url_protocol 捕获日志
_url = 'javascript:alert(1)'
with mock.patch('time.time', return_value=T0 / 1000.0):
    _ok, _rows = capture(S.validate_url_protocol, _url)
assert _ok is False and _rows and _rows[-1][1].startswith('[XSS-BLOCK]')
add_audit('xss_dangerous_protocol',
          {'event': 'XSS-BLOCK', 'now_ms': T0, 'msg': _rows[-1][1],
           'fields': {'url': _url}},
          lvl(_rows[-1][0]), '真 Python 日志（security.py:306）', 'security.py:306')

# DELETE：源码 content.py:144 的字面形式（不入库执行）
add_audit('delete_article',
          {'event': 'DELETE', 'now_ms': T0,
           'msg': '[DELETE] Article: 2024-02-03-hello.html',
           'fields': {'path': '2024-02-03-hello.html'}},
          'INFO', '字面形式取自 content.py:144（不执行文件系统操作）',
          'content.py:144')

# JSON 转义（引号 / 反斜杠 / 非 ASCII）
add_audit('delete_quoting',
          {'event': 'DELETE', 'now_ms': T0,
           'msg': '[DELETE] Article: a"b\\c-中文.html',
           'fields': {'path': 'a"b\\c-中文.html', 'note': '引号\\反斜杠'}},
          'INFO', '钉 JSON 转义与 Python json.dumps 逐字一致', 'content.py:144')

# D-S4-3：源码没有 [AUTH-FAIL] / [RATE-LIMIT]，这两条是 S4-2 新增事件
add_audit('auth_fail_extension',
          {'event': 'AUTH-FAIL', 'now_ms': T0,
           'msg': '[AUTH-FAIL] Login failed from 203.0.113.7',
           'fields': {'client_ip': CLIENT_IP, 'attempts': 6}},
          'WARN', 'D-S4-3：源码无此字面量，S4-2 新增', 'security.py（无）')
add_audit('rate_limit_extension',
          {'event': 'RATE-LIMIT', 'now_ms': T0,
           'msg': '[RATE-LIMIT] Blocked 203.0.113.7 (retry_after=56)',
           'fields': {'client_ip': CLIENT_IP, 'retry_after': 56}},
          'WARN', 'D-S4-3：源码无此字面量，S4-2 新增', 'security.py（无）')

AUDIT_UNKNOWN = {'event': 'NOPE', 'want': ''}

# ── 口令 ──────────────────────────────────────────────────────────
from argon2.low_level import Type, hash_secret_raw  # noqa: E402

PW_SALT = '00112233445566778899aabbccddeeff'
PW = 'correct horse'
argon_hex = hash_secret_raw(PW.encode(), bytes.fromhex(PW_SALT), time_cost=2,
                            memory_cost=19456, parallelism=1, hash_len=32,
                            type=Type.ID).hex()
argon_stored = 'argon2id$2$19456$1$%s$%s' % (PW_SALT, argon_hex)

# 规范的官方向量（标准库·安全册 §11.5）
VEC_SALT = '73616c7453616c7453616c74'
vec_hex = hash_secret_raw(b'password', bytes.fromhex(VEC_SALT), time_cost=2,
                          memory_cost=19456, parallelism=1, hash_len=32,
                          type=Type.ID).hex()
SPEC_VEC = '7784e9edc034c74be067bacf7f12f6cfb5babfbccd53f7654386c604d40eb808'
assert vec_hex == SPEC_VEC, 'Argon2id 官方向量不一致：%s' % vec_hex

PBK_SALT = '73616c74'
pbk_hex = hashlib.pbkdf2_hmac('sha256', b'password', bytes.fromhex(PBK_SALT),
                              600000, 32).hex()
pbk_stored = 'pbkdf2-sha256$600000$32$%s$%s' % (PBK_SALT, pbk_hex)

PASSWORD = {
    'argon2': {
        'salt_hex': PW_SALT, 'password': PW, 't_cost': 2, 'm_cost': 19456,
        'p_cost': 1, 'len': 32,
        'stored': argon_stored,
        'verify_ok': True, 'verify_bad': False,
        'note': 'hash_secret_raw(Type.ID) 与 WLWL 的 ARGON2ID 同参',
    },
    'argon2_spec_vector': {
        'salt_hex': VEC_SALT, 'password': 'password',
        'stored': 'argon2id$2$19456$1$%s$%s' % (VEC_SALT, vec_hex),
        'hex': SPEC_VEC,
        'note': '标准库·安全册 §11.5 的官方向量（Python 独立复算一致）',
    },
    'pbkdf2': {
        'salt_hex': PBK_SALT, 'password': 'password', 'iter': 600000,
        'len': 32, 'stored': pbk_stored, 'hex': pbk_hex,
        'verify_ok': True, 'verify_bad': False,
        'note': 'OWASP 下界 600000；一次调用约 0.8s（CI 可接受）',
    },
    'weak_iter': {'iter': 1000, 'want': '', 'note': 'iter < 600000 ⇒ ""（拒绝）'},
    'config': {'default_algo': 'argon2id', 't_cost': 2, 'm_cost': 19456,
               'p_cost': 1, 'len': 32, 'pbkdf2_min_iter': 600000},
}

baseline = {
    'meta': {
        'generated_by': 'tp/test/gen_security_baseline.py',
        'python_sources': [
            'tinypage/security.py:43 generate_csrf_token',
            'tinypage/security.py:53 validate_csrf_token',
            'tinypage/security.py:116 get_csrf_cookie_header',
            'tinypage/security.py:134 generate_session_token',
            'tinypage/security.py:139 get_session_cookie_header',
            'tinypage/security.py:159 get_session_clear_cookie_header',
            'tinypage/security.py:375 SessionManager',
            'tinypage/security.py:436 RateLimiter',
            'tinypage/security.py:494 AuthFailureTracker',
            'tinypage/content.py:144 [DELETE] 字面形式',
        ],
        'cross_checks': {
            'csrf_token_len': len(TOK0),
            'csrf_decoded_len': len(base64.urlsafe_b64decode(TOK0.encode())),
            'csrf_token_matches_hand_computed_d_s4_1': True,
            'csrf_raw_byte_token_differs': TOK_RAW != TOK0,
            'session_token_len': len(SESS_TOK),
            'argon2_spec_vector_matches': vec_hex == SPEC_VEC,
            'csrf_cases': len(CASES),
            'session_scenarios': 3,
            'rate_scenarios': 3,
            'audit_lines': len(AUDIT),
        },
        'differences': [
            'D-S4-1：HMAC 的 key/data 以 hex 文本参与（WLWL 的 HMAC 只收 STRING）'
            ' ⇒ token 形状一致但不与 Python 原版互通；本文件用 HmacShim 让 Python '
            '控制流原样可跑。',
            'D-S4-2：源码无口令哈希函数；HASH_PASSWORD 的存储格式由本实现自定'
            '（argon2id$t$m$p$salt$hash / pbkdf2-sha256$iter$len$salt$hash）。',
            'D-S4-3：[AUTH-FAIL] / [RATE-LIMIT] 在源码里不存在（grep 全树无字面量），'
            '是 S4-2 新增事件；级别按 WARN 登记。',
            'D-S4-4：SESSION_DESTROY 返回 BOOLEAN（Python destroy_session 返回 None）'
            '——Python 侧结果按 null 记录，测试只比对副作用。',
            'D-S4-5：SESSION_RESET 是「进程重启」的等价替身（同一进程内无法真重启）；'
            '注册表只在内存里，源码语义即重启失效。',
        ],
    },
    'csrf': csrf,
    'csrf_cases': CASES,
    'cookies': COOKIES,
    'sessions': SESSIONS,
    'rate': RATE,
    'audit': {'cases': AUDIT, 'unknown': AUDIT_UNKNOWN},
    'password': PASSWORD,
}

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(baseline, f, ensure_ascii=False, indent=2)
    f.write('\n')

print('wrote %s (csrf=%d, cookies=%d, session_events=%d, rate_events=%d, audit=%d)'
      % (OUT, len(CASES), len(COOKIES),
         len(SESS_EVENTS) + len(EVICT_EVENTS), len(WINDOW_EVENTS) + len(AUTH_EVENTS)
         + len(IPS_EVENTS), len(AUDIT)))
