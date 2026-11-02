"""生成 tp/lib/security.wll —— 卡 S4-1（会话与 CSRF）+ S4-2（限流与审计）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**对齐目标（真 Python 源码树 `tinypage/security.py`）**：
  NEW_CSRF_TOKEN            == generate_csrf_token()            :43
  VALIDATE_CSRF_TOKEN       == validate_csrf_token(...)         :53
  CSRF_COOKIE_HEADER        == get_csrf_cookie_header(...)      :116
  NEW_SESSION_TOKEN         == generate_session_token()         :134
  SESSION_COOKIE_HEADER     == get_session_cookie_header(...)   :139
  SESSION_CLEAR_COOKIE_HEADER == get_session_clear_cookie_header:159
  SESSION_*                 == class SessionManager             :375
  RATE_LIMIT                == class RateLimiter :436 + AuthFailureTracker :494
  AUDIT_EVENT               == 源码里实际出现的 `[TAG]` 日志行（见下）
  HASH_PASSWORD / VERIFY_PASSWORD == 卡片 S4-2 的口令要求（源码暂无对口函数）

⚠ **已知差异 D-S4-1（签名载荷的编码）**：WLWL 的 `HMAC_SHA256` 只收 `STRING`
（UTF-8），而 Python 的 HMAC 收原始字节。字节串在 WLWL 里唯一无损形态是
`ARRAY[INTEGER]`，无法交给 HMAC ⇒ 本模块对 **key 与 data 都先转小写十六进制
文本** 再 HMAC。等价性：hex 是单射编码，签名覆盖的仍是同一份 20 字节；
但 **两边的 token 互不通用**（同一 key/随机数/时间戳下签名值不同）。
随机性、长度、布局（16B random + 4B ts + 32B sig = 52B → 72 字符 base64）逐字节一致。

⚠ **已知差异 D-S4-2（口令存储格式）**：源码没有口令哈希函数；本模块按卡片
S4-2 补 `HASH_PASSWORD` / `VERIFY_PASSWORD`，格式自定（`algo$params$salt$hash`），
默认 ARGON2ID（OWASP 下界 m=19456/t=2/p=1）。PBKDF2 分支强制 iter ≥ 600000。

⚠ **已知差异 D-S4-3（审计事件）**：`[AUTH-FAIL]` / `[RATE-LIMIT]` 在源码里
**不存在**（grep 全树无此字面量）；本模块把它们作为 S4-2 新增事件登记。
其余事件名逐字来自源码（`[CSRF-FAIL]` / `[CSRF-ERROR]` / `[XSS-BLOCK]` /
`[BLOCK]` / `[DELETE]` 等，见 SEC_AUDIT_LEVEL）。

⚠ **不采用 `std.http::RATE_LIMITER`**（本机探针实测）：它虽然按名复用状态，
但返回 `{allowed, remaining, reset, limit, mode}`（秒分桶），**没有** Python
`get_retry_after()` 的 `int(window - (now - oldest)) + 1` 口径，且每次调用都
无条件向 stderr 打一行 `http.audit` 日志 ⇒ 无法与 Python 逐值对齐、还会重复审计。
⇒ 自建注册表（模块级 `LET MUT` 字典），语义逐条照 `RateLimiter` /
`AuthFailureTracker`。

⚠ **不依赖 `std.sync` 的按名复用**（卡片 S4-1 明确：`SHARED_DICT()` /
`COUNTER()` 每次调用都新建）。

时间：所有时间点都可从 `opts.now_ms` 注入（缺省 `NOW()`），测试不依赖真实等待。

用法：python gen_security.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'security.wll')


def main():
    src = []
    A = src.append
    A('// tp/lib/security.wll —— 会话与 CSRF（S4-1）+ 限流与审计（S4-2）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_security.py 生成 —— 请勿手改。')
    A('//')
    A('// 对齐目标：tinypage/security.py（行号见生成器 docstring）')
    A('// 逐字节基准：tp/test/fixtures/security_baseline.json')
    A('//')
    A('// ⚠ 已知差异（详见生成器 docstring）：')
    A('//   D-S4-1 签名载荷走 hex 文本（WLWL 的 HMAC 只收 STRING）⇒ 两边 token 不互通')
    A('//   D-S4-2 口令存储格式由本模块自定（源码无对口函数）')
    A('//   D-S4-3 [AUTH-FAIL] / [RATE-LIMIT] 是 S4-2 新增事件（源码无此字面量）')
    A('//')
    A('// ⚠ #52：本模块所有顶层**私有**名一律 SEC_ 前缀（顶层绑定跨模块共享，')
    A('//   会覆盖被 import 模块的同名私有名，且诊断行号会错标）。')
    A('')
    A('IMPORT("wlwl:std.encode", ["RANDOM_BYTES", "RANDOM_HEX", "HMAC_SHA256", '
      '"TIMING_SAFE_EQ", "ARGON2ID", "PBKDF2_ITER"]);')
    A('IMPORT("wlwl:std.time", ["NOW"]);')
    A('IMPORT("wlwl:std.json", ["STRINGIFY"]);')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_TEST"]);')
    A('')

    # ── 模块级状态（进程内；进程重启即全失效）───────────────────────
    A('// ── 模块级状态（只在进程内存里；进程重启 ⇒ 全部失效）────────────')
    A('// ⚠ 这是本模块唯一的可变状态，刻意不落盘、不进 std.sync。')
    A('LET(SEC_B64_ALPHA, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");')
    A('LET(SEC_HEX_DIGITS, "0123456789abcdef");')
    A('// 32 字节进程密钥（Python: _CSRF_SECRET = secrets.token_bytes(32)）。')
    A('// ⚠ D-S4-1：这里存的是 64 个 hex 字符（32 字节熵），HMAC 的 key 是这 64 字节文本。')
    A('LET(SEC_CSRF_SECRET, RANDOM_HEX(32));')
    A('LET MUT(SEC_SESSIONS, DICT());')
    A('LET MUT(SEC_SESSION_ORDER, []);')
    A('LET MUT(SEC_SESSION_LAST_CLEANUP, -1);')
    A('LET MUT(SEC_RL, DICT());')
    A('LET MUT(SEC_RL_LAST_CLEANUP, -1);')
    A('LET MUT(SEC_AF, DICT());')
    A('LET MUT(SEC_AF_LAST_CLEANUP, -1);')
    A('')

    # ── 字节 / 十六进制 / base64 ────────────────────────────────────
    src += fn('SEC_HEX_VAL', 'ch', [
        '// 十六进制字符 → 0..15；非法 → -1（Python 的 bytes.fromhex 同款拒绝）',
        '// ⚠ 用码点算术，不建字典：字典字面量会触发逗号守卫。',
        'LET(cp, AT(CODEPOINTS(ch), 0, -1))',
        C('IF', '&&(>=(cp, 48), <=(cp, 57))', ['-(cp, 48)'], [
            C('IF', '&&(>=(cp, 97), <=(cp, 102))', ['-(cp, 87)'], [
                C('IF', '&&(>=(cp, 65), <=(cp, 70))', ['-(cp, 55)'], ['-1']),
            ]),
        ]),
    ], '// 十六进制字符 → 0..15')

    src += fn('SEC_HEX_TO_BYTES', 'h', [
        '// hex 文本 → ARRAY[INTEGER]（0..255）；奇数长度或非法字符 → NULL',
        'LET(n, /(LEN(h), 2))',
        'LET MUT(bad, ==(%(LEN(h), 2), 1))',
        'LET MUT(out, [])',
        'LET MUT(i, 0)',
        C('WHILE', '&&(<(i, n), ==(bad, FALSE))', [
            'LET(hi, SEC_HEX_VAL(SUB(h, *(i, 2), 1)))',
            'LET(lo, SEC_HEX_VAL(SUB(h, +(*(i, 2), 1), 1)))',
            C('IF', '||(<(hi, 0), <(lo, 0))', [
                'SET(bad, TRUE)',
            ], [
                'SET(out, PUSH(out, +(*(hi, 16), lo)))',
                'SET(i, +(i, 1))',
            ]),
        ]),
        'IF(bad, NULL, out)',
    ], '// hex → 字节数组（非法 → NULL）')

    src += fn('SEC_BYTES_TO_HEX', 'b', [
        '// 字节数组 → 小写 hex（HEX_ENCODE 只收 STRING ⇒ 自己逐字节转）',
        'LET MUT(out, "")',
        C('FOR', 'x, b', [
            'SET(out, CAT(out, SUB(SEC_HEX_DIGITS, /(x, 16), 1), '
            'SUB(SEC_HEX_DIGITS, %(x, 16), 1)))',
        ]),
        'out',
    ], '// 字节数组 → hex')

    src += fn('SEC_U32_BE', 'n', [
        '// 4 字节大端（Python: int(time.time()).to_bytes(4, "big")）',
        '[%(/(n, 16777216), 256), %(/(n, 65536), 256), %(/(n, 256), 256), %(n, 256)]',
    ], '// 4 字节大端')

    src += fn('SEC_U32_FROM', 'b, off', [
        '// 大端 4 字节 → 整数（Python: int.from_bytes(token_data[16:20], "big")）',
        '+(*(AT(b, off, 0), 16777216), +(*(AT(b, +(off, 1), 0), 65536), '
        '+(*(AT(b, +(off, 2), 0), 256), AT(b, +(off, 3), 0))))',
    ], '// 大端 4 字节 → 整数')

    src += fn('SEC_B64_VAL', 'ch', [
        '// base64 字符 → 0..63；非法 → -1。两张字母表都收（Python b64decode 的放宽）',
        'LET(cp, AT(CODEPOINTS(ch), 0, -1))',
        C('IF', '&&(>=(cp, 65), <=(cp, 90))', ['-(cp, 65)'], [
            C('IF', '&&(>=(cp, 97), <=(cp, 122))', ['-(cp, 71)'], [
                C('IF', '&&(>=(cp, 48), <=(cp, 57))', ['+(cp, 4)'], [
                    C('IF', '==(cp, 45)', ['62'], [
                        C('IF', '==(cp, 95)', ['63'], [
                            C('IF', '==(cp, 43)', ['62'], [
                                C('IF', '==(cp, 47)', ['63'], ['-1']),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ], '// base64 字符 → 0..63')

    src += fn('SEC_B64_ENC', 'b', [
        '// RFC 4648 urlsafe，**带** padding（Python 的 urlsafe_b64encode 带 =）',
        'LET(n, LEN(b))',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, n)', [
            'LET(rem, -(n, i))',
            C('IF', '>=(rem, 3)', [
                'LET(b0, AT(b, i, 0))',
                'LET(b1, AT(b, +(i, 1), 0))',
                'LET(b2, AT(b, +(i, 2), 0))',
                'SET(out, CAT(out, SUB(SEC_B64_ALPHA, /(b0, 4), 1), '
                'SUB(SEC_B64_ALPHA, +(*(%(b0, 4), 16), /(b1, 16)), 1), '
                'SUB(SEC_B64_ALPHA, +(*(%(b1, 16), 4), /(b2, 64)), 1), '
                'SUB(SEC_B64_ALPHA, %(b2, 64), 1)))',
                'SET(i, +(i, 3))',
            ], [
                C('IF', '==(rem, 2)', [
                    'LET(b0, AT(b, i, 0))',
                    'LET(b1, AT(b, +(i, 1), 0))',
                    'SET(out, CAT(out, SUB(SEC_B64_ALPHA, /(b0, 4), 1), '
                    'SUB(SEC_B64_ALPHA, +(*(%(b0, 4), 16), /(b1, 16)), 1), '
                    'SUB(SEC_B64_ALPHA, *(%(b1, 16), 4), 1), "="))',
                    'SET(i, +(i, 2))',
                ], [
                    'LET(b0, AT(b, i, 0))',
                    'SET(out, CAT(out, SUB(SEC_B64_ALPHA, /(b0, 4), 1), '
                    'SUB(SEC_B64_ALPHA, *(%(b0, 4), 16), 1), "=="))',
                    'SET(i, +(i, 1))',
                ]),
            ]),
        ]),
        'out',
    ], '// 字节数组 → urlsafe base64（带 padding）')

    src += fn('SEC_B64_CLEAN', 's', [
        '// 对齐 Python b64decode(validate=False)：**丢弃**字母表外的字符（含 CR/LF）。',
        '// ⚠ 实测：`token + "!"` 在 Python 侧仍能解出 52 字节 ⇒ 不丢垃圾字符就差一条行为。',
        '//   `=` 保留（它是补位标记，位置/数量由 SEC_B64_DEC 校验）。',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, LEN(s))', [
            'LET(ch, SUB(s, i, 1))',
            C('IF', '||(>=(SEC_B64_VAL(ch), 0), ==(ch, "="))', [
                'SET(out, +(out, ch))',
            ], ['NULL']),
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// 丢弃 base64 字母表外的字符')

    src += fn('SEC_B64_DEC', 's', [
        '// urlsafe/标准 base64 → 字节数组；非法 → NULL（Python 侧异常 ⇒ False）',
        '// 规则：先丢字母表外字符；`=` 可省但总长度必须是 4 的倍数（实测 Python 拒绝非 4 倍数）。',
        'LET(s0, SEC_B64_CLEAN(s))',
        'LET(n0, LEN(s0))',
        'LET MUT(pad, 0)',
        'LET MUT(j, n0)',
        C('WHILE', '&&(>(j, 0), ==(SUB(s0, -(j, 1), 1), "="))', [
            'SET(pad, +(pad, 1))',
            'SET(j, -(j, 1))',
        ]),
        'LET(m, -(n0, pad))',
        '// 补位 > 2 / 空 / 总长非 4 倍数 / 数据段 ≡ 1 (mod 4) ⇒ 非法',
        'LET MUT(bad, ||(>(pad, 2), ||(==(m, 0), ||(!=(%(n0, 4), 0), ==(%(m, 4), 1)))))',
        'LET MUT(out, [])',
        'LET MUT(i, 0)',
        C('WHILE', '&&(<(i, m), ==(bad, FALSE))', [
            'LET(rem, -(m, i))',
            'LET(v0, SEC_B64_VAL(SUB(s0, i, 1)))',
            'LET(v1, IF(>=(rem, 2), SEC_B64_VAL(SUB(s0, +(i, 1), 1)), 0))',
            'LET(v2, IF(>=(rem, 3), SEC_B64_VAL(SUB(s0, +(i, 2), 1)), 0))',
            'LET(v3, IF(>=(rem, 4), SEC_B64_VAL(SUB(s0, +(i, 3), 1)), 0))',
            'LET(vtop, IF(>=(rem, 3), v2, 0))',
            C('IF', '||(<(v0, 0), ||(<(v1, 0), ||(<(vtop, 0), &&(>=(rem, 4), <(v3, 0)))))', [
                'SET(bad, TRUE)',
            ], [
                C('IF', '>=(rem, 4)', [
                    'SET(out, PUSH(PUSH(PUSH(out, +(*(v0, 4), /(v1, 16))), '
                    '+(*(%(v1, 16), 16), /(v2, 4))), '
                    '+(*(%(v2, 4), 64), v3)))',
                    'SET(i, +(i, 4))',
                ], [
                    C('IF', '==(rem, 3)', [
                        'SET(out, PUSH(PUSH(out, +(*(v0, 4), /(v1, 16))), '
                        '+(*(%(v1, 16), 16), /(v2, 4))))',
                        'SET(i, +(i, 3))',
                    ], [
                        C('IF', '==(rem, 2)', [
                            'SET(out, PUSH(out, +(*(v0, 4), /(v1, 16))))',
                            'SET(i, +(i, 2))',
                        ], [
                            'SET(bad, TRUE)',
                        ]),
                    ]),
                ]),
            ]),
        ]),
        'IF(bad, NULL, out)',
    ], '// base64 → 字节数组（非法 → NULL）')

    src += fn('SEC_RSTRIP_PAD', 's', [
        '// 去尾部 "="（Python: token_urlsafe 的 .rstrip("=")）',
        'LET MUT(out, s)',
        'LET MUT(i, LEN(out))',
        C('WHILE', '&&(>(i, 0), ==(SUB(out, -(i, 1), 1), "="))', [
            'SET(out, SUB(out, 0, -(i, 1)))',
            'SET(i, -(i, 1))',
        ]),
        'out',
    ], '// 去尾部 base64 padding')

    # ── Cookie 头解析 ──────────────────────────────────────────────
    src += fn('SEC_COOKIE_VALUE', 'hdr, prefix', [
        '// 逐段取 cookie 值（对齐 Python：split(";") → strip → startswith → cookie[11:]）',
        '// ⚠ 首个匹配即定：用 found 标记，空值也不会被后一个同名 cookie 顶掉。',
        'LET(parts, SPLIT(hdr, ";"))',
        'LET MUT(out, "")',
        'LET MUT(found, FALSE)',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, LEN(parts))', [
            'LET(c, TRIM(AT(parts, i, "")))',
            C('IF', '&&(==(found, FALSE), STARTS_WITH(c, prefix))', [
                'SET(out, SUB(c, LEN(prefix), LEN(c)))',
                'SET(found, TRUE)',
            ], [
                'NULL',
            ]),
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// Cookie 头里取指定名字的值')

    # ── 通用小工具 ─────────────────────────────────────────────────
    src += fn('SEC_FILTER_GT', 'arr, cutoff', [
        '// 保留 > cutoff 的元素（Python 的 `t for t in times if t > cutoff`）',
        'LET MUT(out, [])',
        C('FOR', 't, arr', [
            C('IF', '>(t, cutoff)', ['SET(out, PUSH(out, t))'], ['NULL']),
        ]),
        'out',
    ], '// 过滤 > cutoff 的时间戳')

    src += fn('SEC_MIN', 'arr', [
        '// 最小值（空数组调用方自己先挡）',
        'LET MUT(best, AT(arr, 0, 0))',
        C('FOR', 't, arr', [
            C('IF', '<(t, best)', ['SET(best, t)'], ['NULL']),
        ]),
        'best',
    ], '// 数组最小值')

    src += fn('SEC_AGED_REMAIN', 'times, now_ms, span_ms', [
        '// 对齐 Python：int(span_seconds - (now - oldest)) + 1',
        '// ⚠ 先 FLOAT 再除：`/(整数,整数)` 是截断除法（S2-5 实测）。',
        C('IF', '==(LEN(times), 0)', ['0'], [
            'LET(oldest, SEC_MIN(times))',
            '+(INT(/(FLOAT(-(span_ms, -(now_ms, oldest))), FLOAT(1000))), 1)',
        ]),
    ], '// retry-after / lockout 剩余秒数')

    src += fn('SEC_ARR_REMOVE', 'arr, x', [
        '// 删掉所有等于 x 的元素（token 唯一，等价于删一个）',
        'LET MUT(out, [])',
        C('FOR', 'v, arr', [
            C('IF', '!=(v, x)', ['SET(out, PUSH(out, v))'], ['NULL']),
        ]),
        'out',
    ], '// 数组删元素')

    src += fn('SEC_HOSTS', 'admin_port, bind_domain', [
        '// 白名单主机（Python: 127.0.0.1/localhost + 可选 bind_domain 的 http/https）',
        'LET(p, STR(admin_port))',
        'LET MUT(out, [+("http://127.0.0.1:", p), +("http://localhost:", p)])',
        C('IF', '!=(bind_domain, "")', [
            'SET(out, PUSH(PUSH(out, +("http://", bind_domain)), +("https://", bind_domain)))',
        ], ['NULL']),
        'out',
    ], '// 允许的 Origin/Referer 前缀')

    src += fn('SEC_HOST_OK', 'value, hosts', [
        '// Python 是 `any(value.startswith(h))` —— **前缀**匹配，不是等值。',
        '// ⚠ 因此 "http://127.0.0.1:8081.evil.com" 会通过；这是**照抄源码**的行为，',
        '//   已在基准里作为 origin_prefix_spoof 用例钉住（不擅自加固）。',
        'LET MUT(ok, FALSE)',
        C('FOR', 'h, hosts', [
            C('IF', 'STARTS_WITH(value, h)', ['SET(ok, TRUE)'], ['NULL']),
        ]),
        'ok',
    ], '// Origin/Referer 前缀匹配')

    # ── CSRF ──────────────────────────────────────────────────────
    # Python（security.py:43）：
    #   random_bytes = secrets.token_bytes(16)
    #   timestamp = int(time.time()).to_bytes(4, "big")
    #   token_data = random_bytes + timestamp
    #   signature = hmac.new(_CSRF_SECRET, token_data, hashlib.sha256).digest()
    #   return base64.urlsafe_b64encode(token_data + signature).decode("ascii")
    src += fn('NEW_CSRF_TOKEN', 'opts', [
        '// opts 键：secret（hex）/ random_hex（16B，注入用）/ now_ms（注入用）',
        'LET(secret, AT_K(opts, "secret", SEC_CSRF_SECRET))',
        'LET(rhex, AT_K(opts, "random_hex", ""))',
        'LET(now_ms, AT_K(opts, "now_ms", NOW()))',
        'LET(rb0, IF(==(rhex, ""), RANDOM_BYTES(16), SEC_HEX_TO_BYTES(rhex)))',
        C('IF', '==(TYPE(rb0), "NULL")', ['""'], [
            'LET(ts, /(now_ms, 1000))',
            'LET(data, +(rb0, SEC_U32_BE(ts)))',
            '// D-S4-1：HMAC 覆盖 token_data 的 hex 文本（WLWL 的 HMAC 只收 STRING）',
            'LET(sig, SEC_HEX_TO_BYTES(HMAC_SHA256(secret, SEC_BYTES_TO_HEX(data))))',
            C('IF', '==(TYPE(sig), "NULL")', ['""'], [
                'SEC_B64_ENC(+(data, sig))',
            ]),
        ]),
    ], '// CSRF token（对齐 generate_csrf_token）')

    # Python（security.py:53），四重校验顺序：
    #   格式/长度 → HMAC（compare_digest）→ 1h 时限 → cookie 双提交 → Origin/Referer
    src += fn('VALIDATE_CSRF_TOKEN', 'opts', [
        '// opts 键：token / cookie（HTTP_COOKIE 原文）/ origin / referer /',
        '//          admin_port（默认 8081）/ bind_domain / now_ms / secret',
        '// ⚠ 校验顺序与 Python 逐条一致（先格式、再签名、再时限、再 cookie、再 Origin）。',
        'LET(token, AT_K(opts, "token", ""))',
        'LET(secret, AT_K(opts, "secret", SEC_CSRF_SECRET))',
        'LET(now_ms, AT_K(opts, "now_ms", NOW()))',
        'LET(cookie_hdr, AT_K(opts, "cookie", ""))',
        'LET(origin, AT_K(opts, "origin", ""))',
        'LET(referer, AT_K(opts, "referer", ""))',
        'LET(admin_port, AT_K(opts, "admin_port", 8081))',
        'LET(bind_domain, AT_K(opts, "bind_domain", ""))',
        '// ① 格式/长度：空 或 码点数 < 32 ⇒ False（Python: `not token or len(token) < 32`）',
        C('IF', '||(==(token, ""), <(LEN(token), 32))', ['RETURN(FALSE)'], ['NULL']),
        'LET(bytes, SEC_B64_DEC(token))',
        C('IF', '==(TYPE(bytes), "NULL")', ['RETURN(FALSE)'], ['NULL']),
        '// ② 解码后必须恰好 52 字节（16 random + 4 ts + 32 sig）',
        C('IF', '!=(LEN(bytes), 52)', ['RETURN(FALSE)'], ['NULL']),
        'LET(data, SLICE(bytes, 0, 20))',
        'LET(sig, SLICE(bytes, 20, 52))',
        'LET(expect, SEC_HEX_TO_BYTES(HMAC_SHA256(secret, SEC_BYTES_TO_HEX(data))))',
        '// ③ HMAC（常数时间比较；Python 用 hmac.compare_digest）',
        C('IF', 'NOT(TIMING_SAFE_EQ(SEC_BYTES_TO_HEX(sig), SEC_BYTES_TO_HEX(expect)))',
          ['RETURN(FALSE)'], ['NULL']),
        'LET(ts, SEC_U32_FROM(data, 16))',
        '// ④ 时限：now - ts > 3600 或 ts > now + 60 ⇒ False',
        C('IF', '||(>( -(now_ms, *(ts, 1000)), 3600000), >(*(ts, 1000), +(now_ms, 60000)))',
          ['RETURN(FALSE)'], ['NULL']),
        '// ⑤ 双提交 cookie：必须存在且与 token 逐字节相等',
        'LET(cv, SEC_COOKIE_VALUE(cookie_hdr, "csrf_token="))',
        C('IF', '||(==(cv, ""), NOT(TIMING_SAFE_EQ(token, cv)))', ['RETURN(FALSE)'], ['NULL']),
        '// ⑥ Origin/Referer 白名单（空 ⇒ 跳过；"null" 大小写不敏感 ⇒ 跳过）',
        'LET(hosts, SEC_HOSTS(admin_port, bind_domain))',
        C('IF', '&&(!=(origin, ""), !=(LOWER(origin), "null"))', [
            C('IF', 'NOT(SEC_HOST_OK(origin, hosts))', ['RETURN(FALSE)'], ['NULL']),
        ], ['NULL']),
        C('IF', '!=(referer, "")', [
            C('IF', 'NOT(SEC_HOST_OK(referer, hosts))', ['RETURN(FALSE)'], ['NULL']),
        ], ['NULL']),
        'TRUE',
    ], '// CSRF 校验（对齐 validate_csrf_token）')

    # Python（security.py:128）：
    #   cookie = f"csrf_token={token}; Path=/; HttpOnly; SameSite=Strict"
    #   if secure: cookie += "; Secure"
    #   return ("Set-Cookie", cookie)
    src += fn('CSRF_COOKIE_HEADER', 'opts', [
        '// opts 键：token（缺省 ⇒ 新生成）/ secure',
        '// 返回 [name, value]（Python 返回 ("Set-Cookie", cookie) 二元组）。',
        'LET(tok, AT_K(opts, "token", NULL))',
        'LET(secure, AT_K(opts, "secure", FALSE))',
        'LET(t, IF(||(==(TYPE(tok), "NULL"), ==(tok, "")), NEW_CSRF_TOKEN(opts), tok))',
        'LET(cookie, CAT("csrf_token=", t, "; Path=/; HttpOnly; SameSite=Strict", '
        'IF(secure, "; Secure", "")))',
        '["Set-Cookie", cookie]',
    ], '// CSRF Set-Cookie（对齐 get_csrf_cookie_header）')

    src += fn('NEW_SESSION_TOKEN', 'opts', [
        '// 32B 随机 → urlsafe base64 → **去 padding**（Python secrets.token_urlsafe(32)）',
        '// opts 键：random_hex（32B，注入用）',
        'LET(rhex, AT_K(opts, "random_hex", ""))',
        'LET(rb0, IF(==(rhex, ""), RANDOM_BYTES(32), SEC_HEX_TO_BYTES(rhex)))',
        C('IF', '==(TYPE(rb0), "NULL")', ['""'], [
            'SEC_RSTRIP_PAD(SEC_B64_ENC(rb0))',
        ]),
    ], '// 会话 token（对齐 generate_session_token）')

    # Python（security.py:153）：
    #   cookie = f"session_id={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    src += fn('SESSION_COOKIE_HEADER', 'opts', [
        '// opts 键：token（缺省 ⇒ 新生成）/ secure / max_age（默认 86400）',
        'LET(tok, AT_K(opts, "token", NULL))',
        'LET(secure, AT_K(opts, "secure", FALSE))',
        'LET(max_age, AT_K(opts, "max_age", 86400))',
        'LET(t, IF(||(==(TYPE(tok), "NULL"), ==(tok, "")), NEW_SESSION_TOKEN(opts), tok))',
        'LET(cookie, CAT("session_id=", t, "; Path=/; HttpOnly; SameSite=Strict; Max-Age=", '
        'STR(max_age), IF(secure, "; Secure", "")))',
        '["Set-Cookie", cookie]',
    ], '// 会话 Set-Cookie（对齐 get_session_cookie_header）')

    src += fn('SESSION_CLEAR_COOKIE_HEADER', 'opts', [
        '// 清会话：Max-Age=0（Python get_session_clear_cookie_header）',
        'LET(secure, AT_K(opts, "secure", FALSE))',
        'LET(cookie, CAT("session_id=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0", '
        'IF(secure, "; Secure", "")))',
        '["Set-Cookie", cookie]',
    ], '// 清会话 Set-Cookie')

    src += fn('SESSION_CONFIG', 'opts', [
        '// Python 类常量（用于钉 24h / 5000 / 300 三个数，不靠跑满 5000 次）',
        'INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), '
        '"max_age", 86400), "max_tracked", 5000), "cleanup_interval", 300), '
        '"max_failures", 5), "lockout_seconds", 300), '
        '"rate_max_requests", 60)',
    ], '// 会话/限流常量（对齐 SessionManager 类属性）')

    # ── 会话注册表 ────────────────────────────────────────────────
    src += fn('SEC_SESSION_CLEANUP', 'now_ms, max_age_ms, cln_ms', [
        '// 对齐 SessionManager._cleanup：距上次清理 < 300s 就跳过',
        C('IF', '&&(>=(SEC_SESSION_LAST_CLEANUP, 0), <( -(now_ms, SEC_SESSION_LAST_CLEANUP), cln_ms))', [
            'RETURN(NULL)',
        ], ['NULL']),
        'SET(SEC_SESSION_LAST_CLEANUP, now_ms)',
        'LET(cutoff, -(now_ms, max_age_ms))',
        'LET MUT(expired, [])',
        C('FOR', 'tok, SEC_SESSION_ORDER', [
            'LET(created, AT_K(AT_K(SEC_SESSIONS, tok, DICT()), "created_at", 0))',
            C('IF', '<(created, cutoff)', ['SET(expired, PUSH(expired, tok))'], ['NULL']),
        ]),
        C('FOR', 'tok, expired', [
            'SET(SEC_SESSIONS, REMOVE_KEY(SEC_SESSIONS, tok))',
            'SET(SEC_SESSION_ORDER, SEC_ARR_REMOVE(SEC_SESSION_ORDER, tok))',
        ]),
        'NULL',
    ], '// 会话清理（对齐 _cleanup）')

    src += fn('SEC_SESSION_EVICT', 'opts', [
        '// 淘汰 created_at 最小者（Python: min(..., key=created_at)；同值取插入序第一个）',
        '// ⚠ 卡片写「LRU」，源码实际是「最老创建」= FIFO；本实现照源码。',
        'LET MUT(best, "")',
        'LET MUT(best_t, 0)',
        C('FOR', 'tok, SEC_SESSION_ORDER', [
            'LET(created, AT_K(AT_K(SEC_SESSIONS, tok, DICT()), "created_at", 0))',
            C('IF', '||(==(best, ""), <(created, best_t))', [
                'SET(best, tok)',
                'SET(best_t, created)',
            ], ['NULL']),
        ]),
        C('IF', '==(best, "")', ['NULL'], [
            'SET(SEC_SESSIONS, REMOVE_KEY(SEC_SESSIONS, best))',
            'SET(SEC_SESSION_ORDER, SEC_ARR_REMOVE(SEC_SESSION_ORDER, best))',
        ]),
    ], '// 淘汰最老会话')

    # Python（security.py:396）：
    #   now = time.time(); cleanup(now)
    #   if len(_sessions) >= MAX_TRACKED_SESSIONS: del oldest
    #   token = secrets.token_urlsafe(32); store {"created_at": now, "client_ip": ip}
    src += fn('SESSION_CREATE', 'opts', [
        '// opts 键：client_ip / now_ms / token（注入用）/ max_sessions（注入用，默认 5000）',
        'LET(now_ms, AT_K(opts, "now_ms", NOW()))',
        'LET(ip, AT_K(opts, "client_ip", ""))',
        'LET(tok0, AT_K(opts, "token", NULL))',
        'LET(max_s, AT_K(opts, "max_sessions", 5000))',
        'LET(max_age_ms, *(AT_K(opts, "max_age_seconds", 86400), 1000))',
        'LET(cln_ms, *(AT_K(opts, "cleanup_interval_seconds", 300), 1000))',
        'SEC_SESSION_CLEANUP(now_ms, max_age_ms, cln_ms)',
        C('IF', '>=(LEN(KEYS(SEC_SESSIONS)), max_s)', ['SEC_SESSION_EVICT(opts)'], ['NULL']),
        'LET(tok, IF(||(==(TYPE(tok0), "NULL"), ==(tok0, "")), '
        'NEW_SESSION_TOKEN(DICT()), tok0))',
        'LET(data, INDEX_SET(INDEX_SET(DICT(), "created_at", now_ms), "client_ip", ip))',
        C('IF', 'HAS(SEC_SESSIONS, tok)', [
            'SET(SEC_SESSIONS, INDEX_SET(SEC_SESSIONS, tok, data))',
        ], [
            'SET(SEC_SESSIONS, INDEX_SET(SEC_SESSIONS, tok, data))',
            'SET(SEC_SESSION_ORDER, PUSH(SEC_SESSION_ORDER, tok))',
        ]),
        'tok',
    ], '// 新建会话（对齐 create_session）')

    src += fn('SESSION_VALIDATE', 'opts', [
        '// opts 键：token / client_ip / now_ms',
        '// 24h 过期 + 过期即删（Python validate_session）',
        'LET(token, AT_K(opts, "token", ""))',
        'LET(now_ms, AT_K(opts, "now_ms", NOW()))',
        'LET(max_age_ms, *(AT_K(opts, "max_age_seconds", 86400), 1000))',
        'LET(cln_ms, *(AT_K(opts, "cleanup_interval_seconds", 300), 1000))',
        'SEC_SESSION_CLEANUP(now_ms, max_age_ms, cln_ms)',
        C('IF', 'NOT(HAS(SEC_SESSIONS, token))', ['RETURN(FALSE)'], ['NULL']),
        'LET(created, AT_K(AT_K(SEC_SESSIONS, token, DICT()), "created_at", 0))',
        C('IF', '>( -(now_ms, created), max_age_ms)', [
            'SET(SEC_SESSIONS, REMOVE_KEY(SEC_SESSIONS, token))',
            'SET(SEC_SESSION_ORDER, SEC_ARR_REMOVE(SEC_SESSION_ORDER, token))',
            'RETURN(FALSE)',
        ], ['NULL']),
        'TRUE',
    ], '// 校验会话（对齐 validate_session）')

    src += fn('SESSION_DESTROY', 'opts', [
        '// 删除会话；返回「删除前是否存在」（Python destroy_session 返回 None）',
        'LET(token, AT_K(opts, "token", ""))',
        'LET(existed, HAS(SEC_SESSIONS, token))',
        'SET(SEC_SESSIONS, REMOVE_KEY(SEC_SESSIONS, token))',
        'SET(SEC_SESSION_ORDER, SEC_ARR_REMOVE(SEC_SESSION_ORDER, token))',
        'existed',
    ], '// 删除会话')

    src += fn('SESSION_RESET', 'opts', [
        '// 清空注册表 —— 模拟「进程重启」：源码的会话只在内存里，重启即全失效。',
        '// ⚠ 真重启无法在同一进程内测；本函数是等价替身（返回清掉的条数）。',
        'LET(n, LEN(KEYS(SEC_SESSIONS)))',
        'SET(SEC_SESSIONS, DICT())',
        'SET(SEC_SESSION_ORDER, [])',
        'SET(SEC_SESSION_LAST_CLEANUP, -1)',
        'n',
    ], '// 清空会话（模拟进程重启）')

    src += fn('SESSION_COUNT', 'opts', [
        '// 当前会话数（测试/观测用）',
        'LEN(KEYS(SEC_SESSIONS))',
    ], '// 会话条数')

    src += fn('SESSION_FROM_COOKIE', 'opts', [
        '// 对齐 get_session_from_environ：取 session_id= 的值；没有 ⇒ ""',
        'SEC_COOKIE_VALUE(AT_K(opts, "cookie", ""), "session_id=")',
    ], '// 从 Cookie 头取会话 id')

    # ── 限流 + 登录锁定 ────────────────────────────────────────────
    src += fn('SEC_RL_CLEANUP', 'now_ms, win_ms, cln_ms', [
        '// 对齐 RateLimiter._cleanup（每 60s 一次；去掉「最后访问早于窗口」的 IP）',
        C('IF', '&&(>=(SEC_RL_LAST_CLEANUP, 0), <( -(now_ms, SEC_RL_LAST_CLEANUP), cln_ms))', [
            'RETURN(NULL)',
        ], ['NULL']),
        'SET(SEC_RL_LAST_CLEANUP, now_ms)',
        'LET(cutoff, -(now_ms, win_ms))',
        'LET MUT(expired, [])',
        C('FOR', 'ip, KEYS(SEC_RL)', [
            'LET(times, AT_K(SEC_RL, ip, []))',
            C('IF', '||(==(LEN(times), 0), <(AT(times, -(LEN(times), 1), 0), cutoff))', [
                'SET(expired, PUSH(expired, ip))',
            ], ['NULL']),
        ]),
        C('FOR', 'ip, expired', ['SET(SEC_RL, REMOVE_KEY(SEC_RL, ip))']),
        'NULL',
    ], '// 限流表清理')

    src += fn('SEC_RL_HIT', 'ip, now_ms, win_ms, max_req, max_ips', [
        '// 对齐 RateLimiter.is_allowed（滑动窗口；窗口内条数达上限即拒）',
        C('IF', 'NOT(HAS(SEC_RL, ip))', [
            '// 新 IP 且表已满 ⇒ 直接拒（保留已有 IP 的记录）',
            C('IF', '>=(LEN(KEYS(SEC_RL)), max_ips)', ['RETURN(FALSE)'], [
                'SET(SEC_RL, INDEX_SET(SEC_RL, ip, []))',
            ]),
        ], ['NULL']),
        'LET(recent, SEC_FILTER_GT(AT_K(SEC_RL, ip, []), -(now_ms, win_ms)))',
        C('IF', '>=(LEN(recent), max_req)', [
            'SET(SEC_RL, INDEX_SET(SEC_RL, ip, recent))',
            'FALSE',
        ], [
            'SET(SEC_RL, INDEX_SET(SEC_RL, ip, PUSH(recent, now_ms)))',
            'TRUE',
        ]),
    ], '// 记一次请求并判限流')

    src += fn('SEC_AF_CLEANUP', 'now_ms, lock_ms, cln_ms', [
        '// 对齐 AuthFailureTracker._maybe_cleanup（每 60s 一次）',
        C('IF', '&&(>=(SEC_AF_LAST_CLEANUP, 0), <( -(now_ms, SEC_AF_LAST_CLEANUP), cln_ms))', [
            'RETURN(NULL)',
        ], ['NULL']),
        'SET(SEC_AF_LAST_CLEANUP, now_ms)',
        'LET(cutoff, -(now_ms, lock_ms))',
        'LET MUT(expired, [])',
        C('FOR', 'ip, KEYS(SEC_AF)', [
            'LET(times, AT_K(SEC_AF, ip, []))',
            C('IF', '||(==(LEN(times), 0), <(AT(times, -(LEN(times), 1), 0), cutoff))', [
                'SET(expired, PUSH(expired, ip))',
            ], ['NULL']),
        ]),
        C('FOR', 'ip, expired', ['SET(SEC_AF, REMOVE_KEY(SEC_AF, ip))']),
        'NULL',
    ], '// 失败表清理')

    src += fn('SEC_AF_RECORD', 'ip, now_ms, lock_ms, cln_ms', [
        '// 对齐 record_failure：先按 lockout 窗口过滤，再追加',
        'SEC_AF_CLEANUP(now_ms, lock_ms, cln_ms)',
        'LET(recent, SEC_FILTER_GT(AT_K(SEC_AF, ip, []), -(now_ms, lock_ms)))',
        'SET(SEC_AF, INDEX_SET(SEC_AF, ip, PUSH(recent, now_ms)))',
        'LEN(PUSH(recent, now_ms))',
    ], '// 记一次登录失败')

    src += fn('SEC_AF_STATE', 'ip, now_ms, lock_ms, max_fail', [
        '// 对齐 is_locked_out + get_lockout_remaining',
        'LET(recent, SEC_FILTER_GT(AT_K(SEC_AF, ip, []), -(now_ms, lock_ms)))',
        'LET(locked, >=(LEN(recent), max_fail))',
        'LET(rem, IF(locked, SEC_AGED_REMAIN(recent, now_ms, lock_ms), 0))',
        'INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "locked", locked), '
        '"lockout_remaining", rem), "failures", LEN(recent))',
    ], '// 锁定状态')

    src += fn('RATE_LIMIT', 'opts', [
        '// opts 键：client_ip / now_ms / event（request|auth_failure|auth_check）/',
        '//          max_requests(60) / window_seconds(60) / max_failures(5) /',
        '//          lockout_seconds(300) / cleanup_interval(60) / max_ips(10000)',
        '// 返回 DICT：allowed / retry_after / locked / lockout_remaining / failures / tracked_ips',
        'LET(ip, AT_K(opts, "client_ip", ""))',
        'LET(now_ms, AT_K(opts, "now_ms", NOW()))',
        'LET(ev, AT_K(opts, "event", "request"))',
        'LET(max_req, AT_K(opts, "max_requests", 60))',
        'LET(win_s, AT_K(opts, "window_seconds", 60))',
        'LET(max_fail, AT_K(opts, "max_failures", 5))',
        'LET(lock_s, AT_K(opts, "lockout_seconds", 300))',
        'LET(cln_s, AT_K(opts, "cleanup_interval", 60))',
        'LET(max_ips, AT_K(opts, "max_ips", 10000))',
        'LET(win_ms, *(win_s, 1000))',
        'LET(lock_ms, *(lock_s, 1000))',
        'LET(cln_ms, *(cln_s, 1000))',
        C('IF', '==(ev, "request")', [
            'SEC_RL_CLEANUP(now_ms, win_ms, cln_ms)',
        ], [
            'SEC_AF_CLEANUP(now_ms, lock_ms, cln_ms)',
        ]),
        'LET MUT(hit, NULL)',
        C('IF', '==(ev, "request")', [
            'SET(hit, SEC_RL_HIT(ip, now_ms, win_ms, max_req, max_ips))',
        ], [
            C('IF', '==(ev, "auth_failure")', [
                'SEC_AF_RECORD(ip, now_ms, lock_ms, cln_ms)',
            ], ['NULL']),
        ]),
        'LET(af, SEC_AF_STATE(ip, now_ms, lock_ms, max_fail))',
        'LET(locked, AT_K(af, "locked", FALSE))',
        'LET(lock_rem, AT_K(af, "lockout_remaining", 0))',
        'LET(fails, AT_K(af, "failures", 0))',
        'LET(allowed, IF(==(ev, "request"), IF(==(TYPE(hit), "NULL"), FALSE, hit), '
        'NOT(locked)))',
        '// request 用 sliding 窗口的 retry_after；锁定状态用 lockout_remaining。',
        'LET(retry, IF(==(ev, "request"), '
        'SEC_AGED_REMAIN(SEC_FILTER_GT(AT_K(SEC_RL, ip, []), -(now_ms, win_ms)), '
        'now_ms, win_ms), IF(locked, lock_rem, 0)))',
        'INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), '
        '"allowed", allowed), "retry_after", retry), "locked", locked), '
        '"lockout_remaining", lock_rem), "failures", fails), '
        '"tracked_ips", LEN(KEYS(SEC_RL)))',
    ], '// 限流 + 登录锁定（对齐 RateLimiter / AuthFailureTracker）')

    src += fn('RATE_LIMIT_RESET', 'opts', [
        '// 清空限流表与失败表（测试隔离 / 运营手工重置；返回清掉的 IP 条数）',
        'LET(n, +(LEN(KEYS(SEC_RL)), LEN(KEYS(SEC_AF))))',
        'SET(SEC_RL, DICT())',
        'SET(SEC_AF, DICT())',
        'SET(SEC_RL_LAST_CLEANUP, -1)',
        'SET(SEC_AF_LAST_CLEANUP, -1)',
        'n',
    ], '// 清空限流/失败表')

    # ── 审计 ──────────────────────────────────────────────────────
    src += fn('SEC_AUDIT_LEVEL', 'ev', [
        '// 事件名 → 级别。事件名逐字取自源码；未知 ⇒ ""（AUDIT_EVENT 返回 ""）。',
        '// 源码出处：security.py:58/64/71/78/91/103/107/112（CSRF）、281/285（BLOCK）、',
        '//           306/310（XSS-BLOCK）、content.py:144（DELETE）。',
        '// ⚠ D-S4-3：AUTH-FAIL / RATE-LIMIT 在源码里**不存在**，是 S4-2 新增事件。',
        C('IF', '==(ev, "CSRF-FAIL")', ['RETURN("WARN")'], ['NULL']),
        C('IF', '==(ev, "CSRF-ERROR")', ['RETURN("ERROR")'], ['NULL']),
        C('IF', '==(ev, "XSS-BLOCK")', ['RETURN("WARN")'], ['NULL']),
        C('IF', '==(ev, "BLOCK")', ['RETURN("WARN")'], ['NULL']),
        C('IF', '==(ev, "AUTH-FAIL")', ['RETURN("WARN")'], ['NULL']),
        C('IF', '==(ev, "RATE-LIMIT")', ['RETURN("WARN")'], ['NULL']),
        C('IF', '==(ev, "DELETE")', ['RETURN("INFO")'], ['NULL']),
        C('IF', '==(ev, "WRITE")', ['RETURN("INFO")'], ['NULL']),
        C('IF', '==(ev, "WRITE-FAILED")', ['RETURN("ERROR")'], ['NULL']),
        C('IF', '==(ev, "ERROR")', ['RETURN("ERROR")'], ['NULL']),
        C('IF', '==(ev, "INIT")', ['RETURN("INFO")'], ['NULL']),
        C('IF', '==(ev, "AUTH")', ['RETURN("INFO")'], ['NULL']),
        '""',
    ], '// 审计事件 → 级别')

    src += fn('SEC_JSON_FIELDS', 'd', [
        '// fields → JSON 对象（键序 = 调用方的插入序，两边逐字一致）',
        '// ⚠ 不用 STRINGIFY(dict)：它对**容器**按键名排序（page_common 实测），',
        '//   会与 Python 侧的插入序不一致；单标量仍复用 STRINGIFY。',
        'LET MUT(out, "{")',
        'LET MUT(i, 0)',
        C('FOR', 'k, KEYS(d)', [
            C('IF', '>(i, 0)', ['SET(out, +(out, ","))'], ['NULL']),
            'SET(out, CAT(out, STRINGIFY(k), ":", STRINGIFY(AT_K(d, k, NULL))))',
            'SET(i, +(i, 1))',
        ]),
        '+(out, "}")',
    ], '// fields → JSON')

    src += fn('AUDIT_EVENT', 'opts', [
        '// opts 键：event / msg（完整日志文本）/ level（可缺省）/ fields（DICT）/ now_ms',
        '// 产出**一行** JSONL：{"ts":..,"level":..,"event":..,"msg":..,"fields":{..}}',
        '// 未知事件 ⇒ ""（不写日志、不猜级别）。',
        'LET(ev, AT_K(opts, "event", ""))',
        'LET(now_ms, AT_K(opts, "now_ms", NOW()))',
        'LET(lvl, AT_K(opts, "level", ""))',
        'LET(msg, AT_K(opts, "msg", ""))',
        'LET(fields, AT_K(opts, "fields", DICT()))',
        C('IF', '==(ev, "")', ['""'], [
            'LET(level, IF(==(lvl, ""), SEC_AUDIT_LEVEL(ev), lvl))',
            C('IF', '==(level, "")', ['""'], [
                'LET(m, IF(==(msg, ""), CAT("[", ev, "]"), msg))',
                'CAT("{\\"ts\\":", STR(now_ms), ",\\"level\\":", STRINGIFY(level), '
                '",\\"event\\":", STRINGIFY(ev), ",\\"msg\\":", STRINGIFY(m), '
                '",\\"fields\\":", SEC_JSON_FIELDS(fields), "}")',
            ]),
        ]),
    ], '// 审计行（JSONL，单行）')

    # ── 口令 ──────────────────────────────────────────────────────
    src += fn('HASH_PASSWORD', 'opts', [
        '// opts 键：password / algo（argon2id|pbkdf2）/ salt_hex（缺省 RANDOM_HEX(16)）/',
        '//          t_cost(2) / m_cost(19456) / p_cost(1) / len(32) / iter(600000)',
        '// 格式：argon2id$<t>$<m>$<p>$<salt>$<hash>  /  pbkdf2-sha256$<iter>$<len>$<salt>$<hash>',
        '// ⚠ 绝不用 SHA256 存口令（快摘要）；PBKDF2 分支强制 iter ≥ 600000。',
        'LET(pw, AT_K(opts, "password", ""))',
        'LET(algo, AT_K(opts, "algo", "argon2id"))',
        'LET(salt, AT_K(opts, "salt_hex", RANDOM_HEX(16)))',
        'LET(hlen, AT_K(opts, "len", 32))',
        C('IF', '==(algo, "pbkdf2")', [
            'LET(iter, AT_K(opts, "iter", 600000))',
            C('IF', '||(<(iter, 600000), !RE_TEST(RE("^([0-9a-fA-F][0-9a-fA-F])*$"), salt))', [
                '""',
            ], [
                'CAT("pbkdf2-sha256$", STR(iter), "$", STR(hlen), "$", salt, "$", '
                'PBKDF2_ITER(pw, salt, iter, hlen, "sha256"))',
            ]),
        ], [
            'LET(t, AT_K(opts, "t_cost", 2))',
            'LET(m, AT_K(opts, "m_cost", 19456))',
            'LET(p, AT_K(opts, "p_cost", 1))',
            C('IF', '!RE_TEST(RE("^([0-9a-fA-F][0-9a-fA-F])*$"), salt)', [
                '""',
            ], [
                'CAT("argon2id$", STR(t), "$", STR(m), "$", STR(p), "$", salt, "$", '
                'ARGON2ID(pw, salt, t, m, p, hlen))',
            ]),
        ]),
    ], '// 口令哈希（慢哈希；Argon2id 优先）')

    src += fn('VERIFY_PASSWORD', 'opts', [
        '// opts 键：password / stored',
        '// 错口令 / 变形串 ⇒ FALSE；比较用 TIMING_SAFE_EQ。',
        'LET(pw, AT_K(opts, "password", ""))',
        'LET(stored, AT_K(opts, "stored", ""))',
        'LET(parts, SPLIT(stored, "$"))',
        'LET(n, LEN(parts))',
        C('IF', '&&(==(n, 5), ==(AT(parts, 0, ""), "pbkdf2-sha256"))', [
            'LET(iter_s, AT(parts, 1, ""))',
            'LET(len_s, AT(parts, 2, ""))',
            'LET(salt, AT(parts, 3, ""))',
            'LET(want, AT(parts, 4, ""))',
            C('IF', '||(||(==(want, ""), !RE_TEST(RE("^[0-9]+$"), iter_s)), ||(!RE_TEST(RE("^[0-9]+$"), len_s), !RE_TEST(RE("^([0-9a-fA-F][0-9a-fA-F])*$"), salt)))', [
                'RETURN(FALSE)',
            ], ['NULL']),
            'LET(iter, INT(iter_s))',
            C('IF', '<(iter, 600000)', ['RETURN(FALSE)'], ['NULL']),
            'TIMING_SAFE_EQ(PBKDF2_ITER(pw, salt, iter, INT(len_s), "sha256"), want)',
        ], [
            C('IF', '&&(==(n, 6), ==(AT(parts, 0, ""), "argon2id"))', [
                'LET(salt, AT(parts, 4, ""))',
                'LET(want, AT(parts, 5, ""))',
                C('IF', '||(==(want, ""), !RE_TEST(RE("^([0-9a-fA-F][0-9a-fA-F])*$"), salt))', [
                    'RETURN(FALSE)',
                ], ['NULL']),
                'TIMING_SAFE_EQ(ARGON2ID(pw, salt, INT(AT(parts, 1, "0")), '
                'INT(AT(parts, 2, "0")), INT(AT(parts, 3, "0")), '
                '/(LEN(want), 2)), want)',
            ], [
                'FALSE',
            ]),
        ]),
    ], '// 验口令（TIMING_SAFE_EQ）')

    A('EXPORT(["NEW_CSRF_TOKEN", "VALIDATE_CSRF_TOKEN", "CSRF_COOKIE_HEADER", '
      '"NEW_SESSION_TOKEN", "SESSION_COOKIE_HEADER", "SESSION_CLEAR_COOKIE_HEADER", '
      '"SESSION_CREATE", "SESSION_VALIDATE", "SESSION_DESTROY", "SESSION_RESET", '
      '"SESSION_COUNT", "SESSION_FROM_COOKIE", "SESSION_CONFIG", "RATE_LIMIT", '
      '"RATE_LIMIT_RESET", "AUDIT_EVENT", "HASH_PASSWORD", "VERIFY_PASSWORD"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
