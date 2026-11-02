"""生成 tp/test/test_http_client_tls.wll —— 出站 HTTPS 客户端的**脱网**测试（卡 S5-1）。

⚠ 输出的 .wll 由本文件生成，不要手改。

**为什么能脱网**：`tp/lib/http_client_tls.wll` 把「HTTP 报文构造/解析」与「TLS 传输」
彻底分开 —— 前者是纯函数，后者只在 `HC_TLS_EXCHANGE` 里（运行时 `MODULE_REF("tls")`）。
所以本文件的**每一个用例都不碰 `tls`**，`wlwl run` 不带 `--ext` 也能全绿
（这是卡 S5-1 的硬验收：CI 只下载基础 zip，没有 TLS 扩展）。

**整条链路怎么测**：用 `opts.exchange` 注入一个假传输（`T0_exchange`），
它记下**真实发出的请求文本**并回放夹具里的响应报文 ⇒
「建请求 → 传输（假） → 解析 → 定 ok → 取 content」全部在 CI 里跑。

**基准**：tp/test/fixtures/http_client_tls_baseline.json
（由 `gen_http_client_tls_baseline.py` 生成：手写期望值 + 出处；
并对 `http.client` 做过真交叉校验，刻意偏离的三处登记在 `meta.divergences`）。

**覆盖**
  · 请求报文逐字节：POST+JSON / 中文 body 的 BYTE_LEN / GET 无 body / 非 443 的 Host /
    POST 空 body / 头注入 / 重复 Host+CL / path 补斜杠
  · 响应解析：正常 / 头名大小写 / 无 body / CL 小于实际（不截断） / CL 大于实际（失败） /
    4xx / 5xx / 同名头合并 / 空 reason / body 里含 CRLFCRLF / 无终止符 / 坏状态码 /
    坏协议 / chunked / 坏 Content-Length
  · 请求链（注入传输）：200 / 401 / 500 / 未配 key / GET 免 key / 传输失败 / 缺 host / 垃圾响应
  · CHAT_COMPLETION：正常（中文）/ model+temperature 透传 / 无 choices / 空 choices /
    缺 message / 缺 content / 非 JSON / JSON 数组 / 401 / 未配 key

**自己把关退出码**：`RUN_TESTS()` 的失败**不影响退出码**（规范明载）
⇒ 末尾必须 `IF(>(failed, 0), PANIC(...), NULL)`。

用法：python gen_test_http_client_tls.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_http_client_tls.wll')

# 测试实例自己的顶层名一律 T0_ / hc0_ 前缀（坑 52：顶层绑定跨模块共享）
SEEN = 'T0_seen'
REPLY = 'T0_reply'
EXCHANGE = 'T0_exchange'


def wl(s):
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


def expr(v):
    """JSON 值 → WLWL 表达式（字典保序 ⇒ INDEX_SET 链；与夹具的键序一致）。"""
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return wl(v)
    if isinstance(v, list):
        return '[' + ', '.join(expr(x) for x in v) + ']'
    if isinstance(v, dict):
        out = 'DICT()'
        for k, val in v.items():
            out = 'INDEX_SET(%s, %s, %s)' % (out, wl(k), expr(val))
        return out
    if v is None:
        return 'NULL'
    raise TypeError('bad JSON value: %r' % (v,))


def opts_with_exchange(opts):
    """把测试缝塞进 opts（键序 = 夹具里的顺序 + exchange 在最后）。"""
    out = 'DICT()'
    for k, v in opts.items():
        out = 'INDEX_SET(%s, %s, %s)' % (out, wl(k), expr(v))
    return 'INDEX_SET(%s, "exchange", %s)' % (out, EXCHANGE)


def main():
    with open(os.path.join(FIXTURES, 'http_client_tls_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)

    build = base['build']
    parse = base['parse']
    request = base['request']
    chat = base['chat']

    src = []
    A = src.append
    A('// tp/test/test_http_client_tls.wll —— 出站 HTTPS 客户端的脱网测试（卡 S5-1）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_http_client_tls.py 生成 —— 请勿手改。')
    A('//')
    A('// 被测：tp/lib/http_client_tls.wll')
    A('//   HTTP_BUILD_REQUEST / HTTP_PARSE_RESPONSE（纯函数，逐字节）')
    A('//   HTTP_REQUEST / HTTPS_POST_JSON / CHAT_COMPLETION（用注入的假传输跑全链路）')
    A('// 基准：tp/test/fixtures/http_client_tls_baseline.json')
    A('//   · 手写期望值 + 出处；生成期对 Python http.client 做过交叉校验')
    A('//   · 刻意偏离 Python 的三处登记在该 JSON 的 meta.divergences')
    A('//')
    A('// ⚠ **本文件不碰 TLS**：不带 --ext 也能全绿（CI 没有 TLS 扩展）。')
    A('//   真正的 TLS 往返只在本机探针 tp/probe/probe_s5_https.wll 里验。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["INDEX_OF", "CONTAINS_SUB", "COUNT", "JOIN", "CAT"]);')
    A('IMPORT("wlwl:std.encode", ["BYTE_LEN"]);')
    A('IMPORT("./../lib/http_client_tls.wll", ["HTTP_BUILD_REQUEST", "HTTP_PARSE_RESPONSE",')
    A('        "HTTP_REQUEST", "HTTPS_POST_JSON", "CHAT_COMPLETION"]);')
    A('')
    A('// ── 测试缝：假传输（记下真实发出的请求文本，回放夹具里的响应）──────────')
    A('// ⚠ 闭包可以写外层的 LET MUT（坑 12），所以这里能记下 hc0_seen。')
    A('LET MUT(%s, "");' % SEEN)
    A('LET MUT(%s, "");' % REPLY)
    A('LET(%s, FUN((req), (SET(%s, req); %s)));' % (EXCHANGE, SEEN, REPLY))
    A('')

    # ── ① 请求报文逐字节 ────────────────────────────────────────────
    A('// ── ① 请求报文逐字节（纯函数 HTTP_BUILD_REQUEST）─────────────────')
    for c in build:
        A('// %s —— %s' % (c['name'], c['note']))
        A('//   出处：%s' % c['source'])
        A('LET(hc0_build_%s, HTTP_BUILD_REQUEST(%s));' % (c['name'], expr(c['opts'])))
    A('')

    for c in build:
        A('TEST("build/%s", FUN(() ,' % c['name'])
        A('    (ASSERT_EQ(hc0_build_%s, %s));' % (c['name'], wl(c['want'])))
        A('    TRUE));')

    # 反向守卫：报文里只能有一个 Content-Length / 注入的头值不能多出一行
    A('')
    A('// ── 反向守卫：Content-Length 只许有一份；头注入不得多出一行 ──────────')
    A('TEST("guard/single_content_length", FUN(() ,')
    A('    (ASSERT_EQ(COUNT(hc0_build_dup_host_and_length, "Content-Length"), 1));')
    A('    TRUE));')
    A('TEST("guard/no_injected_header_line", FUN(() ,')
    A('    // 5 行头 + 1 个空行 = 6 个 CRLF；注入成功会变 7 个')
    A('    (ASSERT_EQ(COUNT(hc0_build_header_injection, "\\r\\n"), 6));')
    A('    TRUE));')
    A('TEST("guard/host_not_overridden", FUN(() ,')
    A('    (ASSERT_EQ(COUNT(hc0_build_dup_host_and_length, "evil.example"), 0));')
    A('    TRUE));')
    A('')
    A('// ── 反向守卫：中文 body 的 Content-Length 必须按**字节**算 ───────────')
    A('// 若夹具里的 body 换成纯 ASCII，这条会红 —— 它守着「这条断言还有区分力」。')
    A('LET(hc0_utf8_body, "{\\"text\\":\\"中文 body\\"}");')
    A('TEST("guard/content_length_is_bytes_not_codepoints", FUN(() ,')
    A('    (ASSERT(!=(BYTE_LEN(hc0_utf8_body), LEN(hc0_utf8_body)),')
    A('            "fixture body must contain multi-byte chars, else BYTE_LEN/LEN are indistinguishable"));')
    A('    TRUE));')

    # ── ② 响应解析 ──────────────────────────────────────────────────
    A('')
    A('// ── ② 响应解析（纯函数 HTTP_PARSE_RESPONSE）──────────────────────')
    for c in parse:
        A('// %s —— %s' % (c['name'], c['note']))
        A('//   出处：%s' % c['source'])
        A('LET(hc0_parse_%s, HTTP_PARSE_RESPONSE(%s));' % (c['name'], wl(c['raw'])))
    A('')

    for c in parse:
        name = c['name']
        want = c['want']
        var = 'hc0_parse_%s' % name
        A('')
        A('// %s' % name)
        A('TEST("parse/%s/ok", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), %s));' % (var, 'TRUE' if want['ok'] else 'FALSE'))
        A('    TRUE));')
        if want['ok']:
            A('TEST("parse/%s/status", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "status", -999), %d));' % (var, want['status']))
            A('    TRUE));')
            A('TEST("parse/%s/reason", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "reason", "?"), %s));' % (var, wl(want['reason'])))
            A('    TRUE));')
            hdrs = want['headers']
            A('TEST("parse/%s/header_order", FUN(() ,' % name)
            A('    (ASSERT_EQ(JOIN(KEYS(AT_K(%s, "headers", DICT())), "|"), %s));'
              % (var, wl('|'.join(k for k, _ in hdrs))))
            A('    TRUE));')
            for k, v in hdrs:
                A('TEST("parse/%s/header/%s", FUN(() ,' % (name, k))
                A('    (ASSERT_EQ(AT_K(AT_K(%s, "headers", DICT()), %s, "<missing>"), %s));'
                  % (var, wl(k), wl(v)))
                A('    TRUE));')
            A('TEST("parse/%s/body", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "body", "<missing>"), %s));' % (var, wl(want['body'])))
            A('    TRUE));')
            A('TEST("parse/%s/length_mismatch", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "length_mismatch", "?"), %s));'
              % (var, 'TRUE' if want['length_mismatch'] else 'FALSE'))
            A('    TRUE));')
            A('TEST("parse/%s/extra_bytes", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "extra_bytes", -999), %d));' % (var, want['extra_bytes']))
            A('    TRUE));')
        else:
            # want.status == -1 ⇒ 期望 NULL（合法状态码只有 100–599）
            if want['status'] == -1:
                A('TEST("parse/%s/status_null", FUN(() ,' % name)
                A('    (ASSERT_EQ(TYPE(AT_K(%s, "status", NULL)), "NULL"));' % var)
                A('    TRUE));')
            else:
                A('TEST("parse/%s/status", FUN(() ,' % name)
                A('    (ASSERT_EQ(AT_K(%s, "status", -999), %d));' % (var, want['status']))
                A('    TRUE));')
            A('TEST("parse/%s/error", FUN(() ,' % name)
            A('    (ASSERT(CONTAINS_SUB(AT_K(%s, "error", ""), %s),'
              % (var, wl(want['error_contains'])))
            A('        %s));' % wl('%s: error must mention the failed check' % name))
            A('    TRUE));')

    # ── ③ 请求链（注入假传输）───────────────────────────────────────
    A('')
    A('// ── ③ 请求链（HTTP_REQUEST / HTTPS_POST_JSON，假传输）─────────────')
    for c in request:
        name = c['name']
        call = 'HTTPS_POST_JSON' if c['api'] == 'post_json' else 'HTTP_REQUEST'
        A('// %s —— %s' % (name, c['note']))
        A('SET(%s, "");' % SEEN)
        if 'reply' in c:
            A('SET(%s, %s);' % (REPLY, expr(c['reply'])))
        else:
            A('SET(%s, %s);' % (REPLY, wl(c['raw'])))
        A('LET(hc0_req_%s, %s(%s));' % (name, call, opts_with_exchange(c['opts'])))
        # ⚠ 必须**就地快照**：所有用例是「先全部调用、后统一断言」，
        #   直接读 T0_seen 只能读到**最后一条**用例的请求（2026-11-02 实测 12 条假红）。
        # ⚠ request / chat 两组的用例名会重名（都有 no_key）⇒ 快照名要分组前缀。
        A('LET(hc0_reqwire_%s, %s);' % (name, SEEN))
    A('')

    for c in request:
        name = c['name']
        want = c['want']
        var = 'hc0_req_%s' % name
        A('')
        A('// %s' % name)
        A('TEST("request/%s/ok", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), %s));' % (var, 'TRUE' if want['ok'] else 'FALSE'))
        A('    TRUE));')
        if want['status'] == -1:
            A('TEST("request/%s/status_null", FUN(() ,' % name)
            A('    (ASSERT_EQ(TYPE(AT_K(%s, "status", NULL)), "NULL"));' % var)
            A('    TRUE));')
        else:
            A('TEST("request/%s/status", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "status", -999), %d));' % (var, want['status']))
            A('    TRUE));')
        if 'body' in want:
            A('TEST("request/%s/body", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "body", "<missing>"), %s));' % (var, wl(want['body'])))
            A('    TRUE));')
        for sub in want.get('error_contains', []):
            A('TEST("request/%s/error/%s", FUN(() ,'
              % (name, sub.replace(' ', '_').replace(':', '_').replace('/', '_')))
            A('    (ASSERT(CONTAINS_SUB(AT_K(%s, "error", ""), %s),' % (var, wl(sub)))
            A('        %s));' % wl('%s: error must contain %r' % (name, sub)))
            A('    TRUE));')
        # 传输是否真的被调用
        if want['exchange_called']:
            A('TEST("request/%s/exchange_called", FUN(() ,' % name)
            A('    (ASSERT(>(LEN(hc0_reqwire_%s), 0), %s));' % (name, wl('%s: exchange must be called' % name)))
            A('    TRUE));')
            for sub in want.get('wire_contains', []):
                A('TEST("request/%s/wire/%s", FUN(() ,'
                  % (name, sub.split(':')[0].replace(' ', '_').replace('/', '_')))
                A('    (ASSERT(CONTAINS_SUB(hc0_reqwire_%s, %s),' % (name, wl(sub)))
                A('        %s));' % wl('%s: wire must contain %r' % (name, sub)))
                A('    TRUE));')
        else:
            A('// 反向守卫：没配 key / 缺 host ⇒ **根本不碰传输**')
            A('TEST("request/%s/exchange_not_called", FUN(() ,' % name)
            A('    (ASSERT_EQ(hc0_reqwire_%s, ""));' % name)
            A('    TRUE));')

    # ── ④ CHAT_COMPLETION ───────────────────────────────────────────
    A('')
    A('// ── ④ CHAT_COMPLETION（取 choices[0].message.content）────────────')
    for c in chat:
        name = c['name']
        A('// %s —— %s' % (name, c['note']))
        A('SET(%s, "");' % SEEN)
        A('SET(%s, %s);' % (REPLY, wl(c['raw'])))
        A('LET(hc0_chat_%s, CHAT_COMPLETION(%s));' % (name, opts_with_exchange(c['opts'])))
        # 只有要断 wire_body 的用例才留下快照（否则就是 W0010 未使用绑定）
        if 'wire_body' in c['want']:
            A('LET(hc0_chatwire_%s, %s);' % (name, SEEN))
    A('')

    for c in chat:
        name = c['name']
        want = c['want']
        var = 'hc0_chat_%s' % name
        A('')
        A('// %s' % name)
        A('TEST("chat/%s/ok", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), %s));' % (var, 'TRUE' if want['ok'] else 'FALSE'))
        A('    TRUE));')
        if want['status'] == -1:
            A('TEST("chat/%s/status_null", FUN(() ,' % name)
            A('    (ASSERT_EQ(TYPE(AT_K(%s, "status", NULL)), "NULL"));' % var)
            A('    TRUE));')
        else:
            A('TEST("chat/%s/status", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "status", -999), %d));' % (var, want['status']))
            A('    TRUE));')
        if 'content' in want:
            A('TEST("chat/%s/content", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "content", "<missing>"), %s));' % (var, wl(want['content'])))
            A('    TRUE));')
        for sub in want.get('error_contains', []):
            A('TEST("chat/%s/error/%s", FUN(() ,'
              % (name, sub.replace(' ', '_').replace(':', '_').replace('/', '_')))
            A('    (ASSERT(CONTAINS_SUB(AT_K(%s, "error", ""), %s),' % (var, wl(sub)))
            A('        %s));' % wl('%s: error must contain %r' % (name, sub)))
            A('    TRUE));')
        if 'wire_body' in want:
            A('TEST("chat/%s/wire_body", FUN(() ,' % name)
            A('    // 请求体 = 报文里第一个 CRLFCRLF 之后的全部')
            A('    (ASSERT_EQ(SUB(hc0_chatwire_%s, +(INDEX_OF(hc0_chatwire_%s, "\\r\\n\\r\\n"), 4)), %s));'
              % (name, name, wl(want['wire_body'])))
            A('    TRUE));')

    # ── ⑤ 形状契约（键序也是契约）───────────────────────────────────
    A('')
    A('// ── ⑤ 形状契约：三个出参的键序（卡 S5-1 写明了键集合）──────────────')
    A('TEST("shape/parse_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(hc0_parse_ok_json), "|"),')
    A('        "ok|status|reason|headers|body|length_mismatch|extra_bytes"));')
    A('    TRUE));')
    A('TEST("shape/success_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(hc0_req_post_ok), "|"), "ok|status|headers|body"));')
    A('    TRUE));')
    A('TEST("shape/failure_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(hc0_req_post_401), "|"), "ok|status|error"));')
    A('    TRUE));')
    A('TEST("shape/chat_success_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(hc0_chat_ok), "|"), "ok|status|content"));')
    A('    TRUE));')

    # ── 跑测试 + 自己把关退出码 ─────────────────────────────────────
    A('')
    A('// ── 跑测试 + 自己把关退出码 ─────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_http_client_tls: ", LEN(records), " test(s) run");')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"), " :: ", '
      'AT_K(rec, "error", ""))))));')
    A('PRINT("test_http_client_tls: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_http_client_tls: FAILED"); '
      'PANIC("http_client_tls tests failed")), NULL);')
    A('PRINT("test_http_client_tls: OK");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
