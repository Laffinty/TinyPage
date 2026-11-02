"""生成 tp/test/fixtures/http_client_tls_baseline.json —— 出站 HTTPS 客户端的验收基准（卡 S5-1）。

⚠ 输出的 JSON 由本文件生成，不要手改。

**为什么手写期望值**：Python 侧没有与 `HTTP_BUILD_REQUEST` 等价的纯函数
（`tinypage/core/ai_assistance.py:68` 把报文交给 `urllib.request.Request` 去组装），
所以「请求报文逐字节」这一层**只能手写**，逐条标注出处。

**真 Python 交叉校验**（生成期跑，结果写进 JSON 的 `meta.cross_checks`）：
用 `http.client.HTTPResponse` 解析**同一份原始报文**，把 status / reason / 头 /
body 与本基准的期望值对照。语义一致的要求**逐字相等**；不一致的（本卡刻意偏离的）
记为 `divergences` 并附两边的实测值 —— **不是沉默放过**。

**本卡刻意偏离 Python 的两处**（都写进 `divergences`）：
  ① `Content-Length` **小于**实际收到的字节 ⇒ 我们**不截断**（卡 S5-1 反向守卫），
     Python 的 `http.client` 按 CL 截断。
  ② `Transfer-Encoding: chunked` ⇒ 我们 `ok:FALSE`（不实现分块解码），
     Python 会解码。

用法：python gen_http_client_tls_baseline.py
"""
import http.client
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'fixtures', 'http_client_tls_baseline.json')

CRLF = '\r\n'


# ── 报文拼装（手写，只把「长度」交给 len —— 那正是 CL 的定义）────────────
def resp(status_line, headers, body):
    """(状态行, [(k, v)], body) → 原始响应报文（CL 不猜：由调用方显式给或这里不补）。"""
    head = status_line + CRLF + ''.join('%s: %s%s' % (k, v, CRLF) for k, v in headers)
    return head + CRLF + body


def body_len(s):
    return len(s.encode('utf-8'))


# ── ① 请求报文（纯函数 HTTP_BUILD_REQUEST）────────────────────────────
POST_BODY = '{"model":"gpt-3.5-turbo","messages":[]}'
UTF8_BODY = '{"text":"中文 body"}'

BUILD = [
    {
        'name': 'post_json',
        'note': 'POST + Bearer + JSON：请求行 / Host / Authorization / Content-Type / '
                'Content-Length / Connection: close 的**顺序与字节**',
        'source': 'ai_assistance.py:50-54（_build_headers）+ :67-73（Request(data, headers, method)）',
        'opts': {
            'method': 'POST',
            'host': 'api.example.com',
            'path': '/v1/chat/completions',
            'headers': {
                'Authorization': 'Bearer sk-test',
                'Content-Type': 'application/json',
            },
            'body': POST_BODY,
        },
        'want': (
            'POST /v1/chat/completions HTTP/1.1' + CRLF
            + 'Host: api.example.com' + CRLF
            + 'Authorization: Bearer sk-test' + CRLF
            + 'Content-Type: application/json' + CRLF
            + 'Content-Length: %d' % body_len(POST_BODY) + CRLF
            + 'Connection: close' + CRLF
            + CRLF
            + POST_BODY
        ),
    },
    {
        'name': 'post_utf8_body',
        'note': 'body 是中文 ⇒ Content-Length 必须是 **BYTE_LEN**（UTF-8 字节数），不是 LEN（码点数）',
        'source': '卡 S5-1「逐字节」+ 标准库册 §11.3（BYTE_LEN 给字节数）',
        'opts': {
            'method': 'POST',
            'host': 'api.example.com',
            'path': '/v1/chat/completions',
            'headers': {'Content-Type': 'application/json'},
            'body': UTF8_BODY,
        },
        'want': (
            'POST /v1/chat/completions HTTP/1.1' + CRLF
            + 'Host: api.example.com' + CRLF
            + 'Content-Type: application/json' + CRLF
            + 'Content-Length: %d' % body_len(UTF8_BODY) + CRLF
            + 'Connection: close' + CRLF
            + CRLF
            + UTF8_BODY
        ),
    },
    {
        'name': 'get_no_body',
        'note': '无 body 的 GET ⇒ **不发** Content-Length（对齐 urllib 对 GET 的处理），仍发 Connection: close',
        'source': 'ai_assistance.py 只有 POST；GET 分支是本模块的通用层（HTTP_REQUEST）',
        'opts': {
            'method': 'GET',
            'host': 'api.example.com',
            'path': '/v1/models',
            'headers': {},
        },
        'want': (
            'GET /v1/models HTTP/1.1' + CRLF
            + 'Host: api.example.com' + CRLF
            + 'Connection: close' + CRLF
            + CRLF
        ),
    },
    {
        'name': 'host_port_8443',
        'note': '非 443 端口 ⇒ Host 头**带端口**（RFC 7230 §5.4）',
        'source': 'RFC 7230 §5.4（Host = uri-host [":" port]）',
        'opts': {
            'method': 'POST',
            'host': 'api.example.com',
            'port': 8443,
            'path': '/v1/chat/completions',
            'headers': {},
            'body': '{}',
        },
        'want': (
            'POST /v1/chat/completions HTTP/1.1' + CRLF
            + 'Host: api.example.com:8443' + CRLF
            + 'Content-Length: 2' + CRLF
            + 'Connection: close' + CRLF
            + CRLF
            + '{}'
        ),
    },
    {
        'name': 'post_empty_body',
        'note': 'POST + 空 body ⇒ 仍要发 `Content-Length: 0`（POST 有 body 语义）',
        'source': 'RFC 7230 §3.3.2（无 body 的 POST 要显式 0）',
        'opts': {
            'method': 'POST',
            'host': 'api.example.com',
            'path': '/v1/chat/completions',
            'headers': {},
            'body': '',
        },
        'want': (
            'POST /v1/chat/completions HTTP/1.1' + CRLF
            + 'Host: api.example.com' + CRLF
            + 'Content-Length: 0' + CRLF
            + 'Connection: close' + CRLF
            + CRLF
        ),
    },
    {
        'name': 'header_injection',
        'note': '头值里夹 CRLF ⇒ 必须压成一行（否则凭空多一行头 = 头注入）',
        'source': '安全守卫（本模块 HC_ONELINE）；卡 S5-1「手写 HTTP/1.1」的必然要求',
        'opts': {
            'method': 'POST',
            'host': 'api.example.com',
            'path': '/v1/chat/completions',
            'headers': {'X-Evil': 'a\r\nX-Injected: 1'},
            'body': '',
        },
        'want': (
            'POST /v1/chat/completions HTTP/1.1' + CRLF
            + 'Host: api.example.com' + CRLF
            + 'X-Evil: a X-Injected: 1' + CRLF
            + 'Content-Length: 0' + CRLF
            + 'Connection: close' + CRLF
            + CRLF
        ),
    },
    {
        'name': 'dup_host_and_length',
        'note': '调用方自带 Host / Content-Length ⇒ 一律**丢弃**（报文里只允许有一份，且由本模块算）',
        'source': '反向守卫：两个互相矛盾的 Content-Length 会让服务端读到错的位置',
        'opts': {
            'method': 'POST',
            'host': 'api.example.com',
            'path': '/v1/chat/completions',
            'headers': {'Host': 'evil.example', 'Content-Length': '9999'},
            'body': 'abc',
        },
        'want': (
            'POST /v1/chat/completions HTTP/1.1' + CRLF
            + 'Host: api.example.com' + CRLF
            + 'Content-Length: 3' + CRLF
            + 'Connection: close' + CRLF
            + CRLF
            + 'abc'
        ),
    },
    {
        'name': 'path_normalized',
        'note': 'path 不以 "/" 开头 ⇒ 补一个（避免拼出 "POST v1/x HTTP/1.1"）',
        'source': 'RFC 7230 §5.3.1（origin-form = absolute-path）',
        'opts': {
            'method': 'GET',
            'host': 'api.example.com',
            'path': 'v1/models',
        },
        'want': (
            'GET /v1/models HTTP/1.1' + CRLF
            + 'Host: api.example.com' + CRLF
            + 'Connection: close' + CRLF
            + CRLF
        ),
    },
]

# ── ② 响应解析（纯函数 HTTP_PARSE_RESPONSE）────────────────────────────
OK_BODY = '{"a":1}'
_401_BODY = '{"error":"bad key"}'
_500_BODY = '{"error":"boom"}'

PARSE = [
    {
        'name': 'ok_json',
        'note': '200 + Content-Length 正确 ⇒ ok，头名小写，body 逐字节',
        'source': '卡 S5-1「响应解析：状态行 + 头 + body」',
        'raw': resp('HTTP/1.1 200 OK', [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(body_len(OK_BODY))),
        ], OK_BODY),
        'want': {
            'ok': True, 'status': 200, 'reason': 'OK',
            'headers': [['content-type', 'application/json'],
                        ['content-length', str(body_len(OK_BODY))]],
            'body': OK_BODY, 'length_mismatch': False, 'extra_bytes': 0,
        },
    },
    {
        'name': 'headers_mixed_case',
        'note': '头名大小写混写 ⇒ 查表一律按小写（HTTP 头名不区分大小写）',
        'source': 'RFC 7230 §3.2（field-name 大小写不敏感）',
        'raw': resp('HTTP/1.1 200 OK', [
            ('CONTENT-LENGTH', '2'),
            ('Content-TYPE', 'Application/JSON'),
            ('X-Trace-Id', 'abc'),
        ], '{}'),
        'want': {
            'ok': True, 'status': 200, 'reason': 'OK',
            'headers': [['content-length', '2'], ['content-type', 'Application/JSON'],
                        ['x-trace-id', 'abc']],
            'body': '{}', 'length_mismatch': False, 'extra_bytes': 0,
        },
    },
    {
        'name': 'no_body',
        'note': '204 无 Content-Length、空行后无字节 ⇒ body 是空串',
        'source': 'RFC 7230 §3.3（204 无 body）',
        'raw': resp('HTTP/1.1 204 No Content', [
            ('Date', 'Mon, 02 Nov 2026 00:00:00 GMT'),
        ], ''),
        'want': {
            'ok': True, 'status': 204, 'reason': 'No Content',
            'headers': [['date', 'Mon, 02 Nov 2026 00:00:00 GMT']],
            'body': '', 'length_mismatch': False, 'extra_bytes': 0,
        },
    },
    {
        'name': 'cl_smaller_than_actual',
        'note': '**反向守卫**：实收 body 多于 Content-Length ⇒ 不得截断，body 给全部字节 + 记差额',
        'source': '卡 S5-1 反向守卫「响应体超过 Content-Length ⇒ 不得截断读取」',
        'raw': resp('HTTP/1.1 200 OK', [('Content-Length', '5')], 'hello world'),
        'want': {
            'ok': True, 'status': 200, 'reason': 'OK',
            'headers': [['content-length', '5']],
            'body': 'hello world', 'length_mismatch': True, 'extra_bytes': 6,
        },
    },
    {
        'name': 'cl_larger_truncated',
        'note': '实收 body 少于 Content-Length ⇒ ok:FALSE（读不全就是错，不交付半截 body）',
        'source': '反向守卫（本模块取舍 ③）',
        'raw': resp('HTTP/1.1 200 OK', [('Content-Length', '10')], 'hello'),
        'want': {
            'ok': False, 'status': 200, 'error_contains': 'truncated body: 5 of 10',
        },
    },
    {
        'name': 'status_401',
        'note': '4xx：解析层**仍判成形**（ok:TRUE），成败由 HC_VERDICT 定 —— 两件事分开测',
        'source': '卡 S5-1 反向守卫「4xx/5xx 必须 ERR」（落在 HTTP_REQUEST 层）',
        'raw': resp('HTTP/1.1 401 Unauthorized', [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(body_len(_401_BODY))),
        ], _401_BODY),
        'want': {
            'ok': True, 'status': 401, 'reason': 'Unauthorized',
            'headers': [['content-type', 'application/json'],
                        ['content-length', str(body_len(_401_BODY))]],
            'body': _401_BODY, 'length_mismatch': False, 'extra_bytes': 0,
        },
    },
    {
        'name': 'status_500',
        'note': '5xx：同上（解析成形，成败在策略层）',
        'source': '卡 S5-1 反向守卫「4xx/5xx 必须 ERR」',
        'raw': resp('HTTP/1.1 500 Internal Server Error', [
            ('Content-Length', str(body_len(_500_BODY))),
        ], _500_BODY),
        'want': {
            'ok': True, 'status': 500, 'reason': 'Internal Server Error',
            'headers': [['content-length', str(body_len(_500_BODY))]],
            'body': _500_BODY, 'length_mismatch': False, 'extra_bytes': 0,
        },
    },
    {
        'name': 'dup_headers',
        'note': '同名头出现两次 ⇒ 按出现顺序用 ", " 合并（RFC 7230 §3.2.2）',
        'source': 'RFC 7230 §3.2.2（recipient MAY combine field-values with ", "）',
        'raw': resp('HTTP/1.1 200 OK', [
            ('Set-Cookie', 'a=1'),
            ('Set-Cookie', 'b=2'),
            ('Content-Length', '0'),
        ], ''),
        'want': {
            'ok': True, 'status': 200, 'reason': 'OK',
            'headers': [['set-cookie', 'a=1, b=2'], ['content-length', '0']],
            'body': '', 'length_mismatch': False, 'extra_bytes': 0,
        },
    },
    {
        'name': 'status_without_reason',
        'note': '状态行没有 reason 短语 ⇒ reason 是空串（不得报错）',
        'source': 'RFC 7230 §3.1.2（reason-phrase 可以为空）',
        'raw': 'HTTP/1.1 204' + CRLF + CRLF,
        'want': {
            'ok': True, 'status': 204, 'reason': '',
            'headers': [], 'body': '', 'length_mismatch': False, 'extra_bytes': 0,
        },
    },
    {
        'name': 'blank_lines_in_body',
        'note': 'body 里含 CRLFCRLF ⇒ 头块仍切在**第一个** CRLFCRLF（不能被 body 里的空行骗到）',
        'source': 'RFC 7230 §3（头块以**第一个**空行结束）',
        'raw': resp('HTTP/1.1 200 OK', [
            ('Content-Length', str(body_len('{"t":"a\r\n\r\nb"}'))),
        ], '{"t":"a\r\n\r\nb"}'),
        'want': {
            'ok': True, 'status': 200, 'reason': 'OK',
            'headers': [['content-length', str(body_len('{"t":"a\r\n\r\nb"}'))]],
            'body': '{"t":"a\r\n\r\nb"}', 'length_mismatch': False, 'extra_bytes': 0,
        },
    },
    {
        'name': 'no_terminator',
        'note': '没有 CRLFCRLF ⇒ ok:FALSE（不得把整条报文当 body）',
        'source': '反向守卫（本模块取舍：只认 CRLFCRLF）',
        'raw': 'HTTP/1.1 200 OK' + CRLF + 'Content-Length: 2' + CRLF,
        'want': {
            'ok': False, 'status': -1, 'error_contains': 'no CRLFCRLF header terminator',
        },
    },
    {
        'name': 'bad_status_code',
        'note': '状态码不是整数 ⇒ ok:FALSE',
        'source': 'RFC 7230 §3.1.2（status-code = 3DIGIT）',
        'raw': 'HTTP/1.1 ABC OK' + CRLF + 'Content-Length: 0' + CRLF + CRLF,
        'want': {
            'ok': False, 'status': -1, 'error_contains': 'bad status code',
        },
    },
    {
        'name': 'bad_protocol',
        'note': '不是 HTTP/ 开头 ⇒ ok:FALSE',
        'source': 'RFC 7230 §2.6（HTTP-version）',
        'raw': 'FTP/1.1 200 OK' + CRLF + CRLF,
        'want': {
            'ok': False, 'status': -1, 'error_contains': 'bad protocol',
        },
    },
    {
        'name': 'chunked',
        'note': 'Transfer-Encoding: chunked ⇒ ok:FALSE（不实现分块解码，明确失败）',
        'source': '本模块取舍 ④（Python 的 http.client 会解码 —— 已登记差异）',
        'raw': ('HTTP/1.1 200 OK' + CRLF + 'Transfer-Encoding: chunked' + CRLF + CRLF
                + '2' + CRLF + '{}' + CRLF + '0' + CRLF + CRLF),
        'want': {
            'ok': False, 'status': 200, 'error_contains': 'chunked',
        },
    },
    {
        'name': 'bad_content_length',
        'note': 'Content-Length 不是整数 ⇒ ok:FALSE（fail closed，不猜长度）',
        'source': 'RFC 7230 §3.3.2（Content-Length = 1*DIGIT）',
        'raw': 'HTTP/1.1 200 OK' + CRLF + 'Content-Length: abc' + CRLF + CRLF + 'x',
        'want': {
            'ok': False, 'status': 200, 'error_contains': 'invalid Content-Length',
        },
    },
]

# ── ③ 整条请求（HTTP_REQUEST / HTTPS_POST_JSON，注入 exchange 脱网）────
REQ_OK_RAW = resp('HTTP/1.1 200 OK', [
    ('Content-Type', 'application/json'),
    ('Content-Length', str(body_len(OK_BODY))),
], OK_BODY)
REQ_401_RAW = resp('HTTP/1.1 401 Unauthorized', [
    ('Content-Type', 'application/json'),
    ('Content-Length', str(body_len(_401_BODY))),
], _401_BODY)
REQ_500_RAW = resp('HTTP/1.1 500 Internal Server Error', [
    ('Content-Length', str(body_len(_500_BODY))),
], _500_BODY)

REQUEST = [
    {
        'name': 'post_ok',
        'api': 'post_json',
        'note': '200 ⇒ ok:TRUE，status/body 原样透出；请求真的走了 exchange（且带 Bearer）',
        'source': '卡 S5-1 主入口',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com', 'body': '{"x":1}'},
        'raw': REQ_OK_RAW,
        'want': {'ok': True, 'status': 200, 'body': OK_BODY, 'exchange_called': True,
                 'wire_contains': ['Authorization: Bearer sk-test',
                                   'Content-Type: application/json',
                                   'POST /v1/chat/completions HTTP/1.1']},
    },
    {
        'name': 'post_401',
        'api': 'post_json',
        'note': '**反向守卫**：401 ⇒ ok:FALSE，status 保留，error 里带服务端正文',
        'source': '卡 S5-1 反向守卫「4xx/5xx 必须 ERR，不得当正常结果」',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com', 'body': '{"x":1}'},
        'raw': REQ_401_RAW,
        'want': {'ok': False, 'status': 401,
                 'error_contains': ['HTTP 401', 'bad key'], 'exchange_called': True},
    },
    {
        'name': 'post_500',
        'api': 'post_json',
        'note': '**反向守卫**：500 ⇒ ok:FALSE',
        'source': '卡 S5-1 反向守卫「4xx/5xx 必须 ERR」',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com', 'body': '{"x":1}'},
        'raw': REQ_500_RAW,
        'want': {'ok': False, 'status': 500,
                 'error_contains': ['HTTP 500', 'boom'], 'exchange_called': True},
    },
    {
        'name': 'no_key',
        'api': 'post_json',
        'note': '**反向守卫**：未配置 API key ⇒ 明确报错，且**根本不碰传输**（exchange 不该被调）',
        'source': '卡 S5-1 反向守卫「未配置 API key ⇒ 必须明确报错」+ ai_assistance.py:57-58',
        'opts': {'host': 'api.example.com', 'body': '{"x":1}'},
        'raw': REQ_OK_RAW,
        'want': {'ok': False, 'status': -1, 'error_contains': ['API key not configured'],
                 'exchange_called': False},
    },
    {
        'name': 'get_no_key',
        'api': 'http_request',
        'note': '通用层 GET 不要求 API key（key 是 HTTPS_POST_JSON / CHAT 的门）',
        'source': '本模块分层（HTTP_REQUEST 是通用层）',
        'opts': {'method': 'GET', 'host': 'api.example.com', 'path': '/v1/models'},
        'raw': REQ_OK_RAW,
        'want': {'ok': True, 'status': 200, 'body': OK_BODY, 'exchange_called': True,
                 'wire_contains': ['GET /v1/models HTTP/1.1']},
    },
    {
        'name': 'transport_error',
        'api': 'http_request',
        'note': '传输失败 ⇒ ok:FALSE、status NULL、error 原样带出',
        'source': 'ai_assistance.py:86-88（URLError ⇒ AIAssistanceError）',
        'opts': {'method': 'GET', 'host': 'api.example.com'},
        'reply': {'ok': False, 'error': 'tls connect failed: boom'},
        'want': {'ok': False, 'status': -1, 'error_contains': ['tls connect failed: boom'],
                 'exchange_called': True},
    },
    {
        'name': 'host_missing',
        'api': 'http_request',
        'note': '缺 host ⇒ ok:FALSE（不得拼出 "POST  HTTP/1.1" 这种废报文）',
        'source': '本模块的入参守卫',
        'opts': {'method': 'GET'},
        'raw': REQ_OK_RAW,
        'want': {'ok': False, 'status': -1, 'error_contains': ['host is required'],
                 'exchange_called': False},
    },
    {
        'name': 'garbage_response',
        'api': 'http_request',
        'note': '对端回的不是 HTTP ⇒ ok:FALSE（不得当 body 交给上层）',
        'source': '反向守卫（本模块取舍：只认 CRLFCRLF）',
        'opts': {'method': 'GET', 'host': 'api.example.com'},
        'raw': '<html>not http</html>',
        'want': {'ok': False, 'status': -1,
                 'error_contains': ['no CRLFCRLF header terminator'],
                 'exchange_called': True},
    },
]

# ── ④ CHAT_COMPLETION ──────────────────────────────────────────────────
def chat_raw(payload):
    return resp('HTTP/1.1 200 OK', [
        ('Content-Type', 'application/json'),
        ('Content-Length', str(body_len(payload))),
    ], payload)


CHAT_OK = '{"choices":[{"message":{"role":"assistant","content":"你好"}}]}'
CHAT_EMPTY = '{"choices":[]}'
CHAT_NO_MSG = '{"choices":[{"index":0}]}'
CHAT_NO_CONTENT = '{"choices":[{"message":{"role":"assistant"}}]}'
CHAT_WANT_BODY = ('{"messages":[{"content":"hi","role":"user"}],'
                  '"model":"gpt-3.5-turbo","temperature":0.7}')

CHAT = [
    {
        'name': 'ok',
        'note': '正常：取 choices[0].message.content（含中文）',
        'source': 'ai_assistance.py:76-81（result["choices"][0]["message"]["content"]）',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw(CHAT_OK),
        'want': {'ok': True, 'status': 200, 'content': '你好',
                 'wire_body': CHAT_WANT_BODY},
    },
    {
        'name': 'custom_model_temperature',
        'note': 'model / temperature 透传到请求体（键序是 STRINGIFY 的**字典序**）',
        'source': 'ai_assistance.py:61-65（payload 三个键）',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'model': 'deepseek-chat', 'temperature': 0.3,
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw(CHAT_OK),
        'want': {'ok': True, 'status': 200, 'content': '你好',
                 'wire_body': '{"messages":[{"content":"hi","role":"user"}],'
                              '"model":"deepseek-chat","temperature":0.3}'},
    },
    {
        'name': 'no_choices',
        'note': '响应里没有 choices ⇒ ok:FALSE（Python 这里抛 AIAssistanceError）',
        'source': 'ai_assistance.py:78-80（if not choices: raise）',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw('{"id":"x"}'),
        'want': {'ok': False, 'status': 200, 'error_contains': ['no choices array']},
    },
    {
        'name': 'empty_choices',
        'note': 'choices 是空数组 ⇒ ok:FALSE（等价 Python 的 `if not choices`）',
        'source': 'ai_assistance.py:78-80',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw(CHAT_EMPTY),
        'want': {'ok': False, 'status': 200, 'error_contains': ['empty choices']},
    },
    {
        'name': 'missing_message',
        'note': 'choices[0] 没有 message ⇒ ok:FALSE',
        'source': 'ai_assistance.py:81（.get("message", {}) 的缺字段路径）',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw(CHAT_NO_MSG),
        'want': {'ok': False, 'status': 200, 'error_contains': ['message is not an object']},
    },
    {
        'name': 'missing_content',
        'note': 'message 里没有 content ⇒ ok:FALSE（不得静默返回空串）',
        'source': '反向守卫（卡 S5-1「失败返回 ok:FALSE」）',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw(CHAT_NO_CONTENT),
        'want': {'ok': False, 'status': 200,
                 'error_contains': ['content is missing']},
    },
    {
        'name': 'not_json',
        'note': 'body 不是 JSON ⇒ ok:FALSE（**不得**让 PARSE 的 E0070 中止整个运行）',
        'source': '坑 47（PARSE 失败 = E0070 中止）⇒ 先 JSON_VALIDATE',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw('not json'),
        'want': {'ok': False, 'status': 200, 'error_contains': ['not valid JSON']},
    },
    {
        'name': 'json_array',
        'note': 'body 是 JSON 但不是对象 ⇒ ok:FALSE',
        'source': '本模块的类型守卫（坑 35：AT_K 对非 DICT 是 E0030）',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw('[]'),
        'want': {'ok': False, 'status': 200, 'error_contains': ['not an object']},
    },
    {
        'name': 'status_401',
        'note': '后端 401 ⇒ ok:FALSE，status 401（不进入 content 提取）',
        'source': '卡 S5-1 反向守卫 + ai_assistance.py:82-85（HTTPError ⇒ raise）',
        'opts': {'api_key': 'sk-test', 'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': REQ_401_RAW,
        'want': {'ok': False, 'status': 401, 'error_contains': ['HTTP 401']},
    },
    {
        'name': 'no_key',
        'note': '未配置 API key ⇒ ok:FALSE（同 Python 的 `raise AIAssistanceError("API key not configured")`）',
        'source': 'ai_assistance.py:57-58',
        'opts': {'host': 'api.example.com',
                 'messages': [{'role': 'user', 'content': 'hi'}]},
        'raw': chat_raw(CHAT_OK),
        'want': {'ok': False, 'status': -1,
                 'error_contains': ['API key not configured']},
    },
]


# ── Python 交叉校验（http.client 解析同一份报文）────────────────────────
class _FakeSock:
    """给 http.client.HTTPResponse 的最小 socket 替身（只需要 makefile）。"""

    def __init__(self, data):
        self._data = data

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self._data)

    def close(self):
        pass


def py_parse(raw_text):
    """→ (status, reason, {lower_name: joined_value}, body_bytes) 或异常文本。"""
    try:
        r = http.client.HTTPResponse(_FakeSock(raw_text.encode('utf-8')))
        r.begin()
        body = r.read()
        hdrs = {}
        for k, v in r.getheaders():
            lk = k.lower()
            hdrs[lk] = (hdrs[lk] + ', ' + v) if lk in hdrs else v
        return {'status': r.status, 'reason': r.reason, 'headers': hdrs,
                'body_len': len(body), 'error': None}
    except Exception as exc:                      # noqa: BLE001 — 只用于记录
        return {'status': None, 'reason': None, 'headers': {}, 'body_len': None,
                'error': '%s: %s' % (type(exc).__name__, exc)}


def cross_check():
    """逐条对照；语义一致的要求相等，刻意偏离的记为 divergences。"""
    checks = []
    divergences = []
    for case in PARSE:
        want = case['want']
        got = py_parse(case['raw'])
        name = case['name']
        if want['ok']:
            mismatched = []
            if got['status'] != want['status']:
                mismatched.append('status: py=%r want=%r' % (got['status'], want['status']))
            if got['body_len'] != body_len(want['body']):
                mismatched.append('body_len: py=%r want=%r'
                                  % (got['body_len'], body_len(want['body'])))
            py_hdrs = got['headers']
            want_hdrs = {k: v for k, v in want['headers']}
            if py_hdrs != want_hdrs:
                mismatched.append('headers: py=%r want=%r' % (py_hdrs, want_hdrs))
            if mismatched:
                # CL < 实际：Python 截断，我们**不**截断 ⇒ 已登记的刻意偏离
                if (case['name'] == 'cl_smaller_than_actual'
                        and got['body_len'] == 5):
                    divergences.append({
                        'case': name,
                        'ours': 'body = 全部 11 字节（不截断），length_mismatch=TRUE',
                        'python': 'body = 前 5 字节（按 Content-Length 截断）',
                        'why': '卡 S5-1 反向守卫「不得截断读取」要求保留全部实收字节',
                    })
                    checks.append({'case': name, 'verdict': 'diverges (by design)'})
                else:
                    raise SystemExit('cross-check mismatch on %s: %s'
                                     % (name, '; '.join(mismatched)))
            else:
                checks.append({'case': name, 'verdict': 'agree'})
        else:
            # 我们判失败：Python 要么也抛，要么给出不同的结论 —— 都记录证据
            checks.append({
                'case': name,
                'verdict': 'ours=FALSE',
                'python': got['error'] or ('status=%r body_len=%r'
                                           % (got['status'], got['body_len'])),
            })
            if case['name'] == 'chunked':
                divergences.append({
                    'case': name,
                    'ours': 'ok=FALSE（不实现分块解码）',
                    'python': '解码 chunked（body_len=%r）' % got['body_len'],
                    'why': '本模块取舍 ④：宁可明确失败也不把未解码的块当正文',
                })
            if case['name'] == 'bad_content_length':
                divergences.append({
                    'case': name,
                    'ours': 'ok=FALSE（Content-Length 不是整数 ⇒ fail closed）',
                    'python': 'status=200、按「读到 EOF」处理（body_len=%r）' % got['body_len'],
                    'why': '本模块取舍：长度声明坏了就明确失败，不猜',
                })
    return checks, divergences


def main():
    checks, divergences = cross_check()

    doc = {
        'meta': {
            'card': 'S5-1',
            'generator': 'tp/test/gen_http_client_tls_baseline.py',
            'sources': [
                'tinypage/core/ai_assistance.py:45-88（_get_default_endpoint / _build_headers / _call_api）',
                'RFC 7230 §3（报文）、§3.2.2（同名头合并）、§3.3.2（Content-Length）、§5.4（Host）',
                '卡 S5-1（docs/plans/tinypage-wlwl-rewrite-plan.md:1369-1390）',
            ],
            'conventions': [
                'want.status == -1 ⇒ 期望 status 是 **NULL**（合法状态码只有 100–599，-1 不可能是真值）',
                'want.status == None 不会出现；失败用例一律用 -1',
                'parse 用例的 want.ok 只表示「报文是否成形」，4xx/5xx 的成败在 request/chat 用例里测',
            ],
            'divergences': divergences,
            'cross_checks': checks,
        },
        'build': BUILD,
        'parse': PARSE,
        'request': REQUEST,
        'chat': CHAT,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write('\n')
    print('wrote %s' % OUT)
    print('  build=%d parse=%d request=%d chat=%d'
          % (len(BUILD), len(PARSE), len(REQUEST), len(CHAT)))
    print('  cross_checks=%d divergences=%d'
          % (len(checks), len(divergences)))
    # ⚠ print 只用 ASCII：Windows 的 stdout 可能是 GBK（tp/README 坑 57），
    #   一个 "⚠" 就能让整步在 CI / 本机报 UnicodeEncodeError。
    for d in divergences:
        print('  [divergence] %s -- %s' % (d['case'], d['why'].encode('ascii', 'replace').decode('ascii')))


if __name__ == '__main__':
    main()
