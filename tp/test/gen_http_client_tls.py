"""生成 tp/lib/http_client_tls.wll —— 出站 HTTPS 客户端（卡 S5-1）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**权威实现**：`tinypage/core/ai_assistance.py` 的 `_call_api`（`urllib.request.urlopen(req, timeout=30)`
+ `_build_headers` + `_get_default_endpoint`）。协议按 OpenAI 兼容的
`POST /v1/chat/completions` 定。

**分层（本卡的核心设计决定）**
  · `HTTP_BUILD_REQUEST(opts) -> STRING`   纯函数：请求行 + 头 + body 的**逐字节**形态
  · `HTTP_PARSE_RESPONSE(raw) -> DICT`     纯函数：状态行 + 头 + body（**按 Content-Length 判定**）
  · `HTTP_REQUEST(opts) -> DICT`           通用层：建请求 → 传输 → 解析 → 定 ok
  · `HTTPS_POST_JSON(opts) -> DICT`        `HTTP_REQUEST` 的 POST + Bearer + JSON 薄封装
  · `CHAT_COMPLETION(opts) -> DICT`        取 `choices[0].message.content`
  · `HC_TLS_EXCHANGE(...)`                 **唯一碰 `tls.*`** 的地方

**为什么不能把 `IMPORT("tls", …)` 写在顶层**（本机实测 2026-11-02，见 `tp/probe/probe_s5_https.wll`）
  ① `IMPORT` **只允许出现在模块顶层**（放进 `FUN` 体 ⇒ `E0010: 'IMPORT' is only allowed
     at module top level`）；
  ② 顶层 `IMPORT("tls", …)` 在**不带** `--ext` 时是**加载期**失败（`E0040: module 'tls'
     not found`）⇒ 任何 import 本模块的测试都会连带失败，而 CI **只下载基础 zip**（没有 TLS 扩展）。
  ⇒ 只剩运行时 `MODULE_REF("tls")`（本机实测：带 `--ext` 返 DICT，含 CONNECT/SEND/RECV/CLOSE；
     不带 `--ext` 是 `E0040` **诊断中止**，不是 `ERR` 值）。
  ⇒ **代价（必须知道）**：没装扩展时调用三个传输入口会以 `E0040` 中止进程；两个纯函数不受影响
     —— 后者正是 CI 能测的部分。**能加载**才能测，**能加载**就必然没有静态的 tls 绑定。

**测试缝（`opts.exchange`）**
  `HTTP_REQUEST` 在 `opts.exchange` 是 `FUNCTION` 时用它替代 TLS 传输：
  `exchange(request_text)` 返回 `STRING`（原始响应报文）或 DICT（`{ok:TRUE, raw}` /
  `{ok:FALSE, error}`）。CI 用它把「建请求 → 解析 → 定 ok → 取 content」整条链路跑成
  **脱网**测试；生产路径不传它 ⇒ 走 `HC_TLS_EXCHANGE`。
  它不是「可选后端」——它是**唯一**的测试手段（TLS 传输进不了 CI，见上）。

**四处刻意的语义（登记在夹具 meta 里，不是沉默偏离）**
  ① **4xx/5xx ⇒ `ok:FALSE`**（卡 S5-1 反向守卫）。`HTTP_PARSE_RESPONSE` 只判「报文是否成形」，
     状态码的「成败」判断只在 `HC_VERDICT` 一处 ⇒ 解析层能单独测、策略层只有一处。
  ② **实收 body 多于 `Content-Length` ⇒ 不截断**（卡 S5-1 反向守卫「不得截断读取」）：
     `body` 给**全部**实收字节，差额记在 `length_mismatch: TRUE` + `extra_bytes`。
     ⚠ 与 Python `http.client` 不同（它按 CL 截断）—— 差异登记在夹具 `divergences`。
  ③ **实收 body 少于 `Content-Length` ⇒ `ok:FALSE`**（读不全就是错，不交付半截 body）。
  ④ **`Transfer-Encoding: chunked` ⇒ `ok:FALSE`**（不实现分块解码；非流式 JSON API 用
     `Content-Length`，宁可明确失败也不把未解码的块当正文）。

**非目标**：流式（SSE）、多供应商适配、连接池。⚠ `tls.RECV` 会**冻结整个运行时**
（ABI v1 无就绪事件通道，`tp/probe/README.md` 实测）⇒ 一次请求一条连接。

用法：python gen_http_client_tls.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'http_client_tls.wll')

# 一次 RECV 的上限（字节）与整条响应的上限 —— 后者是「不无限读」的硬闸。
CHUNK = 16384
MAX_BYTES = 8388608
DEFAULT_TIMEOUT_MS = 30000
MAX_EXCERPT = 200


def wl(s):
    """Python 字符串 → WLWL 字面量。⚠ 字面美元符在 WLWL 里是插值 ⇒ 写 \\$。"""
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
            out.append(ch)
    return '"' + ''.join(out) + '"'


def iset(pairs, base='DICT()'):
    """[(k, v_expr)] → 一条嵌套 INDEX_SET 表达式（单行；括号由本函数负责配平）。

    ⚠ 手写 7 层 INDEX_SET 数错一个括号就会被 wllgen 的逗号守卫报成假阳性
      （2026-11-02 实测：HC_RESPONSE 少写了第 7 个 INDEX_SET）⇒ 一律用本函数。
    """
    expr = base
    for k, v in pairs:
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl(k), v)
    return expr


def main():
    src = []
    A = src.append
    A('// tp/lib/http_client_tls.wll —— 出站 HTTPS 客户端（卡 S5-1）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_http_client_tls.py 生成 —— 请勿手改。')
    A('//')
    A('// 权威实现：tinypage/core/ai_assistance.py 的 _call_api（urllib.request.urlopen +')
    A('//   _build_headers + _get_default_endpoint）。协议：OpenAI 兼容 POST /v1/chat/completions。')
    A('//')
    A('// 分层：')
    A('//   HTTP_BUILD_REQUEST  纯函数：请求行 + 头 + body 的逐字节形态（脱网可测）')
    A('//   HTTP_PARSE_RESPONSE 纯函数：状态行 + 头 + body（按 Content-Length 判定，脱网可测）')
    A('//   HTTP_REQUEST        建请求 → 传输 → 解析 → 定 ok')
    A('//   HTTPS_POST_JSON     POST + Bearer + JSON 的薄封装（API key 必填）')
    A('//   CHAT_COMPLETION     取 choices[0].message.content')
    A('//   HC_TLS_EXCHANGE     **唯一**碰 tls.* 的地方（运行时 MODULE_REF）')
    A('//')
    A('// ⚠ 为什么没有顶层 `IMPORT("tls", …)`（本机实测 2026-11-02）：')
    A('//   ① IMPORT 只允许在模块顶层 —— 放进 FUN 体报 E0010；')
    A('//   ② 顶层 IMPORT("tls") 不带 --ext 时**加载期**就 E0040 ⇒ 任何 import 本模块的')
    A('//      测试都会连带失败，而 CI 只下载基础 zip（没有 TLS 扩展）。')
    A('//   ⇒ 只能用运行时 MODULE_REF("tls")。**代价**：没装扩展时调用传输三件套会以')
    A('//      E0040 中止进程；两个纯函数不受影响（这正是 CI 能测的部分）。')
    A('//')
    A('// ⚠ 测试缝：opts.exchange 是 FUNCTION 时替代 TLS 传输（CI 用它跑脱网全链路）。')
    A('//')
    A('// ⚠ 顶层绑定跨模块共享（tp/README 坑 52）⇒ 私有名一律 HC_ 前缀；')
    A('//   下面 5 个导出名是本卡的公共面。')
    A('')
    A('IMPORT("wlwl:std.str", ["INDEX_OF", "CONTAINS_SUB", "CAT", "JOIN", "SPLIT_LINES"]);')
    A('IMPORT("wlwl:std.text", ["TO_LOWER", "TO_UPPER", "TO_INT"]);')
    A('IMPORT("wlwl:std.encode", ["BYTE_LEN", "UTF8_DECODE"]);')
    A('IMPORT("wlwl:std.json", ["JSON_VALIDATE", "PARSE", "STRINGIFY"]);')
    A('')
    A('// 一次 RECV 的上限 / 整条响应的上限（超了明确失败，不无限读）')
    A('LET(HC_CHUNK, %d);' % CHUNK)
    A('LET(HC_MAX_BYTES, %d);' % MAX_BYTES)
    A('LET(HC_DEFAULT_TIMEOUT_MS, %d);' % DEFAULT_TIMEOUT_MS)
    A('// 错误消息里引用响应体的最大码点数')
    A('LET(HC_EXCERPT_MAX, %d);' % MAX_EXCERPT)
    A('')

    # ── 基础工具 ─────────────────────────────────────────────────────
    src += fn('HC_ONELINE', 'v', [
        '// 头值 / 路径进报文前的一行化：SPLIT_LINES 吃掉 CR / LF / CRLF，再用空格接回。',
        '// ⚠ 这是**防头注入**（值里夹 \\r\\n 会凭空多一行头）；调用方不得跳过它。',
        'IF(!=(TYPE(v), "STRING"), "", TRIM(JOIN(SPLIT_LINES(v), " ")))',
    ], '// 去掉 CR/LF（防头注入）并去首尾空白')

    src += fn('HC_INT_OR', 'v, d', [
        '// 「可能是整数 / 数字串 / 垃圾」→ 整数（失败取缺省）。',
        '// ⚠ TO_INT 失败返 ERR ⇒ **不能先绑定**（坑 25：LET(r, <ERR>) 不算消费，E0103）。',
        'IF(!=(TYPE(v), "STRING"), IF(==(TYPE(v), "INTEGER"), v, d), IF(IS_ERR(TO_INT(v)), d, TO_INT(v)))',
    ], '// 宽松取整数')

    src += fn('HC_PORT', 'opts, d', [
        '// port 给 INTEGER 或数字串都收（缺省 443）',
        'LET(p, AT_K(opts, "port", d))',
        'IF(==(TYPE(p), "INTEGER"), p, HC_INT_OR(p, d))',
    ], '// 取端口')

    src += fn('HC_TIMEOUT', 'opts', [
        '// 超时缺省 30s（对齐 Python 的 timeout=30）；非正值一律回到缺省。',
        'LET(t, HC_INT_OR(AT_K(opts, "timeout_ms", HC_DEFAULT_TIMEOUT_MS), HC_DEFAULT_TIMEOUT_MS))',
        'IF(<(t, 1), HC_DEFAULT_TIMEOUT_MS, t)',
    ], '// 取超时（毫秒，缺省 30000）')

    src += fn('HC_DICT', 'opts, key', [
        '// 取一个「必须是 DICT」的选项；不是 DICT（含 NULL）就给空字典。',
        '// ⚠ AT_K 的默认值兜不住 NULL 基值（坑 35）⇒ 基值由调用方保证是 DICT。',
        'LET(v, AT_K(opts, key, DICT()))',
        'IF(==(TYPE(v), "DICT"), v, DICT())',
    ], '// 取 DICT 选项')

    src += fn('HC_STR', 'opts, key, d', [
        '// 取一个「必须是 STRING」的选项',
        'LET(v, AT_K(opts, key, d))',
        'IF(==(TYPE(v), "STRING"), v, d)',
    ], '// 取 STRING 选项')

    src += fn('HC_HAS_HDR', 'd, lname', [
        '// 头名不区分大小写 ⇒ 逐键小写后比对（调用方给的 headers 未必是小写）',
        'LET MUT(hit, FALSE)',
        C('FOR', 'k, KEYS(d)', [
            C('IF', '==(TO_LOWER(k), lname)', ['SET(hit, TRUE)'], ['NULL']),
        ]),
        'hit',
    ], '// 头（不分大小写）是否存在')

    src += fn('HC_ERR_TEXT', 'prefix, e', [
        '// ERR 载荷（{kind, op, reason}）→ 一行文本；非字典就只报一句。',
        '// ⚠ 只取 reason / op，**不**把整个载荷塞进消息。',
        'LET(p, ERR_PAYLOAD(e))',
        'IF(!=(TYPE(p), "DICT"), CAT(prefix, " (non-dict error payload)"), CAT(prefix, ": ", AT_K(p, "reason", AT_K(p, "op", "unknown"))))',
    ], '// ERR → 一行文本')

    src += fn('HC_EXCERPT', 's', [
        '// 报文摘要：超长截断并加省略号（错误消息里引用响应体用）',
        'IF(>(LEN(s), HC_EXCERPT_MAX), CAT(SUB(s, 0, HC_EXCERPT_MAX), "..."), s)',
    ], '// 截断长文本')

    # ── 结果字典（三种唯一形状）──────────────────────────────────────
    src += fn('HC_FAIL', 'status, message', [
        '// 失败形状（卡 S5-1）：{"ok": FALSE, "status": INTEGER|NULL, "error": STRING}',
        iset([('ok', 'FALSE'), ('status', 'status'), ('error', 'message')]),
    ], '// 失败结果')

    src += fn('HC_OK_STATUS', 'status, headers, body', [
        '// 成功形状（卡 S5-1）：{"ok": TRUE, "status", "headers", "body"}',
        iset([('ok', 'TRUE'), ('status', 'status'), ('headers', 'headers'), ('body', 'body')]),
    ], '// 成功结果')

    src += fn('HC_RESPONSE', 'status, reason, headers, body, mismatch, extra', [
        '// 解析结果（比成功形状多两个诊断键：length_mismatch / extra_bytes）',
        iset([('ok', 'TRUE'), ('status', 'status'), ('reason', 'reason'),
              ('headers', 'headers'), ('body', 'body'),
              ('length_mismatch', 'mismatch'), ('extra_bytes', 'extra')]),
    ], '// 解析结果（含长度诊断）')

    # ── 请求报文（纯函数）───────────────────────────────────────────
    src += fn('HC_HOST_VALUE', 'host, port', [
        '// Host 头：https/443 与 http/80 省略端口（RFC 7230 §5.4）',
        'IF(||(==(port, 443), ==(port, 80)), host, CAT(host, ":", STR(port)))',
    ], '// Host 头取值')

    src += fn('HC_WANTS_LEN', 'method, body', [
        '// 什么时候发 Content-Length：有 body，或方法本身带 body 语义（POST/PUT/PATCH）。',
        '// ⚠ 无 body 的 GET 不发（对齐 urllib 对 GET 的处理）。',
        '||(>(BYTE_LEN(body), 0), ||(==(method, "POST"), ||(==(method, "PUT"), ==(method, "PATCH"))))',
    ], '// 是否发 Content-Length')

    src += fn('HC_APPEND_HEADER', 'out, k, v', [
        '// 追加一行自定义头。⚠ Host / Content-Length 由本函数自己发 ⇒ 调用方给了也丢掉',
        '//   （否则报文里会出现两个互相矛盾的 Content-Length）。头名/头值都过 HC_ONELINE。',
        'IF(||(==(TO_LOWER(k), "host"), ==(TO_LOWER(k), "content-length")), out, CAT(out, HC_ONELINE(k), ": ", HC_ONELINE(v), "\\r\\n"))',
    ], '// 追加一行头（Host / Content-Length 交给自己发）')

    src += fn('HTTP_BUILD_REQUEST', 'opts', [
        '// opts 键（全部可选）：method / host / port / path / host_header / headers / body',
        '// 产出：请求行 + Host + 自定义头（插入序）+ Content-Length + Connection: close + 空行 + body',
        '// ⚠ Content-Length 用 **BYTE_LEN**（UTF-8 字节数），不是 LEN（码点数）：中文 body 用',
        '//   LEN 会算少，服务端会一直等剩下的字节（卡 S5-1 的「逐字节」验收就是钉这一条）。',
        'LET(method, TO_UPPER(HC_STR(opts, "method", "GET")))',
        'LET(host, HC_STR(opts, "host", ""))',
        'LET(port, HC_PORT(opts, 443))',
        'LET(raw_path, HC_ONELINE(HC_STR(opts, "path", "/")))',
        'LET(path, IF(==(SUB(raw_path, 0, 1), "/"), raw_path, CAT("/", raw_path)))',
        'LET(hh, HC_ONELINE(AT_K(opts, "host_header", HC_HOST_VALUE(host, port))))',
        'LET(body, HC_STR(opts, "body", ""))',
        'LET(hdrs, HC_DICT(opts, "headers"))',
        'LET MUT(out, CAT(method, " ", path, " HTTP/1.1\\r\\n", "Host: ", hh, "\\r\\n"))',
        C('FOR', 'k, KEYS(hdrs)', [
            'SET(out, HC_APPEND_HEADER(out, k, AT_K(hdrs, k, "")))',
        ]),
        C('IF', 'HC_WANTS_LEN(method, body)', [
            'SET(out, CAT(out, "Content-Length: ", STR(BYTE_LEN(body)), "\\r\\n"))',
        ], ['NULL']),
        '// Connection: close —— 不复用连接（tls 等待会冻结整个运行时，做不了池）',
        C('IF', 'HC_HAS_HDR(hdrs, "connection")', ['NULL'], [
            'SET(out, CAT(out, "Connection: close\\r\\n"))',
        ]),
        'CAT(out, "\\r\\n", body)',
    ], '// 请求报文（纯函数，逐字节可对照）')

    # ── 响应解析（纯函数）───────────────────────────────────────────
    src += fn('HC_HEADER_END', 'txt', [
        '// 头块结束位置（"\\r\\n\\r\\n" 的第一个 CR 的下标）；没有就是 -1。',
        '// ⚠ 手写扫描用 INDEX_OF，不用正则（正则无转义、RE_TEST 整串锚定，见坑 26 / 36）。',
        'INDEX_OF(txt, "\\r\\n\\r\\n")',
    ], '// 头块结束下标')

    src += fn('HC_HDR_NAME', 'line', [
        '// 一行头的名字（小写、去空白）；无冒号 ⇒ 空串',
        'LET(i, INDEX_OF(line, ":"))',
        'IF(<(i, 0), "", TO_LOWER(TRIM(SUB(line, 0, i))))',
    ], '// 头名')

    src += fn('HC_HDR_VALUE', 'line', [
        '// 一行头的值（去首尾空白）；无冒号 ⇒ 空串',
        'LET(i, INDEX_OF(line, ":"))',
        'IF(<(i, 0), "", TRIM(SUB(line, +(i, 1))))',
    ], '// 头值')

    src += fn('HC_PUT_HEADER', 'd, k, v', [
        '// 放进头字典：名字小写；同名**按出现顺序**用 ", " 合并（RFC 7230 §3.2.2）。',
        '// 空名（无冒号的行）直接丢。',
        'IF(==(k, ""), d, IF(HAS(d, k), INDEX_SET(d, k, CAT(AT_K(d, k, ""), ", ", v)), INDEX_SET(d, k, v)))',
    ], '// 写入一个头（合并同名）')

    src += fn('HC_ADD_HEADER', 'd, line', [
        '// 一行 → d',
        'HC_PUT_HEADER(d, HC_HDR_NAME(line), HC_HDR_VALUE(line))',
    ], '// 加一行头')

    src += fn('HC_HDR_LINES', 'head', [
        '// 头块（含状态行）→ DICT。⚠ 跳过**第一条**（状态行）：按计数跳过，',
        '//   因为 WLWL 没有数组切片。',
        'LET MUT(out, DICT())',
        'LET MUT(n, 0)',
        C('FOR', 'l, SPLIT_LINES(head)', [
            'SET(n, +(n, 1))',
            C('IF', '!=(n, 1)', [
                'SET(out, HC_ADD_HEADER(out, l))',
            ], ['NULL']),
        ]),
        'out',
    ], '// 头块 → DICT（跳过状态行）')

    src += fn('HC_STATUS_LINE', 'line', [
        '// "HTTP/1.1 200 OK" → {ok:TRUE, status:200, reason:"OK"}',
        '// ⚠ 不用 SPLIT 后取数组尾（没有数组切片）⇒ 用 INDEX_OF 切两刀。',
        'LET(i1, INDEX_OF(line, " "))',
        'LET(rest, SUB(line, +(i1, 1)))',
        'LET(i2, INDEX_OF(rest, " "))',
        'LET(code_txt, IF(<(i2, 0), rest, SUB(rest, 0, i2)))',
        'LET(reason, IF(<(i2, 0), "", TRIM(SUB(rest, +(i2, 1)))))',
        'LET(num, IF(IS_ERR(TO_INT(code_txt)), -1, TO_INT(code_txt)))',
        C('IF', '<(i1, 0)', ['HC_FAIL(NULL, "malformed status line")'], [
            C('IF', '!=(SUB(line, 0, 5), "HTTP/")', [
                'HC_FAIL(NULL, "malformed status line: bad protocol")',
            ], [
                C('IF', '||(<(num, 100), >(num, 599))', [
                    'HC_FAIL(NULL, "malformed status line: bad status code")',
                ], [
                    'INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), "status", num), "reason", reason)',
                ]),
            ]),
        ]),
    ], '// 状态行 → DICT')

    src += fn('HC_STATUS', 'head', [
        '// 状态行 → {ok, status, reason} 或 {ok:FALSE, status:NULL, error}',
        'LET(lines, SPLIT_LINES(head))',
        C('IF', '==(LEN(lines), 0)', ['HC_FAIL(NULL, "empty response")'], [
            'HC_STATUS_LINE(TRIM(AT(lines, 0, "")))',
        ]),
    ], '// 解析状态行')

    src += fn('HC_DECLARED_LEN', 'head', [
        '// Content-Length：缺失 ⇒ -1；有但**不是整数** ⇒ -2（解析要 fail closed）。',
        'LET(d, HC_HDR_LINES(head))',
        'IF(!HAS(d, "content-length"), -1, IF(IS_ERR(TO_INT(AT_K(d, "content-length", ""))), -2, TO_INT(AT_K(d, "content-length", ""))))',
    ], '// 声明的 Content-Length（-1 无 / -2 坏）')

    src += fn('HC_IS_CHUNKED', 'head', [
        '// Transfer-Encoding 含 chunked ⇒ 本模块不实现分块解码（见模块头的取舍 ④）',
        'LET(d, HC_HDR_LINES(head))',
        'IF(!HAS(d, "transfer-encoding"), FALSE, CONTAINS_SUB(TO_LOWER(AT_K(d, "transfer-encoding", "")), "chunked"))',
    ], '// 是否 chunked')

    src += fn('HC_BODY_CHECK', 'head, body, status, reason', [
        '// body 与 Content-Length 的三向判定（卡 S5-1 的两条反向守卫都在这里）',
        'LET(hdrs, HC_HDR_LINES(head))',
        'LET(cl, HC_DECLARED_LEN(head))',
        'LET(avail, BYTE_LEN(body))',
        C('IF', '==(cl, -2)', [
            'HC_FAIL(status, "invalid Content-Length header")',
        ], [
            C('IF', '&&(>=(cl, 0), <(avail, cl))', [
                '// ③ 实收**少于**声明 ⇒ 读不全就是错，不交付半截 body',
                'HC_FAIL(status, CAT("truncated body: ", STR(avail), " of ", STR(cl), " bytes"))',
            ], [
                '// ② 实收**多于**声明 ⇒ **不截断**（卡 S5-1 反向守卫），body 给全部字节；',
                '//   差额记在 extra_bytes。Python 的 http.client 在这里会截断 —— 已登记差异。',
                'HC_RESPONSE(status, reason, hdrs, body, &&(>=(cl, 0), >(avail, cl)), IF(&&(>=(cl, 0), >(avail, cl)), -(avail, cl), 0))',
            ]),
        ]),
    ], '// body 长度三向判定')

    src += fn('HC_PARSE_HEADERS', 'head, body', [
        '// 头块 + body 的成形态检查（chunked 先行，再判长度）',
        'LET(doc, HC_STATUS(head))',
        C('IF', '!AT_K(doc, "ok", FALSE)', [
            'HC_FAIL(NULL, AT_K(doc, "error", "malformed status line"))',
        ], [
            C('IF', 'HC_IS_CHUNKED(head)', [
                'HC_FAIL(AT_K(doc, "status", NULL), "chunked transfer-encoding is not supported")',
            ], [
                'HC_BODY_CHECK(head, body, AT_K(doc, "status", 0), AT_K(doc, "reason", ""))',
            ]),
        ]),
    ], '// 头块 + body → 解析结果')

    src += fn('HTTP_PARSE_RESPONSE', 'raw', [
        '// 纯函数：一条原始响应报文 → 解析结果。',
        '// ⚠ 只判「报文是否成形」；4xx/5xx 的成败在 HC_VERDICT（解析层才能单独测）。',
        '// ⚠ 必须要求 CRLFCRLF：只认 "\\n\\n" 会把 body 里的空行当成头块结束。',
        'LET(end, HC_HEADER_END(raw))',
        C('IF', '<(end, 0)', [
            'HC_FAIL(NULL, "malformed response: no CRLFCRLF header terminator")',
        ], [
            'HC_PARSE_HEADERS(SUB(raw, 0, end), SUB(raw, +(end, 4)))',
        ]),
    ], '// 响应报文 → 解析结果（纯函数）')

    # ── 状态码策略（纯函数）─────────────────────────────────────────
    src += fn('HC_HTTP_ERROR', 'parsed', [
        '// 4xx/5xx 的错误消息：把服务端的错误正文带出来（API 的报错都在 body 里）',
        'LET(st, AT_K(parsed, "status", 0))',
        'LET(reason, AT_K(parsed, "reason", ""))',
        'LET(body, AT_K(parsed, "body", ""))',
        'CAT("HTTP ", STR(st), IF(==(reason, ""), "", CAT(" ", reason)), IF(==(body, ""), "", CAT(": ", HC_EXCERPT(body))))',
    ], '// 4xx/5xx 的错误消息')

    src += fn('HC_VERDICT', 'parsed', [
        '// 解析结果 → 对外结果。**唯一的**状态码策略点（卡 S5-1 反向守卫）。',
        C('IF', '!AT_K(parsed, "ok", FALSE)', [
            'HC_FAIL(AT_K(parsed, "status", NULL), AT_K(parsed, "error", "invalid response"))',
        ], [
            'LET(st, AT_K(parsed, "status", 0))',
            C('IF', '>=(st, 400)', [
                '// 4xx / 5xx ⇒ **必须** ok:FALSE（不得当正常结果）',
                'HC_FAIL(st, HC_HTTP_ERROR(parsed))',
            ], [
                'HC_OK_STATUS(st, AT_K(parsed, "headers", DICT()), AT_K(parsed, "body", ""))',
            ]),
        ]),
    ], '// 解析结果 → 对外结果（4xx/5xx ⇒ ok:FALSE）')

    # ── 传输层（唯一碰 tls.*）───────────────────────────────────────
    src += fn('HC_CONNECT_OPTS', 'opts, host', [
        '// tls.CONNECT 的 opts：server_name（SNI）+ ca（可选）+ verify（默认开）+ 连接预算。',
        '// ⚠ **证书校验默认开启**：只有显式 `verify: FALSE` 才关，且**必须**打告警（卡 S5-1）。',
        '// ⚠ `ca` 为空串时**不放进** opts —— tls 侧会把 `ca: ""` 当成路径去读。',
        'LET MUT(o, DICT())',
        'SET(o, INDEX_SET(o, "server_name", AT_K(opts, "server_name", host)))',
        'SET(o, INDEX_SET(o, "connect_timeout_ms", HC_TIMEOUT(opts)))',
        'LET(ca, AT_K(opts, "ca", ""))',
        C('IF', '==(TYPE(ca), "STRING")', [
            C('IF', '!=(ca, "")', ['SET(o, INDEX_SET(o, "ca", ca))'], ['NULL']),
        ], ['NULL']),
        C('IF', '==(AT_K(opts, "verify", TRUE), FALSE)', [
            'PRINT_ERR("WARNING(http_client_tls): TLS certificate verification DISABLED (verify: FALSE) — connection is NOT authenticated")',
            'SET(o, INDEX_SET(o, "verify", FALSE))',
        ], ['NULL']),
        'INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), "opts", o)',
    ], '// tls.CONNECT 选项（校验默认开）')

    src += fn('HC_ENOUGH', 'txt, got', [
        '// 是否已经能停读：头块到齐、且（有 Content-Length 时）字节数够声明值。',
        '// ⚠ 用 `text` 判头块结束是**安全**的：CRLFCRLF 是 ASCII，lossy 替换只会落在多字节',
        '//   字符处；而这里用的 BYTE_LEN(头块前缀) 在头块完整时也是无损的。',
        'LET(i, HC_HEADER_END(txt))',
        C('IF', '<(i, 0)', ['FALSE'], [
            'LET(cl, HC_DECLARED_LEN(SUB(txt, 0, i)))',
            C('IF', '<(cl, 0)', [
                '// 无（或坏的）Content-Length ⇒ 读到 EOF 为止',
                'FALSE',
            ], [
                '>=(got, +(BYTE_LEN(SUB(txt, 0, i)), +(4, cl)))',
            ]),
        ]),
    ], '// 读够了吗')

    src += fn('HC_TLS_IO', 'h, req, timeout_ms', [
        '// 一条 TLS 连接上的「发请求 → 按 Content-Length 读满 → 关闭」。',
        '// ⚠ 每条路径都必须 CLOSE（含错误路径）—— 漏关会泄漏句柄。',
        '// ⚠ RECV 的 `text` 是 **from_utf8_lossy** 的（仓内源：src/tls/mod.rs::recv）',
        '//   ⇒ 分块边界劈开多字节字符会变 U+FFFD。所以**字节**按 `bytes` 累积、结束时',
        '//   一次性 UTF8_DECODE；`text` 只用来判「头块到没到 + 声明的长度」。',
        'LET MUT(buf, [])',
        'LET MUT(txt, "")',
        'LET MUT(state, "read")',
        'LET MUT(err, "")',
        'LET(sent, SEND(h, req))',
        C('IF', 'IS_ERR(sent)', [
            'SET(state, "error")',
            'SET(err, HC_ERR_TEXT("tls send failed", sent))',
        ], ['NULL']),
        C('WHILE', '==(state, "read")', [
            '// ⚠ 等待必须是循环体的第一条语句（并发册 §17.0 的恢复语义）',
            'LET(chunk, RECV(h, HC_CHUNK, timeout_ms))',
            C('IF', 'IS_ERR(chunk)', [
                'SET(state, "error")',
                'SET(err, HC_ERR_TEXT("tls recv failed", chunk))',
            ], [
                'LET(n, LEN(AT_K(chunk, "bytes", [])))',
                'LET(is_eof, AT_K(chunk, "eof", FALSE))',
                'SET(buf, +(buf, AT_K(chunk, "bytes", [])))',
                'SET(txt, CAT(txt, AT_K(chunk, "text", "")))',
                C('IF', '&&(==(n, 0), !is_eof)', [
                    '// 空读且不是 EOF = 超时（tls 契约：超时返空 + eof:FALSE）',
                    'SET(state, "error")',
                    'SET(err, CAT("tls recv timeout after ", STR(timeout_ms), " ms"))',
                ], [
                    C('IF', 'HC_ENOUGH(txt, LEN(buf))', [
                        'SET(state, "done")',
                    ], [
                        C('IF', 'is_eof', [
                            'SET(state, "done")',
                        ], [
                            C('IF', '>(LEN(buf), HC_MAX_BYTES)', [
                                'SET(state, "error")',
                                'SET(err, CAT("response exceeds ", STR(HC_MAX_BYTES), " bytes"))',
                            ], ['NULL']),
                        ]),
                    ]),
                ]),
            ]),
        ]),
        'CLOSE(h)',
        C('IF', '==(state, "error")', ['HC_FAIL(NULL, err)'], [
            C('IF', 'IS_ERR(UTF8_DECODE(buf))', [
                'HC_FAIL(NULL, "response is not valid UTF-8")',
            ], [
                'INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), "raw", UTF8_DECODE(buf))',
            ]),
        ]),
    ], '// 发送 + 按 Content-Length 读满 + 关闭')

    src += fn('HC_TLS_EXCHANGE', 'host, port, opts, req', [
        '// 真正出网：MODULE_REF("tls") 取成员 → CONNECT → HC_TLS_IO。',
        '// ⚠ 没装扩展时 MODULE_REF 是 **E0040 诊断中止**（不是 ERR 值）⇒ 这里接不住；',
        '//   这是「本模块可被 CI 加载」的必然代价（见模块头）。',
        'LET(copts, HC_CONNECT_OPTS(opts, host))',
        'LET(m, MODULE_REF("tls"))',
        'LET(connect, AT_K(m, "CONNECT", NULL))',
        'LET(h, connect(host, port, AT_K(copts, "opts", DICT())))',
        C('IF', 'IS_ERR(h)', [
            'HC_FAIL(NULL, HC_ERR_TEXT("tls connect failed", h))',
        ], [
            'HC_TLS_IO(h, req, HC_TIMEOUT(opts))',
        ]),
    ], '// TLS 传输（唯一碰 tls.* 的函数）')

    src += fn('HC_AS_EXCHANGE', 'v', [
        '// 测试缝的返回值归一：STRING = 原始报文；DICT = 已经是 {ok, raw|error}',
        'IF(==(TYPE(v), "STRING"), INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), "raw", v), IF(==(TYPE(v), "DICT"), v, HC_FAIL(NULL, "exchange() must return STRING or DICT")))',
    ], '// 归一测试缝的返回值')

    src += fn('HC_EXCHANGE', 'host, port, opts, req', [
        '// 传输选择：opts.exchange 是 FUNCTION ⇒ 走它（CI 的脱网全链路）；否则真出网。',
        '// 这不是「可选后端」，是**唯一的**测试手段（TLS 进不了 CI，见模块头）。',
        'LET(f, AT_K(opts, "exchange", NULL))',
        C('IF', '==(TYPE(f), "FUNCTION")', [
            'HC_AS_EXCHANGE(f(req))',
        ], [
            'HC_TLS_EXCHANGE(host, port, opts, req)',
        ]),
    ], '// 传输（可注入测试缝）')

    # ── 对外三层 ────────────────────────────────────────────────────
    src += fn('HTTP_REQUEST', 'opts', [
        '// 通用版：任意方法（GET / POST …），返回卡 S5-1 的成功 / 失败形状。',
        '// ⚠ 只做 HTTPS（本模块名就是它）；不做明文 HTTP、不跟随重定向、不复用连接。',
        'LET(host, HC_STR(opts, "host", ""))',
        C('IF', '==(host, "")', [
            'HC_FAIL(NULL, "host is required")',
        ], [
            'LET(req, HTTP_BUILD_REQUEST(opts))',
            'LET(res, HC_EXCHANGE(host, HC_PORT(opts, 443), opts, req))',
            C('IF', '!AT_K(res, "ok", FALSE)', [
                'HC_FAIL(NULL, AT_K(res, "error", "transport failed"))',
            ], [
                'HC_VERDICT(HTTP_PARSE_RESPONSE(AT_K(res, "raw", "")))',
            ]),
        ]),
    ], '// 一次 HTTPS 请求（建 → 传 → 解析 → 定 ok）')

    src += fn('HC_API_KEY', 'opts', [
        '// API key：`api_key` 优先，兼容 `key`。空 ⇒ 空串（调用方**必须**判）。',
        'HC_STR(opts, "api_key", HC_STR(opts, "key", ""))',
    ], '// 取 API key')

    src += fn('HC_BODY', 'opts', [
        '// body：STRING 原样；DICT / ARRAY 就 STRINGIFY（便利，且结果确定）；其余当空串。',
        'LET(b, AT_K(opts, "body", ""))',
        'IF(==(TYPE(b), "STRING"), b, IF(||(==(TYPE(b), "DICT"), ==(TYPE(b), "ARRAY")), STRINGIFY(b), ""))',
    ], '// 取 body 文本')

    src += fn('HC_MERGE_HEADERS', 'hdrs, key', [
        '// 补 Authorization（Bearer）+ Content-Type；调用方给了同名头就不覆盖。',
        '// ⚠ 顺序 = Authorization 先、Content-Type 后（与卡 S5-1 的报文示例同序）。',
        'LET MUT(o, hdrs)',
        C('IF', 'HC_HAS_HDR(o, "authorization")', ['NULL'], [
            'SET(o, INDEX_SET(o, "Authorization", CAT("Bearer ", key)))',
        ]),
        C('IF', 'HC_HAS_HDR(o, "content-type")', ['NULL'], [
            'SET(o, INDEX_SET(o, "Content-Type", "application/json"))',
        ]),
        'o',
    ], '// 补齐两个必需头')

    src += fn('HTTPS_POST_JSON', 'opts', [
        '// 一次出站 HTTPS JSON POST（卡 S5-1 的主入口）。',
        '// opts：host / port(443) / path / headers / body / timeout_ms / ca / verify / api_key',
        '// ⚠ **未配置 API key ⇒ 明确报错**，且**在碰传输之前**返回（脱网也测得到这条守卫）。',
        'LET(key, HC_API_KEY(opts))',
        C('IF', '==(key, "")', [
            'HC_FAIL(NULL, "API key not configured")',
        ], [
            'LET(hdrs, HC_MERGE_HEADERS(HC_DICT(opts, "headers"), key))',
            'LET(o, INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(opts, "method", "POST"), "path", HC_STR(opts, "path", "/v1/chat/completions")), "headers", hdrs), "body", HC_BODY(opts)))',
            'HTTP_REQUEST(o)',
        ]),
    ], '// HTTPS JSON POST（API key 必填）')

    src += fn('HC_PAYLOAD', 'opts', [
        '// 请求体：{model, messages, temperature}（对齐 Python _call_api 的三个键）。',
        '// ⚠ STRINGIFY 的键序是**字典序**（messages / model / temperature），不是插入序 ——',
        '//   夹具里钉的就是字典序，别照 Python json.dumps 的顺序写期望值。',
        'LET MUT(d, INDEX_SET(DICT(), "model", HC_STR(opts, "model", "gpt-3.5-turbo")))',
        'SET(d, INDEX_SET(d, "messages", AT_K(opts, "messages", [])))',
        'SET(d, INDEX_SET(d, "temperature", AT_K(opts, "temperature", 0.7)))',
        'STRINGIFY(d)',
    ], '// CHAT 请求体 JSON')

    src += fn('HC_CONTENT', 'status, content', [
        '// CHAT_COMPLETION 的成功形状',
        'INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), "status", status), "content", content)',
    ], '// CHAT 成功结果')

    src += fn('HC_EXTRACT_BODY', 'doc, status', [
        '// doc（已 PARSE 的响应）→ content。每层先判 TYPE：AT_K 对 NULL 基值是 E0030。',
        '// ⚠「缺字段」与「空串」要分开：缺省用 NULL，再判 TYPE == "NULL"。',
        'LET(choices, AT_K(doc, "choices", NULL))',
        C('IF', '!=(TYPE(choices), "ARRAY")', [
            'HC_FAIL(status, "response has no choices array")',
        ], [
            C('IF', '==(LEN(choices), 0)', [
                'HC_FAIL(status, "response has empty choices")',
            ], [
                'LET(c0, AT(choices, 0, NULL))',
                C('IF', '!=(TYPE(c0), "DICT")', [
                    'HC_FAIL(status, "choices[0] is not an object")',
                ], [
                    'LET(msg, AT_K(c0, "message", NULL))',
                    C('IF', '!=(TYPE(msg), "DICT")', [
                        'HC_FAIL(status, "choices[0].message is not an object")',
                    ], [
                        'LET(content, AT_K(msg, "content", NULL))',
                        C('IF', '!=(TYPE(content), "STRING")', [
                            'HC_FAIL(status, "choices[0].message.content is missing")',
                        ], [
                            'HC_CONTENT(status, content)',
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ], '// 响应 DICT → content')

    src += fn('HC_EXTRACT', 'body, status', [
        '// 取 choices[0].message.content。',
        '// ⚠ std.json::PARSE 失败是 **E0070 中止**（坑 47）⇒ 必须先 JSON_VALIDATE。',
        C('IF', 'IS_ERR(JSON_VALIDATE(body))', [
            'HC_FAIL(status, "response body is not valid JSON")',
        ], [
            'LET(doc, PARSE(body))',
            C('IF', '!=(TYPE(doc), "DICT")', [
                'HC_FAIL(status, "response JSON is not an object")',
            ], [
                'HC_EXTRACT_BODY(doc, status)',
            ]),
        ]),
    ], '// 取 choices[0].message.content')

    src += fn('CHAT_COMPLETION', 'opts', [
        '// OpenAI 兼容的一次非流式补全。',
        '// opts：api_key / model / messages / temperature + 传输项（host/port/path/ca/verify/…）',
        '// 返回：{ok:TRUE, status, content} 或 {ok:FALSE, status, error}',
        'LET(key, HC_API_KEY(opts))',
        C('IF', '==(key, "")', [
            'HC_FAIL(NULL, "API key not configured")',
        ], [
            'LET(o, INDEX_SET(INDEX_SET(opts, "path", HC_STR(opts, "path", "/v1/chat/completions")), "body", HC_PAYLOAD(opts)))',
            'LET(r, HTTPS_POST_JSON(o))',
            C('IF', '!AT_K(r, "ok", FALSE)', ['r'], [
                'HC_EXTRACT(AT_K(r, "body", ""), AT_K(r, "status", 200))',
            ]),
        ]),
    ], '// 一次非流式 chat completion')

    A('EXPORT(["HTTP_BUILD_REQUEST", "HTTP_PARSE_RESPONSE", "HTTP_REQUEST",')
    A('        "HTTPS_POST_JSON", "CHAT_COMPLETION"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
