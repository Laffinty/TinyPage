"""生成 tp/bin/serve_tls.wll —— TLS 静态站入口（卡 S3-2）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：`tp/bin/*.wll` 也是产物）。

**为什么必须与 serve_public 分进程**：`tp/probe/README.md` 的两条实测 ——
  ① TLS 的 `ACCEPT` / `RECV` / `SEND` 在**调用线程上阻塞**（扩展 ABI v1 没有
     就绪事件通道）⇒ 等待期间**整个运行时冻结**；
  ② 同进程不能同时跑 `TCP_SERVE` 与 `tls.LISTEN`（两者串行 ⇒ 后一个永远轮不到）。
⇒ 两个入口各自一个进程，由部署层决定跑哪个 / 都跑。`static_serve.wll`
**不** import `tls`（否则没装扩展时连它都编译不了）。

**跑法**（扩展必须显式 `--ext`；⚠ 加载原生库 = 把进程权限交给它）：
  ```powershell
  $env:TP_ROOT="D:/site"; $env:TP_HOST="127.0.0.1"; $env:TP_PORT="18443"
  $env:TP_CERT=".../server.crt"; $env:TP_KEY=".../server.key"
  & D:\\wlwl_v0.12.1\\wlwl.exe run --ext D:\\wlwl_v0.12.1\\lib\\wlwl_tls.dll `
      --ext-sha256 202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b `
      tp\\bin\\serve_tls.wll
  curl -k -sI https://127.0.0.1:18443/index.html
  ```

**配置（环境变量；`wlwl run` 不透传脚本参数 —— 本机实测）**：
  · `TP_ROOT` 产物根目录，缺省 `pages`
  · `TP_HOST` 监听地址，缺省 `0.0.0.0`
  · `TP_PORT` 监听端口，缺省 `443`
  · `TP_CERT` / `TP_KEY` **必填**（证书 / 私钥路径）

**反向守卫（卡 S3-2）**：
  · 证书或私钥缺失 / 文件不存在 ⇒ **启动即明确失败**，绝不降级成明文监听
  · `tls.LISTEN` 返 `ERR` ⇒ **显式消费**（打印 + PANIC），不让它逃到顶层
  · 一条坏连接（握手失败 / 空读 / 报文畸形）**不得**终止 accept 循环

⚠ 多语句分支一律交给 `C()` 渲染器算括号（手写多行语句字符串会被逐行补 `;`，
  tp/README 坑 29）⇒ 本文件里没有手写的多行调用。

用法：python gen_serve_tls.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, render, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'bin', 'serve_tls.wll')

REASONS = [
    (200, 'OK'), (400, 'Bad Request'), (404, 'Not Found'),
    (405, 'Method Not Allowed'), (500, 'Internal Server Error'),
]


def reason_expr():
    """状态码 → 理由短语（嵌套 IF 链；确定性映射）。"""
    expr = '"Internal Server Error"'
    for code, text in REASONS:
        expr = 'IF(==(status, %d), "%s", %s)' % (code, text, expr)
    return expr


def main():
    src = []
    A = src.append

    def emit(node):
        """渲染一个顶层调用节点并补分号（括号由渲染器负责）。"""
        lines = render(node)
        lines[-1] += ';'
        src.extend(lines)

    A('// tp/bin/serve_tls.wll —— TLS 静态站入口（卡 S3-2）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_serve_tls.py 生成 —— 请勿手改。')
    A('//')
    A('// 需要 TLS 扩展（`--ext .../wlwl_tls.dll`）；HTTP 语义全在')
    A('// tp/lib/static_serve.wll —— 本文件只做「TLS 收字节 → HANDLE → 发字节」。')
    A('//')
    A('// ⚠ 与 serve_public **分进程**：TLS 等待冻结整个运行时（probe 实测）')
    A('//   ⇒ 同进程跑不了第二个循环。')
    A('//')
    A('// 配置（环境变量；`wlwl run` 不透传脚本参数）：')
    A('//   TP_ROOT  产物根目录（缺省 pages）')
    A('//   TP_HOST  监听地址（缺省 0.0.0.0）')
    A('//   TP_PORT  监听端口（缺省 443）')
    A('//   TP_CERT  证书路径（**必填**）')
    A('//   TP_KEY   私钥路径（**必填**）')
    A('')
    A('IMPORT("tls", ["LISTEN", "ACCEPT", "RECV", "SEND", "CLOSE", "LOCAL_ADDR"]);')
    A('IMPORT("wlwl:std.http", ["PARSE_REQUEST"]);')
    A('IMPORT("wlwl:std.env", ["ENV_GET"]);')
    A('IMPORT("wlwl:std.signal", ["ON_SIGNAL", "STOP"]);')
    A('IMPORT("wlwl:std.fs", ["PATH_CANONICAL", "FILE_META"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "INDEX_OF"]);')
    A('IMPORT("wlwl:std.text", ["TO_INT"]);')
    A('IMPORT("wlwl:std.encode", ["BYTE_LEN"]);')
    A('IMPORT("./../lib/static_serve.wll", ["HANDLE"]);')
    A('')

    # ── 小工具 ───────────────────────────────────────────────────────
    src += fn('PATH_OF', 't', [
        '// 请求目标里 "?" 之前的部分',
        'LET(i, INDEX_OF(t, "?"))',
        'IF(<(i, 0), t, SUB(t, 0, i))',
    ], '// 切出 path')

    src += fn('QUERY_OF', 't', [
        '// 请求目标里 "?" 之后的部分',
        'LET(i, INDEX_OF(t, "?"))',
        'IF(<(i, 0), "", SUB(t, +(i, 1)))',
    ], '// 切出 query')

    src += fn('REASON', 'status', [
        '// 状态码 → 理由短语（本入口自己拼响应行；TCP_SERVE 那边由宿主补）',
        reason_expr(),
    ], '// 状态码理由短语')

    src += fn('STATUS_LINE', 'status', [
        '// "HTTP/1.1 <code> <reason>\\r\\n"',
        'CAT("HTTP/1.1 ", STR(status), " ", REASON(status), "\\r\\n")',
    ], '// 响应行')

    src += fn('WIRE', 'resp', [
        '// 把 HANDLE 的 {status, headers, body} 拼成一条**无 keep-alive** 的报文。',
        '// ⚠ Content-Length 是 HANDLE 已算好的（HEAD 时是真实长度）⇒ 这里不得再补，',
        '//   否则 HEAD 会出现两个互相矛盾的 Content-Length。',
        'LET(status, AT_K(resp, "status", 500))',
        'LET(hdrs, AT_K(resp, "headers", DICT()))',
        'LET MUT(out, STATUS_LINE(status))',
        C('FOR', 'k, KEYS(hdrs)', [
            'SET(out, CAT(out, k, ": ", AT_K(hdrs, k, ""), "\\r\\n"))',
        ]),
        'CAT(out, "Connection: close\\r\\n\\r\\n", AT_K(resp, "body", ""))',
    ], '// 响应报文')

    src += fn('SEND_WIRE', 'conn, resp', [
        '// 发一条响应；发送失败只记一笔（**不得**终止 accept 循环）',
        C('IF', 'IS_ERR(SEND(conn, WIRE(resp)))', [
            'PRINT_ERR("tls SEND failed")',
        ], ['NULL']),
    ], '// 发响应')

    src += fn('SEND_PLAIN', 'conn, status, message', [
        '// 传输层自己的错误响应（**不**带静态层的安全头 —— 它连请求都没解析出来）',
        'LET(h, INDEX_SET(INDEX_SET(DICT(), "Content-Type", "text/plain"), '
        '"Content-Length", STR(BYTE_LEN(message))))',
        'SEND_WIRE(conn, INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", status), '
        '"headers", h), "body", message))',
    ], '// 传输层错误响应')

    src += fn('RESPONSE_FOR', 'parsed', [
        '// 已解析的请求字典 → HANDLE 的响应（复用静态内核，入口不含任何业务规则）',
        'LET(target, AT_K(parsed, "path", "/"))',
        'HANDLE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "root", root), "method", '
        'AT_K(parsed, "method", "GET")), "path", PATH_OF(target)), '
        '"query", QUERY_OF(target)))',
    ], '// 解析结果 → 响应（复用静态内核）')

    src += fn('SERVE_CONN', 'conn', [
        '// 一条连接的完整生命周期：RECV → PARSE_REQUEST → HANDLE → SEND → CLOSE。',
        '// ⚠ 每条路径都必须 CLOSE（漏关会泄漏句柄）。',
        '// ⚠ 空读 = 超时 / 对端已关 ⇒ 直接关，不写响应（写也写不出去）。',
        'LET(io, RECV(conn, 16384, 5000))',
        C('IF', 'IS_ERR(io)', [
            'PRINT_ERR("tls RECV failed: ", ERR_PAYLOAD(io))',
            'CLOSE(conn)',
        ], [
            C('IF', '==(AT_K(io, "text", ""), "")', [
                'CLOSE(conn)',
            ], [
                'LET(raw, AT_K(io, "text", ""))',
                C('IF', 'IS_ERR(PARSE_REQUEST(raw))', [
                    'SEND_PLAIN(conn, 400, "Bad Request")',
                    'CLOSE(conn)',
                ], [
                    'SEND_WIRE(conn, RESPONSE_FOR(PARSE_REQUEST(raw)))',
                    'CLOSE(conn)',
                ]),
            ]),
        ]),
    ], '// 服务一条 TLS 连接')

    # ── 配置 ─────────────────────────────────────────────────────────
    A('// ── 配置（环境变量；缺省值 = tinypage/config.py 的缺省 + 443 端口）───────')
    A('LET(root, PATH_CANONICAL(ENV_GET("TP_ROOT", "pages")));')
    A('LET(host, ENV_GET("TP_HOST", "0.0.0.0"));')
    A('LET(port_s, ENV_GET("TP_PORT", "443"));')
    A('LET(port_t, TO_INT(port_s));')
    A('LET(port, IF(IS_ERR(port_t), -1, port_t));')
    A('LET(cert, ENV_GET("TP_CERT", ""));')
    A('LET(key, ENV_GET("TP_KEY", ""));')
    A('LET MUT(running, TRUE);')
    A('LET MUT(served, 0);')
    A('LET MUT(accept_errors, 0);')
    A('')

    # ── 启动守卫 ─────────────────────────────────────────────────────
    A('// ── 启动守卫 ①：证书 / 私钥必填（缺 ⇒ 明确失败，**不得**降级成明文监听）──')
    emit(C('IF', '||(==(cert, ""), ==(key, ""))', [
        'PRINT_ERR("TP_CERT / TP_KEY are required — refusing to serve without TLS")',
        'PANIC("missing TP_CERT / TP_KEY")',
    ], ['NULL']))
    A('')
    A('// ── 启动守卫 ②：证书 / 私钥文件必须真的存在 ─────────────────────────')
    A('LET(cert_meta, FILE_META(cert));')
    emit(C('IF', '!AT_K(cert_meta, "exists", FALSE)', [
        'PRINT_ERR("TP_CERT does not exist: ", cert)',
        'PANIC("bad TP_CERT")',
    ], ['NULL']))
    A('LET(key_meta, FILE_META(key));')
    emit(C('IF', '!AT_K(key_meta, "exists", FALSE)', [
        'PRINT_ERR("TP_KEY does not exist: ", key)',
        'PANIC("bad TP_KEY")',
    ], ['NULL']))
    A('')
    A('// ── 启动守卫 ③：端口 / 产物根目录 ──────────────────────────────────')
    emit(C('IF', '<(port, 0)', [
        'PRINT_ERR("TP_PORT is not a valid port number: ", port_s)',
        'PANIC("bad TP_PORT")',
    ], ['NULL']))
    A('LET(root_meta, FILE_META(root));')
    emit(C('IF', '||(!AT_K(root_meta, "exists", FALSE), !AT_K(root_meta, "is_dir", FALSE))', [
        'PRINT_ERR("TP_ROOT is not a directory: ", root)',
        'PANIC("bad TP_ROOT")',
    ], ['NULL']))
    A('')
    A('// ── 优雅停机：ON_SIGNAL 置标志 + STOP()（STOP 只**请求**，不杀进程）────')
    A('ON_SIGNAL("SIGINT", FUN(() , (SET(running, FALSE); STOP())));')
    A('ON_SIGNAL("SIGTERM", FUN(() , (SET(running, FALSE); STOP())));')
    A('')

    # ── LISTEN + accept 循环 ─────────────────────────────────────────
    A('// ── tls.LISTEN：返 ERR ⇒ **显式消费**（打印 + PANIC），不让它逃到顶层 ────')
    A('LET(l, LISTEN(host, port, INDEX_SET(INDEX_SET(DICT(), "cert", cert), "key", key)));')
    loop = C('WHILE', 'running', [
        'LET(conn, ACCEPT(l, 1000))',
        C('IF', 'IS_ERR(conn)', [
            # 握手失败（例如明文客户端连 TLS 端口）⇒ 记一笔、继续下一条
            'PRINT_ERR("tls ACCEPT failed: ", ERR_PAYLOAD(conn))',
            'SET(accept_errors, +(accept_errors, 1))',
        ], [
            C('IF', '==(TYPE(conn), "NULL")', [
                # accept 超时 = **正常值** ⇒ 回到循环顶部看停机标志
                'NULL',
            ], [
                'SERVE_CONN(conn)',
                'SET(served, +(served, 1))',
            ]),
        ]),
    ])
    emit(C('IF', 'IS_ERR(l)', [
        'PRINT_ERR("tls.LISTEN failed: ", ERR_PAYLOAD(l))',
        'PANIC("tls listen failed")',
    ], [
        'PRINT("serve_tls: listening on ", host, ":", '
        'AT_K(LOCAL_ADDR(l), "port", 0), " root=", root)',
        'PRINT("serve_tls: cert=", cert)',
        loop,
    ]))
    A('')
    A('CLOSE(l);')
    A('PRINT("serve_tls: served=", served, " accept_errors=", accept_errors, " — bye");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
