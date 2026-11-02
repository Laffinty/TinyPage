"""生成 tp/bin/serve_public.wll —— 明文 HTTP 静态站入口（卡 S3-1）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：`tp/bin/*.wll` 也是产物）。

**入口只做传输，业务逻辑全在 `tp/lib/static_serve.wll`**：
  收请求（`TCP_SERVE` 原生帧内）→ 调 `HANDLE` → 把 `{status, headers, body}`
  原样交给 `TCP_SERVE` 写回。本文件**不含**任何静态文件规则。

**为什么用 `TCP_SERVE` 而不是手写 accept 链**：它在一个原生帧内推进
「accept → 读满一次请求 → handler → 写回 → 下一条」，单条坏连接只废那一条
（`tp/probe/README.md` 的 `probe_serve.wll` 实测：垃圾连接不计数、循环存活）。
⚠ 代价：`TCP_SERVE` 期间**阻塞调用线程** ⇒ 用 1000ms 的 accept 超时让循环
每秒回到 WLWL 层一次，`ON_SIGNAL` 的处理器才有安全点可跑（见下）。

**配置走环境变量**（⚠ `wlwl run` **没有**脚本参数透传：`run <file> --port 18080`
会被 CLI 当成未知选项拒掉 —— 本机实测）：
  · `TP_ROOT` 产物根目录，缺省 `pages`（= `tinypage/config.py` 的 `root_dir` 缺省）
  · `TP_HOST` 监听地址，缺省 `0.0.0.0`
  · `TP_PORT` 监听端口，缺省 `80`

**停机**：`ON_SIGNAL` 把标志置 FALSE + `STOP()`；`STOP()` 只**请求**停机
（不杀进程），主循环在下一轮（≤1s）看到标志就收工、关监听器、打印已服务数。

用法：python gen_serve_public.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, render, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'bin', 'serve_public.wll')


def main():
    src = []
    A = src.append
    A('// tp/bin/serve_public.wll —— 明文 HTTP 静态站入口（卡 S3-1）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_serve_public.py 生成 —— 请勿手改。')
    A('//')
    A('// 传输在此，**HTTP 语义全在** tp/lib/static_serve.wll（HANDLE 是纯函数）。')
    A('//')
    A('// 配置（环境变量；`wlwl run` 不透传脚本参数）：')
    A('//   TP_ROOT  产物根目录（缺省 pages）')
    A('//   TP_HOST  监听地址（缺省 0.0.0.0）')
    A('//   TP_PORT  监听端口（缺省 80）')
    A('//')
    A('// 本机跑法：')
    A('//   $env:TP_ROOT="D:/site"; $env:TP_HOST="127.0.0.1"; $env:TP_PORT="18080"')
    A('//   & D:\\wlwl_v0.12.1\\wlwl.exe run tp\\bin\\serve_public.wll')
    A('//   curl -sI http://127.0.0.1:18080/index.html')
    A('')
    A('IMPORT("wlwl:std.net", ["TCP_LISTEN", "TCP_SERVE", "TCP_CLOSE_LISTENER",')
    A('    "TCP_LOCAL_ADDR"]);')
    A('IMPORT("wlwl:std.env", ["ENV_GET"]);')
    A('IMPORT("wlwl:std.signal", ["ON_SIGNAL", "STOP"]);')
    A('IMPORT("wlwl:std.fs", ["PATH_CANONICAL", "FILE_META"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "INDEX_OF"]);')
    A('IMPORT("wlwl:std.text", ["TO_INT"]);')
    A('IMPORT("./../lib/static_serve.wll", ["HANDLE"]);')
    A('')

    # ── 配置 ─────────────────────────────────────────────────────────
    src += fn('PATH_OF', 't', [
        '// 请求目标里 "?" 之前的部分（没有 "?" ⇒ 原样）',
        'LET(i, INDEX_OF(t, "?"))',
        'IF(<(i, 0), t, SUB(t, 0, i))',
    ], '// 切出 path')

    src += fn('QUERY_OF', 't', [
        '// 请求目标里 "?" 之后的部分（没有 ⇒ 空串）',
        'LET(i, INDEX_OF(t, "?"))',
        'IF(<(i, 0), "", SUB(t, +(i, 1)))',
    ], '// 切出 query')

    A('// ── 配置（环境变量；缺省值 = tinypage/config.py 的缺省 + 80 端口）────────')
    A('LET(root, PATH_CANONICAL(ENV_GET("TP_ROOT", "pages")));')
    A('LET(host, ENV_GET("TP_HOST", "0.0.0.0"));')
    A('LET(port_s, ENV_GET("TP_PORT", "80"));')
    A('LET(port_t, TO_INT(port_s));')
    A('LET(port, IF(IS_ERR(port_t), -1, port_t));')
    A('')
    A('// 启动即失败的两道门（不得「起来了但每请求都 404」）')
    A('IF(<(port, 0), (PRINT_ERR("TP_PORT is not a valid port number: ", port_s);')
    A('                  PANIC("bad TP_PORT")), NULL);')
    A('LET(root_meta, FILE_META(root));')
    A('IF(||(!AT_K(root_meta, "exists", FALSE), !AT_K(root_meta, "is_dir", FALSE)),')
    A('   (PRINT_ERR("TP_ROOT is not a directory: ", root); PANIC("bad TP_ROOT")), NULL);')
    A('')
    A('LET MUT(running, TRUE);')
    A('LET MUT(served, 0);')
    A('')

    # ── handler ──────────────────────────────────────────────────────
    src += fn('HANDLE_REQUEST', 'req', [
        '// TCP_SERVE 的请求字典：{method, path, version, headers, body}',
        '// ⚠ `path` 是**请求目标原样**（可能带查询串）⇒ 这里切成 path / query。',
        '// 返回的 {status, headers, body} 正是 TCP_SERVE 要的响应形状。',
        'LET(target, AT_K(req, "path", "/"))',
        'HANDLE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "root", root), "method", '
        'AT_K(req, "method", "GET")), "path", PATH_OF(target)), "query", QUERY_OF(target)))',
    ], '// 一次请求 → 响应（直接交给 TCP_SERVE）')

    # ── 信号 ─────────────────────────────────────────────────────────
    A('// ── 优雅停机：ON_SIGNAL 置标志 + STOP()（STOP 只**请求**，不杀进程）────')
    A('// ⚠ 处理器由主线程在**安全点**执行（std.signal 的约定）⇒ TCP_SERVE 的')
    A('//   1000ms accept 超时就是「多久能响应一次信号」的上界。')
    A('ON_SIGNAL("SIGINT", FUN(() , (SET(running, FALSE); STOP())));')
    A('ON_SIGNAL("SIGTERM", FUN(() , (SET(running, FALSE); STOP())));')
    A('')

    # ── 主循环 ───────────────────────────────────────────────────────
    A('// ── 主循环：每轮一次 TCP_SERVE（accept 超时 1000ms ⇒ 每秒回到 WLWL 层）──')
    A('// ⚠ TCP_SERVE 不关监听器 ⇒ 退循环后自己关。')
    A('// ⚠ read_timeout_ms 给 5000：缺省 0 = 无截止时间，一个慢客户端就能把')
    A('//   循环卡住、连停机标志都读不到（安全点进不来）。')
    A('LET(serve_opts, INDEX_SET(DICT(), "read_timeout_ms", 5000));')
    A('LET(l, TCP_LISTEN(host, port));')
    # ⚠ 多语句分支必须交给渲染器（`C`）算括号；手写多行语句字符串会被
    #   逐行补 ';'（tp/README 坑 29）。
    main_block = C('IF', 'IS_ERR(l)', [
        'PRINT_ERR("TCP_LISTEN failed: ", ERR_PAYLOAD(l))',
        'PANIC("listen failed")',
    ], [
        'PRINT("serve_public: listening on ", host, ":", '
        'AT_K(TCP_LOCAL_ADDR(l), "port", 0), " root=", root)',
        C('WHILE', 'running', [
            'LET(cnt, TCP_SERVE(l, 1000, serve_opts, HANDLE_REQUEST))',
            C('IF', 'IS_ERR(cnt)', [
                'PRINT_ERR("TCP_SERVE failed: ", ERR_PAYLOAD(cnt))',
                'SET(running, FALSE)',
            ], [
                'SET(served, +(served, IF(IS_ERR(cnt), 0, cnt)))',
            ]),
        ]),
    ])
    block_lines = render(main_block)
    block_lines[-1] += ';'
    src.extend(block_lines)
    A('')
    A('TCP_CLOSE_LISTENER(l);')
    A('PRINT("serve_public: served=", served, " — bye");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
