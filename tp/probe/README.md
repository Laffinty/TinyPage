# tp/probe —— WLWL 运行时约束探针

这些探针用来**测量 WLWL 运行时的行为约束**，每一份对应构建计划
`docs/plans/tinypage-wlwl-rewrite-plan.md` §2 里的一条结论。

> ⚠ **它们是本机探针，CI 不跑**（`.github/workflows/wlwl.yml` 只跑 `tp/lib` 与
> `tp/test`）。原因：部分探针依赖**本机的 WLWL 安装目录**（TLS 证书在
> `D:\wlwl_v0.12.1\wlwl-src\...`），换机器就要改路径。

## 硬编码路径（换机器需改）

| 探针 | 依赖 | 改法 |
|---|---|---|
| `probe_blocking3.wll` / `tls_probe.wll` / `tls_middleware.wll` | `CERT_PATH` / `KEY_PATH` 指向 **WLWL 安装目录**里的测试证书 | 改成你本机的 `wlwl-src/impl/ext/wlwl-tls-ext/tests/fixtures/server.{crt,key}` |
| `probe_fs.wll` / `probe_sort.wll` | 仓库内路径（`README.md` / `tinypage/`） | 可改成相对路径 |
| `md_proto.wll` | 仓库内 `fixture.md` | 可改成相对路径 |

## 每条探针对应的结论

| 探针 | 测什么 | 结论 |
|---|---|---|
| `md_caps.wll` | 正则能力、拼接复杂度、递归深度 | 正则**禁反向引用/前瞻**（E0030）；拼接线性；递归上限 2000 层 |
| `scale.wll` | 拼接曲线 + 递归极限 | 320KB=53ms、640KB=107ms；`rec(2000)` 通过、`rec(5000)` → E0101 |
| `probe_sort.wll` | `SORT` 复杂度 | 200=850ms / 500=6.1s / 1000=28.2s ⇒ **二次复杂度，禁用 SORT** |
| `probe_blocking3.wll` | TLS 是否冻结运行时 | 两任务各 `ACCEPT(1500ms)`：A=1500ms、**B=3006ms** ⇒ **串行** |
| `probe_two_serve.wll` | 同进程两个 `TCP_SERVE` | A=2006ms、**B=4013ms** ⇒ **串行** ⇒ 公开站与 admin 必须分进程 |
| `probe_serve.wll` | `TCP_SERVE` 循环容错 | 垃圾连接不计数（`SERVED_COUNT 3`），循环存活 ⇒ 单条坏连接不杀循环 |
| `probe_egress.wll` | 出站 HTTPS | `tls.CONNECT` + 手写 HTTP/1.1 可行，45ms 往返 |
| `tls_middleware.wll` + `run_mw.ps1` | TLS 中间件全链路 | TLS 终止 → 解析 → 转发上游 → 回写 ⇒ 可行 |
| `tls_probe.wll` + `run_tls_probe.ps1` | TLS 终止最小样例 | `curl -k` 拿到响应；严格校验报 `SEC_E_UNTRUSTED_ROOT` ⇒ 确实是 TLS |
| `probe_fs.wll` | 文件元数据 | `FILE_META` 给 `{exists,is_dir,mtime,mtime_http,size}` ⇒ 增量构建可用 |
| `upstream.wll` | 明文 HTTP 上游 | 用 `TCP_SERVE` 写的上游（**零 Python**）⇒ 探针链本身不含 Python |
| `md_proto.wll` + `fixture.md` | Markdown 原型 | 40KB 文档 → 324–427ms；两次输出一致 |

## 怎么跑

```powershell
$WLWL = 'D:\wlwl_v0.12.1\wlwl.exe'
& $WLWL run tp\probe\md_caps.wll
& $WLWL run tp\probe\probe_sort.wll        # ≈ 3 分钟（2000 元素项）

# 需要 TLS 扩展的：
& $WLWL run --ext D:\wlwl_v0.12.1\lib\wlwl_tls.dll `
    --ext-sha256 202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b `
    tp\probe\probe_blocking3.wll

# 端到端（curl 驱动）
powershell -File tp\probe\run_mw.ps1
powershell -File tp\probe\run_serve.ps1
```

⚠ **TLS 探针的证书是自签测试证书**，仅限 `127.0.0.1`，**不得**用于任何真实服务。
