# TinyPage

一个**纯 WLWL** 的静态站点生成器 + 后台管理服务。内容存成文件，不需要数据库。

**运行时不含 Python、不含 nginx、不含任何 WSGI 服务器。** 站点生成、静态服务、
TLS 终止、后台 CRUD、上传、AI 助手全部由 WLWL（v0.12.1）实现。

| 组件 | 实现 | 入口 |
|---|---|---|
| 构建 | `tp/bin/build.wll` | `wlwl.exe run tp\bin\build.wll` |
| 公开站（TLS） | `tp/bin/serve_tls.wll` | 需 `--ext wlwl_tls.dll` |
| 公开站（明文） | `tp/bin/serve_public.wll` | 无需扩展 |
| 后台 | `tp/bin/serve_admin.wll` | 只绑回环 |

> 为什么公开站有两个入口：WLWL 的等待点（TLS 握手、`TCP_SERVE` 的 accept）会冻结
> **整个运行时**，同一进程里开不了两个服务。TLS 与明文是两个独立进程。

---

## 1. 前置

- **WLWL 编译器 v0.12.1**（Windows `x86_64-pc-windows-msvc`）。
  本机路径示例：`D:\wlwl_v0.12.1\wlwl.exe`。
  运行时目录需完整（`lib/stdlib/*.wll`、`lib/wlwl_tls.dll`）。
- 系统上**不需要** Python / nginx / Docker（Docker 只在用容器部署时需要）。
- Windows 10/11 桌面版或 Server 2019+。

`wlwl.exe` 与 `lib/` **没有**入库（体积与来源纪律）——下面命令一律写绝对路径占位
`D:\wlwl_v0.12.1\wlwl.exe`，换成你自己的即可。

---

## 2. 构建站点

```powershell
cd D:\Project\TinyPage
D:\wlwl_v0.12.1\wlwl.exe run tp\bin\build.wll
```

输出形如 `build: articles= 3  written= 12  ok= TRUE  pages= 1  categories= 2  injected= 9`。

> ⚠ 在**当前仓库**直接跑，实际看到的是这一行（因为 `pages\article\` 里还没有文章）：
> ```
> build: articles= 0  written= 0  ok= FALSE  pages= 0  categories= 0  injected= 9
> ```
> 这是**预期**行为，不是故障（见下条）。有文章之后 `articles` / `written` 才会非零、
> `ok` 才变 `TRUE`；这条成功路径由 `tp\test\test_build.wll` 用合成语料覆盖，
> 它把产物与参考实现做过逐字节 sha256 对照。

- **资产注入**：`static_inject\` 下的 9 个顶层文件每次构建都会**逐字节**拷到
  `pages\` 根（`admin.css` / `admin.js` / `highlight-theme.css` / `highlight.min.js` /
  `htmx.min.js` / `manifest.json` / `search.js` / `sw.js` / `HIGHLIGHT.md`），
  这样页面里引用的 `/highlight.min.js`、`/search.js`、`/manifest.json` 才能取到。
  拷贝数单独回报成 `injected=`，**不计入** `written=`（后者对齐的是渲染产物数）。
  这 9 个路径在 `.gitignore` 里，不会污染 `pages\` 的提交状态。

- 源文章放在 **`pages\article\*.md`**；⚠ **该目录不存在时构建直接失败**
  （`ok= FALSE`，`error= "article dir missing: pages/article"`）——这是照抄原 Python
  版 `cli.py:107-110` 的口径，不是 bug。
- 产物也写进 `pages\`（`index.html` / `list\` / `category\` / `standalone\` /
  `rss.xml` / `sitemap.xml` / `search-index.json` / `robots.txt` …），
  这些路径在 `.gitignore` 里，**不入库**。
- 构建是**全量**的。原 Python 版的 `--incremental` 只影响「少写几个文件」，
  不改变任何产物形态，本实现不提供该开关。

---

## 3. 起公开站

### 3.1 明文（内网 / 调试）

```powershell
$env:TP_ROOT='pages'
$env:TP_HOST='127.0.0.1'
$env:TP_PORT='18080'
D:\wlwl_v0.12.1\wlwl.exe run tp\bin\serve_public.wll
```

```powershell
curl.exe -sI http://127.0.0.1:18080/index.html
```

### 3.2 TLS（对外）

```powershell
$env:TP_ROOT='pages'
$env:TP_HOST='0.0.0.0'
$env:TP_PORT='443'
$env:TP_CERT='C:\certs\fullchain.pem'   # 必填
$env:TP_KEY ='C:\certs\privkey.pem'     # 必填
D:\wlwl_v0.12.1\wlwl.exe run --ext D:\wlwl_v0.12.1\lib\wlwl_tls.dll `
    --ext-sha256 202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b `
    tp\bin\serve_tls.wll
```

- 证书由**外部签发**（Let's Encrypt / 商业证书），本程序不申请证书、不做 ACME。
- 缺 `TP_CERT` / `TP_KEY` 或文件不存在 ⇒ **拒绝启动并 PANIC**，不会静默降级成明文。
- `--ext-sha256` 是扩展的完整性校验（小写 hex，64 字符），首次用前请自己算一次：
  `(Get-FileHash D:\wlwl_v0.12.1\lib\wlwl_tls.dll -Algorithm SHA256).Hash.ToLower()`
- ⚠ 加载原生扩展等于把**整个进程权限**交给它，它**不是沙箱**。启动时宿主会打一行告警。

实测响应头（5 个安全头，顺序固定）：

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: max-age=300, must-revalidate
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
```

---

## 4. 起后台

```powershell
$env:TP_ROOT='pages'
$env:TP_ADMIN_HOST='127.0.0.1'          # ⚠ 设成别的值会直接 PANIC
$env:TP_ADMIN_PORT='8081'
$env:TP_ADMIN_USER='admin'
$env:TP_ADMIN_PASS='<至少 16 位>'
D:\wlwl_v0.12.1\wlwl.exe run tp\bin\serve_admin.wll
```

打开 <http://127.0.0.1:8081/login>。

- **后台只绑回环**，不做 admin 侧 TLS（回环不经过网络）。设 `TP_ADMIN_HOST` 为非
  `127.0.0.1` 会被拒绝启动——这是故意的，不提供「改绑」开关。
- `TP_ADMIN_PASS` 为空 ⇒ 登录返回 **503**（对齐原实现的「未配置口令即不可登录」）。
- 未登录访问除 `/login` 以外的路由 ⇒ **302** 到 `/login`。
- 无 CSRF token 的 POST ⇒ **403**。

---

## 5. 测试与本地 CI

```powershell
# 全量（生成器无漂移 → 静态检查 → wlwl check → 反向守卫 → 27 个测试文件）
powershell -ExecutionPolicy Bypass -File tp\test\ci_local_check.ps1

# 单个模块
D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_md.wll

# 只做语法/括号检查
D:\wlwl_v0.12.1\wlwl.exe check tp\lib\md.wll
python tp\test\paren_check.py tp\lib\md.wll
```

⚠ **测试自己把关**：`RUN_TESTS()` 失败**不会**改进程退出码，所以每个测试文件末尾
自己 `PANIC`。看退出码是可靠的；看 `failed= 0` 也是。

---

## 6. 环境变量

**公开站（`serve_public.wll` / `serve_tls.wll`）**

| 变量 | 说明 | 缺省 |
|---|---|---|
| `TP_ROOT` | 产物根目录 | `pages` |
| `TP_HOST` | 监听地址 | `0.0.0.0` |
| `TP_PORT` | 监听端口 | `80`（TLS 入口 `443`） |
| `TP_CERT` | 证书路径（TLS 入口**必填**） | — |
| `TP_KEY` | 私钥路径（TLS 入口**必填**） | — |

**后台（`serve_admin.wll`）**

| 变量 | 说明 | 缺省 |
|---|---|---|
| `TP_ADMIN_HOST` | 只接受 `127.0.0.1` | `127.0.0.1` |
| `TP_ADMIN_PORT` / `ADMIN_PORT` | 监听端口 | `8081` |
| `TP_ADMIN_USER` / `ADMIN_USER` | 登录用户名 | `admin` |
| `TP_ADMIN_PASS` / `ADMIN_PASS` | 登录口令 | 空 ⇒ 登录 503 |
| `TP_ROOT` | 站点根 | `pages` |
| `TP_THEMES_DIR` | 主题目录 | `themes` |
| `TP_THEME` | 主题名 | `default` |
| `TP_AI_ENABLED` | `true` 才启用 AI | `false` |
| `TP_AI_API_KEY` | AI 服务的 key | 空 ⇒ 功能关闭 |
| `TP_AI_MODEL` | 模型名 | `gpt-3.5-turbo` |
| `TP_AI_PROVIDER` | `openai` / `custom` | `openai` |
| `TP_AI_ENDPOINT` | 自定义 base URL | 按 provider 推导 |

`wlwl run` **不透传脚本参数**（`--port` 会被编译器拒掉），所以端口/路径一律走环境变量。

后台的站点设置（主题等）持久化在 **`.tinypage/config.json`**，与前台共用同一份站点根。

---

## 7. Docker

`Dockerfile` 与 `docker-compose.yml` 已按上面的进程划分写好（`public` / `admin` / `build`
三个服务，**不含 nginx**）。⚠ **尚未在真 Docker 上构建过**：只有 Windows 构建的
`wlwl.exe` ⇒ 必须是 Windows 容器（`servercore`，因为它导入 `VCRUNTIME140.dll`），
而编写这套文件的环境里没有 Docker。用它之前请先在目标机验一遍：

```powershell
docker build -t tinypage:wlwl .
docker compose up -d
curl.exe -k --resolve localhost:443:127.0.0.1 https://localhost/index.html
```

构建前需把 WLWL 运行时放进构建上下文的 `wlwl-runtime\`：
`wlwl-runtime\wlwl.exe`、`wlwl-runtime\lib\wlwl_tls.dll`、`wlwl-runtime\lib\stdlib\*.wll`。

---

## 8. 目录结构

```
TinyPage/
├── tp/
│   ├── lib/              # 25 个 WLWL 模块（解析器 / 内容模型 / 安全 / 静态服务 / AI）
│   ├── bin/              # 4 个入口：build / serve_public / serve_tls / serve_admin
│   ├── test/             # 26 个测试文件 + smoke + 58 个生成器 + fixtures/
│   └── probe/            # 一次性实测探针（入库，供复查结论）
├── pages/                # 站点根：article/*.md 是正文真相源，其余是产物（不入库）
├── themes/default/       # 主题：theme.css / theme.dark.css / manifest.json
├── admin_templates/      # 后台页面模板（7 个）
├── static_inject/        # 前端资产：htmx / highlight / search.js / sw.js / manifest
├── scripts/git-hooks/    # pre-commit / pre-push（sh）
├── .tinypage/config.json # 后台持久化的站点设置
├── Dockerfile
└── docker-compose.yml
```

---

## 9. 开发约定（重要）

1. **`.wll` 由 Python 生成器产出，不要手写。**
   WLWL 的括号诊断**不告诉你缺几层**（`E0011`），手写基本靠猜。改实现请改
   `tp/test/gen_<模块>.py` 再 `python tp\test\gen_<模块>.py`。
   CI 的 no-drift 步骤会拦住「改了生成器忘了跑」和「手改了 .wll」两种情况。
2. **没有 Python 也跑得起来站点**：仓库里剩下的 `.py` 只是**开发期生成器**，
   站点运行期一个都不用。想彻底删干净就必须放弃「与参考实现逐字节对照」的能力
   （见下一条）。
3. **23 个生成器已在 S6-2 冻结删除**（它们 `import tinypage` 或按路径读取它）。
   对应产物变成**只读的历史基准**：
   - 22 个 `tp/test/fixtures/*_baseline.json`
   - `tp/test/test_toc.wll`
   这些文件只能比对、**不能再生成**。改相关 `.wll` 时若与基准不符，以基准为准并
   说明差异；确实要改基准，就手改 JSON 并在提交信息里写清依据。
4. 顶层名字跨模块共享（实测：后绑定会覆盖被 import 模块的同名**私有**名，而且诊断
   的文件/行会错标）⇒ 每个模块的顶层名字都带专属前缀（`SEC_` / `ADM_` / `AI_` …）。
5. 内建 `SORT` 是二次复杂度（1000 元素 28 秒）⇒ 排序一律走 `sort_util.wll`。

---

## 10. 安全说明

- 后台只绑 `127.0.0.1`，不对外；对外只有公开站。
- 公开站 5 个安全头顺序固定；路径含 `..`、隐藏文件、`admin_password.txt` / `.env`
  / `.git` 一律 404；非 GET/HEAD ⇒ 405。
- CSRF 用 HMAC token + double-submit cookie；上传按扩展名白名单 + magic bytes 校验。
- 后台口令请自己设且别写进仓库；`.env` / 证书 / 私钥都在 `.gitignore` 与
  `.dockerignore` 里。

---

## License

MIT License — 见 [LICENSE](LICENSE)。

Copyright (c) 2026 Laffinty
