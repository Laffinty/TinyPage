# TinyPage → WLWL 完全重构：构建计划

> **状态**：计划已就绪，待开工。
> **目标**：把 TinyPage 从「Python 静态站点生成器 + WSGI 后台 + nginx 反代」整体重写为**纯 WLWL 实现**，
> 运行时不依赖 nginx、不依赖 Python、不依赖任何需要 Python 才能执行的组件。
> **基准**：WLWL 编译器 `v0.12.1`（`D:\wlwl_v0.12.1\wlwl.exe`），规范 `v1.0.4`。
> **本计划的所有数字都来自本机实测**，不是规范推断。每条都附了可重跑的证伪命令。

---

## §0 本文档的格式契约（先读这一节）

**怎么读**：§1 是结论与范围边界；§2 是实测事实台账（所有结论的证据）；§3 是目标架构；
§4 是分阶段任务卡（每张卡可独立执行、独立验收）；§5 是风险登记；§6 是验收门禁；§7 是决策记录。

**每条事实自带证伪命令**。命令红了以**命令**为准，不以本文档为准 —— 文档会过期，运行期不会。

**状态标记**：`[已核实]` = 本机实测过，附原始读数；`[待验证]` = 尚未实测，进阶段时补；
`[已裁决]` = 业主已拍板，不再讨论；`[挂起]` = 依赖外部条件，暂不推进。

**每张任务卡自带**：`依赖` / `交付物` / `验收命令` / `反向守卫`（做错了会立刻炸的检查）/ `非目标`。
`反向守卫` 是刻意设计的失败检查 —— 没有守卫的卡等于没写。

**进度写在本文档内**（§0.1 进度表），不依赖对话上下文。

### §0.1 进度表

| 阶段 | 状态 | 交付物 |
|---|---|---|
| S0 运行时与工具链准备 | ✅ 完成 | WLWL 0.12.1 已部署；skill 已装；`docs/` 规范已补齐；`tp/probe/` 探针链已入库（零 Python） |
| S1-1 骨架 | ✅ 完成 | `tp/{lib,bin,test}/` + `tp/README.md` + `tp/wlwl.toml`；`smoke.wll` 通过；反向守卫验证 `wlwl check` 对坏文件非零退出 |
| S1-1b 开发工具链 | ✅ 完成 | `tp/test/` 下 5 个静态检查器（括号/中缀/分号/生成器参数/逐函数编译）+ 逐行深度追踪 |
| S1-2 行内解析器 | ✅ 完成 | `tp/lib/md_inline.wll`（生成器产出）；**21/21 测试通过**，含 3 个反向守卫 |
| S1-3 块级解析器 | ✅ 完成 | `tp/lib/md.wll`（生成器产出）；**28/28 对照 mistune 3.2.1 逐字节通过**（25 基准 + 3 守卫）；链接去掉自加的 `rel` 属性以逐字节对齐 |
| S1-4 front-matter/TOC/脚注/wikilink | ✅ 完成 | `frontmatter.wll` / `toc.wll` / `footnotes.wll` / `wikilink.wll` + 共享 `esc.wll`（全部生成器产出）；**38/38 + 41/41 + 23/23 + 28/28 + esc 19/19 全绿**；本地 CI 5 步全过（21 生成器 / 21 产物无 drift） |
| S2 内容模型与生成器 | 🔄 **S2-1～S2-4 已完成**；余 S2-5（增量构建） | S2-1 ✅ `article_store.wll` **277/277**／S2-2 ✅ `sort_util.wll` **39/39**／S2-3 ✅ `template.wll` + `theme.wll` **162+68**／S2-4 ✅ `page_common` + `article_page` + `list_page` + `feeds` + `search_index` **42+33+21+30+29 = 155**（共 10 个导出、91 条基准、24 条反向守卫）；S2-5 ⬜ |
| S3 前台静态服务（TLS） | ⬜ 未开始 | `serve_public.wll`（TLS 终止 + 静态文件） |
| S4 Admin 后台 | ⬜ 未开始 | `serve_admin.wll` + 会话/CSRF/限流/CRUD |
| S5 AI 助手（出站 HTTPS） | ⬜ 未开始 | `ai.wll`（`tls.CONNECT` + 手写 HTTP/1.1） |
| S6 部署与切换 | ⬜ 未开始 | Dockerfile/compose 改造 + 停用 nginx |

### §0.2 S1 已沉淀的工程约定（**后续所有 .wll 都适用**）

1. **`.wll` 由 Python 生成器产出，不手写。**
   `tp/lib/*.wll` 与 `tp/test/*.wll` 由 `tp/test/gen_*.py` 产出。
   理由（实测）：WLWL 的括号诊断 `E0011` 只说「expected `)` got X」，**不告诉你缺了几层**；
   本次开发同一个函数来回改了 6 次仍不对。生成器把括号配平交给 Python，
   产出**括号必然平衡**的源码。
2. **每个模块产出后必须过三道静态检查**（秒级反馈，早于编译）：
   ```powershell
   python tp\test\paren_check.py  <file.wll>   # 括号平衡 + 无中缀算术
   python tp\test\check_semis.py  <file.wll>   # 顶层语句都有分号
   python tp\test\check_c_args.py <gen_*.py>  # 生成器里 C(...) 参数的括号平衡
   ```
   再 `wlwl check <file.wll>`，最后 `wlwl run` 跑测试。
3. **测试必须自己把关退出码**：`RUN_TESTS()` 的失败**不影响退出码**（规范明载）
   ⇒ 测试文件末尾要 `IF(>(failed, 0), (PRINT_ERR(...); PANIC(...)), NULL);`，
   否则「测试失败但 CI 绿」。
4. **实测得到的二十四条 WLWL 陷阱**见 `tp/README.md` 的对照表（无中缀算术、`CAT` 不拼数组、
   `WHILE` 值为 NULL、顶层语句缺分号、`std.*` 须 IMPORT、`&&`/`||` 而非 `AND`/`OR`、
   字符串转义白名单、布尔大写、递归上限 2000、`SORT` 二次复杂度、`FUN` 两组括号、
   闭包读写外层 `LET MUT`、`CAT` 遇 NULL 拼出字面 `NULL`、无逗号表达式、
   `RE_TEST` 整串锚定、正则无前瞻、`$1` 而非 `\1`、`\w` 不含非 ASCII、内建 `HTML_ESCAPE` 出 `&#39;`、
   正则不认 `\uXXXX`、**读数组绑定深拷贝 ⇒ `AT`/`LEN` 实测 O(n)**、**`PUSH` 是纯函数不原地修改**、
   **`READ_FILE`/`WRITE_FILE` 不转换行尾（Python `read_text` 会转）**、**`WRITE_FILE_ATOMIC` 成功返回 `NULL`、失败返回 `ERR`**）。
5. **项目根 = 含 `wlwl.toml` 的最近祖先目录** ⇒ `tp/wlwl.toml` 必须存在，
   否则 `tp/test/` 里的 `IMPORT("./../lib/...")` 越界（`E0040`）。
6. **共享工具只留一份**：HTML 转义统一走 `tp/lib/esc.wll::ESCAPE_HTML`
   （对齐 Python `html.escape(quote=True)`，含单引号 → `&#x27;`）。
   任何需要「输出转义 HTML」的模块都 `IMPORT("./esc.wll", [...])`，**不得**自己再实现。
7. **CI 已就位**（`.github/workflows/wlwl.yml`，Windows runner，9 步）：
   ① 下载官方 WLWL 0.12.1 Windows zip（**校验 sha256**）② 验证版本
   ③ **重跑生成器并要求 `git diff` 为空**（产物与生成器必须一致）
   ④ 静态检查器（括号+中缀 / 分号 / 生成器参数）
   ⑤ `wlwl check` 全部 `.wll` ⑥ **反向守卫**（坏文件必须被 check 拒掉）
   ⑦ 跑 `smoke.wll` 与全部 `test_*.wll`。
   ⇒ 本地可一键复现全部步骤：`powershell -File tp\test\ci_local_check.ps1`。
   ⚠ 生成器**不得**硬编码绝对路径（CI 上仓库在别处）⇒ 产物路径由 `__file__` 推导。
   ✅ **实测状态：GitHub Actions run 41317062756 ⇒ 9/9 步全绿**（S1-3 后 run #37 仍全绿）。

   **⚠ 第 ③④⑦ 步已改为「自动发现」**（S1-4 期间发现的缺口）：原先是**硬编码的
   生成器/测试清单**，导致 S1-3 的 `gen_md.py`/`gen_test_md.py` **没被 no-drift 守卫、
   `test_md.wll` 没被跑**。现改为 `Get-ChildItem tp\test -Filter 'gen_*.py'` /
   `'test_*.wll'` 全量遍历 ⇒ 新增模块无需改 CI；drift 检查范围同时纳入
   `tp/test/fixtures/*.json`（基准也必须可复现）。本地脚本同步改造。

   **⚠ 写 CI 时踩到的三个坑（都已在配置里规避并注释）**：
   | # | 坑 | 症状 | 规避 |
   |---|---|---|---|
   | a | PowerShell 把 native 命令的 stderr 当错误流 | pwsh 7 下守卫步**误报红**（退出码明明是 3） | 该步用 `shell: cmd` + `call :label` 取退出码，**不让 PowerShell 参与** |
   | b | cmd 的 `REM` 行不认 UTF-8 | yml 里的中文注释被当命令执行 | CI yml 与 `.ps1` 的注释**一律英文** |
   | c | PowerShell 5.1 读无 BOM 的 `.ps1` 按 ANSI 码页解析 | 中文注释让字节错位 ⇒ 引号被破坏 ⇒ `Unexpected token '}'` | `.ps1` 保持**纯 ASCII**；`.gitattributes` 用 `text eol=crlf` |

### §0.3 断点快照（2026-11-02 07:00–08:15 因运行额度中止）

> 两个 worker 被中止。**本节是接续工作的唯一依据** —— 恢复时先读这里，再读 §2.1。
>
> ⚠ **2026-11-02 08:15 后补记**：本节所描述的「未提交的改动」已由 `36f330a` 提交并推送，
> 且期间修掉了一个只在校 CI 复现的门禁缺陷（见本节末尾「中止后的两笔提交」）。
> **下方的断点描述保持原样**（记录的是中止当时的事实），接续时以本补记为准。

**中止时的整体状态**：S1 全部完成并已推送（CI run #5 十步全绿）；
S2-2 已完成并核验；S2-1 完成了一半（基准已交付，实现未写）；
S2-2 的「补两个缺口导出」已完成实现、**但基准与测试未补**。
工作区**自洽**（三个 sort_util 生成器幂等、无 drift），**但有未提交的改动**。

#### 中止后的两笔提交（2026-11-02 08:15 起）

| 提交 | 内容 | CI |
|---|---|---|
| `36f330a` | S2-2 `sort_util.wll` + S2-1 基准 246 条 + 本节断点快照 + README 陷阱表 24 条 + `.gitattributes` 钉夹具行尾 | run #6 **红**（no-drift），已由 `803e904` 修 |
| `803e904` | 修 no-drift 在 CI 上的漂移：`gen_article_store_baseline.py` 先 `realpath()` 归一临时目录 + 跳出 base 即抛错的守卫 | run #7 **11 步全绿** |

⚠ **run #6 那次红是「环境相关漂移」，不是代码错**（值得记住的坑）：
GitHub Windows runner 的 `tempfile.gettempdir()` 返回 **8.3 短名**
（`C:\Users\RUNNER~1\AppData\Local\Temp\tmpXXXX`），而 `safe_path_check` 内部对
base 与 target 都做 `resolve()`、返回**长名**（`runneradmin`）⇒ 生成器侧
`relpath(长, 短)` 算出 `..\..\..\runneradmin\AppData\Local\Temp\...` 这种
**机器相关**相对路径并写进夹具。本机卷不生成 8.3 短名 ⇒ **本地永远复现不出来**
（连干净 clone 重跑也不行），只有看 CI 日志的实际 diff 行才定位得到。

#### ✅ 已完成且经父进程独立核验

| 项 | 状态 | 读数 |
|---|---|---|
| 卡 S2-2 首轮（`SORT_BY_DATE` / `SORT_STRINGS`） | ✅ 完成 | `wlwl check` OK (6648 bytes)；`wlwl run` **25/25**（22 基准 + 3 守卫），failed=0，exit 0；2000 元素 **635ms** vs 内建 `SORT` 约 113s |
| §2.1 台账 F18–F24（7 条新事实） | ✅ 已入册 | 均附父进程独立实测读数与归因实验 |
| `tp/README.md` 陷阱表 | ✅ 扩到 **24 条** | 新增 #21–#24（数组绑定克隆 / `PUSH` 纯函数 / 行尾不转换 / 原子写返回语义） |
| S2-1～S2-5 + S3-1 的 Python 侧权威落点 | ✅ 已入卡片 | 含 `validate_filename` 7 项规则、写入 5 步校验顺序、删除 8 步回滚、渲染 7 步顺序、模板 19 占位符、产物 9 个函数位置、nginx 5 安全头等 |

#### ⚠ 卡 S2-1（`article_store.wll`）—— **基准已交付，实现未写**

| 文件 | 状态 |
|---|---|
| `tp/test/gen_article_store_baseline.py` | ✅ **已交付**（453 行） |
| `tp/test/fixtures/article_store_baseline.json` | ✅ **已交付**（**246 条 / 11 组**，只有 2 条已知差异） |
| `tp/test/gen_article_store.py`（实现生成器） | ❌ **未写** |
| `tp/lib/article_store.wll` | ❌ 未生成 |
| `tp/test/gen_test_article_store.py`（测试生成器） | ❌ **未写** |
| `tp/test/test_article_store.wll` | ❌ 未生成 |

- **基准的 11 组**：`validate_filename`(31) / `validate_content`(13) / `validate_date_format`(23) /
  `validate_title`(7) / `safe_path_check`(18) / `source_path`(9) / `write_source`(4) /
  `decode_content`(22) / `decode_legacy_body`(22) / `unescape_to_fixpoint`(90) / `meta_value`(7)。
- **全部直接 `import` 真 Python 实现**；唯一的「复刻」是 `validate_title`
  （Python 侧无独立函数，规则内联在 `content.py:270`，已在 `TITLE_RULE_SOURCE` 标注出处）。
- **基准已登记的 2 条已知差异**：
  - **D2** `validate_filename/f30`：Python `re` 的 `\d` 匹配 Unicode 数字（`int()` 也能解析），
    WLWL 的 `\d` 只认 ASCII ⇒ **WLWL 拒绝、Python 接受**。
  - **D3** `safe_path_check/p15`：卡片要求「拒绝含 `..` 的输入」（WLWL 的 `PATH_CANONICAL`
    是词法判定、不解析符号链接）⇒ **WLWL 拒绝、Python 允许**（Python 的 `resolve()` 会消解 `..`）。
- ⚠ `safe_path_check` 的扩展名白名单分支**依赖目标是否真实存在** ⇒
  基准用固定相对布局 `dirs=['sub'] files=['ok.html','bad.exe','sub/a.txt']`，
  基准与测试**必须用同一份布局**。
- ⚠ 基准路径一律用 `PurePosixPath` 渲染（Windows 上 `Path` 会渲染成 `\`）⇒ 夹具跨机器稳定。

**接续要点**：实现生成器要覆盖 11 个对应导出；`validate_title` 与 `safe_path_check` 两条
**按基准的 `want` 走**（不是 Python 的 `python` 值）；路径安全必须**额外**加「拒绝含 `..` 的输入」
（卡片明确要求，且已作为 D3 登记）。

#### ⚠ 卡 S2-2 补缺口 —— **实现已落地，但零测试覆盖**

| 文件 | 状态 |
|---|---|
| `tp/test/gen_sort_util.py` | ✅ 已改为 **4 个导出**：`SORT_BY_DATE` / `SORT_BY_NUM_DESC` / `SORT_BY_TITLE_OR_FILE` / `SORT_STRINGS` |
| `tp/test/gen_sort_util_baseline.py` | ✅ 已改为新结构 `{"cases":[{name, fn, input, expected, note}]}` |
| `tp/test/gen_test_sort_util.py` | ✅ 已适配新结构（按 `case['fn']` 选导出） |
| 三个产物 | ✅ 已重生成，**幂等**（重跑哈希不变 ⇒ no-drift 不会红） |
| `tp/lib/sort_util.wll` | ✅ `wlwl check` OK (13778 bytes)，269 行 |

- **现有 25 条测试仍全绿**（22 基准 + 3 守卫），2000 元素 **618ms**。
- ⚠⚠ **缺口 A / 缺口 B 的基准用例与测试用例都还没写** ⇒
  `SORT_BY_TITLE_OR_FILE` 与 `SORT_BY_NUM_DESC` **零覆盖**。
  基准 JSON 的 `fn` 分布实测为 `{'SORT_STRINGS': 11, 'SORT_BY_DATE': 11}` ⇒ **无新导出用例**。
- **父进程已做的冒烟验证**（临时探针，已删）—— 两个新导出行为与 Python **一致**：
  | | Python 权威 | WLWL 实测 |
  |---|---|---|
  | A 顺序（`title` 空串回落 `file`） | `z.html \| b.html \| aaa.html`（键 `['Alpha','Beta','aaa.html']`） | 同 |
  | B 顺序（数值倒序、相等键稳定） | `b a c`（键 `[0.9, 0.5, 0.5]`） | 同 |
  | A 空数组 / B 单元素 | `0` / `1` | `0` / `1` |

  ⇒ **但这只是冒烟**（3 组输入），**不是逐字节基准**。接续时**必须**补：
  ① `gen_sort_util_baseline.py` 里加 `SORT_BY_TITLE_OR_FILE` 与 `SORT_BY_NUM_DESC` 的用例
  （期望值由**真 Python** `sorted(..., key=...)` 产出；A 的键要用 `SimpleNamespace`
  复刻 `ArticleMeta` 的**属性访问**语义，不是 dict）；② `gen_test_sort_util.py` 随之自动覆盖；
  ③ 用例至少含：空 title 回落、相等键稳定性、数值倒序、空数组、单元素。

#### 恢复后的执行顺序（建议）

1. **先补 S2-2 缺口 A/B 的基准与测试**（生成器已就位，只差加用例）→ 跑全量本地 CI。
2. **再写 S2-1 的实现生成器 + 测试生成器**（基准已有 246 条，实现有明确目标）。
3. 两者都绿后**一次性提交推送**，确认 GitHub Actions 全绿。
4. 之后才进 **S2-3（模板与主题）**。

#### 中止时的收尾动作（已完成）

- 两个 worker 的 **47 个 `tmp_probe*` 临时探针** + **6 个 `probe_out*` 目录**已清理
  （⚠ 这些 `.wll` 会被 CI 静态检查器扫到，语法不合法的会让 CI 直接红 ⇒ **必须清**）。
- 父进程自己的探针（`_probe_*` / `_tmp_*`）亦已全部清理。
- `sort_util` 三个生成器已重跑确认幂等 ⇒ 工作区无 drift。

---

## §1 结论与范围边界

### 1.1 结论

**可以做，但有三处不可回避的取舍**，业主已裁决其中三处方向（§7）：

| # | 事实 | 影响 | 裁决 |
|---|---|---|---|
| C1 | WLWL 的 TLS/HTTP 等待**冻结整个运行时** | 单进程内无法并发服务两个端口 ⇒ 公开站与 admin **必须分进程** | 已裁决：双端口 |
| C2 | `std.collection::SORT` 是**二次复杂度** | 500 篇以上文章排序会让一次构建卡到分钟级 ⇒ **禁用 SORT**，排序手写 | 本计划强制 |
| C3 | 无 Python 语法高亮等价物 | pygments 的数百种 lexer 不可复刻 ⇒ 改前端高亮 | 已裁决：前端高亮 |

### 1.2 范围边界

**在范围内**：
- 静态站点生成器（Markdown → HTML + 主题 + RSS/sitemap/搜索索引/分页/分类页/PWA）
- 前台静态服务（TLS 终止 + 静态文件 + 安全头 + 缓存头）
- Admin 后台（登录/会话/CSRF/限流/审计/文章 CRUD/独立页 CRUD/主题切换/预览/上传/AI 入口）
- 出站 HTTPS 客户端（AI 助手）
- 部署形态改造（Dockerfile / compose，**删除 nginx 服务**）
- 保留既有前端资产（`static_inject/`、`admin_templates/`、`themes/`）—— 它们是 HTML/JS/CSS，不是 Python 组件

**明确不在范围内**：
- 重写任何 JavaScript / CSS / HTML 模板（除：高亮方案切换所需的最小改动）
- 改变内容目录约定（`pages/article/*.html` + 同名 `.md` + `<!-- key: value -->` 元数据）——
  这是**用户数据格式**，改了等于迁移全部历史文章
- 引入数据库（继续保持「无数据库」这一产品定位）
- 实现 CommonMark 全部语法（见 §4.1 的明确范围）
- 多进程/多 worker 静态服务（WLWL 运行时限制，见 C1）

---

## §2 实测事实台账

> 全部为 **2026-11-01 本机实测**（wlwl 0.12.1，Windows）。
> 每条给出可重跑命令。**命令红了以命令为准。**

### 2.1 语言与运行时约束

| # | 事实 | 证据 / 证伪命令 |
|---|---|---|
| F1 | **递归上限 2000 层**（`E0101`） | `tp/probe/scale.wll`：`rec(1000)` 通过，`rec(5000)` → `E0101` |
| F2 | 字符串拼接**线性** | `tp/probe/scale.wll` → 320KB=53ms、640KB=107ms |
| F3 | 正则**禁反向引用/前瞻/命名组**（`E0030`） | `tp/probe/md_caps.wll` → `(\*\*|__)(.+?)\1` 直接 `E0030` |
| F4 | 字符串转义白名单仅 `\" \\ / \n \r \t \b \f \0 \$` | 正则里 `\*` 必须写成 `\\*`，否则 `E0001` |
| F5 | 布尔字面量是 **`TRUE`/`FALSE`（大写）** | `["verify": false]` → `E0020: undefined name 'false'` |
| F6 | `std.*` 成员**不是全局名**，必须 `IMPORT` | `BYTE_LEN` 未 import → `E0020`；`CAT` 未 import → handler failed |
| F7 | **`SLEEP_ASYNC` 放进任务里的 `WHILE` 循环会挂死**（段首重放重置计数器） | `tp/probe/probe_blocking.wll` 首版即挂死 60s 超时 |
| F8 | `ERR` 未消费会报 `E0103`；`IS_ERR` 只观察不解除 | WLWL v1.0 错误模型，skill §8.6 |
| F9 | **`RE_TEST` 整串锚定且忽略 `(?m)`**；行锚定只有 `RE_SEARCH`/`RE_REPLACE`/`RE_FIND_ALL` 认 `(?m)` | `RE_TEST(RE("(?m)^b$"), "a\nb\nc")` = FALSE；`RE_SEARCH` 同模式 = `[matched: b, start: 2, end: 3]` |
| F10 | **正则不支持前瞻/后顾**（与 F3 同源，但会当场 `E0030`） | `RE("\\[\\^[^\\]]+\\](?!:)")` → `E0030: lookahead is not supported (it would break linear time)` |
| F11 | **`RE_REPLACE` 的组引用是 `$1` 不是 `\1`**；`RE_SEARCH` 返回 `[matched, start, end, groups]`，start/end 是**码点**下标 | `RE_REPLACE(RE("(\\d+)-(\\d+)"), "a 12-34 b", "$2/$1")` = `a 34/12 b` |
| F12 | **`\w` 的 Unicode 语义与 Python 不同**：WLWL 的 `\w` **不含**非 ASCII 字母 | `RE_REPLACE(RE("[^\\w\\u4e00-\\u9fa5-]"), "café", "-")` = `caf-`；Python 同模式 = `café` |
| F13 | **内建 `HTML_ESCAPE` 出 `&#39;`，Python `html.escape` 出 `&#x27;`** ⇒ 逐字节对照必红 | `HTML_ESCAPE("<a>'b'&c")` = `&lt;a&gt;&#39;b&#39;&amp;c`；Python = `&#x27;b&#x27;` ⇒ 统一走 `tp/lib/esc.wll::ESCAPE_HTML` |
| F14 | **`CAT` 遇 `NULL` 拼出字面 `"NULL"`**（不是空串） | `CAT("A", NULL, "B")` = `ANULLB` |
| F15 | **`FUN` 是两个括号组** `FUN((params), (body))`；零参写 `FUN((), (body))` | `FUN((body))` → `E0010: expected parameter name, got If` |
| F16 | **闭包可读可写外层 `LET MUT`**（`SET` 直达外层绑定） | 探针：`LET MUT(y, "Y0"); LET(g, FUN((), (SET(y, CAT(y, "+g"))))); g(); g();` ⇒ `y = Y0+g+g` |
| F17 | **WLWL 正则不认 `\uXXXX`**：未知转义 `\u` 退化成**字面 `u`** ⇒ `\u4e00-\u9fa5` 匹配的是文本 `u4e00-u9fa5` 而**不是 CJK**。Python `re` 则认得它（`re.match(r"[一-龥]", "中")` → True） | 探针（wlwl 0.12.1）：`RE_TEST(RE("^[一-龥]+$"), "中文")` → **TRUE**；`RE_TEST(RE("^\\u4e00-\\u9fa5$"), "中")` → **FALSE**；同式对 `"u4e00-u9fa5"` → **TRUE** ⇒ 证明是字面匹配。**写字符类一律用字面 `一-龥`**（toc.wll 实测与 Python 逐字节一致） |
| **F18** | ⚠⚠ **求值一个数组绑定会克隆整个数组** ⇒ `AT(arr,i)` / `arr[i]` / `LEN(arr)` 实测都是 **O(n)**，**违反规范 §18.3 的 O(1) 规范性上界**（⚠ 且 §18.6「参考实现未达标项」清单**没有登记这一条** ⇒ 可反馈上游的缺口） | 父进程独立实测（wlwl 0.12.1，300 次固定访问）：`AT` 在 500 元素数组 12ms / 2000 元素数组 35ms（**比值 2.9**）；`LEN` 8ms / 30ms（**比值 3.75**）。**归因实验**（2000 元素 × 300 次）：直接读绑定 **34ms** / 别名 `LET(alias,arr)` **39ms** / 字典取值 `AT_K(d,"a",[])` **42ms** / **字符串对照 `LEN(str1)` 仅 1ms** ⇒ **不是 `LEN` 本身慢，是「求值数组绑定」这一步克隆**（值语义 §19.1），且**别名与字典都绕不过**。⇒ **任何数组密集算法在本解释器上都是 O(n²)**，这是 S2-4（拼 HTML 数组）、S2-5（扫文件列表）、S3（发文件）的共同性能基线。**规避手段：把需要的元素/长度缓存进局部标量，绝不在热循环里反复读数组绑定** |
| **F19** | **`PUSH` 是纯函数，不原地修改任何已有数组**（参数与自己上次返回值都不改）⇒ 必须 `SET(x, PUSH(x, v))` 或 `LET(x, PUSH(x, v))`，否则元素**静默丢失** | 父进程独立实测：`LET(x,[1,2,3]); PUSH(x,4);` ⇒ `LEN(x)` 仍 **3**；`LET(y,PUSH(x,4));` ⇒ `LEN(x)=3` `LEN(y)=4`；`PUSH(z2,10);` ⇒ `LEN(z2)` 仍 **4**（连它自己上次返回的数组也不改） |
| **F20** | **`PUSH` 规范上是 O(n) 最坏**（「数组不可变，**必须**产出新数组」，§18.3）**，但参考实现识别了「可变累加器形态」**（§18.6 登记已达标）⇒ 循环内 `SET(p, PUSH(p,x))` 实测为**线性摊还 O(1)**，逐元素追加不退化成二次 | 父进程独立实测 `SET(p, PUSH(p,"x"))` 循环：1000 次 **3ms** / 2000 次 **6ms** / 4000 次 **8ms**（线性）。⚠ 注意：若**丢弃**返回值来测，数组永远不长 ⇒ 会误测成「更快的 O(1)」，两种测法结论不同 |
| **F21** | **字符串比较是码点序**，与 Python `sorted` 完全一致 ⇒ 字符串排序可逐字节对照（UTF-8 字节序 == 码点序） | S2-2 实测：`"A"<"a"` ✔、`"中">"a"` ✔、`"é">"z"` ✔、`""<"z"` ✔、`"-"<"0"` ✔ |
| **F22** | ⚠⚠ **`READ_FILE` / `WRITE_FILE` 不做任何行尾转换**（CRLF 原样保留），而 **Python 的 `Path.read_text()` 用 universal newlines ⇒ CRLF 转 LF** ⇒ **同一文件两边读出的字符串差 CRLF 个字符** | 父进程独立实测（`themes/default/theme.css`，**20326 bytes / 805 个 CRLF**）：Python `read_text()` → **19517 字符、无 CR**；WLWL `READ_FILE` → **20322 字符、有 CR**（`first_cr_index=63` 与 `first_lf_index=64` 相邻）⇒ **差 805**。写-读往返也保留（写 `"a\r\nb\r\n"` 读回长度 6）。⇒ **凡是要与 Python 逐字节对照的文件读取，WLWL 侧必须自己做 CRLF→LF 归一化**（S2-3 读 `theme.css` 必踩） |
| **F23** | **`REMOVE` 只能删文件，删非空目录失败** | `REMOVE(dir)` → ERR `FsError: 目录不是空的 (os error 145)` | 删目录要先删其中文件；或用 `MKDIRS` 前先确保为空 |
| **F24** | **`WRITE_FILE_ATOMIC` 成功返回 `NULL`（非 `TRUE`）；失败返回 `ERR`**（`FsError`/`op`/`reason`）⇒ 未消费即 `E0103` | 父进程独立实测：写成功 ⇒ 返回 NULL、文件存在、`FILE_META.size` 正确、**不留 `.tmp` 残留**、覆盖写正常；写不存在的父目录 ⇒ ERR `cannot write (...): parent directory does not exist` | 用 `IS_ERR(x)` 判断成败（不要 `==(x, TRUE)`）；**父目录必须先 `MKDIRS`**（不会自动建） |

### 2.2 标准库能力（`wlwl namespace` 实测导出）

| 命名空间 | 成员数 | 对本项目的关键成员 |
|---|---|---|
| `std.fs` | 26 | `WRITE_FILE_ATOMIC`（对应 Python `os.replace`）、`FILE_META`/`FILE_MTIME`（增量构建）、`PATH_CANONICAL`/`PATH_CONTAINS`、`LOCK_FILE`/`UNLOCK_FILE`、`WRITE_BYTES`/`READ_BYTES`（**读上限 1MiB**） |
| `std.http` | 16 | `PARSE_REQUEST`、`BUILD_RESPONSE`、`SERVE_STREAM`、`ROUTE`/`MATCH_ROUTE`、`PARSE_FORM`、`PARSE_COOKIES`/`SET_COOKIE`、`STATIC_FILE`、`RATE_LIMITER`、`RULESET_LOAD`、`CLIENT_IP` |
| `std.net` | 16 | `TCP_LISTEN`/`TCP_SERVE`/`TCP_RECV`/`TCP_SEND`、`HTTP_REQUEST`（**仅明文 http**）、`HTTP_REQUEST_ASYNC` |
| `std.test` | 13 | `TEST`/`ASSERT_EQ`/`EXPECT_ERR`/`RUN_TESTS`/`TEST_CASES` |
| `std.encode` | 16 | `SHA256`/`HMAC_SHA256`/`PBKDF2_ITER`/`ARGON2ID`/`RANDOM_BYTES`/`RANDOM_HEX`/`TIMING_SAFE_EQ`/`BASE64_*`/`BYTE_LEN` |
| `std.log` | 7 | `LOG`（JSONL）、`LOG_FILE`、`LOG_SET_LEVEL`、`METRIC_*` |
| `std.json` | 11 | `STRINGIFY`/`PARSE`/`JSON_VALIDATE`（带 offset/line/column） |
| `std.regex` | 8 | `RE`/`RE_TEST`/`RE_SEARCH`/`RE_FIND_ALL`/`RE_REPLACE`/`RE_SPLIT` |
| `std.collection` | 27 | `MAP`/`FILTER`/`REDUCE`/`RANGE`/`GROUP_BY`/`KEY_BY`（**线性**）；`SORT`/`SORT_BY`/`UNIQ`（**二次，禁止**） |
| `std.sync` | 8 | `COUNTER`/`SHARED_DICT`（原子；同名复用需自建注册表） |
| `std.text` | 11 | `TO_INT`（宽松解析）、`NFC`/`NFD`（Unicode 归一） |
| `std.str` | 9 | `CAT`（变参拼接）、`SPLIT_LINES`、`INDEX_OF`、`QUERY_PARSE` |
| `std.signal` | 2 | `ON_SIGNAL`/`STOP`（优雅停机） |

### 2.2.1 探针怎么跑（§2 全部结论的自证入口）

探针在 `tp/probe/`，**入库**，随仓库走。共用的两个前置：

```powershell
# WLWL 解释器
$WLWL = 'D:\wlwl_v0.12.1\wlwl.exe'
# TLS 扩展（探针带 --ext 时需要）
$EXT  = 'D:\wlwl_v0.12.1\lib\wlwl_tls.dll'
$SHA  = '202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b'
```

| 探针 | 命令 | 预期读数 | 耗时 |
|---|---|---|---|
| 正则/拼接/递归 | `& $WLWL run tp\probe\md_caps.wll` | 全 TRUE；`rec_depth_1000`=1000 | < 5s |
| 递归极限 | `& $WLWL run tp\probe\scale.wll` | `rec_2000` 通过；`rec_5000` → **E0101** | < 10s |
| 排序复杂度 | `& $WLWL run tp\probe\probe_sort.wll` | 200≈850ms / 500≈6.1s / 1000≈28.2s | **~3 分钟**（2000 元素项） |
| TLS 串行判据 | `& $WLWL run --ext $EXT --ext-sha256 $SHA tp\probe\probe_blocking3.wll` | A=1500ms、**B=3006ms**、TOTAL≈3011ms | ~3s |
| 双 TCP_SERVE 判据 | `& $WLWL run tp\probe\probe_two_serve.wll` | A=2006ms、**B=4013ms**、TOTAL≈4017ms | ~4s |
| TCP_SERVE 容错 | `powershell -File tp\probe\run_serve.ps1` | `SERVED_COUNT 3`（垃圾连接不计数），第 4 次连接仍成功 | ~15s |
| 出站 HTTPS | `& $WLWL run --ext $EXT --ext-sha256 $SHA tp\probe\probe_egress.wll` | `CONNECT_OK` + 证书链 + 45ms 往返 | ~2s |
| TLS 中间件全链路 | `powershell -File tp\probe\run_mw.ps1` | `upstream hit: /one`；严格校验报 `SEC_E_UNTRUSTED_ROOT` | ~10s |
| 文件元数据 | `& $WLWL run tp\probe\probe_fs.wll` | `{"exists":true,…,"mtime":…,"size":…}` | < 2s |
| Markdown 原型 | `& $WLWL run tp\probe\md_proto.wll` | 22359 码点 → **324–427ms**；`same_out TRUE` | ~2s |

⚠ **探针依赖本机的 WLWL 安装路径**（`D:\wlwl_v0.12.1`）。换机器时改探针顶部的
`CERT_PATH`/`KEY_PATH` 常量与上述 `$WLWL`/`$EXT` 变量即可。
⚠ **TLS 探针的证书是仓库自带的测试用自签证书**（`wlwl-src/impl/ext/wlwl-tls-ext/tests/fixtures/`），
仅限 `127.0.0.1`、**不得**用于任何真实服务。
⚠ **整条探针链零 Python** —— 包括 `run_mw.ps1` 用的上游服务（`tp/probe/upstream.wll`，
用 `TCP_SERVE` 起一个明文 HTTP 上游）。这是有意的：**探针本身也必须满足
「不留需要 Python 才能执行的组件」这条目标**，否则它就成了该目标的反例。

### 2.3 排序复杂度（决定 C2）

```
D:\wlwl_v0.12.1\wlwl.exe run tp\probe\probe_sort.wll
```
| N | SORT 耗时 |
|---|---|
| 200 | 850 ms |
| 500 | 6.1 s |
| 1000 | 28.2 s |

⇒ 二次复杂度确认。**任何超过 500 元素的排序必须手写。**

### 2.4 TLS 与网络（决定 C1 与 S3/S5）

| 事实 | 读数 | 证伪命令 |
|---|---|---|
| TLS 扩展有**服务端**成员 | `tls.LISTEN`/`ACCEPT`/`RECV`/`SEND`/`CLOSE`/`LOCAL_ADDR`/`CERT_FINGERPRINT`/`CERT_INFO` | `D:\wlwl_v0.12.1\wlwl.exe run --ext D:\wlwl_v0.12.1\lib\wlwl_tls.dll --ext-sha256 202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b tp\probe\tls_probe.wll` |
| TLS 终止 + 手写 HTTP 响应 | `curl -k` 取到 `hello over tls`；严格校验报 `SEC_E_UNTRUSTED_ROOT`（自签 ⇒ 确实是 TLS） | `tp/probe/run_tls_probe.ps1` |
| **TLS 终止整个运行时** | 两任务各 `ACCEPT(1500ms)`：A=1500ms、**B=3006ms** | `tp/probe/probe_blocking3.wll` |
| **TLS 中间件吞吐** | 20 次请求 1752ms ≈ **87.6ms/次、11.4 req/s**（每次重新握手） | `tp/probe/run_mw.ps1` |
| TLS 完整中间件链路可行 | TLS 终止 → `PARSE_REQUEST` → `HTTP_REQUEST` 转发上游 → 回写，拿到 `upstream hit: /one` | `tp/probe/run_mw.ps1` |
| **同进程两个 `TCP_SERVE` 串行** | A=2004ms、**B=4022ms**、TOTAL=4027ms | `tp/probe/probe_two_serve.wll` |
| `TCP_SERVE` 循环**不被单条坏连接打断** | 4 次连接，垃圾连接不计数（`SERVED_COUNT 3`），循环存活 | `tp/probe/run_serve.ps1` |
| `TCP_SERVE` 的 handler 在**原生帧**内 | handler 里做 I/O 会失败（需自己管 socket） | skill §29.2 |
| **出站 HTTPS 可行** | `tls.CONNECT` + `SEND`/`RECV` 手写 HTTP/1.1，45ms 往返，拿到证书链与 SPKI 指纹 | `tp/probe/probe_egress.wll` |
| 扩展加载**不是沙箱** | 宿主打印告警：hands the extension FULL PROCESS PRIVILEGES | 任意 `--ext` 运行 |

### 2.5 Markdown 可行性

| 事实 | 读数 | 证伪命令 |
|---|---|---|
| block+inline 原型可跑 | 40KB 文档 / 22,359 码点 → 单次 **324–427ms**，两次输出一致 | `tp/probe/md_proto.wll` |
| 吞吐 | 约 0.3ms/行 ⇒ 100 篇约 30–45s | 同上 |
| 强调必须**手扫定界符** | 反向引用被 `E0030` 拒绝（F3） | `tp/probe/md_caps.wll` |

### 2.6 命名决策与清单文件的边界（业主裁决 D6 + S1 实测修正）

**业主裁决（2026-11-01）**：目录 `wlwl/` → **`tp/`**；清单 `wlwl.toml` → **`tp.toml`**；
两者在**方案（本文档）与实际文件**里都要改。

| 项 | 决定 | 后果 |
|---|---|---|
| 源码目录 | `wlwl/` → **`tp/`** | ✅ 无副作用。纯路径改名，已同步 §2.2.1 全部证伪命令、§3.2 目录树、§4 全部交付物路径 |
| 清单文件 | `wlwl.toml` → **`tp.toml`** | ⚠ **对 WLWL 运行时无作用**，见下 |

**⚠ 硬约束：`wlwl.toml` 这个文件名在 WLWL 运行时是写死的。**
源码 `impl/crates/wlwl-cli/src/main.rs`：
`find_project_root()` 从被检查文件所在目录**向上查找字面量 `"wlwl.toml"`**；
`load_features()`（读 `[features]`）、`try_write_lock()`（写 `wlwl.lock`）、
`reserved_project_namespaces()`（算保留命名空间）**全部依赖这个名字**。

**实测对照**（同一份 `[features] gradual_typing = "error"` + 一个类型不匹配的 `.wll`）：

| 清单文件名 | 结果 | 退出码 |
|---|---|---|
| `wlwl.toml` | `error[E0110]: annotation mismatch: expected INTEGER, found STRING` | **1** |
| `tp.toml` | **无任何诊断**，正常打印 | **0** |

⇒ 改名后静态契约层（`gradual_typing` / `match_exhaustiveness` / `strict_types`）
**永久静默失效**：写了类型标注也查不出错，且**没有任何提示**。

**为什么本项目可以接受**：
所有 `[features]` 开关默认就是 `off`；**无清单 = 零诊断**是 WLWL 的保证行为
（ADR-0020 S1）。本项目当前**不使用**类型注解、不用 `SEALED`、不写 `.wll.sig`
⇒ 静态层本来就是关着的 ⇒ 清单当前是**面向人的项目说明**，不是运行时配置。

---

**⚠⚠ S1 开发中新发现的第二个硬约束 —— 清单名还决定「项目根」，而项目根决定 IMPORT 能否越界。**

规范 §9.2：**「解析结果不得越出项目根 —— 项目根是最近的含 `wlwl.toml` 的祖先目录；
没有清单时，项目根就是发起方的模块所在目录。」**

S1 实测（`tp/test/test_md_inline.wll` 需要 `IMPORT("./../lib/md_inline.wll", ...)`）：

| 清单 | 项目根 | `IMPORT("./../lib/...")` |
|---|---|---|
| `tp/wlwl.toml` 存在 | `tp/` | ✅ 允许 |
| 只有 `tp/tp.toml` | `tp/test/`（模块所在目录） | ❌ **E0040**：`module './../lib/md_inline.wll' not found outside project root (D:\Project\TinyPage\tp\test)` |

⇒ **只叫 `tp.toml` 会让 `tp/test/` 无法引用 `tp/lib/`**（除非把库放进 `tp/test/`，
或把测试与库放平）。

**当前的落地处理（S1 已实施）**：
- `tp/wlwl.toml` —— **真清单**，让项目根 = `tp/`，跨目录 IMPORT 可用；
  `[features]` 全部保持默认 `off` ⇒ **不开启任何静态检查**（与 D6 的意图不冲突）。
- `tp/tp.toml` —— **业主指定名的项目说明文件**（保留 D6 的字面要求），
  内容与 `wlwl.toml` 一致但 `gradual_typing` 显式写 `off`。
- ⚠ **两份并存时，`wlwl.toml` 会被运行时读到，`tp.toml` 不会被** ——
  静态层的开关由 `wlwl.toml` 决定，所以**必须保证 `wlwl.toml` 里的开关全是 `off`**。
  两份文件的 `[features]` 必须同步，任何一份改动都要同时改另一份。

**⚠ 何时必须打开静态层**：若将来要开启 `gradual_typing`（给 `LET(x: INTEGER, …)`
加类型注解、或给库模块写 `.wll.sig`），**必须先确认 `tp/wlwl.toml` 的
`gradual_typing` 被打开**（而不是只改 `tp/tp.toml`），否则类型写错也查不出来。
计划 §4 各卡的验收命令里凡涉及类型注解的，都要先确认这一点。

**副作用：清单存在时会自动生成 `wlwl.lock`**。`try_write_lock()` 在每次成功 `run` 后
于清单同目录写 `wlwl.lock`（本项目的对照实验实测生成了 `{"schema_version":"0.3.1","entries":[]}`）。
⇒ `tp/wlwl.lock` 应加进 `.gitignore`。

### 2.7 TinyPage 侧（代码事实）
| 能力 | 现状 | 迁移难度 |
|---|---|---|
| Markdown 渲染 | mistune `escape=True`，**无插件**；无 mistune 时降级到手写 30 行转换器 | 中（手写子集，见 §4.1） |
| 元数据 | **非 YAML**，是 HTML 注释 `<!-- key: value -->`，只读前 7 行，键白名单 | 低（保持格式） |
| 正文存储 | 同名 `.md` 兄弟文件为唯一真源 | 低 |
| 模板 | `string.Template` + `$占位符` + `substitute()` | 低（WLWL 拼串） |
| 搜索索引 | `json.dumps`，字段 `title/summary/url/date/tags/category`，**不含正文**，前端子串匹配 | 低 |
| 路由 | 手写 dict 表，GET 9 + POST 14；**import 期用 `inspect.signature` 校验形参个数** | 低 |
| 会话 | 内存 dict + `threading.Lock`，24h 过期，LRU 上限 5000 | 低（`SHARED_DICT`） |
| CSRF | 自实现：16B 随机 + 4B 时间戳 + HMAC-SHA256(32B) → 52B → urlsafe base64；四重校验 | 低（`HMAC_SHA256` + `TIMING_SAFE_EQ`） |
| 限流 | 自写滑动窗口 60 次/60s | 低（`std.http::RATE_LIMITER` 更强） |
| 上传 | base64 字段 + 扩展名白名单 + magic bytes 校验（PNG/JPEG/GIF/WEBP） | 中（`BASE64_DECODE` + 字节比较） |
| AI 助手 | `urllib` → OpenAI 兼容 `/chat/completions`，非流式，30s 超时 | 中（须改走 `tls.CONNECT`） |
| 原子写 | `write .html.tmp` → `os.replace` | 低（`WRITE_FILE_ATOMIC`） |
| 增量构建 | `st_mtime` 比较（**不用 hash**） | 低（`FILE_META`） |
| **死代码（不迁）** | `mermaid_init.py` 全文件、`tag_graph.py` 的两个导出、`incremental.py` 5 个函数、`security.check_basic_auth`（仅测试引用）、`ai_assistance.fallback_summarize` | — |

---

## §3 目标架构

### 3.1 进程与端口（C1 的直接后果）

```
                 ┌─────────────────────────────────────────┐
   :443 (TLS)   │  进程 1: serve_public.wll                │
   ───────────▶ │  · tls.LISTEN + 手写 accept 循环          │
                 │  · 静态文件 + 安全头 + 缓存头             │
                 │  · 读 pages/ 下的产物，不写               │
                 └─────────────────────────────────────────┘

                 ┌─────────────────────────────────────────┐
   127.0.0.1    │  进程 2: serve_admin.wll                 │
   :8081 (HTTP) │  · TCP_SERVE + 路由表                    │
   ───────────▶ │  · 会话/CSRF/限流/审计/CRUD/上传/AI入口  │
                 │  · 写 pages/，触发构建                   │
                 └─────────────────────────────────────────┘

                 ┌─────────────────────────────────────────┐
   本机 :8082   │  进程 3（按需）: build.wll                │
   ───────────▶ │  · CLI 风格：build / serve-admin / check  │
                 └─────────────────────────────────────────┘
```

**为什么必须分进程**：WLWL 的等待点（TLS 握手、`TCP_SERVE` 的 accept、阻塞 `HTTP_*`）都**冻结整个运行时**。
同进程内公开站的 TLS accept 会冻结 admin，后台一次写操作会让前台整站不可用。
实测依据：F 表里的「同进程两个 `TCP_SERVE` 串行」（A=2004ms / B=4022ms）。

**admin 只绑回环** ⇒ 由业主决策：**不需要 admin 的 TLS**（回环不经过网络），
admin 用明文 `TCP_SERVE`。这也避开了 TLS 扩展在 admin 侧的额外开销。

### 3.2 目录布局（新增 `tp/` 树，Python 树在 S6 删除）

```
TinyPage/
├── tp/                         # 新增：WLWL 实现
│   ├── lib/
│   │   ├── md.wll              # Markdown 引擎（块级+行内）
│   │   ├── md_inline.wll       # 行内解析（强调/链接/代码/wikilink）
│   │   ├── frontmatter.wll     # <!-- key: value --> 解析与写回
│   │   ├── toc.wll             # 目录抽取 + 锚点 slug + 去重
│   │   ├── footnotes.wll       # [^k] 定义与引用
│   │   ├── wikilink.wll        # [[标题]] 与反向链接
│   │   ├── article_store.wll   # 文章读写 + 原子写 + 校验
│   │   ├── template.wll        # 页面骨架拼装
│   │   ├── theme.wll           # 主题清单与 CSS 加载
│   │   ├── generator.wll       # 站点产物生成
│   │   ├── feeds.wll           # RSS / sitemap / robots / JSON-LD
│   │   ├── search_index.wll    # 搜索索引 JSON
│   │   ├── security.wll        # CSRF / 会话 / 限流 / 审计 / 转义
│   │   ├── http_util.wll       # 请求解析 / 响应构造 / 路由匹配
│   │   ├── static_serve.wll    # 静态文件服务（含路径安全）
│   │   └── ai.wll              # 出站 HTTPS 客户端 + OpenAI 兼容调用
│   ├── bin/
│   │   ├── build.wll           # CLI: build
│   │   ├── serve_public.wll    # CLI: serve --public
│   │   └── serve_admin.wll     # CLI: serve --admin
│   ├── test/
│   │   ├── test_md.wll
│   │   ├── test_frontmatter.wll
│   │   ├── test_toc.wll
│   │   ├── test_security.wll
│   │   └── test_generator.wll
│   ├── probe/                    # 运行时约束探针（入库；本计划 §2 的证伪载体）
│   │   ├── md_caps.wll           # 正则能力 / 拼接复杂度 / 递归深度
│   │   ├── scale.wll             # 拼接曲线 + 递归极限（E0101 @ 2000）
│   │   ├── probe_sort.wll        # SORT 复杂度曲线（200/500/1000/2000）
│   │   ├── probe_blocking3.wll   # TLS 串行判据（两任务各 ACCEPT(1500)）
│   │   ├── probe_two_serve.wll   # 同进程双 TCP_SERVE 串行判据
│   │   ├── probe_serve.wll       # TCP_SERVE 循环容错（坏连接不杀循环）
│   │   ├── probe_egress.wll      # 出站 HTTPS（tls.CONNECT + 手写 HTTP/1.1）
│   │   ├── probe_fs.wll          # FILE_META / LIST_DIR
│   │   ├── tls_probe.wll         # TLS 终止最小样例
│   │   ├── tls_middleware.wll    # TLS 中间件全链路
│   │   ├── upstream.wll          # 明文 HTTP 上游（WLWL 实现，零 Python）
│   │   ├── md_proto.wll          # Markdown 原型 + 计时
│   │   ├── fixture.md            # 40KB 测试语料
│   │   └── run_*.ps1             # 驱动脚本（curl 端到端验证）
│   └── tp.toml                   # 项目说明（业主指定名；⚠ 见 §2.6）
├── tp/                            # ⚠ 实际布局见 §3.2a（S1 已落地）
├── pages/                      # 内容（用户数据，格式不变）
├── themes/                     # 主题（不变）
├── static_inject/              # 前端资产（不变，仅高亮库有增减）
├── admin_templates/            # 后台模板（不变）
├── tinypage/                   # S6 删除（Python 实现）
├── tests/                      # S6 删除（pytest）
├── scripts/                    # S6 删除（Python git hooks）或改写为 shell
├── Dockerfile                  # S6 改造
├── docker-compose.yml          # S6 改造：删 nginx 服务
└── nginx.conf                  # S6 删除
```

### 3.2a S1 已落地的实际布局

```
TinyPage/
├── tp/                            # WLWL 实现（业主指定名，原 wlwl/）
│   ├── README.md                  # 工程说明 + 开发流程 + 十条 WLWL 陷阱对照表
│   ├── wlwl.toml                  # ⚠ 真清单：决定项目根（见 §2.6）
│   ├── tp.toml                    # 业主指定名的项目说明（运行时**不读**）
│   ├── lib/                       # 实现模块（由生成器产出）
│   │   └── md_inline.wll          # ✅ S1-2：Markdown 行内解析
│   ├── bin/                       # 可执行入口（待 S2/S3）
│   ├── test/                      # 测试 + 生成器 + 静态检查器
│   │   ├── gen_md_inline.py       # 生成 lib/md_inline.wll
│   │   ├── gen_test_md_inline.py  # 生成 test/test_md_inline.wll
│   │   ├── gen_smoke.py           # 生成 test/smoke.wll
│   │   ├── paren_check.py         # 括号平衡 + 中缀算术
│   │   ├── check_semis.py         # 顶层语句分号
│   │   ├── check_c_args.py        # 生成器 C(...) 参数括号
│   │   ├── check_funcs.py         # 逐顶层语句编译
│   │   ├── depth_trace.py         # 逐行括号深度
│   │   ├── smoke.wll              # ✅ 工具链冒烟（exit 0）
│   │   ├── test_md_inline.wll     # ✅ 行内解析 21/21（exit 0）
│   │   └── broken/                # 反向守卫：故意写错（check ⇒ E0011 exit 3）
│   └── probe/                     # ✅ 运行时约束探针（S0 产出，见 §2.2.1）
├── docs/
│   └── plans/tinypage-wlwl-rewrite-plan.md   # 本文档
├── pages/                         # 内容（用户数据，格式不变）
├── themes/                        # 主题（不变）
├── static_inject/                 # 前端资产（不变，仅高亮库有增减）
├── admin_templates/               # 后台模板（不变）
├── tinypage/                      # S6 删除（Python 实现）
├── tests/                         # S6 删除（pytest）
├── scripts/                       # S6 删除（Python git hooks）或改写为 shell
├── Dockerfile                     # S6 改造
├── docker-compose.yml             # S6 改造：删 nginx 服务
└── nginx.conf                     # S6 删除
```

> ⚠ **`.wll` 是生成物**：`tp/lib/*.wll` 与 `tp/test/*.wll` 由 `tp/test/gen_*.py` 产出，
> **不要手改** —— 改实现请改生成器（原因见 §0.2 第 1 条）。

### 3.3 依赖策略

| 能力 | 方案 | 说明 |
|---|---|---|
| Markdown | **自研子集**（§4.1 明确范围） | 无 Python，无第三方 |
| 代码高亮 | **前端 highlight.js** | 引入 `static_inject/highlight.js` + 主题 CSS；服务端只输出 `<pre><code class="language-xxx">` |
| TLS | `wlwl_tls.dll` 扩展（宿主加载） | `--ext` + `--ext-sha256`；**证书外部签发，WLWL 只读文件**（已裁决） |
| 出站 HTTPS | `tls.CONNECT` + 手写 HTTP/1.1 | 已在 `tp/probe/probe_egress.wll` 实证 |
| 加密 | `std.encode` | CSRF/口令用 `SHA256`/`HMAC_SHA256`/`PBKDF2_ITER`/`TIMING_SAFE_EQ` |
| 模板 | 字符串拼装 + `CAT`/`FORMAT` | 对应 `string.Template` |
| JSON | `std.json::STRINGIFY`/`PARSE` | |
| 测试 | `wlwl:std.test` | 对应 pytest |

---

## §4 任务卡

> 每张卡可独立执行。**顺序即依赖**。完成一张就在 §0.1 进度表打勾，并填入验收命令的实测读数。

### S1 骨架 + Markdown 引擎

#### 卡 S1-1：项目骨架与工具链固化 ✅ 已完成

- **依赖**：无（S0 已完成）
- **交付物**：`tp/lib/`、`tp/bin/`、`tp/test/` 目录；`tp/README.md` 写明「如何跑一个 .wll」
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\smoke.wll
  ```
  期望：`exit 0` + 打印一行确认
- **反向守卫**：故意写一个语法错误文件，`wlwl check` 必须**非零退出**并给出 `E00xx` 码
  —— 若它静默通过，说明命令用法错了，后面所有验收都不可信
- **非目标**：不写任何业务逻辑
- **✅ 实测读数（2026-11-01）**：
  - `run tp\test\smoke.wll` ⇒ `smoke: 2 test(s) run` / `failed= 0` / **exit 0**
  - 反向守卫 `tp\test\broken\broken.wll` ⇒ `wlwl check` ⇒ **E0011, exit 3**；
    `wlwl run` 同样 exit 3 ⇒ 守卫成立
  - 附带产出：`tp/test/` 下 5 个**可复用的静态检查器**（见 §0.2 第 2 条）——
    这是本次开发的实际收获：**没有它们，WLWL 的括号诊断不可用**

#### 卡 S1-2：Markdown 行内解析器 ✅ 已完成

- **依赖**：S1-1
- **交付物**：`tp/lib/md_inline.wll`，导出
  `INLINE(text) -> STRING`（HTML 转义 → 行内代码 → 粗体 → 斜体 → 链接 → wikilink）
- **必须支持的语法**（对齐 TinyPage 实际使用）：
  `` `code` ``、`**bold**`、`*italic*`、`[text](url)`、`[[wikilink]]`、`[[title|display]]`
- **必须实现**：
  - **定界符手扫**（F3 禁反向引用 ⇒ 粗体/斜体必须自己配对扫描）
  - 链接协议白名单（对应 Python `validate_url_protocol`：禁 `javascript:`/`data:`/`vbscript:`/`file:`）
  - `wiki` 链接的 `article_map` 查表（大小写不敏感），未命中回退 `/article/{slug}.html`
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_md_inline.wll
  ```
  期望：`RUN_TESTS` 全绿 + 逐条断言（含 `javascript:` 被拒、`<script>` 被转义）
- **反向守卫**：
  - 输入含 `**` 不配对 ⇒ **不得**吞掉后面的正文
  - 输入含 `<script>alert(1)</script>` ⇒ 输出必须已转义（`&lt;script&gt;`）
  - 输入 `[x](javascript:alert(1))` ⇒ 不得生成 `<a href>`
- **非目标**：不做块级解析、不做表格、不做嵌套强调（`**a *b* c**`）
- **✅ 实测读数（2026-11-01）**：**21/21 全绿，exit 0**
  - 基础：`inline/{code,bold,italic,bold_before_italic,link,wikilink,wikilink_alias}`
  - 守卫：`guard/{unpaired_bold_keeps_rest,unpaired_italic_keeps_rest,script_is_escaped,`
    `quotes_are_escaped,javascript_protocol_blocked,data_protocol_blocked,vbscript_protocol_blocked}`
  - 协议：`url/{safe_protocols,dangerous_protocols,unknown_protocol_rejected}`
  - 其他：`wiki/article_map`、`inline/{code_has_priority,mixed,deterministic}`
  - 实际输出抽样：
    `INLINE("use \`x\` here")` ⇒ `use <code>x</code> here`
    `INLINE("**粗** 与 *斜* 与 \`码\` 与 [链](https://x.y)")` ⇒
    `<strong>粗</strong> 与 <em>斜</em> 与 <code>码</code> 与 <a href="https://x.y" rel="noopener noreferrer">链</a>`
    `WIKILINK_TARGET("没找到", {})` ⇒ `/article/没找到.html`（**保留 CJK**，对齐 `security.py::slugify`）
- **⚠ 实现方式的调整（偏离原卡）**：原计划「手写 `tp/lib/md_inline.wll`」，
  实际改为**由 `tp/test/gen_md_inline.py` 生成**（原因见 §0.2 第 1 条）。
  实现逻辑未变，只是排版与括号由生成器保证。

#### 卡 S1-3：Markdown 块级解析器

- **依赖**：S1-2
- **交付物**：`tp/lib/md.wll`，导出 `RENDER_MD(text) -> STRING`
- **必须支持的块**（**明确范围，超出即非目标**）：
  标题 `#`~`######`、段落、围栏代码块（```）、无序列表、有序列表、引用块、分隔线
- **必须支持的行内**（同 S1-2）
- **明确不支持**（本版）：表格、嵌套列表、图片、引用式链接、setext 标题、缩进代码块、行内 HTML 透传
- **参考行为**：TinyPage 的 mistune 是 `escape=True` ⇒ **源码里的 HTML 一律转义**，本实现必须保持（安全语义）
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_md.wll
  ```
  + 规模测试（对应 `tp/probe/md_proto.wll`）：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\bench_md.wll
  ```
  期望：40KB 文档 ≤ 600ms（原型实测 324–427ms，留 40% 余量）；输出**两次一致**
- **反向守卫**：
  - 代码块内的 `# 不是标题` ⇒ **不得**生成 `<h1>`
  - 代码块内的 `**粗体**` ⇒ **不得**被转成 `<strong>`
  - 递归深度 ≤ 1500（F1 上限 2000，留余量；本卡不应需要深递归）
  - 块级状态机遇到未闭合围栏 ⇒ 必须闭合而非吞掉剩余全文
- **非目标**：不做 CommonMark 全覆盖；不做表格/嵌套列表（本版明确放弃，§1.2）

#### 卡 S1-4：front-matter / TOC / 脚注 / wikilink

- **依赖**：S1-3
- **交付物**：`frontmatter.wll`、`toc.wll`、`footnotes.wll`、`wikilink.wll`
  + **`esc.wll`（本轮新增的共享地基）** —— 三个模块都要输出「对齐 Python
  `html.escape(quote=True)`」的 HTML，只留一份实现（见 §0.2「共享工具」）。
- **行为对齐点**（逐条照搬 Python 语义，**不改数据格式**）：
  - 元数据：只读**前 7 行**；键白名单 `title/date/slug/tags/summary/category/status/markdown`；多余键静默忽略
  - 元数据写回：`html.escape(quote=True)` 等价 + **连续** `\r`/`\n` 序列压成**一个**空格（`re.sub(r"[\r\n]+", " ", v)`，注意 `+` ⇒ 不是每行一个空格）
  - TOC：正则 `^(#{1,6})\s+(.+)$`；slug = 删非 `[a-zA-Z0-9\u4e00-\u9fa5\s]` → 空白转 `-` → 小写；**重复加 `-2`/`-3`**；默认层级 2–3
  - 脚注：定义 `\[\^([^\]]+)\]:\s*(.+)$`（**无行首锚定** ⇒ 行中间的定义也会被识别；`(?m)` 使 `$` 落在行尾、`.` 不跨行 ⇒ **只取第一行**）；引用 `\[\^([^\]]+)\]` + 手工跳过冒号后随（**WLWL 无前瞻**，见 §2.1 F10）；渲染前替换
  - wikilink：`[[标题]]` / `[[标题|显示]]`，渲染前替换为标准 Markdown 链接
- **⚠ 实测发现的与 Python 差异（已登记，非缺陷）**：
  - **脚注顺序**：Python 用 `set` 收集键 ⇒ `build_footnotes_html` 的 `<li>`
    顺序**跨进程不确定**（父进程实测 5 次运行给出 4 种顺序）⇒ 逐字节对照无法
    依赖它。WLWL 侧取**定义出现顺序**（确定性），基准序列化前重排。
  - **`\w`**（§2.1 F12）：只影响 wikilink 的 slug；该路径复用 S1-2 已交付并已
    测试的 `md_inline.wll::WIKILINK_TARGET`，不重写 slug 规则。
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_esc.wll
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_frontmatter.wll
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_toc.wll
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_footnotes.wll
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_wikilink.wll
  ```
- **反向守卫**：
  - 元数据第 8 行的键 ⇒ **不得**被读入
  - 两个同名标题 ⇒ slug 必须是 `x` 与 `x-2`，**不得**都是 `x`
  - 脚注定义含换行 ⇒ 只取第一行（对齐 Python）
  - 单引号必须出 `&#x27;`（不是内建的 `&#39;`）
- **非目标**：不做 YAML front-matter（保持现有私有格式）
- **✅ 实测状态（2026-11-02 完成）**：四模块 + `esc.wll` 全部由 4 个 worker 并行交付
  （文件级互斥），父进程逐个独立复跑核验：

  | 模块 | 构成 | 读数 |
  |---|---|---|
  | `esc.wll` | 17 基准 + 2 守卫 | **19/19**，exit 0 |
  | `frontmatter.wll` | 33 基准 + 5 守卫 | **38/38**，exit 0 |
  | `toc.wll` | 34 基准 + 7 守卫 | **41/41**，exit 0 |
  | `footnotes.wll` | 17 基准 + 6 守卫 | **23/23**，exit 0 |
  | `wikilink.wll` | 22 基准 + 6 守卫 | **28/28**，exit 0 |

  本地 CI 5 步全过：21 生成器 / 21 产物无 drift、静态检查、15 文件 `wlwl check`、
  反向守卫、8 个测试文件全绿。
- **🔧 本卡揪出并修复的上游真 bug（S1-2 交付物）**：
  `gen_md_inline.py` 的 `trim_dashes` **尾部循环条件写反** —— 写成
  `WHILE(&&(>(start, end), …))`，而 `start` 从 0 起、`end = LEN(s)` ⇒ `start > end`
  **恒为假** ⇒ 尾部 `-` **一次都没裁过**（首部条件 `<(start, end)` 是对的）。
  - 影响面：`WIKILINK_TARGET` 与 `INLINE_WITH_MAP` **两个导出**（不是 wikilink 单点）。
  - **为什么此前 21 条测试没抓到**：所有用例的标题都不以非词字符结尾 ⇒ 测试盲区。
  - 修复：条件改 `<(start, end)`，重生成 md 系列产物；**新增回归用例**
    `wiki/slug_strips_both_ends`（4 条断言，期望值取自真 Python `slugify_for_link`）
    钉住双向裁剪，盲区不再复发。
  - 连带影响：`café` 的 wikilink 差异钉值由 `/article/caf-.html` 更新为
    `/article/caf.html`（`\w` 口径差异本身仍在，只是尾 `-` 现在被正确裁掉）。

### S2 内容模型与生成器

#### 卡 S2-1：文章存储与原子写

- **依赖**：S1-4
- **交付物**：`tp/lib/article_store.wll`
- **必须实现**：文件名校验 `^\d{4}-\d{2}-\d{2}-[a-zA-Z0-9\u4e00-\u9fa5-]+\.html$` + 日期范围；
  标题长度 ≤200；内容长度上限 50000 字符；写 `.md` 源 + `WRITE_FILE_ATOMIC` 写 `.html`；
  删除时的**备份-校验-回滚**；路径穿越防护
- **路径安全**（对齐 Python 的 `resolve()` + `is_relative_to()`）：
  WLWL 的 `PATH_CANONICAL`/`PATH_CONTAINS` 是**词法**判定（不解析符号链接）⇒
  **额外**要求：拒绝路径中含 `..` 的输入，并对最终路径做规范化后再比对
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_article_store.wll
  ```
- **反向守卫**：
  - `../etc/passwd` 形态的 slug ⇒ 必须被拒
  - `pages-evil/x.html` 形态（Python 注释里记过的前缀绕过）⇒ 必须被拒
  - 写入中途失败 ⇒ 不得留下半截 `.html`
- **非目标**：不做数据库、不做并发写入协调（单进程单写者）
- **🔎 Python 侧权威落点（2026-11-02 核查，基准生成器照此 import）**：
  | 校验项 | 权威函数 | 位置 | 精确规则 |
  |---|---|---|---|
  | 文件名 | `validate_filename` | `tinypage/security.py:228` | 先过 `SAFE_FILENAME_PATTERN`（`security.py:22`：`^\d{4}-\d{2}-\d{2}-[a-zA-Z0-9一-龥-]+\.html$`），**再**按 `-` 切分取前 3 段 → `2000<=year<=2100 and 1<=month<=12 and 1<=day<=31` |
  | 标题 | `content.py:270` | `tinypage/content.py:270` | `len(title) > 200` ⇒ 拒绝（**200 合法，201 拒绝**） |
  | 正文 | `validate_content` | `tinypage/security.py:256` | `len>50000` 拒；`len(utf8字节)>50000*4` 拒；**控制字符占比 >10% 拒**（`ord(c)<32` 且非 `\t\n\r`） |
  | 日期串 | `validate_date_format` | `tinypage/security.py:243` | `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$` **且** `strptime` 成功 **且** `2000<=year<=2100` |
  | 路径 | `safe_path_check` | `tinypage/security.py:269` | `resolve()` + `is_relative_to()`（**不是字符串前缀**）⇒ `pages-evil` 绕过已被 Python 修掉；扩展名白名单 `.html/.xml/.json/.txt/.js/.css/.png/.jpg/.jpeg/.gif/.svg/.ico/.woff2` |
  | 元数据值 | `meta_value` | `tinypage/core/article_store.py:90` | **复用 S1-4 的 `frontmatter.wll`**（已实现），不重写 |

  ⚠ **两处 Python 侧既存缺陷，重写时不要"顺手修好"，按现状对齐**：
  ① `validate_filename` 的日期只查 `1<=day<=31`，**不查当月天数** ⇒ `2026-02-31-x.html`
  **合法**。逐字节对齐必须接受这一点。
  ② `tinypage/core/article_store.py` 里 `_unescape_to_fixpoint` **定义了两次**
  （132–150 行与 152–169 行，内容相同）⇒ 是冗余不是两套语义。
- **🔎 写入/删除的完整流程（2026-11-02 核查，`write_article` 在 `content.py:241`）**：
  - **校验顺序**（`content.py:268-275`，顺序即报错先后）：
    `validate_filename(fname)` → `len(title)>200` → `validate_content(content)` →
    `validate_date_format(date)` → 路径穿越检查。
  - **路径检查**（`content.py:278`）：`path.resolve().relative_to(article_dir.resolve())`
    —— 抛 `ValueError` 即穿越。**注意**：WLWL 的 `PATH_CANONICAL`/`PATH_CONTAINS`
    是词法判定（**消解 `..`，但不解析符号链接**）⇒ 额外要求「拒绝含 `..` 的输入」+
    「规范化后再比对」。
  - **🔎 `PATH_CONTAINS` / `PATH_CANONICAL` 的实测语义（父进程独立实测，wlwl 0.12.1）**：
    | 调用 | 结果 |
    |---|---|
    | `PATH_CONTAINS("pages", "pages-evil")` | **FALSE** ⇒ 天然挡住「同前缀兄弟目录」绕过 |
    | `PATH_CONTAINS("pages", "pages-evil/x.html")` | **FALSE** |
    | `PATH_CONTAINS("pages", "pages/a.html")` | TRUE |
    | `PATH_CONTAINS("pages", "pages/../etc/passwd")` | **FALSE** |
    | `PATH_CONTAINS("pages", "etc/passwd")` | FALSE |
    | `PATH_CANONICAL("pages/../etc/passwd")` | `etc/passwd` ⇒ **确实消解 `..`** |
    | `PATH_CANONICAL("pages/./a.html")` / `PATH_CANONICAL("pages//a.html")` | `pages/a.html`（两者都归一） |

    ⇒ **反向守卫 `pages-evil/x.html` 靠 `PATH_CONTAINS` 本身就能挡住**（不需要额外字符串前缀判断）。
    ⇒ 但「拒绝含 `..` 的**输入**」这条仍要保留：`PATH_CONTAINS` 是在**规范化之后**判定的，
    规范化会把 `pages/../etc` 变成 `etc`（落在 base 外 ⇒ FALSE，安全），
    但**规范化本身**不应替代「输入侧就拒绝 `..`」的显式检查（防御深度）。
  - **🔎 `WRITE_FILE_ATOMIC` 的实测语义（父进程独立实测）**：
    | 项 | 读数 |
    |---|---|
    | 签名 | `WRITE_FILE_ATOMIC(path, content)` |
    | 成功返回 | **NULL**（不是 `TRUE`） |
    | 失败返回 | **ERR**（`FsError`，kind=`FsError`，op=`WRITE_FILE_ATOMIC`，reason 形如 `cannot write (<path>): parent directory does not exist`）⇒ **未消费即 `E0103`「unhandled ERR was discarded」**（F8） |
    | 是否留临时文件 | **不留**（写完目录里只有目标文件，无 `.tmp` 残留） |
    | 覆盖写 | 正常（内容被替换，长度可变） |
    | 父目录不存在 | **失败**（**不会自动建目录**）⇒ 写入前必须先 `MKDIRS` |
    | `FILE_META` | `{exists, is_dir, mtime, mtime_http, size}` ⇒ `size` 为写入后的字节数 |
  - **渲染管线顺序**（`content.py:283-305`，S1 四个模块的接线点，**不能调换**）：
    ```
    process_footnotes(content)          -> (processed_content, footnotes_html)
    extract_headings(processed_content) -> headings
    build_toc_html(headings)            -> toc_html
    parse_bidirectional_links(...)     -> (processed_content, found_links)
    render_markdown(processed_content)  -> html_body
    add_heading_ids(html_body, headings)-> html_body
    highlight_code_blocks(html_body)    -> html_body
    ```
    ⇒ 这四个模块正是 S1-4 刚交付的 `footnotes.wll` / `toc.wll` / `wikilink.wll` /
    `md.wll`（`render_markdown`）+ `md_inline.wll`（`highlight` 相关）。
  - **删除的备份-校验-回滚**（`content.py:122` `delete_article`）：
    ① `copy2` 到 `.html.backup`；② `.md` 源存在则 `copy2` 到 `.md.backup`；
    ③ 删 `.html`；④ 删 `.md`（若原本存在）；⑤ **校验 `.html` 已不存在**，
    否则抛 `OSError("File deletion verification failed")`；
    ⑥ 删两个 backup；**任何异常 ⇒ 把 backup 移回原位并向上抛**。

- **✅ 实测状态（2026-11-02 完成，父进程独立复跑核验）**：
  | 项 | 读数 |
  |---|---|
  | `wlwl check tp/lib/article_store.wll` | `OK: parsed`（~20KB），exit 0 |
  | `wlwl run tp/test/test_article_store.wll` | **277/277**，failed=0，末行 `test_article_store: OK`，exit 0 |
  | 导出面（11 个） | `VALIDATE_FILENAME` / `VALIDATE_CONTENT` / `VALIDATE_DATE_FORMAT` / `VALIDATE_TITLE` / `SAFE_PATH_CHECK` / `SOURCE_PATH` / `WRITE_SOURCE` / `DECODE_CONTENT` / `DECODE_LEGACY_BODY` / `UNESCAPE_TO_FIXPOINT` / `META_VALUE`（后者**复用** `frontmatter.wll`） |
  | 基准来源 | **直接 import 真 Python**：security / content / core.article_store 共 11 个函数，**246 条**用例（11 组） |
  | 已知差异（已登记在夹具 `note`） | **D2** 文件名 `\d` 认 Unicode 数字（WLWL 拒）／**D3** 含 `..` 的输入（WLWL 故意更严）／**D4** 日期**年位置**的 Unicode 数字（WLWL 拒：`TO_INT` 不接受、`NFKC` 也不归一） |
  | 反向守卫（5 条） | `../etc/passwd` 拒／`../pages-evil/x.html` 拒／`sub/../ok.html` 拒（D3）／写入失败不留半截文件／原子写不留 `.tmp` |
  | 实现要点（实测） | `RE_TEST` 整串锚定 ⇒ 用 `$` 处先剥结尾单个 `\n`；正则 `\xNN`/`\.` 是**字面**字符 ⇒ 用字符类 `[.]`；无 `ORD`/`CHR` ⇒ 控制字符靠 `UTF8_DECODE` 造字符逐个比；`LET(r,<ERR>)` 不算消费 ERR（E0103 报在绑定行）⇒ ERR 就地进 `IS_ERR(...)`；`PATH_JOIN` 对绝对路径只拼接 |
  | 本地 CI | 5 步全过（21 生成器无 drift / 19 个 `.wll` check 过 / 反向守卫 / 10 个测试文件全绿） |

#### 卡 S2-2：手写排序（替代 `SORT`）

- **依赖**：S2-1
- **交付物**：`tp/lib/sort_util.wll`，导出 `SORT_BY_DATE(items)` / `SORT_STRINGS(items)`
- **理由**：C2 —— `SORT` 在 500 元素就要 6.1s，1000 元素 28.2s
- **实现要求**：**归并排序**（稳定、可比较自定义键），不得用 `SORT`
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_sort_util.wll
  ```
  期望：对 2000 个随机日期字符串，排序耗时 **≤ 200ms**（`SORT` 在此规模需数分钟）
- **反向守卫**：
  - **静态检查**：`tp/lib/` 下 grep 不到 `SORT(` / `SORT_BY(` ⇒ 违反即失败
    ⚠ 但本卡导出的 `SORT_BY_DATE` / `SORT_STRINGS` **本身就含 `SORT_BY` 子串** ⇒
    守卫必须用能区分「调用内建 `SORT`/`SORT_BY`」与「自己导出的函数名」的精确
    模式（如 `\bSORT_BY\(` 会误伤 `SORT_BY_DATE(`，需另行处理）。
  - 排序 2000 元素耗时若 > 1s ⇒ 说明误用了 `SORT`
    ⚠ CI 机器可能比本地慢 ⇒ 守卫阈值放宽到 **2s**（仍远小于 `SORT` 在 2000
    元素的数分钟），本地实测值另行记录。
    ✅ **实测后调整为 5000ms**（理由见下方「实测状态」第 4 点）。
- **✅ 实测状态（2026-11-02 完成，父进程独立复跑核验）**：
  | 项 | 读数 |
  |---|---|
  | `wlwl check tp/lib/sort_util.wll` | `OK: parsed`，exit 0 |
  | `wlwl run tp/test/test_sort_util.wll` | **39/39**（36 基准 + 3 守卫），failed=0，末行 `test_sort_util: OK`，exit 0 |
  | 导出面（4 个） | `SORT_BY_DATE`（日期倒序，稳定）/ `SORT_STRINGS`（码点升序，稳定）/ `SORT_BY_TITLE_OR_FILE`（`title or file` 升序，稳定，缺口 A）/ `SORT_BY_NUM_DESC`（数值键倒序，稳定，缺口 B） |
  | 元素形态 | `SORT_BY_DATE` 接受 `ARRAY[DICT{"date":…}]` **或** `ARRAY[STRING]`（可混排）；`SORT_STRINGS` 接受 `ARRAY[STRING]`；`SORT_BY_TITLE_OR_FILE` 接受 `ARRAY[DICT{"title","file"}]`；`SORT_BY_NUM_DESC` 接受 `ARRAY[ARRAY[payload, number]]`（键取元素[1]，INTEGER/FLOAT 均可） |
  | 基准来源 | **每个导出两个互相独立的 Python 来源**：① Python 内建 `sorted`；② 真项目函数 —— `list_articles()`（日期）/ `list_standalones()`（缺口 A，`content.py:698` 的 `title or file`）/ `find_related_articles()`（缺口 B，`content.py:237` 的 Jaccard 倒序） |
  | 缺口 A/B 覆盖 | 各 **7 条**（空数组/单元素/基本/空标题回落文件名/相等键稳定性/非 ASCII/真项目函数）；缺口 A 的 B 类来源**真实造了空标题与无 title 注释**的独立页，确保「空串回落」被验到 |
  | 静态检查器 | `paren_check` / `check_semis` / `check_c_args`（三个生成器）全过 |
  | 本地 CI | 5 步全过（生成器无 drift、19 个 `.wll` 全 check 过、反向守卫、10 个测试文件全绿） |

  1. **日期键只取前 16 字符**（对齐 `content.py:185` 的 `meta.date[:16]`，分钟精度）。
     原因不是偷懒：若比较整串（可能带秒），同一分钟内带秒的两篇文章两侧顺序会不同 ⇒ 逐字节对照会红。
  2. **稳定性**：归并时相等键**取左半**（升序 `<=`、降序 `>=`）⇒ 与 Python `sorted`（含 `reverse=True` 保持稳定）一致。
     2000 元素用例里只有 398 个不同日期、1985 个元素共享日期 ⇒ 若不稳定，逐字节对照**必然红**。
  3. **性能**：本地实测 2000 元素 **649ms**（4 次连跑 629–881ms），**未达卡片原定的 200ms 目标**。
     根因不是归并算法，而是 **§2.1 F18：读数组绑定会深拷贝 ⇒ `AT`/`LEN` 是 O(n)** ⇒ 数组路线在本解释器里理论下界约 300–450ms。
     对比：内建 `SORT` 在 2000 元素约 **113s**（1000 元素实测 28.2s 二次外推）⇒ 本实现**快约 170 倍**，
     C2 的决策目标（「500 篇以上不让构建卡到分钟级」）**已达成**。
  4. **CI 守卫阈值定 5000ms**：本机 649ms，CI 按慢 3–5 倍算约 2–3.3s，留 1.5–2.5 倍余量；
     同时比 `SORT` 的约 113s **低 22 倍** ⇒ 误用 `SORT` 必被抓住（守卫语义成立）。
  5. **「无内建 SORT」守卫的实现**：放在 `gen_test_sort_util.py` 的**生成期**（⇒ CI 的「重跑生成器 + 要求无 drift」那步就会红，**不需要改 CI 配置**），
     扫 `tp/lib/*.wll`，模式 `\bSORT\b|\bSORT_BY\b`（**整词**）且**先剥掉 `//` 行注释**。
     不误伤自己的导出名：`SORT_BY_DATE` / `SORT_STRINGS` 里 `SORT` 后紧跟 `_`（词字符）⇒ **不构成词边界**。
     挡得住内建调用：`SORT(x)` / `SORT_BY(x,f)` 的 `SORT` 前后是 `(`/空格 ⇒ 构成词边界；连 `IMPORT(…, ["SORT"])` 里的字符串 `"SORT"`（引号非词字符）也命中 ⇒ **导入也算用**。
     已用正例单测（10/10）与端到端负例（临时放一个含内建 `SORT` 的 `.wll` ⇒ 生成器 exit=1）验证。
  6. **已登记缺口（首轮交付时登记 → 2026-11-02 已安排补齐，不留给 S2-4）**：
     ① **页面按标题排**（`content.py:698` `pages.sort(key=lambda x: x.title or x.file)`）
     —— `list_standalones()` 被 `cli.py` build、`generate_static_pages`、**admin 的每个动作**调用 ⇒ 在 S2-4 必经路径上。
     ② **按数值键排序**（`content.py:237` Jaccard 相似度倒序）—— `find_related_articles()` 在 `content.py:606` 生成文章页「相关文章」时必经。
     ⇒ **两处都在 S2-4 路径上** ⇒ 已另派一轮在 `sort_util.wll` 上补
     `SORT_BY_TITLE`（`title` 为**空串也回落** `file`，对齐 Python `or` 语义）与
     `SORT_BY_NUMBER`（数值倒序、相等键稳定），**不留给 S2-4 跨卡返工**。
     （另一处数值排序 `core/ai_assistance.py:258` 词频属卡 S5，本轮不要求。）
  7. **已知差异**：日期串**格式非法**时，Python `list_articles` 会 `strptime` 失败并**整篇丢弃**
     （`content.py:186-187`），而排序函数不校验格式、按字面码点比较 ⇒ **不可达**（写入侧
     `validate_date_format` + `content.py:274` 已拦），已登记不修。
- **非目标**：不做通用排序框架，只做项目需要的两种
- **⚠ 若业主仍要求 ≤200ms**：需**另开一张卡 S2-2b「链表版归并排序」**并明确授权引入 OOP 范式
  （实测 `SET_PROP` 只能作用于 `self` ⇒ `E0032`，OOP 路线受限）。**本卡未擅自走这条路。**
- **🔎 Python 侧真实用法（2026-11-02 核查，3 种形态，不止卡片写的 1 种）**：
  | 位置 | 排什么 | 键 | 方向 |
  |---|---|---|---|
  | `tinypage/content.py:196` | 文章列表 | `x.date_obj or datetime.min` | **倒序** |
  | `tinypage/content.py:698` | 独立页列表 | `x.title or x.file` | 正序 |
  | `tinypage/generator.py:684`、`tinypage/admin/views.py:133` | 分类名（去重集合） | 字符串本身 | 正序 |

  ⇒ **`SORT_BY_DATE` 的「date」不是「日期字符串」而是「datetime 对象」**
  （卡片原文写「随机日期字符串」是简化说法）。WLWL 侧需定一个可承载的形态：
  以**排序键字符串**（如 `YYYY-MM-DD HH:MM:SS`）为准最直接，但必须与 Python
  `date_obj` 的**缺失回落 `datetime.min`** 语义对齐（缺失项排最后，因倒序）。
  ⇒ 另有「键可能为 None」的形态（`title or file`），须有确定的回落规则。
- **非目标**：不做通用排序框架，只做项目需要的两种

#### 卡 S2-3：模板与主题

- **依赖**：S2-1
- **交付物**：`tp/lib/template.wll`、`tp/lib/theme.wll`
- **必须实现**：
  - 页面骨架（对齐 `core/template.py`）：DOCTYPE/head（charset/viewport/color-scheme/pwa/vt/description/og/json-ld/manifest/title）
    + 内联 `<style>` 主题 CSS + body(header/nav/main/footer) + 尾部脚本
  - 暗色模式：`theme.dark.css` 包进 `<style media="(prefers-color-scheme: dark)">` + 内联脚本读写 `localStorage.theme`
  - 主题清单：`themes/{name}/manifest.json`（`name/version/description/layouts/variables`）
  - 主题 CSS 只读 `theme.css` / `theme.dark.css`
- **对齐点**：Python 用 `substitute()`（**缺键即错**）vs 后台模板用 `safe_substitute`（缺键留 `$var`）——
  两套语义**要分别实现**，不要合并成一个
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_template.wll
  ```
- **反向守卫**：
  - 缺占位符 ⇒ 前台模板必须**报错**，不得静默留 `$var`
  - 主题名 `../../etc` ⇒ 必须被拒（Python 侧有此缺陷，见 §2.7 与 §5 R4）
- **非目标**：不做模板继承/局部模板（Python 侧也没有）
- **🔎 Python 侧权威落点（2026-11-02 核查，S2-3 开工前必读）**：
  - `render_skeleton` 在 `tinypage/core/template.py:52`，模板常量 `_PAGE_SKELETON`（同文件 1–49 行）。
  - **19 个占位符**（`template.py:109-130` 的 `substitute(...)` 实参，顺序即模板变量名）：
    `page_type` / `lang` / `site_title` / `page_title` / `description` / `dark_mode_meta` /
    `pwa_meta` / `vt_meta` / `og_html` / `json_ld_html` / `pwa_manifest` / `theme_css` /
    `dark_css_block` / `dark_mode_script` / `nav_links` / `theme_toggle` / `footer_text` /
    `body_content` / `search_script` / `mermaid_script`
    （其中 `dark_css_block` 是**派生占位符**，不是入参：`template.py:104-107`
    由 `dark_css` 计算 `<style media="(prefers-color-scheme: dark)">…</style>`，空则空串。）
  - **哪些值被 escape**：只有 `lang`/`site_title`/`page_title`/`description` 被
    `escape_html`（用 S1-4 的 `esc.wll::ESCAPE_HTML`），且 `footer_text` 是
    **条件 escape**（`template.py:126`：空则空串，否则 escape）。
    `body_content`/`theme_css`/`nav_links`/`*_script`/`og_html` 等**不 escape**
    （它们是已构造好的 HTML 片段）。
  - **两套语义必须分开实现**：
    ① 前台 `substitute()`（`template.py:109`）⇒ **缺键即 `KeyError`**；
    ② 后台 `safe_substitute()`（另一处调用）⇒ **缺键留 `$var` 原样**。
    ⇒ WLWL 侧要实现**两个**替换函数，**不要**合并成一个。
  - `substitute` 语义细节：`$var` 与 `${var}` 两种写法都支持；`$$` 转义成字面 `$`。
  - **🔎 主题加载的两个必踩点（父进程 2026-11-02 实测）**：
    ① **CRLF 必须自己归一化**（§2.1 F22）：`themes/default/theme.css` 是 **20326 bytes /
       805 个 CRLF**；Python `load_theme_css` 用 `read_text()` ⇒ **19517 字符（无 CR）**，
       而 WLWL `READ_FILE` ⇒ **20322 字符（有 CR）** ⇒ **差 805**。
       ⇒ WLWL 侧读 CSS 后**必须自己做 CRLF→LF**，否则与 Python 逐字节对照必红。
       （`theme.dark.css` 同样：520 bytes / 20 CRLF。）
    ② **Pygments CSS 追加那段不迁**：`generator.py:141-149` 的 `load_theme_css` 会
       `base_css + "\n/* Pygments syntax highlighting */\n" + pygments_css`。
       但 **D3 裁决「代码高亮改前端 highlight.js」** ⇒ 这段**不迁**，
       WLWL 侧只输出 `theme.css` 原文（归一化后）+ `theme.dark.css` 原文。
       ⚠ 这一条会让「与 Python 版产物逐字节相同」**不成立** ⇒ 属**预期差异**，
       基准里要显式标注，别当成 bug 去"修"。
  - **主题清单实际形态**（`themes/default/manifest.json`）：字段为
    `name` / `version`（如 `3.1.0`）/ `description` / `layouts`（数组，如 `["blog"]`）/
    `variables`（对象，如 `{"primary": "#a3e635", "accent": "#22c55e"}`）——
    与卡片写的 `name/version/description/layouts/variables` 一致。
  - **🔎 范围边界（2026-11-02 裁，避免两块地无人认领）**：本卡的「暗色模式」只做
    **`dark_css_block` 那个派生占位符**（`template.py:104-107` 把 `dark_css` 包进
    `<style media="(prefers-color-scheme: dark)">`）。下面这些是 `generator.py:99-115`
    里拼好的 **HTML 片段常量**，它们作为**入参**喂给 `render_skeleton` ⇒
    **归卡 S2-4**，不在本卡：
    `dark_mode_meta`（`<meta name="color-scheme" …>`）、`dark_mode_script`（读
    `localStorage.theme` 的内联 `<script>`）、`theme_toggle`（🌓 按钮 + 写
    `localStorage.setItem('theme', …)`）、`pwa_meta` / `pwa_manifest` / `vt_meta` /
    `search_script`、以及 `nav`（`_nav_links`）。
    ⇒ 本卡只需保证「传进来什么就原样嵌入什么、**不 escape**」。

- **✅ 实测状态（2026-11-02 完成，两个并行 worker 交付 + 父进程独立复核）**：
  | 项 | 读数 |
  |---|---|
  | `tp/lib/template.wll` | 导出 `SUBSTITUTE` / `SAFE_SUBSTITUTE` / `RENDER_SKELETON`；`wlwl check` OK（20345 B） |
  | `tp/lib/theme.wll` | 导出 `VALIDATE_THEME_NAME` / `LOAD_THEME_CSS` / `LOAD_THEME_MANIFEST` / `LIST_THEMES`；`wlwl check` OK（11271 B） |
  | `wlwl run tp/test/test_template.wll` | **162/162**，failed=0，exit 0（基��� 156 条：substitute 69 / safe_substitute 69 / render_skeleton 18） |
  | `wlwl run tp/test/test_theme.wll` | **68/68**，failed=0，exit 0（基准 33 条：名校验 14 / CSS 8 / 清单 7 / 列表 4） |
  | **父进程独立逐字节复核** | 用**真 Python 另算**的四组 `render_skeleton` 输出与 WLWL 产物比 SHA256：`minimal` 554 字符 `f9604f0d…` / `with_dark` 572 `3a5ca7bd…` / `escaped` 574 `31ec6a9f…` / `empty_footer` 513 `c5d7ac1e…` ⇒ **四组全 MATCH**（这条不依赖 worker 的夹具，是独立证据） |
  | **父进程独立复核主题** | 对**真实** `themes/default` 实测：`css_len=19517`、`css_CR_hits=0`、`dark_len=498`、`has_dark=TRUE`、`manifest` 解析出 `name=default`、`../etc` 返 `NULL`（D5）、`LIST_THEMES` 给 1 个 ⇒ 与 Python `read_text` 的字符数逐项吻合 |
  | escape 口径（最关键的一条） | 四组渲染里 `site_title=A & B` / `page_title=<tag>` / `description=q"q'q` / `lang=en"US` / `footer_text=F & G` 全部被 escape；而 `body_content` 的 `RAW & <b>` **原样保留** ⇒ 证明只有那四个 + footer 被转义 |
  | `Template` 边界 | `$$`→`$`；缺键 strict 版返 ERR（对齐 Python `KeyError`）、safe 版留 `$x`；`$` 与 `$ a` 两种非法占位符 strict 版返 ERR、safe 版原样；`$a1/$_b/${c}` 全通过；`$1x` 按非法处理 |
  | 幂等 | 五个生成器重跑两次，五个产物 SHA256 全等；全仓 step1（27 生成器重跑）**无漂移** |
  | 生成期自检 | `gen_template_baseline.py` 断言骨架字面量 `== _PAGE_SKELETON`（抄错或上游漂移立刻炸）；`ValueError` 的 `pos` 由 CPython 消息反推后逐条校验 `tmpl[pos] == '$'` |
  | 已知差异（夹具 `note` + `_meta.known_differences`） | **D5** 主题名校验 WLWL 更严（Python 无此校验）／**D6** `LIST_THEMES` 固定名称升序（Python `iterdir` 顺序不可复现）／**D7** 不追加 Pygments CSS（D3 裁决）／**D8** mapping 值**非字符串**时的渲染口径：`NULL`⇒`"NULL"`（Python `"None"`）、`TRUE`⇒`"TRUE"`（Python `"True"`）、字典⇒`[k: 1]`（Python `"{'k': 1}"`）—— 根因是宿主 `str()` 口径，与 `Template` 语义无关（标量与整数/浮点完全一致） |
  | 反向守卫 | 缺占位符 ⇒ 前台 `SUBSTITUTE` 返 ERR（不静默留 `$var`）；主题名 `../etc` 形态必须被拒；`_` 读出的 CSS **不含 CR**；`LIST_THEMES` 逆序建目录后仍按名升序 |
  | 变异测试 | 去掉 `site_title` 的 escape ⇒ 变红 + PANIC + exit 1；标识符首字符放宽到数字 ⇒ 3 条精确变红；把换行归一退化成「只替 CRLF」⇒ `c05` 变红 ⇒ 证明断言不是空转 |

#### 卡 S2-4：站点产物生成

- **✅ 实测状态（2026-11-02 完成；交付物由计划的 3 个模块拆成 5 个，理由见下）**：
  | 模块 | 导出 | 测试 | 基准 |
  |---|---|---|---|
  | `tp/lib/page_common.wll`（**新增，计划的隐藏前置**） | `JSON_LD` / `NAV_LINKS` / `COMMON_CONTEXT` | **42/42** | 15 条 |
  | `tp/lib/article_page.wll` | `ARTICLE_PAGE` / `STANDALONE_PAGE` | **33/33** | 26 条 |
  | `tp/lib/list_page.wll` | `LIST_PAGE` / `CATEGORY_PAGE` / `SEARCH_PAGE` | **21/21** | 15 条 |
  | `tp/lib/feeds.wll` | `RSS` / `SITEMAP` / `ROBOTS` | **30/30** | 23 条 |
  | `tp/lib/search_index.wll` | `SEARCH_INDEX` | **29/29** | 12 条 |
  | **合计** | 10 个导出 | **155 个断言，全部 failed=0、exit 0** | 91 条基准 |

  **为什么拆成 5 个而不是卡片的 3 个**：`generator.py` 的 `build_json_ld` / `_nav_links` /
  `_build_common_context` 被 **5 个页面函数共用**。若让并行 worker 各写一份，必然漂移
  （正是 §0.2 第 6 条要防的）⇒ 单独抽成 `page_common.wll` 作为共享前置，其余模块只 import、不重写。
  另外 `generator.wll` 一拆为二（`article_page` / `list_page`）是**为了让 4 路并行拥有互不重叠的文件所有权**。

  | 其他读数 | 值 |
  |---|---|
  | 本地 CI | 5 步全过：**33 个 `.wll` check** / **17 个测试文件全绿** / 27 个生成器重跑无 drift |
  | 幂等 | 5 个模块的生成器各自重跑，产物 SHA256 全等 |
  | 父进程独立核验 | `page_common` 用**真 Python 另算**的 ctx 12 字段 / JSON-LD 三组 / nav 两组，与 WLWL 产物逐字节 MATCH（不依赖 worker 的夹具） |
  | 变异测试 | 各模块都做了：改空格数、关草稿过滤、放宽标识符、退化换行归一 ⇒ 都能让对应用例变红并使退出码为 1 |
  | 反向守卫合计 | 24 条（含「`title` 必转义而 `content` 不转义」的对照组、`site_url` 空时不得有 `ld+json`/`og:title`/`share-btn`、RSS 不得有裸 `&`、sitemap 不得有 `lastmod`/`changefreq`、`SEARCH_INDEX` 草稿**必须**原样通过） |

  **⚠ 两条已知缺口（未修，已登记，附现成修法）**：
  1. **`tags` 的 strip 口径**：WLWL 内建 `TRIM` 只剥 **ASCII** 空白，Python 的 `str.strip()`
     还剥 U+3000 / U+00A0 / U+0085 / U+2000–200A / U+2028–2029 / U+202F / U+205F。
     ⇒ `list_page.wll` 与 `search_index.wll` 的 tags 在**含非 ASCII 空白**时会与 Python 不同
     （`article_page.wll` **已修**：自建 `PY_WS()` 用 `RE_REPLACE` 两侧剥 Unicode 空白集合，用例 `a12` 钉住）。
     **修法**（已排除其他选项）：照抄 `article_page.wll` 的 `PY_WS()` 换掉那两处的 `TRIM`，
     各加一条 `tags="\u3000a\u3000, \xa0b\xa0"` 用例；属**行为变更**，须单独一轮做并全量复跑。
  2. **`RSTRIP_SLASH` 有三份**（`page_common.wll` 私有、`article_page.wll`、`feeds.wll`）：
     `page_common` 的那份**未导出**，而契约只允许它导出三个函数 ⇒ 各自自带 8 行。
     **可接受的依据**：三处行为都被各自的逐字节用例钉住，漂移必红，不存在静默分叉；
     若将来要收敛，让 `page_common` 导出 `RSTRIP_SLASH` 再改两处 import 即可。

#### 卡 S2-4（原卡片正文，交付物已按上文拆分）

- **依赖**：S2-2、S2-3
- **交付物**：`tp/lib/generator.wll`、`feeds.wll`、`search_index.wll`
- **产物清单**（与 Python 侧对齐）：
  `index.html`、`list/{n}.html`、`article/*.html`、`standalone/*.html`、`category/{cat}.html`、
  `search.html`、`rss.xml`、`sitemap.xml`、`robots.txt`、`search-index.json`
- **语义对齐点**：
  - 搜索索引字段 = `title/summary/url/date/tags/category`，**不含正文**；草稿不进索引
  - RSS 最多 20 条、排除草稿；`<pubDate>` 沿用现有 `iso_date` 形式（**不追求 RFC822 严格性**，与现状一致）
  - sitemap 无 `lastmod`/`changefreq`（与现状一致）
  - JSON-LD 仅当 `site_url` 非空
  - 分页 `page_size` 默认 10；第 2 页 `prev_url` 指向 `/`
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\bin\build.wll
  ```
  期望：退出 0；`pages/` 下生成上述产物；**人工比对**与 Python 版产物结构
- **反向守卫**：
  - 构建后 `git status` **不得**出现非预期产物（只允许 §3.2 列出的路径）
  - 生成 100 篇 → 耗时 ≤ 60s（按 0.3ms/行推算）
- **⚠ 卡片措辞与源码分层的两处冲突（2026-11-02 实测 + 父进程读源码复核；以源码为准）**：
  | 卡片原话 | 源码实情 | 本轮的裁决 |
  |---|---|---|
  | 「RSS 最多 20 条、**排除草稿**」 | `generate_rss`（`generator.py:542`）**不过滤**，只 `articles[:20]`；过滤在调用方 `generator.py:730` 的 `published = [a for a in articles if a.is_published]` | **`RSS()` 不过滤**（照函数现状），排除草稿由**调用方**（构建编排层）做 —— 否则与 `generate_rss` 逐字节对照必红 |
  | 「草稿不进**搜索索引**」 | `generate_search_index`（`generator.py:599-625`）**不过滤**；排除发生在 `cli.py:139` 的 `list_articles(include_drafts=False)`（过滤点在 `content.py:187-189`） | 同上：`SEARCH_INDEX()` 不过滤，草稿排除归**调用方** |
  | 「反向守卫：草稿不得出现在 **sitemap**」 | `generator.py:736` 传给 `generate_sitemap` 的是**未过滤**的 `articles` ⇒ 真实实现里**草稿在 sitemap 里** | **按现状实现**，并把它写成守卫 `guard/sitemap_draft_present_upstream`（上游哪天改了这条会红，正是提醒） |

  ⇒ **统一口径（避免「两套语义」）**：**过滤草稿是构建编排层的唯一职责**，各产物模块一律照抄对应 Python 函数的现状（不过滤）。
  这条对后续接线者尤其重要：接 `RSS()` / `SEARCH_INDEX()` 时**必须**先过滤，否则草稿会漏进发布物；
  而 `SITEMAP()` 要喂**未过滤**列表才与现状一致（这是上游既有行为，不是新引入的偏差）。

- **⚠ 已知 blocker：`pages/` 下没有真实文章**（2026-11-02 实测）：
  `pages/` 里只有 `pages/.tinypage/backlinks.json`（30 bytes），
  **`.html` 0 个、`.md` 0 个** ⇒ 没有真实语料可跑端到端。
  ⇒ **S1-3 / S1-4 / S2 各卡一律用「合成语料」验收**（基准生成器在临时目录造语料）。
  ⇒ **S2-4 的验收口径**：用**合成语料**（如 100 篇含标题/日期/标签/分类/正文/
  脚注/标题层级/双链的合成文章）跑一次构建，与 **Python 版在同样合成语料上的产物**
  做逐字节/结构对照；**真实语料**验收待业主提供 `pages/article/*.md` 后补。
  ⇒ ⚠ **另有一个未决问题**（已两次询问未获答复，不再阻塞推进）：
  真实文章**是否使用表格**？S1-3 的 Markdown 范围明确**不做表格**
  （§2.5），若真实文章用了表格则渲染结果与现状不一致。
- **🔎 Python 侧权威落点（2026-11-02 核查）**：`tinypage/generator.py`
  | 函数 | 位置 | 产物 |
  |---|---|---|
  | `generate_article_html` | 154 | `article/*.html` |
  | `generate_list_page` | 298 | `index.html` / `list/{n}.html` |
  | `generate_search_page` | 389 | `search.html` |
  | `generate_standalone_html` | 429 | `standalone/*.html` |
  | `generate_category_page` | 484 | `category/{cat}.html` |
  | `generate_rss` | 542 | `rss.xml`（`generator.py:730-731`，**排除草稿**） |
  | `generate_sitemap` | 571 | `sitemap.xml`（`generator.py:734-737`） |
  | `generate_search_index` | 599 | `search-index.json`（`generator.py:724-726`） |
  | `generate_static_pages` | 628 | 编排全部；`robots.txt` 在 740-744 |
  - `site_url` 为空时回落 `"http://localhost:8080"`（`generator.py:545`、`579`）；
    `robots.txt` 的 `Sitemap:` 行用 `cfg.site_url or ''`（`generator.py:742`）⇒ **不回落**。
  - `robots.txt` 内容固定 3 行（`generator.py:740-743`）。
  - 重复构建两次 ⇒ 产物**逐字节一致**（幂等）
- **非目标**：不生成 RSS 的 RFC822 严格日期；不做 sitemap 的 lastmod

#### 卡 S2-5：增量构建

- **依赖**：S2-4
- **交付物**：`tp/lib/incremental.wll`
- **判定**：源 `.md` 的 `FILE_META.mtime` > 产物 `.html` 的 mtime ⇒ 需重建
- **对齐点**：Python 侧用 `st_mtime`（**不用 hash**），保持一致；Python 侧 `--incremental`
  因目录不匹配而几乎恒全量重建（§5 R5）—— 本卡**修正**这个缺陷，
  但**判定口径仍是 mtime**（不引入 hash，以保持与现有行为一致）
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\bin\build.wll --incremental
  ```
  期望：改 1 篇 ⇒ 只重建 1 篇；未改 ⇒ 0 篇重建
- **反向守卫**：改一篇文章后，产物必须**确实**变了（不得因 mtime 精度问题跳过）
- **非目标**：不做内容 hash 缓存（Python 侧也没有实际使用）
- **🔎 Python 侧权威落点（2026-11-02 核查，`tinypage/core/incremental.py`）**：
  - `should_use_incremental`（约 130–156 行）：`article_count < threshold` ⇒ 不用增量；
    `modified_ratio = len(modified)/article_count` ⇒ **`< 0.1` 才用增量**。
  - `build_cache_key`（159 行）：对 `sorted(article_dir.glob("*.html"))` 取
    `f"{name}:{int(st_mtime)}"` 拼 `|` ⇒ `sha256` 前 12 位。
    ⚠ **`int(st_mtime)` 是秒级截断** ⇒ 同秒内改动检测不到。
  - `get_unchanged_articles`（182 行）：按 cache 分「未变/已变」两组。
  - ⚠ 本卡**修正**的是「判定目录不匹配导致恒全量重建」的缺陷（R5），
    **判定口径仍用 mtime**，不引入 hash。

### S3 前台静态服务（TLS）

#### 卡 S3-1：静态文件服务内核

- **依赖**：S2-4（需要产物存在）
- **交付物**：`tp/lib/static_serve.wll` + `tp/bin/serve_public.wll`
- **技术路线**：`TCP_SERVE`（明文，端口 80）+ `tls.LISTEN` 手写 accept 循环（端口 443）
  —— 二者**不能同时在一个进程**（C1）⇒ **两个进程**或**一个进程只跑一个**：
  **本卡交付两个独立入口**，由部署层决定跑哪个/都跑
- **必须实现**（对齐 `nginx.conf`）：
  - 安全头：`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
    `Referrer-Policy: no-referrer`、`Cross-Origin-Opener-Policy: same-origin`、
    `Permissions-Policy: accelerometer=(), camera=(), ...`
  - 静态资源长缓存：`Cache-Control: public, max-age=31536000, immutable`（`js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2`）
  - 隐藏文件拒绝：`/\.` 前缀 ⇒ 404
  - 敏感文件拒绝：`admin_password.txt` / `.env` / `.git` ⇒ 404
  - 目录 ⇒ 回落 `index.html`；不存在 ⇒ 404（对齐 `try_files $uri $uri/ =404`）
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\bin\serve_public.wll --port 18080
  curl -sI http://127.0.0.1:18080/index.html
  ```
  期望：200 + 五个安全头 + `Cache-Control`
- **反向守卫**：
  - 请求 `/.git/config` ⇒ 404
  - 请求 `/../secret` ⇒ 404
  - 请求 `/admin_password.txt` ⇒ 404
  - 请求不存在的路径 ⇒ 404，**不得** 500
- **非目标**：不做 gzip/brotli（nginx 现在也没做）；不做 HTTP/2
- **🔎 权威落点（2026-11-02 核查，`nginx.conf` 全文 58 行 + `tinypage/security.py`）**：
  - **5 个安全头**：`nginx.conf:9-13` 与 `security.py:331` 的 `get_security_headers()`
    **逐字一致**（顺序也同）：
    `X-Content-Type-Options: nosniff` / `X-Frame-Options: DENY` /
    `Referrer-Policy: no-referrer` / `Cross-Origin-Opener-Policy: same-origin` /
    `Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()`
    ⚠ `Permissions-Policy` 的完整取值是 **9 项**（卡片的 `...` 不要漏）。
  - **静态资源长缓存**：`nginx.conf:43-47` 的 `location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$`
    ⇒ `expires 1y` + `Cache-Control: public, immutable`。
    ⚠ **nginx 的 `expires 1y` 会展开成 `Cache-Control: max-age=31536000`**，
    且 `add_header Cache-Control "public, immutable"` 与 `expires` 产生的头**并存**
    （nginx 会输出两个 `Cache-Control`）⇒ WLWL 侧是发**一个**还是**两个**头，
    必须对齐现状并登记（建议实测 Python 版 `StaticApp` 的实际输出）。
  - **隐藏文件**：`nginx.conf:50-53` `location ~ /\. { deny all; return 404; }`
    ⇒ 任何路径含 `/.` ⇒ 404（不只是前缀）。
  - **敏感文件**：`nginx.conf:54-57` `location ~* (admin_password\.txt|\.env|\.git)` ⇒ 404
    （注意是**子串匹配**，不限于文件名）。
  - **目录回落**：`nginx.conf:18-20` `try_files $uri $uri/ =404` + `index index.html`
    ⇒ 目录 ⇒ 回落 `index.html`；都不存在 ⇒ 404。
  - **admin/api 反代**：`nginx.conf:23-40`，`client_max_body_size 10m`。
    ⚠ **D4 裁决「完全移除 nginx」后这两段反代不复存在** ⇒ admin 与公开站**分进程分端口**（C1/D2），
    WLWL 侧不需要反代逻辑，但**请求体 10MB 上限**这个语义要保留到 admin 侧。
  - `security.py:342` `get_csp_header()` 是 **admin 专用**的 CSP（`default-src 'self'` 等），
    **公开站不发**（nginx 公开站段没有 CSP）⇒ 别给公开站多加 CSP。

#### 卡 S3-2：TLS 终止

- **依赖**：S3-1
- **交付物**：`tp/bin/serve_public_tls.wll`
- **必须实现**：
  - `tls.LISTEN(host, port, {"cert": <路径>, "key": <路径>})`，**路径来自配置/环境变量**
  - 手写 accept 循环：`ACCEPT(l, timeout_ms)` → `NULL` 表示超时（**正常值**）→ 继续循环
  - 每条连接：`RECV` → `PARSE_REQUEST` → 交给静态服务内核 → `SEND` → `CLOSE`
  - **一个连接的失败不得终止循环**（对齐 `TCP_SERVE` 的容错语义）
- **必须实现**：`ON_SIGNAL`/`STOP` 优雅停机
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run --ext D:\wlwl_v0.12.1\lib\wlwl_tls.dll --ext-sha256 202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b tp\bin\serve_public_tls.wll --cert <cert.pem> --key <key.pem> --port 18443
  curl -k -sI https://127.0.0.1:18443/index.html
  ```
  期望：200 + 安全头
- **反向守卫**：
  - 证书文件不存在 ⇒ 启动即**明确失败**，不得降级成明文监听
  - 一次坏连接后，下一次正常请求**必须仍能成功**（对齐 `tp/probe/run_serve.ps1` 的验证法）
  - 缺 `cert`/`key` ⇒ `tls.LISTEN` 返回 ERR ⇒ 必须**显式消费**该 ERR，不得让它逃到顶层
- **非目标**：不做 HTTP→HTTPS 跳转（80 端口的重定向是部署层的事）；不做 ACME

### S4 Admin 后台

#### 卡 S4-1：会话与 CSRF

- **依赖**：S2-1
- **交付物**：`tp/lib/security.wll`
- **会话**：内存注册表（`SHARED_DICT` 或自建字典）+ 32B 随机 token + 24h 过期 + 上限 5000 + LRU 淘汰
  - ⚠ `std.sync::COUNTER`/`SHARED_DICT` **每次调用创建新容器、无名查找** ⇒
    「同名复用」必须自建注册表（对齐 Python 的 `SessionManager`）
- **CSRF**：16B 随机 + 4B 时间戳 + `HMAC_SHA256(32B 进程密钥)` = 52B → urlsafe base64；
  校验四重：格式/长度 → HMAC（`TIMING_SAFE_EQ`）→ 1 小时时限 → cookie 双提交一致 → Origin/Referer 白名单
- **口令**：`PBKDF2_ITER`（OWASP 2025 下限 `iter ≥ 600000`）或 `ARGON2ID`；**不得**用 `SHA256` 直接存口令
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_security.wll
  ```
- **反向守卫**：
  - 篡改 1 字节 token ⇒ 必须被拒
  - 过期 token（>1h）⇒ 必须被拒
  - cookie 与 token 不一致 ⇒ 必须被拒
  - 进程重启 ⇒ 旧会话全部失效（对齐 Python 行为）
- **非目标**：不做会话持久化（Python 侧也没有）

#### 卡 S4-2：限流与审计

- **依赖**：S4-1
- **交付物**：同 `security.wll`
- **限流**：优先用 `std.http::RATE_LIMITER`（sliding / token_bucket）；
  登录失败锁定每 IP 5 次锁 300 秒（对齐 Python）
- **审计**：`std.log::LOG` 输出 JSONL，事件名对齐 Python 的
  `[AUTH-FAIL]`/`[RATE-LIMIT]`/`[XSS-BLOCK]`/`[DELETE]` 等
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_security.wll
  ```
- **反向守卫**：连续 6 次错误登录 ⇒ 第 6 次必须 429 + `Retry-After`
- **非目标**：不做日志轮转（Python 侧也没有）

#### 卡 S4-3：路由与请求处理

- **依赖**：S4-1、S4-2
- **交付物**：`tp/lib/http_util.wll` + `tp/bin/serve_admin.wll`
- **路由表**：GET 9 条 + POST 14 条，**逐字对齐** Python 的 `admin/app.py`：
  GET `/`、`/pages`、`/new`、`/new-page`、`/edit`、`/edit-page`、`/theme`、`/login`；
  POST `/upload`、`/create`、`/create-page`、`/save`、`/save-page`、`/delete`、`/delete-page`、
  `/regen`、`/preview`、`/set-theme`、`/ai-assist`、`/translate`、`/login`、`/logout`
- **表单**：`PARSE_FORM`（Python 侧只支持 `application/x-www-form-urlencoded`）
- **会话 Cookie**：`SET_COOKIE`，属性 `HttpOnly; SameSite=Strict; Max-Age`（对齐 Python）
- **绑定**：**仅 127.0.0.1**（业主裁决）
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\bin\serve_admin.wll --port 18081
  curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18081/login
  ```
  期望：200
- **反向守卫**：
  - **从非回环地址访问 admin 端口必须连不上**（实测：监听地址须显式为 127.0.0.1）
  - 未登录访问 `/` ⇒ 必须 302 到 `/login`（对齐 Python）
  - POST 缺 CSRF ⇒ 必须 403
- **非目标**：不做路径参数与正则路由（Python 侧也没有）

#### 卡 S4-4：文章/独立页 CRUD + 上传

- **依赖**：S4-3、S2-4
- **交付物**：`tp/lib/admin_actions.wll`
- **必须实现**：创建/保存/删除文章、创建/保存/删除独立页、主题切换、实时预览（`/preview`）、
  重新生成（`/regen`）、图片上传
- **语义对齐点**：
  - 每次写操作后**全站重建**（对齐 Python）—— 但 WLWL 下这是秒级到分钟级，
    故 `/regen` 必须是**长任务**且要能反馈；本卡按「同步重建 + HTMX 提示」实现，
    **增量优化留给 S2-5 的接线**
  - 删除独立页改 slug ⇒ 先删旧文件（对齐 Python）
  - 上传：base64 字段 → `BASE64_DECODE` → 扩展名白名单 → **magic bytes 校验**
    （PNG/JPEG/GIF/WEBP；WEBP 校验 `RIFF`+`WEBP`）→ 写 `pages/static/images/YYYY-MM/` → 重名加 `-1`/`-2`
  - `/preview` 只做 Markdown 渲染（**不加高亮、不加 TOC/脚注**，对齐 Python）
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_admin_actions.wll
  ```
- **反向守卫**：
  - 上传 `.php` / `.html` ⇒ 必须被扩展名白名单拒绝
  - 上传扩展名是 `.png` 但内容是 PHP ⇒ 必须被 magic bytes 拒绝
  - 删除失败 ⇒ 必须回滚，文章仍在
- **非目标**：不做 multipart（Python 侧也没有）

#### 卡 S4-5：前端高亮切换

- **依赖**：S2-4
- **交付物**：`static_inject/highlight.js` + 主题 CSS；`generator.wll` 输出
  `<pre><code class="language-xxx">`；删除 Python 侧 pygments 逻辑
- **验收命令**：构建后检查产物里存在 `class="language-python"`；
  浏览器打开页面确认着色生效
- **反向守卫**：产物里**不得**残留 pygments 的 `class="k"` 之类 token span
- **非目标**：不做服务端高亮（已裁决前端方案）

### S5 AI 助手（出站 HTTPS）

#### 卡 S5-1：出站 HTTPS 客户端

- **依赖**：S4-3
- **交付物**：`tp/lib/http_client_tls.wll`
- **必须实现**：
  - `tls.CONNECT(host, port, {"server_name": <sni>, "ca": <ca 路径或省略>})`
  - 手写 HTTP/1.1 请求（`POST /v1/chat/completions`、`Authorization: Bearer <key>`、
    `Content-Type: application/json`、`Content-Length`）
  - 响应解析：状态行 + 头 + body（**按 `Content-Length` 读**，不是读到 EOF）
  - JSON 解析用 `std.json::PARSE`，取 `choices[0].message.content`
- **必须实现**：**证书校验默认开启**（不传 `verify: FALSE`）；要关必须显式且打告警
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_http_client_tls.wll
  ```
  （测试用本地自签 TLS 服务 + `ca` 指向测试 CA）
- **反向守卫**：
  - 响应体超过 `Content-Length` ⇒ 不得截断读取
  - 服务端返回 4xx/5xx ⇒ 必须返回 ERR，**不得**当作正常结果
  - 未配置 API key ⇒ 必须明确报错，不得静默返回空
- **非目标**：不做流式（SSE）；不做多供应商适配（只 OpenAI 兼容协议，对齐 Python）

#### 卡 S5-2：五个 AI 能力与后台接线

- **依赖**：S5-1
- **交付物**：`tp/lib/ai.wll` + `/ai-assist`、`/translate` 端点
- **五个能力**：`complete`（t=0.8）、`polish`（0.5）、`translate`（0.3）、
  `summarize`（0.3）、`suggest_tags`（0.3）；system+user 两条消息；非流式；30s 超时
- **降级**：未配置 ⇒ 不构建 AI 模块（对齐 Python）；`suggest_tags` 的词频降级保留
  （自写词频 + 中英停用词表，`[a-zA-Z\u4e00-\u9fff]{2,}` 切词）
- **翻译**：目标语言沿用硬编码 `en`/`ja`（对齐 Python）
- **验收命令**：
  ```
  D:\wlwl_v0.12.1\wlwl.exe run tp\test\test_ai.wll
  ```
- **反向守卫**：后端错误**必须**返回 JSON（Python 侧错误也返回 200 + `{"error":…}`，保持一致）
- **非目标**：不引入 `openai`/`deepseek` Python 包（Python 侧声明了但从未使用，属声明冗余）

### S6 部署与切换

#### 卡 S6-1：Docker 改造

- **依赖**：S3-2、S4-4
- **交付物**：新 `Dockerfile`（基于 WLWL 运行时镜像，含 `wlwl.exe`/`lib/`/`wlwl-skill`）
  + `docker-compose.yml`（**删除 nginx 服务**）
- **必须实现**：三个服务 = `public`（443/80）、`admin`（仅 `127.0.0.1` 暴露给 public 容器）、
  可选 `build`；证书与密钥用 volume 挂载，**不入镜像**
- **验收命令**：`docker compose config` 通过；起栈后 `curl -k https://localhost/` 返回站点
- **反向守卫**：compose 里**不得**再有 `nginx` 服务；镜像里**不得**含 Python
- **非目标**：不做自动证书签发（已裁决外部签发）

#### 卡 S6-2：Python 组件清退

- **依赖**：S6-1
- **交付物**：删除 `tinypage/`、`tests/`、`scripts/git-hooks/*.py`、`tiny_page.py`、
  `pyproject.toml`、`nginx.conf`、`Dockerfile`（旧）、`docker-compose.yml`（旧）
- **保留**：`pages/`、`themes/`、`static_inject/`、`admin_templates/`、`docs/`、
  `tp/`、`.gitignore`、README（改写）
- **git hooks**：`.git-hooks/pre-commit`/`pre-push` 是 **shell**（可保留），
  `scripts/git-hooks/install.py` 是 Python（须改写为 shell 或删除）
- **验收命令**：
  ```
  git ls-files | Select-String -Pattern '\.py$'
  ```
  期望：**无输出**（`.gitignore` 与 `docs/` 中的示例除外）
- **反向守卫**：
  - `static_inject/` 与 `admin_templates/` **不得**被删（它们不是 Python 组件）
  - `pages/` 里的用户文章**一个都不能少**（对比删除前的文件清单）
  - 删除前**必须**确认 `pages/` 已全部入库（`git status` 干净）
- **非目标**：不删除历史提交（用一次独立提交完成删除）

#### 卡 S6-3：验收与文档

- **依赖**：S6-2
- **交付物**：改写 `README.md`（安装、运行、证书配置、构建）；`docs/plans/` 本文档更新为已完成
- **验收命令**：见 §6 门禁清单
- **反向守卫**：README 里的每条命令**必须**逐条实跑过
- **非目标**：不写部署运维手册（超出本次范围）

---

## §5 风险登记

| # | 风险 | 证据 | 缓解 | 状态 |
|---|---|---|---|---|
| R1 | **TLS/HTTP 冻结运行时** ⇒ 单进程无法并发 | §2.4 实测 | 公开站与 admin **分进程**（§3.1） | 已缓解 |
| R2 | **`SORT` 二次复杂度** | §2.3 实测 | 卡 S2-2 手写归并；反向守卫静态 grep | 已缓解 |
| R3 | **Markdown 覆盖不全** | §2.5 | 明确范围（§4 卡 S1-3）；手写子集 | 已接受 |
| R4 | **路径/主题名穿越** | Python 侧 `set-theme` 直接拼路径无 `..` 校验 | 卡 S2-3/S2-1 反向守卫 | 待处理 |
| R5 | Python `--incremental` 目录不匹配恒全量重建 | §2.7 | 卡 S2-5 修正 | 待处理 |
| R6 | **出站 HTTPS 需手写 HTTP/1.1** | §2.4 实测可行 | 卡 S5-1 | 已缓解 |
| R7 | **11.4 req/s 吞吐**（TLS 每次重新握手） | §2.4 实测 | 定位为「单机小流量」；如需更高，`TCP_SERVE`+会话复用（**本版不做**） | 已接受 |
| R8 | `std.fs` 的 `READ_BYTES` **1MiB 读上限** | skill §9.12 | 二进制资源不读进内存（直接流式或拆分） | 已缓解 |
| R9 | `STATIC_FILE` 包含性判定**不解析符号链接** | skill §9.12 | 卡 S3-1 增加「拒绝路径含 `..`」+ 词法规范化 | 待处理 |
| R10 | 前端高亮引入外部 JS | 业主裁决 | vendored 进 `static_inject/`，不进 CDN（与 htmx 一致） | 已缓解 |
| R11 | Python 侧 CSRF 密钥**进程级**（重启即失效） | §2.7 | 保持行为一致（不引入外部密钥文件），但在 README 注明 | 已接受 |
| R12 | `WRITE_FILE_ATOMIC` 语义与 `os.replace` 是否逐字一致 | 未实测 | 卡 S2-1 单独验；红了按实测调整 | **待验证** |

---

## §6 验收门禁

全部满足才算完成。**每条都有可重跑命令。**

| # | 门禁 | 命令 | 期望 |
|---|---|---|---|
| G1 | 无 Python 残留 | `git ls-files \| Select-String '\.py$'` | 无输出 |
| G1b | 探针链零 Python | `Get-ChildItem tp\probe -Filter *.py` | 无输出（上游已用 WLWL 的 `TCP_SERVE` 实现） |
| G2 | 无 nginx 残留 | `git ls-files \| Select-String 'nginx'` | 无输出 |
| G3 | 构建可跑 | `wlwl.exe run tp\bin\build.wll` | exit 0 |
| G4 | 构建幂等 | 连续两次构建后 `git status --short pages/` | 第二次无变化 |
| G5 | 产物一致 | 与 Python 版产物做结构 diff（人工核对清单） | 结构等价 |
| G6 | 静态服务 | `curl -sI http://127.0.0.1:18080/index.html` | 200 + 5 个安全头 |
| G7 | TLS 服务 | `curl -k -sI https://127.0.0.1:18443/index.html` | 200 |
| G8 | admin 仅回环 | 从非回环 IP 访问 admin 端口 | 连不上 |
| G9 | 后台可用 | 登录 → 建文章 → 前台可见 | 全链路通 |
| G10 | CSRF 生效 | 无 token 的 POST | 403 |
| G11 | 上传校验 | 伪装扩展名的文件 | 被拒 |
| G12 | 测试全绿 | `wlwl.exe run tp\test\run_all.wll` | 全绿 |
| G13 | 无 `SORT` | `Select-String -Path 'tp\lib\*.wll' -Pattern '\bSORT(_BY)?\('` | 无输出 |
| G14 | 无残留 `E0103` | 运行全流程，stderr 无 `unhandled ERR` | 无输出 |
| G15 | 命名一致 | 全仓库 grep `wlwl/` 与 `wlwl\.toml` | 无命中（语言名/安装路径除外） |
| G16 | 静态层未被误开 | `Select-String -Path 'tp\wlwl.toml' -Pattern 'gradual_typing'` | 必须是 `off`（开了也没类型注解，白担风险） |
| G17 | 两份清单同步 | 比较 `tp/wlwl.toml` 与 `tp/tp.toml` 的 `[features]` 段 | 两边一致（改动任何一份都要改另一份） |
| G18 | 静态检查器全绿 | `python tp\test\paren_check.py tp\lib\*.wll` 等四条 | 全部 OK |
| G19 | **CI 全绿** | GitHub Actions `wlwl` workflow | 9 步全过（生成物无漂移 / 静态检查 / check / 反向守卫 / 两个测试）✅ run 41317062756 |

---

## §7 决策记录（已裁决，不再讨论）

| # | 决策 | 选择 | 理由 | 裁决日 |
|---|---|---|---|---|
| D1 | TLS 证书来源 | **外部签发，WLWL 只读证书文件** | 扩展已实测支持服务端握手；ACME 需出站 HTTPS 回调，工作量与风险过高 | 2026-11-01 |
| D2 | 端口与暴露姿态 | **双端口：公开站对外，admin 只绑 127.0.0.1** | 保持后台不暴露公网；admin 走回环 ⇒ 无需 admin 侧 TLS | 2026-11-01 |
| D3 | 代码高亮 | **改前端高亮**（服务端只输出语言类） | pygments 数百 lexer 不可复刻；与既有 mermaid/CDN 思路一致 | 2026-11-01 |
| D4 | nginx | **完全移除**，TLS 终止与静态服务都由 WLWL 承担 | 业主明确要求 | 2026-11-01 |
| D5 | Python 组件 | **不留任何需要 Python 才能执行的组件** | 业主明确要求 | 2026-11-01 |
| D6 | 目录与清单命名 | 源码目录 `wlwl/` → **`tp/`**；清单 `wlwl.toml` → **`tp/tp.toml`** | 业主明确要求（方案与实际文件都改）。⚠ 清单改名对 WLWL 运行时**无作用**；且清单名还决定**项目根** ⇒ S1 额外保留了 `tp/wlwl.toml` 以支持跨目录 IMPORT。边界与实测见 §2.6 | 2026-11-01 |
| D7 | `.wll` 源码的产出方式 | **由 Python 生成器产出，不手写** | WLWL 括号诊断不可用（`E0011` 不说缺几层）；S1 实测同一个函数来回改了 6 次。生成器保证括号必然平衡。工程约定见 §0.2 | 2026-11-01 |

---

## §8 变更日志

| 日期 | 变更 |
|---|---|
| 2026-11-01 | 初版。基于 WLWL 0.12.1 本机实测（§2）+ TinyPage 代码盘点 + 业主三项裁决建立。 |
