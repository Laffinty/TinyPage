# tp —— TinyPage 的 WLWL 实现

TinyPage 从 Python 重构为 **纯 WLWL**（编译器 `v0.12.1`，规范 `v1.0.4`）的实现树。
运行时不依赖 nginx、不依赖 Python、不依赖任何需要 Python 才能执行的组件。

> ⚠ **本目录是「生成器 + 生成物」的结构。**
> `lib/*.wll` 与 `test/*.wll` 由 `test/gen_*.py` 产出，**不要手改**——
> WLWL 的括号诊断（`E0011`）只说「expected `)` got X」，不告诉你缺了几层，
> 手写嵌套代码时反复数括号极低效且极易错。改实现请改生成器。

## 目录

```
tp/
├── lib/                 # 实现模块（由生成器产出）
│   └── md_inline.wll    # Markdown 行内解析
├── bin/                 # 可执行入口（规划中）
├── test/                # 测试 + 生成器 + 静态检查器
│   ├── gen_*.py         # 生成器：产出 lib/ 与 test/ 下的 .wll
│   ├── paren_check.py   # 静态检查：括号平衡 + 中缀算术
│   ├── check_semis.py   # 静态检查：顶层语句分号
│   ├── check_c_args.py  # 静态检查：生成器里 C(...) 参数的括号平衡
│   ├── check_funcs.py   # 逐个顶层语句编译（用 wlwl check）
│   ├── depth_trace.py   # 打印逐行括号深度（定位不平衡点）
│   └── broken/          # 反向守卫：故意写错的文件（用于验证 check 会失败）
└── wlwl.toml            # 项目清单
```

## 项目根与 IMPORT

WLWL 的**项目根 = 最近的含 `wlwl.toml` 的祖先目录**。`IMPORT` 的相对路径
**不得越出项目根**（越界 ⇒ `E0040`）。

- `tp/wlwl.toml` 存在 ⇒ 项目根 = `tp/` ⇒ `tp/test/` 里的模块可以
  `IMPORT("./../lib/md_inline.wll", [...])`。
- ⚠ 若把清单删掉，项目根会退化成「模块所在目录」，`../lib/...` 立刻越界。

## 怎么跑

```powershell
$WLWL = 'D:\wlwl_v0.12.1\wlwl.exe'

# 冒烟
& $WLWL run tp\test\smoke.wll            # ⇒ 退出码 0

# 行内解析器测试（21 个用例）
& $WLWL run tp\test\test_md_inline.wll   # ⇒ 退出码 0

# 静态检查
& $WLWL check tp\lib\md_inline.wll      # ⇒ OK: parsed ...
```

## CI（GitHub Actions，Windows runner）

`.github/workflows/wlwl.yml`，9 步，触发条件：`tp/**` 或 workflow 自身变更
（文档改动不烧配额）。

| # | 步骤 | 作用 |
|---|---|---|
| 1 | 下载官方 WLWL 0.12.1 Windows zip | **校验 sha256** `7b8c9650…8e545` |
| 2 | 验证版本 | 必须是 0.12.1 |
| 3 | **重跑生成器 + 要求 `git diff` 为空** | ⭐ **产物必须与生成器一致** |
| 4 | 静态检查器 | 括号平衡 / 无中缀 / 分号 / 生成器参数 |
| 5 | `wlwl check` 全部 `.wll` | 语法 |
| 6 | **反向守卫** | 坏文件必须被 check 拒掉（非零退出） |
| 7 | 跑 `smoke.wll` + `test_md_inline.wll` | 行为 |

⭐ **第 3 步是本 CI 存在的首要理由**：`.wll` 是生成物，若有人改了生成器却忘了重跑
（或直接手改 `.wll`），产物就与生成器不一致 —— 而这种不一致**编译期不报错**，
只在运行期行为诡异（占位符没被还原、括号层级错位）。

**本地一键复现全部 9 步**：
```powershell
powershell -File tp\test\ci_local_check.ps1
```

⚠ **生成器不得硬编码绝对路径**（CI 上仓库在别处）⇒ 产物路径由 `__file__` 推导。

## 开发流程

1. **改生成器**，不改 `.wll`：
   ```powershell
   python tp\test\gen_md_inline.py
   python tp\test\gen_test_md_inline.py
   python tp\test\gen_smoke.py
   ```
2. **跑静态检查器**（在编译之前就能发现问题，秒级反馈）：
   ```powershell
   python tp\test\paren_check.py tp\lib\md_inline.wll   # 括号平衡 + 无中缀算术
   python tp\test\check_semis.py tp\lib\md_inline.wll   # 顶层语句都有分号
   python tp\test\check_c_args.py tp\test\gen_md_inline.py  # 生成器参数括号
   ```
3. **编译 + 跑测试**：
   ```powershell
   & $WLWL check tp\lib\md_inline.wll
   & $WLWL run   tp\test\test_md_inline.wll
   ```

## 写 WLWL 时踩过的坑（实测，勿重蹈）

| # | 坑 | 症状 | 正确写法 |
|---|---|---|---|
| 1 | **没有中缀算术** | `E0011 expected ')' got Plus` | `+(a, b)`，不是 `a + b` |
| 2 | **`CAT` 不拼数组** | `CAT([], ["x"])` 得到字符串 `"[x]"` | 数组拼接用 `+(a, b)` |
| 3 | **`WHILE` 的值是 NULL** | 循环后的表达式写在 WHILE body 里 ⇒ 返回 NULL | 表达式写在 WHILE **外面** |
| 4 | 顶层语句缺分号 | `E0013`，但**位置指向下一条语句** | 每条顶层语句都以 `;` 结尾 |
| 5 | `std.*` 成员不是全局名 | `E0020 undefined name` | 必须 `IMPORT`（如 `CONTAINS_SUB`） |
| 6 | 逻辑与/或 | `E0020 undefined name 'AND'` | `&&(a, b)` / `||(a, b)`，没有 `AND`/`OR` |
| 7 | 字符串转义白名单 | `E0001 invalid escape '\u'` | 只有 `\" \\ \/ \n \r \t \b \f \0 \$` |
| 8 | 布尔字面量大写 | `E0020 undefined name 'false'` | `TRUE` / `FALSE` |
| 9 | 递归上限 2000 层 | `E0101` | 递归下降解析器按此设计 |
| 10 | `SORT` 是二次复杂度 | 500 元素 6.1s | 自己写排序 |
| 11 | **`FUN` 是两个括号组** | `FUN((body))` → `E0010 expected parameter name` | `FUN((参数), (函数体))`；零参写 `FUN((), (body))`（实测 2026-11-01） |
| 12 | 闭包可读可写外层 `LET MUT` | — | 实测 SET/读均直达外层绑定（`_probe_closure` 已删，结论入此） |
| 13 | **`CAT` 遇 `NULL` 拼出字面 `"NULL"`** | 输出里冒出 `NULL` 前缀 | 拼接前保证各参数非 NULL（flush 返回值被 `SET(out, ...)` 吞过一次，见 S1-3） |
| 14 | **没有逗号表达式** | `(SET(n,1), NULL)` → `E0011` | 多语句用语句序列 `(stmt1; stmt2)`；生成器有 `assert_no_comma_expr` 守卫 |

## 参考

- 构建计划：`docs/plans/tinypage-wlwl-rewrite-plan.md`
- WLWL 规范（合并册）：`D:\wlwl_v0.12.1\docs\wlwl-spec-reference.md`
- 内建名注册表：`D:\wlwl_v0.12.1\docs\appendix_G.md`
- WLWL skill：`D:\Minimax_Data\.minimax\skills\writing-wlwl\SKILL.md`
