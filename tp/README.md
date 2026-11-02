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
| 15 | **`RE_TEST` 整串锚定、忽略 `(?m)`** | 多行模式用它测恒 FALSE | 行锚定用 `RE_SEARCH`/`RE_REPLACE`/`RE_FIND_ALL`（只有它们认 `(?m)`） |
| 16 | **正则无前瞻/后顾/反向引用** | `RE("(?!:)")` → `E0030 lookahead is not supported` | 手写扫描：`RE_SEARCH` 取 `start`/`end`，看 `end` 后一个字符，再 `SUB` 切片拼接 |
| 17 | **`RE_REPLACE` 用 `$1` 不是 `\1`** | `"\1"` 是字面量 | `RE_REPLACE(re, s, "$2/$1")`（实测与 Python `\2/\1` 一致） |
| 18 | **`\w` 不含非 ASCII 字母**（与 Python 不同） | `café` 的 `é` 被判非法 | 别拿 Python 的 `\w` 语义照抄；CJK 用**字面** `一-龥`（⚠ 不是 `\u4e00-\u9fa5`，那个写法在 WLWL 里不生效，见 #20） |
| 19 | **内建 `HTML_ESCAPE` 出 `&#39;`，Python 出 `&#x27;`** | 逐字节对照红 | `tp/lib/esc.wll` 的 `ESCAPE_HTML` 已做后处理，**统一用它** |
| 20 | **正则不认 `\uXXXX`**：未知转义 `\u` 退化成**字面 `u`** | `RE("\\u4e00-\\u9fa5")` 匹配的是文本 `u4e00-u9fa5`，对 `"中"` 返回 **FALSE**（Python `re` 同式返回 True） | 字符类一律写字面 `一-龥`。实测：`RE_TEST(RE("^[一-龥]+$"), "中文")` → TRUE |
| 21 | ⚠ **求值数组绑定会克隆整个数组** ⇒ `AT`/`arr[i]`/**`LEN`** 实测都是 **O(n)**（规范 §18.3 写的是 O(1)） | 2000 元素的数组，`LEN()` 一次要 ~110µs；**字符串只要 3µs** | 数组密集算法在 WLWL 上是 **O(n²)**。热循环里**把下标和长度缓存到局部变量**，别反复读数组绑定（别名/字典取值都绕不过） |
| 22 | **`PUSH` 是纯函数，不原地修改** | `PUSH(x, 4);` 之后 `LEN(x)` 还是原值 ⇒ 元素**静默丢失** | 必须 `SET(x, PUSH(x, v))` 或 `LET(x, PUSH(x, v))`（保留返回值时实测是线性摊还 O(1)） |
| 23 | ⚠ **`READ_FILE`/`WRITE_FILE` 不转换行尾**，Python 的 `read_text()` 会把 CRLF 转 LF | 读同一个 CRLF 文件，WLWL 比 Python **多出 CRLF 个字符**（实测 theme.css：20322 vs 19517） | 要与 Python 逐字节对照时，**自己先做 CRLF→LF 归一化** |
| 24 | **`WRITE_FILE_ATOMIC` 成功返回 `NULL`，失败返回 `ERR`** | 用 `==(x, TRUE)` 判成功会误判；不消费 ERR 会 `E0103` | 用 `IS_ERR(x)` 判成败；**父目录要先 `MKDIRS`**（不会自动建） |
| 25 | ⚠⚠ **`LET(r, <ERR>)` 绑定不算消费 ERR** —— `E0103` 报在**绑定那一行**，后面再 `IS_ERR(r)` 也救不回来 | 期望「先取值再判」的写法直接编译失败 | 把会返回 ERR 的调用**直接**放进 `IS_ERR(...)`/`IF` 条件里：`IF(IS_ERR(WRITE_FILE_ATOMIC(p, c)), 失败分支, 成功分支)`。实测 `LET(r, WRITE_FILE_ATOMIC(坏路径, "x"))` + 下一行 `IS_ERR(r)` ⇒ E0103 |
| 26 | **正则模式里 `\xNN` / `\.` 不是转义，是字面字符**（与「模式字符串怎么写」无关） | 源码写 `RE("^\\.$")`（引擎收到 `^\.$`）实测对 `"."` 匹配、但 `RE("^[.][.]$")` 才是「两个字面点」；而 `RE("^\\x41$")` 对 `"A"` 是 **FALSE**、对 `"x41"` 是 **TRUE** | 字面点用**字符类** `[.]`；控制字符**不要**指望 `\xNN` 字符类 —— 改用「逐字符 + 与 `UTF8_DECODE([n])` 造出的字符比对」 |
| 27 | **零参函数写 `NAME` 得到的是函数值，不是调用** | `RESULT_REJECT`（少写括号）被当字典用 ⇒ `AT_K: expected DICT, got function` | 零参函数一律 `NAME()`。`fn()` 生成的 `FUN((), ...)` 也遵循这条 |
| 28 | **`&`/`||` 都是二元的**，`&&(a, b, c, d)` ⇒ `E0022 expects 2 argument(s), got 4` | 想写四条件与，直接报元数错 | 嵌套成 `&&(a, &&(b, &&(c, d)))`；或先 `LET` 出中间布尔 |
| 29 | **多行「语句字符串」会被逐行补 `;`** ⇒ 把一条 `IF(...)` 拆成几行字符串会变成 `IF(...,;` | `E0010: expected expression, got Semicolon` | 一条表达式的**参数**不能跨行拆；要么写成**单行**字符串，要么用 `C('IF', cond, [then语句], [else语句])`（分支是**语句列表**时才用 list） |
| 30 | **`PATH_JOIN(base, 绝对路径)` 只拼接、不覆盖**（Python 的 `base / abs` 会覆盖） | 传绝对路径进去得到 `base/C:/x/y.html` 这种废路径 | 先判绝对（`SUB(p,0,1)=="/"` 或盘符 `C:`），绝对时**直接用自身**取代 base。⚠ `TEMP_DIR()` 返回**反斜杠**形式，盘符判定要同时认 `:/` 与 `:\` |
| 31 | **`PATH_BASE` 不剥扩展名、`PATH_EXT` 不含前导点** | 照 Python `Path.suffix`（含点）写 ⇒ 少砍一个字符 | 有后缀时砍 `LEN(ext) + 1` 个码点；`PATH_DIR` 的无父目录返回 `""`（不是 `"."`） |
| 32 | ⚠⚠ **字符串字面量里 `${...}` / `$var` 是插值，不是字面量** | 写 `PRINT("a${d}b")` 会去取变量 `d`；`"${unclosed"` 直接 `E0002`（报错位置指到行首，极难认） | 要**字面美元符**一律写 `\$`（`"\\$x"` ⇒ 输出 `$x`）。实现 `$` 模板引擎时这一条是前提 |
| 33 | **`wlwl check` 只解析、不解析名字** | `PRINT(TO_STRING(42))` 过 check，run 时才 `E0020: undefined name` | 「check OK」≠「符号存在」⇒ 只能靠 `wlwl run` 验证 |
| 34 | **`+` 不做隐式转字符串** | `+(out, NULL)` ⇒ `E0030: +: cannot add string and null` | 拼接前 `STR(x)`（Python 侧靠隐式 `str()` 的地方都要补） |
| 35 | **`AT_K(NULL, k, default)` 是运行时 `E0030`** —— 默认值**不兜** NULL 基值 | Python 的 `d.get(k, x) if d else x` 照抄过来就崩 | 先判 `TYPE(d) == "NULL"` 再取值 |
| 36 | **`RE_TEST` 整串锚定 ⇒ 不能当「包含子串」用** | `RE_TEST(RE("[.][.]"), s)` 只匹配 `s == ".."`，判不出 `"a..b"` | 「含某子串」用 `LEN(RE_FIND_ALL(re, s)) > 0` |
| 37 | **`LIST_DIR` 已排序 + 正斜杠 + 完整前缀；对「不存在」和「传入文件」都返 `ERR`** | 想先 `LET(x, LIST_DIR(p))` 再遍历 ⇒ E0103；顺序也不是现场顺序 | 结果**只能内联**用：`FOR(e, LIST_DIR(p), …)`；空目录返 `[]` |
| 38 | ⚠ **`wllgen.C()` 的参数里不能放嵌套 `C()` 节点** | `render_call` 会把内层调用渲染**两遍**（`F(g(x)` / `g(x))`）⇒ 产出坏代码，再被逗号守卫误报成假阳性 | `C()` 的参数一律用**表达式字符串**（既有生成器全是这么写的，原因就在这） |
| 39 | **`UNWRAP_OR` 只吃 OK/ERR** | 对普通串报 `E0030: expected OK/ERR, got string` | 「STRING 或 ERR」的接地用 `IS_ERR(调用)` 判别；载荷一步取用 `std.result::TAKE_ERR(调用)`（`NULL` 表示非 ERR） |
| 40 | **Python 的 `read_text()` 还会把「孤立 CR」转成 LF** | 只做 CRLF→LF 归一化，遇到老 Mac 换行的文件仍与 Python 不一致 | CRLF **和** 孤立 CR 都要归一成 LF（`themes/default/theme.css` 本身无孤立 CR，但基准里有专门用例钉这条） |
| 41 | ⚠ **内建 `TRIM` 只剥 ASCII 空白**（Python `str.strip()` 剥 Unicode 空白） | `TRIM("\u3000a\u3000")` **原样保留**；粘来的标签常带 NBSP/全角空格 ⇒ 静默漏剥 | 需要 Python 口径时自己构造空白集合再用 `RE_REPLACE` 两侧剥；`tp/lib/article_page.wll` 的 `PY_WS()` 是可复用写法 |
| 42 | **`UTF8_DECODE` 的实参是「字节」不是码点** | 传 12288 报 `E0030: byte out of range` | 只能给 0–255；造多字节字符要自己拼 UTF-8 字节序列 |
| 43 | **`SPLIT` / `TRIM` / `PUSH` 是**全局内建**，不是 `wlwl:std.str` 成员** | `IMPORT("wlwl:std.str", ["SPLIT"])` ⇒ `E0023` | 直接用裸名；`SPLIT_LINES` 才是 `std.str` 的 |
| 44 | **`TO_LOWER` / `TO_UPPER` 必须从 `wlwl:std.text` IMPORT** | 不 import 报 `E0020`，且提示是误导性的 `did you mean LOWER?`（`LOWER` 是另一个真实存在的全局名） | 一律显式 `IMPORT("wlwl:std.text", ["TO_LOWER"])` |
| 45 | **`CONTAINS_SUB` 的空子串是运行时 `E0030`** | 拿 `CONTAINS_SUB(s, "")` 当「恒真」会炸 | 判「包含」用 `RE_FIND_ALL` 计数或非空子串 |
| 46 | **`(ASSERT(...));` 行首那个 `(` 是分组括号，多断言时**每条**都要带** | 漏一条就每行多一个 `)`，而 `paren_check` 只报「lines X-Y ends at depth N」、**不指出真正出错的行** | 照抄范本形态：每行 `    (ASSERT(...));` 或 `    ASSERT(...);`（二者**不可混用**） |
| 47 | **`std.json::PARSE` 返回的是原始值**（`TYPE` = `ARRAY`/`DICT`），不是 `RESULT`；解析失败才是 `E0070` 中止 | 对 `PARSE` 的返回值调 `UNWRAP_OR` ⇒ `E0030: expected OK/ERR, got array` | 只有 `JSON_VALIDATE` 返回 `RESULT`；要「解析失败可处置」必须先 `JSON_VALIDATE` 再 `PARSE` |
| 48 | **没有中缀 `==`**：`TYPE(d) == "NULL"` 是 `E0012` | 从 Python 习惯直译过来就编译失败 | 一律前言式：`==(TYPE(d), "NULL")`。同理 `!=` / `<` / `>` / `+` 都不能中缀 |
| 49 | ⚠ **`wlwl run` 不透传脚本参数** | `wlwl run x.wll --port 18080` ⇒ `error: unexpected argument '--port'`（clap 直接拒） | 需要外部配置的脚本（服务入口等）一律用**环境变量** + `std.env::ENV_GET`，别设计 `--flag` 接口 |
| 50 | **`wlwl check` 只解析、不认 `--ext`** | 依赖 TLS 扩展的文件也能 `check` 通过，但 `run` 不带 `--ext` 就起不来 | `check` 当「语法门」用、`run --ext` 当「行为门」用；别以为 check 过了就能跑 |
| 51 | **`LET(h, …)` 之后再 `SET(h, …)` ⇒ `E0024`**，且报错位置指向**调用点**（不是定义处） | 在测试里改字典会报「cannot SET immutable binding」，而行号指向 `TEST(...)` 那一行，容易误判成测试框架的问题 | 要改就用 `LET MUT`；报 E0024 时往上找被改的变量，别看报错行 |

## 参考

- 构建计划：`docs/plans/tinypage-wlwl-rewrite-plan.md`
- WLWL 规范（合并册）：`D:\wlwl_v0.12.1\docs\wlwl-spec-reference.md`
- 内建名注册表：`D:\wlwl_v0.12.1\docs\appendix_G.md`
- WLWL skill：`D:\Minimax_Data\.minimax\skills\writing-wlwl\SKILL.md`
