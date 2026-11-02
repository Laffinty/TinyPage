"""生成 tp/lib/article_store.wll —— 文章存储与原子写（卡 S2-1）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出；
WLWL 的括号诊断只说「expected ')' got X」，不告诉你缺了几层）。

**对齐目标（真 Python 源码树）**：
  · `VALIDATE_FILENAME(f)`  == tinypage/security.py:228 `validate_filename`
  · `VALIDATE_CONTENT(c)`  == tinypage/security.py:256 `validate_content`
  · `VALIDATE_DATE_FORMAT(d)` == tinypage/security.py:243 `validate_date_format`
  · `VALIDATE_TITLE(t)`   == tinypage/content.py:270 的标题长度判定
  · `SAFE_PATH_CHECK(p, base)` == tinypage/security.py:269 `safe_path_check`
  · `SOURCE_PATH(p)`      == tinypage/core/article_store.py:67 `source_path`
  · `WRITE_SOURCE(p, c)`  == tinypage/core/article_store.py:72 `write_source`
  · `DECODE_CONTENT(t)`   == tinypage/core/article_store.py:104 `decode_content`
  · `DECODE_LEGACY_BODY(t)` == tinypage/core/article_store.py:121 `decode_legacy_body`
  · `UNESCAPE_TO_FIXPOINT(t)` == tinypage/core/article_store.py:132 `_unescape_to_fixpoint`
  · `META_VALUE(v)`       == tinypage/core/article_store.py:90 `meta_value`
    ⚠ **复用 S1-4 的 frontmatter.wll::META_VALUE**，不重写（§0.2 第 6 条）。

**逐字节对照基准**：tp/test/fixtures/article_store_baseline.json
    （由 tp/test/gen_article_store_baseline.py 用**真 Python** 生成）

**本机实测得到的语义差异（都写进代码注释；每条都有探针依据）**：
  ① `RE_TEST` 是**整串锚定**（两端都锚），而 Python 的 `re.match` 只锚**开头**。
     ⇒ Python 的 `$` 允许**结尾一个 \\n**（实测 `re.match(r'^a$', 'a\\n')` 为真），
       WLWL 的 `RE_TEST(RE("^a$"), "a\\n")` 为**假**。
       ⇒ 本模块凡用 `$` 的地方，一律「先剥掉结尾的单个 \\n，再整串锚定」。
  ② WLWL 正则的 `\\d` **只认 ASCII**（Python 的 `re` 默认 Unicode）⇒
     已知差异 D2（validate_filename/f30）。
     ⇒ 本模块用**显式** `[0-9]` 写数字类（与 `\\d` 在 ASCII 上等价），
       明确排除 Unicode 数字 ⇒ 这正是 D2 的来源。
  ③ WLWL 正则的**字符类里不能写 `\\xNN`** —— 引擎把它当**字面 'x' + 数字**
     （实测：源码写 `\\\\x41` 时，`RE_TEST(RE("^\\\\x41$"), "x41")` 为真、
     对 "A" 为**假** ⇒ 引擎看到的是字面 "x41"）。
     ⇒ 控制字符的统计**不能用 `\\x` 字符类**，改用「运行时构造 29 个控制字符
       的字面串，再用它去逐个比对」的办法。
  ④ WLWL **没有** `ORD`/`CHR` 内建 ⇒ 取不到码点；用 `UTF8_DECODE([n])` 造字符。
  ⑤ `HTML_UNESCAPE` 一次调用**只解一层**（`&amp;amp;` → `&amp;`），
     而 Python 的 `html.unescape` 也是单层；Python 的「解到不动点」是
     **外层循环**做的 ⇒ 本模块必须自己写循环。
  ⑥ `HTML_UNESCAPE` 与 Python `html.unescape` 的**实体表逐条一致**
     （实测含 `&notit;`→`¬it;`、`&AMP;`→`&`、`&amp`（无分号）→`&`、
     `&#1114112;`→`\\ufffd`、`&#xZZ;`→原样）⇒ 可直接用。
  ⑦ `TO_INT` 对 Unicode 数字返回 **ERR**（Python 的 `int()` 接受）⇒ 与 D2 同源。
  ⑧ `WRITE_FILE_ATOMIC` 成功返回 **NULL**、失败返回 **ERR**（不消费 ERR ⇒ E0103）。
  ⑨ `PATH_EXT` 给的扩展名**不含前导点**（Python 的 `Path.suffix` 含点）⇒
     白名单按**不带点**的形态比较。

**已知差异（与真 Python 的偏差，已在基准里登记）**：
  · **D2** `validate_filename`：Python 的 `re` 的 `\\d` 匹配 Unicode 数字
    （`int()` 也能解析）⇒ Python 接受、**WLWL 拒绝**（基准 want=false）。
  · **D3** `safe_path_check`：卡片 S2-1 明确要求「拒绝路径中含 `..` 的输入」
    （WLWL 的 `PATH_CANONICAL` 是**词法**判定、不解析符号链接）⇒
    **WLWL 拒绝、Python 允许**（基准 want=false）。

用法：python gen_article_store.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'article_store.wll')

# ── 正则模式（正则引擎该看到的字符序列）────────────────────────────────
# ⚠ WLWL 字符串字面量的合法转义只有 \" \\ / \n \r \t \b \f \0 \$
#   ⇒ 想让正则看到 `\d` / `\s` / `\r` / `\n`，源码里必须写 `\\d` / `\\s` ……
#   （写 `\d` 会 E0001「invalid escape '\d'」，见 tp/README.md 坑 7）

FILENAME_RE = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-zA-Z0-9一-龥-]+\.html$"
DATE_RE = r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}$"

# legacy 标记（Python: _LEGACY_MARKER_EXACT / _LEGACY_MARKER_LOOSE）
# ⚠ Python 用 re.DOTALL ⇒ `.` 匹配换行；WLWL 正则默认 `.` **不**匹配换行
#   ⇒ 模式里加 `(?s)`（RE2/Go 的 inline flag，与 Python 的 DOTALL 等价）。
# ⚠ EXACT 与 LOOSE 的差别就在**尾部的空格**：
#   EXACT 强制 ` -->` ⇒ 保留 payload 里的结尾换行；
#   LOOSE 的 `\s*` 会把结尾换行一起吃掉 ⇒ 只作兜底。
LEGACY_EXACT_RE = r"(?s)<!--\s*markdown:\s*(.*?) -->"
LEGACY_LOOSE_RE = r"(?s)<!--\s*markdown:\s*(.*?)\s*-->"

# v2 头（Python: _V2_HEADER = re.compile(r"<!--\s*tinypage:markdown\s+(\d+)\s*-->\r?\n?")）
V2_HEADER_RE = r"<!--\s*tinypage:markdown\s+([0-9]+)\s*-->\r?\n?"

# 扩展名白名单（Python 的 safe_exts）—— ⚠ **不带前导点**（PATH_EXT 的形态）
SAFE_EXTS = ['html', 'xml', 'json', 'txt', 'js', 'css',
             'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff2']


def wl_re(pattern):
    """把「正则引擎该看到的字符序列」渲染成 WLWL 字符串字面量。

    每个反斜杠在 WLWL 源码里要写成两个 ⇒ 这里把每个 `\\` 变 `\\\\`。
    """
    return '"' + pattern.replace('\\', '\\\\') + '"'


def main():
    src = []
    A = src.append
    A('// tp/lib/article_store.wll —— 文章存储与原子写（卡 S2-1）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_article_store.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树）：')
    A('//   VALIDATE_FILENAME     == security.py:228  validate_filename')
    A('//   VALIDATE_CONTENT      == security.py:256  validate_content')
    A('//   VALIDATE_DATE_FORMAT  == security.py:243  validate_date_format')
    A('//   VALIDATE_TITLE        == content.py:270   的标题长度判定')
    A('//   SAFE_PATH_CHECK       == security.py:269  safe_path_check')
    A('//   SOURCE_PATH           == core/article_store.py:67  source_path')
    A('//   WRITE_SOURCE          == core/article_store.py:72  write_source')
    A('//   DECODE_CONTENT        == core/article_store.py:104 decode_content')
    A('//   DECODE_LEGACY_BODY    == core/article_store.py:121 decode_legacy_body')
    A('//   UNESCAPE_TO_FIXPOINT  == core/article_store.py:132 _unescape_to_fixpoint')
    A('//   META_VALUE            == core/article_store.py:90  meta_value')
    A('//     （META_VALUE **复用 S1-4 的 frontmatter.wll**，不重写）')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/article_store_baseline.json')
    A('//   （由 tp/test/gen_article_store_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ 本机实测的四条语义差异（详见生成器 docstring）：')
    A('//   ① `RE_TEST` 整串锚定；Python 的 `$` 允许结尾一个 \\n')
    A('//      ⇒ 凡用 `$` 处先剥掉结尾单个 \\n（见 STRIP_FINAL_NL）。')
    A('//   ② WLWL 正则的 `\\d` 只认 ASCII ⇒ 已知差异 D2。')
    A('//   ③ 正则**字符类里不能写 `\\xNN`**（引擎当字面 \'x\'+数字）')
    A('//      ⇒ 控制字符统计用「逐字符 + 与预构造字符比对」。')
    A('//   ④ `PATH_EXT` 的扩展名**不带前导点** ⇒ 白名单按不带点比较。')
    A('//')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_TEST", "RE_SEARCH", "RE_FIND_ALL", '
      '"RE_REPLACE"]);')
    A('IMPORT("wlwl:std.sanitize", ["HTML_UNESCAPE"]);')
    A('IMPORT("wlwl:std.fs", ["PATH_CANONICAL", "PATH_CONTAINS", "PATH_JOIN", '
      '"PATH_EXT", "PATH_BASE", "PATH_DIR", "FILE_META", "WRITE_FILE_ATOMIC", '
      '"MKDIRS"]);')
    A('IMPORT("wlwl:std.encode", ["BYTE_LEN", "UTF8_DECODE"]);')
    A('IMPORT("wlwl:std.text", ["TO_INT", "TO_LOWER"]);')
    A('IMPORT("./frontmatter.wll", ["META_VALUE"]);')
    A('')
    A('// 整数取模（WLWL 的 `%(a, b)` —— 起个短名，避免与生成器的 % 格式化混淆）')
    A('LET(MOD, FUN((a, b), (%(a, b))));')
    A('')

    # ── 正则模式常量 ────────────────────────────────────────────────
    A('// 文件名模式 —— Python: SAFE_FILENAME_PATTERN')
    A('// ⚠ CJK 区间写成**字面** `一-龥`（`\\uXXXX` 在 WLWL 里不生效）。')
    A('// ⚠ 用 `[0-9]` 而非 `\\d`：明确只认 ASCII ⇒ 这就是 D2 的来源。')
    A('LET(FILENAME_RE, RE(' + wl_re(FILENAME_RE) + '));')
    A('')
    A('// 日期串模式 —— Python: re.match(r"^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}$", s)')
    A('LET(DATE_RE, RE(' + wl_re(DATE_RE) + '));')
    A('')
    A('// legacy 标记（Python: _LEGACY_MARKER_EXACT / _LEGACY_MARKER_LOOSE）')
    A('// ⚠ `(?s)` == Python 的 re.DOTALL（`.` 匹配换行）。')
    A('LET(LEGACY_EXACT_RE, RE(' + wl_re(LEGACY_EXACT_RE) + '));')
    A('LET(LEGACY_LOOSE_RE, RE(' + wl_re(LEGACY_LOOSE_RE) + '));')
    A('')
    A('// v2 长度头（Python: _V2_HEADER）')
    A('LET(V2_HEADER_RE, RE(' + wl_re(V2_HEADER_RE) + '));')
    A('')
    A('// 字面 ".."（两个点）—— ⚠ WLWL 正则**不支持反斜杠转义**')
    A('//   （实测 `\\.` 被当字面反斜杠+点、`\\x41` 被当字面 "x41"）')
    A('//   ⇒ 用**字符类** `[.][.]` 表达字面点。')
    A('LET(DOTDOT_RE, RE(' + wl_re('[.][.]') + '));')
    A('')
    A('// 任意单字符（逐字符遍历用；提成常量避免每次调用重新编译模式）')
    A('LET(ANY_CHAR_RE, RE("."));')
    A('')

    # ── 剥结尾换行 ─────────────────────────────────────────────────
    src += fn('STRIP_FINAL_NL', 's', [
        '// Python 的 `$` 允许**结尾一个** \\n；WLWL 的 RE_TEST 整串锚定、不允许。',
        '// ⇒ 用 `$` 的地方先剥掉结尾的单个 \\n，再整串锚定。',
        C('IF', '&&(>(LEN(s), 0), ==(SUB(s, -(LEN(s), 1), 1), "\\n"))', [
            'SUB(s, 0, -(LEN(s), 1))',
        ], [
            's',
        ]),
    ], '// 剥掉字符串结尾的单个 \\n（对齐 Python `$` 的语义）')

    # ── 辅助函数（必须定义在使用之前 —— WLWL 不允许前向引用）──────
    # ⚠ 字典**字面量** `["k": v]` 会触发 wllgen 的逗号表达式守卫
    #   （守卫把 `[` 前是 `(` 的分组误判成裸分组）⇒ 一律用 INDEX_SET 构造。
    src += fn('RESULT_REJECT', '', [
        '// 路径检查失败：{ok: FALSE, rel: NULL}',
        'INDEX_SET(INDEX_SET(DICT(), "ok", FALSE), "rel", NULL)',
    ], '// 路径检查失败的结果')

    src += fn('RESULT_OK', 'rel', [
        '// 路径检查通过：{ok: TRUE, rel: <rel>}',
        'INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), "rel", rel)',
    ], '// 路径检查通过的结果')

    src += fn('RESULT_WRITE_FAIL', '', [
        '// 原子写失败：{ok: FALSE, path: NULL}',
        'INDEX_SET(INDEX_SET(DICT(), "ok", FALSE), "path", NULL)',
    ], '// 原子写失败的结果')

    src += fn('RESULT_WRITE_OK', 'path', [
        '// 原子写成功：{ok: TRUE, path: <path>}',
        'INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), "path", path)',
    ], '// 原子写成功的结果')

    # 绝对路径判定
    src += fn('IS_ABS_PATH', 'p', [
        '// p 是否是绝对路径（以 "/" 开头，或 **Windows 盘符** "C:" / "C:\\" 开头）',
        '// ⚠ Python 的 `base / path_str`：path_str 绝对时**覆盖** base（pathlib 语义）',
        '//    ⇒ WLWL 侧不能用 PATH_JOIN（它只会拼接）',
        '// ⚠ TEMP_DIR() 返回的是**反斜杠**形式（实测 C:\\Users\\...）',
        '//    ⇒ 盘符判定要同时认 ":/" 与 ":\\"；调用的 p 已过 PATH_CANONICAL 归一。',
        '||(==(SUB(p, 0, 1), "/"), &&(>(LEN(p), 2), &&(==(SUB(p, 1, 1), ":"), '
        '||(==(SUB(p, 2, 1), "/"), ==(SUB(p, 2, 1), "\\\\")))))',
    ], '// 是否绝对路径')

    # 相对路径
    src += fn('REL_TO_BASE', 'base, target', [
        '// target 相对 base 的相对路径（Python: os.path.relpath(target, base)）。',
        '// 已知调用点已保证 target 在 base 之内（或 == base）。',
        C('IF', '==(target, base)', ['"."'], [
            'SUB(target, +(LEN(base), 1))',
        ]),
    ], '// target 相对 base 的相对路径')

    # 扩展名白名单
    src += fn('SAFE_EXTS', '', [
        'LET MUT(out, [])',
        'SET(out, PUSH(out, "html"))',
        'SET(out, PUSH(out, "xml"))',
        'SET(out, PUSH(out, "json"))',
        'SET(out, PUSH(out, "txt"))',
        'SET(out, PUSH(out, "js"))',
        'SET(out, PUSH(out, "css"))',
        'SET(out, PUSH(out, "png"))',
        'SET(out, PUSH(out, "jpg"))',
        'SET(out, PUSH(out, "jpeg"))',
        'SET(out, PUSH(out, "gif"))',
        'SET(out, PUSH(out, "svg"))',
        'SET(out, PUSH(out, "ico"))',
        'SET(out, PUSH(out, "woff2"))',
        'out',
    ], '// 扩展名白名单（对齐 Python 的 safe_exts；⚠ 不带前导点）')

    # 去掉结尾所有 \n
    src += fn('TRIM_TRAILING_NL', 's', [
        '// Python: body.rstrip("\\n") —— 去掉**结尾所有** \\n',
        'LET MUT(out, s)',
        'LET MUT(i, LEN(out))',
        C('WHILE', '>(i, 0)', [
            C('IF', '==(SUB(out, -(i, 1), 1), "\\n")', [
                'SET(out, SUB(out, 0, -(i, 1)))',
                'SET(i, -(i, 1))',
            ], [
                'SET(i, 0)',
            ]),
        ]),
        'out',
    ], '// 去掉结尾所有 \\n（对齐 Python 的 rstrip("\\n")）')

    # ── 控制字符计数 ───────────────────────────────────────────────
    # Python: control_chars = sum(1 for c in content if ord(c) < 32 and c not in "\t\n\r")
    # ⚠ WLWL 没有 ORD/CHR ⇒ 拿不到码点。
    # ⚠ 正则**不支持反斜杠转义**（实测 `\\.` 被当字面反斜杠+点、`\\x41` 被当
    #   字面 "x41"）⇒ 字符类里不能写 `\\x00`。
    # ⚠ NUL（码点 0）**拼进字符串时会被丢弃**（实测：单独 UTF8_DECODE([0]) 的
    #   长度是 1，但拼进串后 29 个控制字符只剩 28 个 ⇒ NUL 丢失），
    #   且含 NUL 的正则字符类匹配不到 NUL（实测计数为 0）⇒ **字符类路线不可用**。
    # ⇒ 唯一可靠的路线：**逐字符取出**（RE_FIND_ALL(RE("."), s) 给出每个字符），
    #   再与**预构造的 29 个控制字符**逐个 `==` 比对。
    #   ⚠ 预构造的串同样会丢 NUL ⇒ NUL 用**单独**的 `==` 比对（不拼进串）。
    src += fn('IS_CTRL_CHAR', 'c', [
        '// c 是否是控制字符（ord<32 且非 tab/nl/cr）',
        '// ⚠ NUL 单独比（拼进串会被丢弃）；其余 28 个拼成串后逐个比。',
        '||(==(c, "' + '\\0' + '"), CONTAINS(CTRL_CHARS(), c))',
    ], '// 是否控制字符')

    src += fn('CTRL_CHARS', '', [
        '// 28 个控制字符（码点 1..31 去掉 9/10/13）的**字面**串。',
        '// ⚠ NUL（码点 0）不包含在内 —— 它拼进串时会被丢弃（实测）。',
        '// ⚠ WLWL 没有 ORD/CHR ⇒ 用 UTF8_DECODE([n]) 造字符。',
        'LET MUT(out, "")',
        'LET MUT(n, 1)',
        'LET MUT(is_ctrl, FALSE)',
        C('WHILE', '<(n, 32)', [
            'SET(is_ctrl, &&(!=(n, 9), &&(!=(n, 10), !=(n, 13))))',
            C('IF', 'is_ctrl', [
                'SET(out, +(out, UTF8_DECODE([n])))',
            ], [
                'NULL',
            ]),
            'SET(n, +(n, 1))',
        ]),
        'out',
    ], '// 28 个控制字符的字面串（不含 NUL）')

    src += fn('COUNT_CTRL_CHARS', 's', [
        '// 数出 s 里的控制字符个数（ord<32 且非 tab/nl/cr）',
        '// ⚠ 逐字符比对（没有 ORD、不能用 \\x 字符类、NUL 不能拼进串）',
        'LET(chars, RE_FIND_ALL(ANY_CHAR_RE, s))',
        'LET MUT(count, 0)',
        C('FOR', 'ch, chars', [
            'LET(c, AT_K(ch, "matched", ""))',
            C('IF', 'IS_CTRL_CHAR(c)', [
                'SET(count, +(count, 1))',
            ], [
                'NULL',
            ]),
        ]),
        'count',
    ], '// 控制字符计数（对齐 Python 的 ord(c)<32 口径）')

    # ── VALIDATE_FILENAME ─────────────────────────────────────────
    src += fn('VALIDATE_FILENAME', 'filename', [
        '// ① 模式匹配（先剥结尾的单个 \\n ⇒ 对齐 Python 的 `$`）',
        'LET(stripped, STRIP_FINAL_NL(filename))',
        C('IF', '!RE_TEST(FILENAME_RE, stripped)', [
            'FALSE',
        ], [
            '// ② 按 `-` 切分取前 3 段（Python: filename.split("-")）',
            'LET(parts, SPLIT(stripped, "-"))',
            C('IF', '<(LEN(parts), 4)', [
                'FALSE',
            ], [
                '// ③ 转整数（TO_INT 对非数字返回 ERR ⇒ 判 IS_ERR）',
                'LET(y, TO_INT(parts[0]))',
                'LET(mo, TO_INT(parts[1]))',
                'LET(d, TO_INT(parts[2]))',
                C('IF', '||(IS_ERR(y), ||(IS_ERR(mo), IS_ERR(d)))', [
                    'FALSE',
                ], [
                    '// ④ 范围判定（Python: 2000<=y<=2100 and 1<=mo<=12 and 1<=d<=31）',
                    '//    ⚠ Python **不查当月天数** ⇒ 2026-02-31 合法（基准 f18=true）',
                    C('IF', '&&(&&(>=(y, 2000), <=(y, 2100)), &&(>=(mo, 1), <=(mo, 12)))', [
                        C('IF', '&&(>=(d, 1), <=(d, 31))', ['TRUE'], ['FALSE']),
                    ], [
                        'FALSE',
                    ]),
                ]),
            ]),
        ]),
    ], '// 文件名校验（对齐 security.py:228；D2：Unicode 数字被拒）')

    # ── VALIDATE_CONTENT ──────────────────────────────────────────
    src += fn('VALIDATE_CONTENT', 'content', [
        '// ① 长度上限（Python: len(content) > 50000）—— LEN 是**码点数**',
        C('IF', '>(LEN(content), 50000)', [
            'FALSE',
        ], [
            '// ② UTF-8 字节数上限（Python: len(content.encode("utf-8")) > 50000*4）',
            C('IF', '>(BYTE_LEN(content), 200000)', [
                'FALSE',
            ], [
                '// ③ 控制字符占比 > 10% ⇒ 拒',
                '//    ⚠ Python 是 `control_chars > len(content) * 0.1`（严格大于）',
                '//    ⇒ WLWL 侧用 `ctrl * 10 > len` 表达（整数、无浮点误差）',
                'LET(ctrl, COUNT_CTRL_CHARS(content))',
                C('IF', '>(*(ctrl, 10), LEN(content))', ['FALSE'], ['TRUE']),
            ]),
        ]),
    ], '// 正文校验（对齐 security.py:256）')

    # ── VALIDATE_DATE_FORMAT ──────────────────────────────────────
    src += fn('VALIDATE_DATE_FORMAT', 'date_str', [
        '// ① 模式（**不剥**结尾 \\n —— Python 的 strptime 对尾随 \\n 直接报错）',
        'LET(stripped, date_str)',
        C('IF', '!RE_TEST(DATE_RE, stripped)', [
            'FALSE',
        ], [
            '// ② 取各段（位置固定：YYYY-MM-DD HH:MM）',
            'LET(y, TO_INT(SUB(stripped, 0, 4)))',
            'LET(mo, TO_INT(SUB(stripped, 5, 2)))',
            'LET(d, TO_INT(SUB(stripped, 8, 2)))',
            'LET(h, TO_INT(SUB(stripped, 11, 2)))',
            'LET(mi, TO_INT(SUB(stripped, 14, 2)))',
            C('IF', '||(IS_ERR(y), ||(IS_ERR(mo), ||(IS_ERR(d), ||(IS_ERR(h), IS_ERR(mi)))))', [
                '// ⚠ D4：TO_INT 拒绝 Unicode 数字（Python 的 %Y 用 int() 接受）',
                'FALSE',
            ], [
                '// ③ 日历合法性（Python: strptime 的语义）',
                '//    · 月 1..12；日 1..当月天数；时 0..23；分 0..59',
                '//    · 闰年：y%4==0 且 (y%100!=0 或 y%400==0)',
                C('IF', '&&(&&(>=(mo, 1), <=(mo, 12)), &&(>=(h, 0), <=(h, 23)))', [
                    C('IF', '&&(>=(mi, 0), <=(mi, 59))', [
                        C('IF', '>=(d, 1)', [
                            '// ④ 当月天数',
                            'LET(is_leap, &&(==(MOD(y, 4), 0), '
                            '||(!=(MOD(y, 100), 0), ==(MOD(y, 400), 0))))',
                            'LET(dim, IF(==(mo, 2), '
                            'IF(is_leap, 29, 28), '
                            'IF(||(==(mo, 4), ||(==(mo, 6), ==(mo, 9))), 30, 31)))',
                            C('IF', '<=(d, dim)', [
                                C('IF', '&&(>=(y, 2000), <=(y, 2100))', ['TRUE'], ['FALSE']),
                            ], [
                                'FALSE',
                            ]),
                        ], [
                            'FALSE',
                        ]),
                    ], [
                        'FALSE',
                    ]),
                ], [
                    'FALSE',
                ]),
            ]),
        ]),
    ], '// 日期串校验（对齐 security.py:243；含 strptime 的日历语义；D4：Unicode 数字）')

    # ── VALIDATE_TITLE ────────────────────────────────────────────
    src += fn('VALIDATE_TITLE', 'title', [
        '// Python: len(title) > 200 ⇒ 拒绝（**200 合法、201 拒绝**）',
        C('IF', '>(LEN(title), 200)', ['FALSE'], ['TRUE']),
    ], '// 标题校验（对齐 content.py:270 的长度规则）')

    # ── SAFE_PATH_CHECK ───────────────────────────────────────────
    src += fn('HAS_DOTDOT', 'p', [
        '// p 里是否含字面 ".."（两个点）',
        '// ⚠ WLWL 正则**不支持反斜杠转义**（实测 `\\.` 被当字面反斜杠+点，',
        '//   `\\x41` 被当字面 "x41"）⇒ 用**字符类** `[.][.]` 表达字面点。',
        '// ⚠ 也不能用 SPLIT(p, "..") + CONTAINS(..., "") 判：',
        '//   实测 SPLIT("a..b", "..") = ["a","b"]（不含空串）⇒ 判不出 "a..b"。',
        '>(LEN(RE_FIND_ALL(DOTDOT_RE, p)), 0)',
    ], '// 是否含字面 ".."')

    # ⚠ WLWL 的函数体/分组的值 = **最后一个语句的值**（探针 3o 实测）。
    #   ⇒ 分支用 list（语句分组）是**对的**写法；分支里最后一条语句的值即返回值。
    # ⚠ 零参函数必须写成 `NAME()` 才是调用；写 `NAME` 得到的是**函数值**
    #   （实测 `AT_K: expected DICT, got function`）⇒ RESULT_REJECT 要带括号。
    src += fn('SAFE_PATH_CHECK', 'path_str, base_dir', [
        '// ① D3：**拒绝输入里含 `..` 的路径**（卡片 S2-1 明确要求；',
        '//    WLWL 的 PATH_CANONICAL 是词法判定、不解析符号链接 ⇒ 防御深度）',
        C('IF', 'HAS_DOTDOT(path_str)', [
            'RESULT_REJECT()',
        ], [
            '// ② 去掉开头的 `/`（Python: if path_str.startswith("/"): path_str = path_str[1:]）',
            'LET(rel_in, IF(==(SUB(path_str, 0, 1), "/"), SUB(path_str, 1), path_str))',
            'LET(base, PATH_CANONICAL(base_dir))',
            '// ③ 绝对路径：Python 的 `base / path_str` 里绝对路径**覆盖** base',
            '//    （pathlib 语义）⇒ WLWL 侧不能用 PATH_JOIN（它只会拼接）',
            'LET(is_abs, IS_ABS_PATH(path_str))',
            'LET(target, IF(is_abs, PATH_CANONICAL(path_str), '
            'PATH_CANONICAL(PATH_JOIN(base, rel_in))))',
            '// ④ 包含判定（Python: target != base and not target.is_relative_to(base) ⇒ 拒）',
            '//    PATH_CONTAINS 是**逐段**判定 ⇒ 天然挡住 `pages-evil` 这类同前缀兄弟目录',
            C('IF', '&&(!=(target, base), !PATH_CONTAINS(base, target))', [
                'RESULT_REJECT()',
            ], [
                '// ⑤ 扩展名白名单（Python: 后缀不在白名单**且**目标是真实文件 ⇒ 拒）',
                '//    ⚠ PATH_EXT 的扩展名**不带点** ⇒ 白名单也按不带点比',
                'LET(ext, TO_LOWER(PATH_EXT(target)))',
                'LET(meta, FILE_META(target))',
                'LET(is_file, &&(AT_K(meta, "exists", FALSE), !AT_K(meta, "is_dir", TRUE)))',
                C('IF', '&&(!CONTAINS(SAFE_EXTS(), ext), is_file)', [
                    'RESULT_REJECT()',
                ], [
                    'RESULT_OK(REL_TO_BASE(base, target))',
                ]),
            ]),
        ]),
    ], '// 路径安全检查（对齐 security.py:269；D3：含 .. 的输入直接拒）')

    # ── SOURCE_PATH ───────────────────────────────────────────────
    # Python: html_path.with_suffix(".md")
    # ⚠ with_suffix 只替换**最后一个**后缀；无有效后缀则追加。
    #   "x.tar.gz" → "x.tar.md"（只去掉 .gz）
    #   "foo."    → "foo..md"（"." 不是有效后缀 ⇒ 追加）
    #   ".bashrc" → ".bashrc.md"（点开头不算后缀 ⇒ 追加）
    #   "noext"   → "noext.md"
    src += fn('SOURCE_PATH', 'html_path', [
        '// Python: html_path.with_suffix(".md")',
        '// ⚠ with_suffix 的精确规则（实测对齐 Python）：',
        '//   · 有有效后缀 ⇒ 砍掉「点 + 后缀」，再接 ".md"',
        '//     "x.tar.gz" → "x.tar.md"（只砍 .gz）',
        '//   · 无有效后缀 ⇒ **追加** ".md"（不砍任何东西）',
        '//     "foo."    → "foo..md"（点结尾 ⇒ 无后缀）',
        '//     ".bashrc" → ".bashrc.md"（点开头 ⇒ 无后缀）',
        '//     "noext"   → "noext.md"',
        '// ⚠ PATH_BASE 给的是**最后一段且不剥扩展名**；PATH_EXT 给的是',
        '//   **不带点**的扩展名（无后缀 ⇒ ""）⇒ 与 Python 的 suffix 口径一致。',
        'LET(base, PATH_BASE(html_path))',
        'LET(ext, PATH_EXT(html_path))',
        'LET(dir, PATH_DIR(html_path))',
        C('IF', '==(ext, "")', [
            '// 无有效后缀 ⇒ 整段追加 ".md"',
            'IF(==(dir, ""), +(base, ".md"), +(dir, +("/", +(base, ".md"))))',
        ], [
            '// 有后缀 ⇒ 砍掉「点 + 后缀」',
            '//   （SUB 的第三参是**长度**：LEN(base) - LEN(ext) - 1）',
            'LET(stem, SUB(base, 0, -(LEN(base), +(LEN(ext), 1))))',
            'IF(==(dir, ""), +(stem, ".md"), +(dir, +("/", +(stem, ".md"))))',
        ]),
    ], '// .html → .md 源路径（对齐 core/article_store.py:67）')

    # ── WRITE_SOURCE ──────────────────────────────────────────────
    src += fn('WRITE_SOURCE', 'html_path, content', [
        '// 原子写 .md 源（Python: 临时文件 + os.replace）',
        'LET(target, SOURCE_PATH(html_path))',
        '// ⚠ Python 的 write_source **不建父目录**（open 直接抛）⇒ 失败返回 None/抛异常。',
        '//   WLWL 侧同样**不** MKDIRS：父目录不存在 ⇒ WRITE_FILE_ATOMIC 返回 ERR。',
        '// ⚠⚠ **ERR 必须就地消费**：`LET(r, <ERR>)` 绑定**不算**消费 ——',
        '//   实测 E0103 会报在 LET 那一行，即使后面 IS_ERR(r) 也救不回来',
        '//   （§8.2：ERR 只在 §8.3 消费点被吃掉；绑定不是消费点）。',
        '//   ⇒ 把调用**直接**放进 IS_ERR(...) 里，让 ERR 在产生处就被消费。',
        'IF(IS_ERR(WRITE_FILE_ATOMIC(target, content)), RESULT_WRITE_FAIL(), RESULT_WRITE_OK(target))',
    ], '// 原子写 .md 源（对齐 core/article_store.py:72）')

    # ── UNESCAPE_TO_FIXPOINT ──────────────────────────────────────
    src += fn('UNESCAPE_TO_FIXPOINT', 'text', [
        '// 剥到不动点（Python: 最多 32 轮，变了才继续）',
        'LET MUT(current, text)',
        'LET MUT(i, 0)',
        'LET MUT(done, FALSE)',
        C('WHILE', '&&(<(i, 32), !done)', [
            'LET(decoded, HTML_UNESCAPE(current))',
            C('IF', '==(decoded, current)', [
                'SET(done, TRUE)',
            ], [
                'SET(current, decoded)',
            ]),
            'SET(i, +(i, 1))',
        ]),
        'current',
    ], '// HTML 反转义到不动点（对齐 core/article_store.py:132）')

    # ── DECODE_LEGACY / DECODE_CONTENT / DECODE_LEGACY_BODY ───────
    src += fn('DECODE_LEGACY', 'text', [
        '// legacy 体（Python: _decode_legacy）',
        '// ① EXACT 优先（Python: 第一个 pattern）',
        'LET(m, RE_SEARCH(LEGACY_EXACT_RE, text))',
        C('IF', '==(TYPE(m), "NULL")', [
            '// ② LOOSE 兜底（Python: 第二个 pattern）',
            'LET(m2, RE_SEARCH(LEGACY_LOOSE_RE, text))',
            C('IF', '==(TYPE(m2), "NULL")', [
                'NULL',
            ], [
                'UNESCAPE_TO_FIXPOINT(AT(AT_K(m2, "groups", []), 1, ""))',
            ]),
        ], [
            'UNESCAPE_TO_FIXPOINT(AT(AT_K(m, "groups", []), 1, ""))',
        ]),
    ], '// 从 legacy 注释里取出正文（对齐 _decode_legacy）')

    src += fn('DECODE_CONTENT', 'text', [
        '// ① v2 长度头优先（Python: _V2_HEADER.search(text)）',
        'LET(h, RE_SEARCH(V2_HEADER_RE, text))',
        C('IF', '==(TYPE(h), "NULL")', [
            '// ② 没有 v2 头 ⇒ 走 legacy',
            'DECODE_LEGACY(text)',
        ], [
            '// ③ body = 头之后的全部；按声明长度截断',
            'LET(groups, AT_K(h, "groups", []))',
            'LET(declared, TO_INT(AT(groups, 1, "0")))',
            'LET(start, AT_K(h, "end", 0))',
            'LET(body, SUB(text, start))',
            '//    Python: body[:length] if length <= len(body) else body.rstrip("\\n")',
            C('IF', '>(declared, LEN(body))', [
                'TRIM_TRAILING_NL(body)',
            ], [
                'SUB(body, 0, declared)',
            ]),
        ]),
    ], '// 从 HTML 里取回内嵌正文（对齐 core/article_store.py:104）')

    src += fn('DECODE_LEGACY_BODY', 'text', [
        '// 有 v2 头 ⇒ None（Python: 迁移路径用它区分「已迁移」与「待抽取」）',
        C('IF', '==(TYPE(RE_SEARCH(V2_HEADER_RE, text)), "NULL")', [
            'DECODE_LEGACY(text)',
        ], [
            'NULL',
        ]),
    ], '// 只取 legacy 体（对齐 core/article_store.py:121）')

    A('EXPORT(["VALIDATE_CONTENT", "VALIDATE_DATE_FORMAT", "VALIDATE_FILENAME", '
      '"VALIDATE_TITLE", "SAFE_PATH_CHECK", "SOURCE_PATH", "WRITE_SOURCE", '
      '"DECODE_CONTENT", "DECODE_LEGACY_BODY", "UNESCAPE_TO_FIXPOINT", '
      '"META_VALUE"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
