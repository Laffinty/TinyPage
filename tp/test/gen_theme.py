"""生成 tp/lib/theme.wll —— 主题加载与校验（卡 S2-3 的「主题」部分）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出；
WLWL 的括号诊断只说「expected ')' got X」，不告诉你缺了几层）。

**对齐目标（真 Python 源码树）**：
  · `VALIDATE_THEME_NAME(n)`    == **无对应**（Python 侧不做任何校验）⇒ 新增，见 D5
  · `LOAD_THEME_CSS(dir)`       == tinypage/generator.py:134 `load_theme_css`
  · `LOAD_THEME_MANIFEST(n, d)` == tinypage/core/template.py:133 `load_theme_manifest`
  · `LIST_THEMES(d)`            == tinypage/core/template.py:144 `list_themes`

**逐字节对照基准**：tp/test/fixtures/theme_baseline.json
    （由 tp/test/gen_theme_baseline.py 用**真 Python** 生成）

**三条已裁决的预期差异（夹具 note / _meta 里都登记）**：
  · **D5** 主题名校验：Python **没有**这道校验（它直接 `themes_dir / name / "manifest.json"`）
    ⇒ `"../etc"` 这类名字 WLWL 返 `NULL`、Python 真能读到东西。WLWL **故意更严**。
  · **D6** `LIST_THEMES` 顺序：WLWL 固定**目录名升序**，Python 用 `iterdir()` 顺序
    （随文件系统变化、不可复现）。
  · **D7** `LOAD_THEME_CSS` **不追加 Pygments CSS**：Python 在 `base_css` 后面追加
    `"\\n/* Pygments syntax highlighting */\\n" + pygments_css`（业主已裁决代码高亮改
    前端 highlight.js）⇒ 这一段**不迁**。

**本机实测得到的语义事实（每条都有探针依据，写进代码注释）**：
  ① `READ_FILE` **不转换行尾**，而 Python 的 `read_text()` 走**通用换行** ——
     `\\r\\n` 与**孤立 `\\r`** 都归一成 `\\n`。只替 `\\r\\n` 不够（见 tp/README 坑 23）。
  ② `LET(x, READ_FILE(p))` **不算消费 ERR**（坑 25）⇒ 可能返 ERR 的调用一律
     **直接**放进 `IS_ERR(...)`；连 `LIST_DIR` 的返回值也**不能**先绑定再遍历。
  ③ `AT_K(NULL, key, dflt)` 是**运行时 E0030**（实测），`dflt` 不兜 `NULL` 基值
     ⇒ 必须先 `TYPE(m) == "NULL"` 判空（Python 侧 `(m.get(k, d) if m else d)` 同理）。
  ④ `std.json::PARSE` 失败是 **E0070 诊断并中止整个运行、不可捕获**（规范明文冻结）
     ⇒ 必须**先** `JSON_VALIDATE`（它失败返 `ERR` 值）。
  ⑤ WLWL 正则**不支持反斜杠转义**（坑 26）⇒ 字面点用字符类 `[.][.]`。
  ⑥ `RE_TEST` 是**整串锚定** ⇒ 不能用 `RE_TEST(RE("[.][.]"), s)` 做「含 `..`」判定，
     必须用 `RE_FIND_ALL` 的命中数（同 S2-1 的 `HAS_DOTDOT`）。
  ⑦ `LIST_DIR` 的契约就是**结果已排序**、每项是**以入参为前缀的完整路径**、
     不存在/非目录 ⇒ `ERR`（本机实测：空目录给了 `[]`、传文件路径给了 `ERR`）。
     ⇒ 直接沿用它的顺序，不用内建 `SORT`（坑 10：二次复杂度）。

**生成器自身的坑（本文件踩过，写下来省下一个人的时间）**：
  ⚠ `wllgen.C(name, *args)` 的参数**只能**是表达式**字符串**与**语句分组 list**。
    把 `C('READ_FILE', 'p')` 直接当参数节点传进去，`render_call` 会把内层调用
    渲染**两遍**（`NORMALIZE_NEWLINES(READ_FILE(p)` / `READ_FILE(p))`），
    产出语法坏掉的文件 —— 既有生成器一律用字符串参数，本文件照办。

用法：python gen_theme.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'theme.wll')

# WLWL 字符串字面量的转义白名单：\" \\ \/ \n \r \t \b \f \0 \$
# ⚠ `$` 也要转义 —— 未转义的 `$` 可能被当成 `${}` 插值的起点（实测 `"\$"` → `$`）。
ESCAPES = {
    '\\': '\\\\', '"': '\\"', '\n': '\\n', '\r': '\\r',
    '\t': '\\t', '\b': '\\b', '\f': '\\f', '\0': '\\0', '$': '\\$',
}


def W(s):
    """Python 字符串 → WLWL 字符串字面量。"""
    return '"' + ''.join(ESCAPES.get(ch, ch) for ch in s) + '"'


def main():
    src = []
    A = src.append
    A('// tp/lib/theme.wll —— 主题加载与校验（卡 S2-3 的「主题」部分）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_theme.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树）：')
    A('//   VALIDATE_THEME_NAME    == **无对应**（Python 不做校验）⇒ 新增，见 D5')
    A('//   LOAD_THEME_CSS         == generator.py:134      load_theme_css')
    A('//   LOAD_THEME_MANIFEST    == core/template.py:133  load_theme_manifest')
    A('//   LIST_THEMES            == core/template.py:144  list_themes')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/theme_baseline.json')
    A('//   （由 tp/test/gen_theme_baseline.py 用真 Python 生成）')
    A('//')
    A('// 三条已裁决的预期差异：')
    A('//   D5  主题名校验 —— Python 没有 ⇒ WLWL **故意更严**（"../etc" 直接拒）')
    A('//   D6  LIST_THEMES 顺序 —— WLWL 固定目录名升序，Python 用 iterdir() 顺序')
    A('//   D7  LOAD_THEME_CSS 不追加 Pygments CSS（业主裁决：高亮改前端 highlight.js）')
    A('//')
    A('// 本机实测的语义事实（详见生成器 docstring）：')
    A('//   ① READ_FILE 不转换行尾；Python 的 read_text() 连**孤立 \\r** 也归一成 \\n')
    A('//      ⇒ 只替 \\r\\n 不够（见 NORMALIZE_NEWLINES 与 tp/README 坑 23）。')
    A('//   ② 可能返 ERR 的调用（READ_FILE / LIST_DIR / JSON_VALIDATE）**不能先绑定**')
    A('//      （坑 25：`LET(x, <ERR>)` 不算消费）⇒ 一律直接放进 IS_ERR(...)。')
    A('//   ③ AT_K(NULL, k, d) 是**运行时 E0030**，默认值不兜 NULL 基值（实测）')
    A('//      ⇒ 先判 TYPE(m) == "NULL"（对齐 Python 的 `if m else`）。')
    A('//   ④ std.json::PARSE 失败会 **E0070 中止整个运行、不可捕获**')
    A('//      ⇒ 必须先 JSON_VALIDATE。')
    A('//   ⑤ 正则不支持反斜杠转义 ⇒ 字面点写字符类 `[.][.]`；')
    A('//      RE_TEST 整串锚定 ⇒ 判「含 ..」用 RE_FIND_ALL 的命中数。')
    A('')
    A('IMPORT("wlwl:std.fs", ["PATH_JOIN", "PATH_BASE", "READ_FILE", "LIST_DIR", '
      '"FILE_META"]);')
    A('IMPORT("wlwl:std.json", ["PARSE", "JSON_VALIDATE"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_REPLACE", "RE_FIND_ALL"]);')
    A('IMPORT("wlwl:std.str", ["CONTAINS_SUB"]);')
    A('')

    # ── 正则常量（只编译一次）────────────────────────────────────────
    A('// CRLF —— `\\r` / `\\n` 在 WLWL 字面量里是**真实字符**（转义白名单含它们）')
    A('LET(CRLF_RE, RE(' + W('\r\n') + '));')
    A('// 孤立 CR（通用换行的第二条规则；Python 也把它当换行）')
    A('LET(CR_RE, RE(' + W('\r') + '));')
    A('// 字面 ".."（字符类，不是转义 —— 坑 26）')
    A('LET(DOTDOT_RE, RE("[.][.]"));')
    A('')

    # ── NORMALIZE_NEWLINES ───────────────────────────────────────────
    src += fn('NORMALIZE_NEWLINES', 's', [
        '// 对齐 Python `read_text()` 的**通用换行**：',
        '//   `\\r\\n` → `\\n`，**孤立 `\\r`** → `\\n`（实测两条都要）。',
        '// ⚠ WLWL 的 READ_FILE **不转换**（坑 23）⇒ 必须自己归一，否则与 Python',
        '//   逐字节对照必然差「CRLF 个数」个字符。',
        '// ⚠ 顺序不可换：先吃 `\\r\\n`，再把剩下的孤立 `\\r` 换掉。',
        'RE_REPLACE(CR_RE, RE_REPLACE(CRLF_RE, s, ' + W('\n') + '), ' + W('\n') + ')',
    ], '// 换行归一（CRLF 与孤立 CR → LF；对齐 Python 的通用换行）')
    A('')

    # ── READ_TEXT_OR_EMPTY ───────────────────────────────────────────
    src += fn('READ_TEXT_OR_EMPTY', 'p', [
        '// Python: `p.read_text(encoding="utf-8") if p.exists() else ""`',
        '// ⚠ READ_FILE 对「不存在」与「是目录」都返 ERR（实测）⇒ 统一当 "" 处理。',
        '// ⚠ ERR 必须**就地**消费（坑 25：先绑定再 IS_ERR 会在绑定行报 E0103）',
        '//   ⇒ 调用直接写在 IS_ERR(...) 里。',
        C('IF', 'IS_ERR(READ_FILE(p))', [W('')],
          ['NORMALIZE_NEWLINES(READ_FILE(p))']),
    ], '// 读文本，缺失/不可读 ⇒ ""（含换行归一）')
    A('')

    # ── VALIDATE_THEME_NAME ──────────────────────────────────────────
    # ⚠ D5：Python 侧**没有**这道校验 ⇒ 这是新增的安全边界，不是复刻。
    # 六个「非法」条件用二元 `||` 折叠（WLWL 的 || 只吃 2 个实参，坑 28）。
    bad_conds = [
        '==(name, ' + W('') + ')',
        '==(name, ' + W('.') + ')',
        '==(name, ' + W('..') + ')',
        '>(LEN(RE_FIND_ALL(DOTDOT_RE, name)), 0)',
        'CONTAINS_SUB(name, ' + W('/') + ')',
        'CONTAINS_SUB(name, ' + W('\\') + ')',
    ]
    bad_expr = bad_conds[-1]
    for cond in reversed(bad_conds[:-1]):
        bad_expr = '||(%s, %s)' % (cond, bad_expr)

    src += fn('VALIDATE_THEME_NAME', 'name', [
        '// D5：Python **没有**这道校验（它直接 themes_dir / name / "manifest.json"）',
        '// ⇒ "../etc" 在 Python 侧能读到 themes 目录之外的东西。本函数**故意更严**。',
        '// 契约：非空、不是 "."、不是 ".."、不含 "/"、不含 "\\\\"、不含子串 ".."。',
        '// ⚠ 六个条件用**二元** || 折叠（坑 28：&&/|| 只吃 2 个实参）。',
        '// ⚠ 「含 ..」不能用 RE_TEST（整串锚定）—— 用命中数（见生成器 docstring ⑥）。',
        '!' + bad_expr,
    ], '// 主题名校验（D5：WLWL 新增、比 Python 更严）')
    A('')

    # ── LOAD_THEME_CSS ───────────────────────────────────────────────
    src += fn('LOAD_THEME_CSS', 'theme_dir', [
        '// Python: generator.py:134 load_theme_css',
        '//   base_css = theme.css          (缺失 ⇒ "")',
        '//   dark_css = theme.dark.css     (缺失 ⇒ "")',
        '//   has_dark = bool(dark_css)',
        '// ⚠ D7：Python 还会在 base_css 后追加 Pygments 样式表 —— **不迁**',
        '//   （业主裁决：代码高亮改前端 highlight.js）。',
        '// ⚠ PATH_JOIN 只拼不覆盖（坑 30）；这里的 theme_dir 是**目录**，不涉绝对路径。',
        'LET(base_path, PATH_JOIN(theme_dir, "theme.css"))',
        'LET(dark_path, PATH_JOIN(theme_dir, "theme.dark.css"))',
        'LET(base_css, READ_TEXT_OR_EMPTY(base_path))',
        'LET(dark_css, READ_TEXT_OR_EMPTY(dark_path))',
        '// 返回值形状与 Python 的 3 元组一一对应',
        'LET MUT(out, DICT())',
        'SET(out, INDEX_SET(out, "css", base_css))',
        'SET(out, INDEX_SET(out, "dark_css", dark_css))',
        '// Python: bool(dark_css) —— 非空即 TRUE（不 strip）',
        'SET(out, INDEX_SET(out, "has_dark", !=(LEN(dark_css), 0)))',
        'out',
    ], '// 读主题 CSS（D7：不追加 Pygments）')
    A('')

    # ── LOAD_THEME_MANIFEST ──────────────────────────────────────────
    src += fn('MANIFEST_FROM_TEXT', 'text', [
        '// ⚠⚠ `std.json::PARSE` 失败是 **E0070 诊断 + 中止整个运行**（规范明文',
        '//   冻结了 v0.3 遗留的两成员行为）⇒ **无法捕获**。',
        '//   ⇒ 必须先 `JSON_VALIDATE`（它失败返 **ERR 值**，可判）。',
        '//   Python 侧是 try/except json.JSONDecodeError ⇒ 两边都是「不合法就当没有」。',
        '// ✅ 这条写法**依赖 IF 的惰性求值**（未被选中的分支不求值）—— 已由基准',
        '//   m02（`{"name": ` 这种非法 JSON）**实测**钉住：若 IF 是严格求值，',
        '//   该用例会直接 E0070 中止，而它现在是绿的。',
        C('IF', 'IS_ERR(JSON_VALIDATE(text))', ['NULL'],
          ['PARSE(text)']),
    ], '// 文本 → 字典（非法 JSON ⇒ NULL，绝不触发 E0070）')
    A('')

    src += fn('MANIFEST_FROM_PATH', 'p', [
        '// Python: `if not manifest_path.is_file(): return None`',
        '// ⚠ manifest.json 是**目录**时：Python 的 is_file() 为假；WLWL 的 READ_FILE',
        '//   返 ERR（实测）⇒ 两边都是 NULL，无需额外判定。',
        C('IF', 'IS_ERR(READ_FILE(p))', ['NULL'],
          ['MANIFEST_FROM_TEXT(READ_FILE(p))']),
    ], '// 路径 → 字典（不是文件 ⇒ NULL）')
    A('')

    src += fn('LOAD_THEME_MANIFEST', 'theme_name, themes_dir', [
        '// ① D5：先校验主题名 —— 非法名直接 NULL，**不**去拼路径。',
        '//    Python 没有这一步（它会真的拼出 themes_dir/../etc/manifest.json）。',
        '// ② 路径 = themes_dir/theme_name/manifest.json',
        C('IF', '!VALIDATE_THEME_NAME(theme_name)', ['NULL'], [
            'LET(manifest_path, '
            'PATH_JOIN(PATH_JOIN(themes_dir, theme_name), "manifest.json"))',
            'MANIFEST_FROM_PATH(manifest_path)',
        ]),
    ], '// 读主题清单（D5：非法主题名 ⇒ NULL）')
    A('')

    # ── MANIFEST_FIELD / THEME_ENTRY / LIST_THEMES ───────────────────
    src += fn('MANIFEST_FIELD', 'manifest, key, fallback', [
        '// Python: `manifest.get(key, fallback) if manifest else fallback`',
        '// ⚠ `AT_K(NULL, k, d)` 是**运行时 E0030**（实测），默认值**不兜** NULL 基值',
        '//   ⇒ 必须先判空，这与 Python 的 `if manifest else` 一一对应。',
        '// ⚠ 键存在但值为 `null` 时**不**回落（实测 AT_K 原样给 NULL）——',
        '//   与 Python 的 `dict.get` 同口径（只有**缺键**才回落）。',
        C('IF', '==(TYPE(manifest), "NULL")', ['fallback'],
          ['AT_K(manifest, key, fallback)']),
    ], '// 取清单字段（清单为 NULL 时回落到默认值）')
    A('')

    src += fn('THEME_ENTRY', 'name, themes_dir', [
        '// Python: template.py:152 的那 5 个键 + 各自的回落规则',
        'LET(manifest, LOAD_THEME_MANIFEST(name, themes_dir))',
        'LET MUT(entry, DICT())',
        'SET(entry, INDEX_SET(entry, "name", name))',
        '// display_name 回落 manifest["name"]，再回落**目录名**',
        'SET(entry, INDEX_SET(entry, "display_name", '
        'MANIFEST_FIELD(manifest, "name", name)))',
        'SET(entry, INDEX_SET(entry, "description", '
        'MANIFEST_FIELD(manifest, "description", "")))',
        '// layouts 回落 ["blog"]',
        'SET(entry, INDEX_SET(entry, "layouts", '
        'MANIFEST_FIELD(manifest, "layouts", ["blog"])))',
        'SET(entry, INDEX_SET(entry, "default_layout", '
        'MANIFEST_FIELD(manifest, "default_layout", "blog")))',
        'entry',
    ], '// 一个主题的清单条目（5 个键）')
    A('')

    src += fn('LIST_THEMES', 'themes_dir', [
        '// 对齐 Python: template.py:144 list_themes',
        '// ⚠ 非目录 / 不存在 ⇒ LIST_DIR 返 ERR（实测）⇒ 返回空数组',
        '//   （Python: `if not themes_dir.is_dir(): return []`）。',
        '// ⚠ ERR 不能先绑定（坑 25）⇒ LIST_DIR 的调用直接写在 IS_ERR / FOR 里。',
        C('IF', 'IS_ERR(LIST_DIR(themes_dir))', ['[]'], [
            'LET MUT(out, [])',
            '// ⚠ D6：顺序。LIST_DIR 的契约就是**结果已排序**（spec std.fs），',
            '//   而它每项是「以入参为前缀的完整路径」⇒ 同一前缀下即**目录名升序**。',
            '//   Python 的 iterdir() 顺序随文件系统变化 ⇒ 这就是 D6。',
            '//   （不用内建 SORT：坑 10，二次复杂度；这里也不需要。）',
            C('FOR', 'e, LIST_DIR(themes_dir)', [
                C('IF', 'AT_K(FILE_META(e), "is_dir", FALSE)', [
                    'SET(out, PUSH(out, '
                    'THEME_ENTRY(PATH_BASE(e), themes_dir)))',
                ], ['NULL']),
            ]),
            'out',
        ]),
    ], '// 列出全部主题（D6：固定目录名升序）')
    A('')

    A('EXPORT(["VALIDATE_THEME_NAME", "LOAD_THEME_CSS", "LOAD_THEME_MANIFEST", '
      '"LIST_THEMES"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
