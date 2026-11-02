"""生成 tp/lib/template.wll —— 页面骨架模板与 string.Template 复刻（卡 S2-3）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出；
WLWL 的括号诊断只说「expected ')' got X」，不告诉你缺了几层）。

**对齐目标（真 Python 源码树）**：
  · `SUBSTITUTE(tmpl, mapping)`      == `string.Template(tmpl).substitute(mapping)`
  · `SAFE_SUBSTITUTE(tmpl, mapping)` == `string.Template(tmpl).safe_substitute(mapping)`
  · `RENDER_SKELETON(page_type, opts)` == `tinypage/core/template.py:52 render_skeleton`
  · `ESCAPE_HTML`                    == `tinypage.security.escape_html`（复用 tp/lib/esc.wll）

**逐字节对照基准**：tp/test/fixtures/template_baseline.json
    （由 tp/test/gen_template_baseline.py 用**真 Python** 生成）

**两套语义不合并（卡片硬要求）**：`SUBSTITUTE`（严格，缺键/非法 ⇒ `ERR`）与
`SAFE_SUBSTITUTE`（宽容，缺键/非法 ⇒ 原样保留）在 WLWL 侧是**两个独立函数**，
运行时**没有**任何 mode 开关 —— Python 侧本来就是两个方法。
生成器里两者共用一段「扫描骨架」的**发射代码**（同一个字符级扫描器），
差别只在「拿到 name 之后做什么」与「非法占位符怎么办」两组语句上；
⚠ 这是 Python 侧复用，产出的 WLWL 里是两份独立实现。

**`string.Template` 的精确口径（照 CPython 的 pattern 逐条复刻）**：
  pattern = `\\$(?:(?P<escaped>\\$)|(?P<named>[_a-z][_a-z0-9]*)|{(?P<braced>[_a-z][_a-z0-9]*)}|(?P<invalid>))`
  带 `re.IGNORECASE`，且 idpattern 用 `(?a:...)` ⇒ **ASCII only**：
    · `$$`      ⇒ 一个字面 `$`
    · `$name`   ⇒ `mapping[name]`（**大小写照抄**，不做归一）
    · `${name}` ⇒ `mapping[name]`
    · `$` 后面**既不是** `$` / 标识符 / `{标识符}` ⇒ invalid
    · 标识符首字符**不能**是数字；`$1x` 是 invalid
  strict：缺键 ⇒ `KeyError`；invalid ⇒ `ValueError`
  safe  ：缺键 ⇒ **原样保留**那段文本（`$name` / `${name}`）；invalid ⇒ 原样保留 `$`

**`ERR` 载荷形状（本模块自己的约定，测试侧按此断言）**：
  · `["kind": "KeyError", "key": <缺失的键名>]`
  · `["kind": "ValueError", "what": "invalid_placeholder", "pos": <`$` 的码点下标>]`
  ⚠ 构造字典**必须**用 `INDEX_SET(INDEX_SET(DICT(), …))`，不能用字典字面量
    （wllgen 的逗号表达式守卫会把 `["k": v]` 误判成裸分组 ⇒ 生成期就抛）。

**本机实测踩到的 WLWL 坑（这个模块踩到的，全部写进注释）**：
  ① **字符串字面量里的 `${...}` 是插值** —— 不是字面量。实测
     `PRINT("a${d}b")` 在 `d="k"` 时输出 `akb`；未闭合的 `"${"` 直接报
     `E0002`（unterminated string literal inside `${...}` interpolation）。
     ⇒ 本生成器把每个 `$` 都写成 `\\$`（合法转义，实测 `"\\$x"` ⇒ 字面 `$x`），
       否则夹具里的 `${a}` 会被当插值、页面骨架同理。
  ② `LET(r, <ERR>)` **绑定不算消费**（§8.5 / §8.6.3）⇒ 会返回 `ERR` 的调用
     只在**返回位**构造一次，绝不在中途绑定；`ERR(...)` 也只在函数末尾出现。
  ③ `UNWRAP_OR` **只吃 OK/ERR**（实测 `E0030: expected OK/ERR, got string`）
     ⇒ 不能拿它给「STRING | ERR」的返回值做接地；测试侧用
     `IS_ERR(...)` 判别 + `TAKE_ERR(...)` 取载荷（`TAKE_ERR` 一步取载荷且消费）。
  ④ `CONTAINS(KEYS(mapping), name)` 判键存在 —— 比 `AT_K(..., NULL)` 稳：
     后者会把**值为 NULL** 的键误判成缺失（Python 会 `str(None)` ⇒ "None"）。
  ⑤ Python 的 `convert()` 是 `str(mapping[named])` ⇒ 值**不一定**是字符串。
     WLWL 的 `+` 不做隐式转换（实测 `+(out, NULL)` ⇒
     `E0030: +: cannot add string and null`）⇒ 取值处必须 `STR(...)` 一道。
     ⚠ `STR` 与 Python 的 `str()` 只在**标量**上逐字相同：
     整数/浮点/字符串一致，`NULL`⇒"NULL"（Python "None"）、`TRUE`⇒"TRUE"
     （Python "True"）、字典⇒`[k: 1]`（Python "{'k': 1}"）⇒ 这三条
     **已在基准里登记为已知差异**（want = WLWL 实际值 + note 说明根因）。

用法：python gen_template.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'template.wll')

# ── 页面骨架 ──────────────────────────────────────────────────────
# 逐字抄自 tinypage/core/template.py:11-49。
# ⚠ **没有**结尾换行（源码是三引号串，末行 `</html>` 后紧跟 `"""`）。
# ⚠ 抄错一个字节就会被基准逐字节对拍抓住 —— 且 gen_template_baseline.py
#   会在生成期直接断言 `SKELETON == _PAGE_SKELETON`（见该文件的漂移守卫）。
SKELETON = """<!DOCTYPE html>
<html lang="$lang">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
$dark_mode_meta
$pwa_meta
$vt_meta
<meta name="description" content="$description">
$og_html
$json_ld_html
$pwa_manifest
<title>$page_title - $site_title</title>
<style>
$theme_css
</style>
$dark_css_block
$dark_mode_script
</head>
<body>
<div class="container">
  <header class="site-header">
    <a href="/" class="site-title">$site_title</a>
    <nav class="site-nav" aria-label="站点导航">
      $nav_links
      $theme_toggle
    </nav>
  </header>
  <main>
$body_content
  </main>
  <footer class="site-footer">
    <p>$footer_text</p>
  </footer>
</div>
$search_script
$mermaid_script
</body>
</html>"""

# ── render_skeleton 的参数表（照 Python 的签名与缺省值）────────────
# Python: render_skeleton(page_type, *, site_title, page_title, description,
#         body_content, theme_css, dark_css="", has_dark=False, nav_links="",
#         footer_text="", lang="zh-CN", dark_mode_meta="", pwa_meta="",
#         vt_meta="", og_html="", pwa_manifest="", dark_mode_script="",
#         search_script="", mermaid_script="", json_ld_html="", theme_toggle="")
#
# 前 5 个 Python 侧**必填**（调用方漏传会 TypeError）⇒ 本模块同样不给缺省值
# 以外的补救（缺省成 ""），因为骨架替换对空串与缺省是同一种结果 —— 差异只在
# 「Python 会抛 TypeError」这一边，已登记进基准的 note 讨论。
ESCAPED_OPTS = [
    # (键名, 缺省值) —— **必须** escape（对齐 Python 的 escape_html 调用点）
    ('lang', 'zh-CN'),
    ('site_title', ''),
    ('page_title', ''),
    ('description', ''),
]

RAW_OPTS = [
    # (键名, 缺省值) —— **不** escape（它们是已构造好的 HTML 片段）
    ('dark_mode_meta', ''),
    ('pwa_meta', ''),
    ('vt_meta', ''),
    ('og_html', ''),
    ('json_ld_html', ''),
    ('pwa_manifest', ''),
    ('theme_css', ''),
    ('dark_mode_script', ''),
    ('nav_links', ''),
    ('theme_toggle', ''),
    ('body_content', ''),
    ('search_script', ''),
    ('mermaid_script', ''),
]

# dark_css_block 的 HTML 形状 —— 逐字对齐 template.py:104-107
#   f'<style media="(prefers-color-scheme: dark)">{dark_css}</style>'
DARK_STYLE_OPEN = '<style media="(prefers-color-scheme: dark)">'
DARK_STYLE_CLOSE = '</style>'


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 白名单：`\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`（其余控制字符无法写进字面量）。
    ⚠⚠ `$` **必须**转义成 `\\$`：WLWL 的字符串字面量支持 `${...}` **插值**
       （实测 `PRINT("a${d}b")` 在 `d="k"` 时输出 `akb`）⇒ 夹具里的 `${a}`
       与骨架里的 `$lang` 若原样写进去，轻则被改写、重则 E0002。
    """
    out = []
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\0':
            out.append('\\0')
        elif ch == '$':
            out.append('\\$')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


# ── 扫描器的两组「关键动作」 ──────────────────────────────────────
def _on_name(vals, strict):
    """拿到 `name` 之后的动作（缺键分支在这里分叉）。

    vals：命中占位符后要 `SET(i, …)` 到的下标表达式
          （裸形态是 `j`，花括号形态是 `+(j, 1)`）。
    """
    if strict:
        miss = [
            'SET(ekind, "KeyError")',
            'SET(ekey, name)',
            'SET(i, ' + vals + ')',
        ]
    else:
        miss = [
            '// safe：缺键 ⇒ **原样保留**整段占位符（Python: return mo.group()）',
            'SET(out, +(out, SUB(tmpl, i, -(' + vals + ', i))))',
            'SET(i, ' + vals + ')',
        ]
    return [
        C('IF', 'HAS_KEY(mapping, name)', [
            '// Python 的 convert() 是 `str(mapping[named])` ⇒ 这里必须 STR() 一道',
            '// （不加就会对非字符串值报 `E0030: +: cannot add string and null`）。',
            '// ⚠ 已知差异：NULL / 布尔 / 容器的渲染与 Python 的 str() 不同，见基准的 note。',
            'SET(out, +(out, STR(AT_K(mapping, name, ""))))',
            'SET(i, ' + vals + ')',
        ], miss),
    ]


def _on_invalid(strict):
    """非法占位符的动作。

    ⚠ Python 的 `invalid` 组匹配的是**空串**（模式末尾的 `(?P<invalid>)`）
      ⇒ `mo.group()` 就是那个孤立的 `$`；safe 模式原样保留 `$`、只前进 1，
      后面的字符照常重扫（例：`$3` ⇒ `$` + 字面 `3`）。
    """
    if strict:
        return [
            'SET(ekind, "ValueError")',
            'SET(epos, i)',
            'SET(i, +(i, 1))',
        ]
    return [
        '// safe：非法 ⇒ 原样保留那个 `$`（Python: return mo.group()）',
        'SET(out, +(out, "$"))',
        'SET(i, +(i, 1))',
    ]


def _subst_body(strict):
    """生成 SUBSTITUTE / SAFE_SUBSTITUTE 的函数体语句列表。"""
    bad = _on_invalid(strict)

    # 花括号形态 `${name}` —— 必须「首字符是标识符起始」且立刻有个 `}`
    brace = [
        '// `${` 后面必须紧跟标识符起始字符（`${1}` / `${a b}` / `${}` 都是 invalid）',
        C('IF', '&&(<(+(i, 2), n), IS_ID_START(SUB(tmpl, +(i, 2), 1)))', [
            'SET(j, +(i, 2))',
            C('WHILE', '&&(<(j, n), IS_ID_CHAR(SUB(tmpl, j, 1)))', [
                'SET(j, +(j, 1))',
            ]),
            C('IF', '&&(<(j, n), ==(SUB(tmpl, j, 1), "}"))', [
                'SET(name, SUB(tmpl, +(i, 2), -(j, +(i, 2))))',
            ] + _on_name('+(j, 1)', strict), bad),
        ], bad),
    ]

    # 裸形态 `$name`
    bare = [
        'SET(j, +(i, 1))',
        C('WHILE', '&&(<(j, n), IS_ID_CHAR(SUB(tmpl, j, 1)))', [
            'SET(j, +(j, 1))',
        ]),
        'SET(name, SUB(tmpl, +(i, 1), -(j, +(i, 1))))',
    ] + _on_name('j', strict)

    loop_body = [
        C('IF', '!= (SUB(tmpl, i, 1), "$")', [
            '// 普通字符 —— 原样搬过去',
            'SET(out, +(out, SUB(tmpl, i, 1)))',
            'SET(i, +(i, 1))',
        ], [
            '// 命中 `$` —— 按 CPython pattern 的**分支顺序**判定：',
            '//   `$$` → named → braced → invalid',
            C('IF', '>=(+(i, 1), n)', [
                '// 结尾孤立的 `$`（后面什么都没有）',
            ] + bad, [
                'SET(next, SUB(tmpl, +(i, 1), 1))',
                C('IF', '==(next, "$")', [
                    '// `$$` ⇒ 一个字面 `$`',
                    'SET(out, +(out, "$"))',
                    'SET(i, +(i, 2))',
                ], [
                    C('IF', '==(next, "{")', brace, [
                        C('IF', 'IS_ID_START(next)', bare, bad),
                    ]),
                ]),
            ]),
        ]),
    ]

    body = [
        '// 逐**码点**扫描（LEN / SUB 都是码点口径，与 Python 的 str 索引一致）',
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        'LET(n, LEN(tmpl))',
        'LET MUT(next, "")',
        'LET MUT(j, 0)',
        'LET MUT(name, "")',
    ]
    if strict:
        body += [
            '// 错误状态用**普通值**携带（绝不在中途绑定 ERR —— 绑定不算消费）',
            'LET MUT(ekind, "")',
            'LET MUT(ekey, "")',
            'LET MUT(epos, -1)',
        ]
        cond = '&&(<(i, n), ==(ekind, ""))'
    else:
        cond = '<(i, n)'

    body.append(C('WHILE', cond, loop_body))
    # ⚠ 单条表达式**必须写单行**（多行「语句字符串」会被逐行补 `;`）
    #   ⇒ 这里的收尾表达式写成**一个**字符串项，注释另行一项。
    if strict:
        body.append(
            'IF(==(ekind, ""), out, IF(==(ekind, "KeyError"), '
            'ERR(INDEX_SET(INDEX_SET(DICT(), "kind", "KeyError"), "key", ekey)), '
            'ERR(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "kind", "ValueError"), '
            '"what", "invalid_placeholder"), "pos", epos))))'
        )
    else:
        body.append('out')
    return body


def main():
    src = []
    A = src.append
    A('// tp/lib/template.wll —— 页面骨架模板与 string.Template 复刻（卡 S2-3）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_template.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树）：')
    A('//   SUBSTITUTE(tmpl, mapping)   == string.Template(tmpl).substitute(mapping)')
    A('//   SAFE_SUBSTITUTE(tmpl, mp)   == string.Template(tmpl).safe_substitute(mp)')
    A('//   RENDER_SKELETON(type, opts) == core/template.py:52 render_skeleton')
    A('//   ESCAPE_HTML                 == security.py  escape_html（复用 ./esc.wll）')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/template_baseline.json')
    A('//   （由 tp/test/gen_template_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ 两套语义**不合并**：严格与宽容是两个独立函数，运行时没有 mode 开关。')
    A('//')
    A('// ⚠ 本机实测的四条坑（详见生成器 docstring）：')
    A('//   ① WLWL 字符串字面量里 `${...}` 是**插值** ⇒ 所有 `$` 写成 `\\$`。')
    A('//   ② `LET(r, <ERR>)` 绑定不算消费 ⇒ ERR 只在**返回位**构造一次。')
    A('//   ③ `UNWRAP_OR` 只吃 OK/ERR ⇒ 测试侧用 IS_ERR + TAKE_ERR。')
    A('//   ④ 判键存在用 `CONTAINS(KEYS(d), k)`（`AT_K(d,k,NULL)` 会误判 NULL 值）。')
    A('//   ⑤ Python 的 convert() 是 `str(mapping[named])` ⇒ 取值必须 `STR(...)`')
    A('//      （`+` 不隐式转串：实测 `+(out, NULL)` ⇒ E0030）。')
    A('//      ⚠ STR 与 Python 的 str() 只在**标量**上逐字相同：NULL/布尔/字典')
    A('//        的渲染口径不同 ⇒ 已登记 3 条已知差异（见基准的 note）。')
    A('//')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_TEST"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('')
    A('// 标识符字符集 —— 对齐 string.Template 的 idpattern `(?a:[_a-z][_a-z0-9]*)`')
    A('// ⚠ **ASCII only**：`$中文` 在 Python 侧是 invalid（因为 `(?a:…)`），')
    A('//   这里同样只认 A-Z a-z 0-9 _（不得加 CJK 区间）。')
    A('// ⚠ 用**单字符整串锚定**的 RE_TEST（它两端都锚，正合此处需要）。')
    A('LET(ID_START_RE, RE("^[A-Za-z_]$"));')
    A('LET(ID_CHAR_RE, RE("^[A-Za-z0-9_]$"));')
    A('')
    src += fn('IS_ID_START', 'c', [
        'RE_TEST(ID_START_RE, c)',
    ], '// c 是否是标识符的**起始**字符（`[A-Za-z_]`，ASCII only）')
    src += fn('IS_ID_CHAR', 'c', [
        'RE_TEST(ID_CHAR_RE, c)',
    ], '// c 是否是标识符的**后续**字符（`[A-Za-z0-9_]`，ASCII only）')
    src += fn('HAS_KEY', 'd, k', [
        '// Python 侧的 `k in mapping` —— ⚠ 不用 `AT_K(d, k, NULL)`：',
        '//   那会把**值为 NULL** 的键误判成缺失（Python 会 str(None) ⇒ "None"）。',
        'CONTAINS(KEYS(d), k)',
    ], '// 字典是否有键 k（对齐 Python 的 `k in mapping`）')

    src += fn('SUBSTITUTE', 'tmpl, mapping', _subst_body(True),
              '// 严格替换（对齐 string.Template.substitute；缺键/非法 ⇒ ERR）')
    src += fn('SAFE_SUBSTITUTE', 'tmpl, mapping', _subst_body(False),
              '// 宽容替换（对齐 safe_substitute；缺键/非法 ⇒ 原样保留）')

    # ── 页面骨架常量 ─────────────────────────────────────────────
    A('// 页面骨架 —— 逐字抄自 tinypage/core/template.py:11-49（⚠ 无结尾换行）')
    A('// ⚠ 19 个占位符全是裸 `$name`（无花括号形态）；`$page_type` **不存在** ——')
    A('//   Python 侧虽然把 page_type 传进 substitute，但骨架里没有用到它。')
    A('LET(SKELETON, ' + wl_string(SKELETON) + ');')
    A('')

    # ── RENDER_SKELETON ──────────────────────────────────────────
    body = [
        '// ① 构造 mapping（Python: t.substitute(**{...}) 的关键字表）',
        'LET MUT(m, DICT())',
        'LET MUT(dcb, "")',
        'LET MUT(ft, "")',
    ]
    for key, default in ESCAPED_OPTS:
        body.append('SET(m, INDEX_SET(m, "%s", ESCAPE_HTML(AT_K(opts, "%s", %s))))'
                    % (key, key, wl_string(default)))
    for key, default in RAW_OPTS:
        body.append('// `%s` **不** escape（已构造好的 HTML 片段）' % key)
        body.append('SET(m, INDEX_SET(m, "%s", AT_K(opts, "%s", %s)))'
                    % (key, key, wl_string(default)))
    body += [
        '// ② footer_text 是**条件** escape：空 ⇒ ""，非空 ⇒ escape',
        '//    （Python: escape_html(footer_text) if footer_text else ""）',
        C('IF', '==(AT_K(opts, "footer_text", ""), "")', [
            'SET(ft, "")',
        ], [
            'SET(ft, ESCAPE_HTML(AT_K(opts, "footer_text", "")))',
        ]),
        'SET(m, INDEX_SET(m, "footer_text", ft))',
        '// ③ dark_css_block 是**派生**占位符，不是入参',
        '//    Python: f\'<style media="(prefers-color-scheme: dark)">{dark_css}</style>\' if dark_css else ""',
        C('IF', '==(AT_K(opts, "dark_css", ""), "")', [
            'SET(dcb, "")',
        ], [
            'SET(dcb, +(' + wl_string(DARK_STYLE_OPEN) + ', +(AT_K(opts, "dark_css", ""), '
            + wl_string(DARK_STYLE_CLOSE) + ')))',
        ]),
        'SET(m, INDEX_SET(m, "dark_css_block", dcb))',
        '// ④ 复用 SUBSTITUTE（不另写一套替换）',
        '// ⚠ `has_dark` 参数 Python 接了但**没用到** ⇒ 这里同样不读（不自己发挥）。',
        '// ⚠ `page_type` 同理：骨架里没有 `$page_type`，只是签名的一部分。',
        'SUBSTITUTE(SKELETON, m)',
    ]
    src += fn('RENDER_SKELETON', 'page_type, opts', body,
              '// 渲染整页 HTML（对齐 core/template.py:52 render_skeleton）')

    A('EXPORT(["SUBSTITUTE", "SAFE_SUBSTITUTE", "RENDER_SKELETON"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
