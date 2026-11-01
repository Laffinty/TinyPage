"""生成 tp/lib/frontmatter.wll —— front-matter 元数据模块。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**对齐目标**（语义逐条来自真实实现，基准由 gen_frontmatter_baseline.py 生成）：
  · PARSE_META(text) -> DICT   == tinypage.content.parse_meta 的头部注释读取部分
      ① 只看前 7 行（索引 0..6）；② 每行先 strip；
      ③ re.match(r"<!--\\s*(\\w+):\\s*(.*)\\s*-->")（锚行首不锚行尾，(.*) 贪婪
        ⇒ 值吃到**最后一个** `-->` 之前的全部内容）；④ 白名单外静默忽略；
      ⑤ 没读到 status（或为空串）⇒ 兜底 "published"。
      ⚠ summary 从正文截 200 字属 content 层，本模块**不做**。
  · META_VALUE(v) -> STRING     == tinypage.core.article_store.meta_value
      顺序必须是：STR(v) → 连续 \\r\\n 压成**一个**空格 → ESCAPE_HTML → TRIM。
  · META_HEADER(t,d,s,tags,sum,cat,st) -> STRING
                                == tinypage.content._meta_header
      7 字段固定顺序，每行 `<!-- {k}: {META_VALUE(v)} -->\\n`，无额外分隔。

基准：tp/test/fixtures/frontmatter_baseline.json
  （meta_value / meta_header 调**真 Python 函数**；parse_meta 用逐字复刻的
    parse_meta_from_text —— 真 parse_meta 接文件路径没法直接喂字符串）

已知边界（不入测试、与 Python 的细微口径差）：
  · wlwl 正则的 \\w / \\s 是 **ASCII-only**（Python 默认 Unicode）⇒ 值两端若是
    Unicode 空白（如 U+00A0、全角空格），strip 口径可能不同；测试只用 ASCII 空白。
  · 单独 \\r 作行分隔符（老 Mac 换行）不切行（SPLIT_LINES 按 \\n 切）；测试只用
    \\n 与 \\r\\n。

用法：python gen_frontmatter.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'frontmatter.wll')

ALLOWED_KEYS = [
    'title', 'date', 'slug', 'tags',
    'summary', 'category', 'status', 'markdown',
]
HEADER_KEYS = [
    'title', 'date', 'slug', 'tags', 'summary', 'category', 'status',
]


def _allowed_chain():
    """is_allowed_key 的 || 链（左嵌套，括号由构造保证平衡）。"""
    expr = '==(key, "%s")' % ALLOWED_KEYS[0]
    for k in ALLOWED_KEYS[1:]:
        expr = '||(%s, ==(key, "%s"))' % (expr, k)
    return expr


def _header_call():
    """META_HEADER 的单条 CAT 调用（7 字段固定顺序，每行以 \\n 结尾）。"""
    parts = []
    for k in HEADER_KEYS:
        parts.append('"<!-- %s: "' % k)
        parts.append('META_VALUE(%s)' % k)
        # 生成器 → .wll：文件里是 `\n`（反斜杠+n 两字符），WLWL 解析成换行
        parts.append('" -->\\n"')
    return 'CAT(%s)' % ', '.join(parts)


def main():
    src = []
    A = src.append
    A('// tp/lib/frontmatter.wll —— front-matter 元数据模块')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_frontmatter.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python）：')
    A('//   PARSE_META  == tinypage.content.parse_meta 的头部注释读取部分')
    A('//   META_VALUE  == tinypage.core.article_store.meta_value')
    A('//   META_HEADER == tinypage.content._meta_header')
    A('// 逐字节对照基准：tp/test/fixtures/frontmatter_baseline.json')
    A('//   （由 tp/test/gen_frontmatter_baseline.py 用真 Python 生成）')
    A('//')
    A('// 语义要点：')
    A('//   · PARSE_META 只读**前 7 行**；每行先 strip；白名单外的键静默忽略；')
    A('//     `(.*)` 贪婪 ⇒ 值吃到最后一个 `-->` 之前的全部内容；')
    A('//     没读到 status（或为空串）⇒ 兜底 "published"。')
    A('//   · META_VALUE 顺序：STR(v) → 连续换行压成一个空格 → HTML 转义 → TRIM')
    A('//     （顺序不可换：转义后就没有裸换行可压了）。')
    A('//   · META_HEADER 7 行固定顺序，恰好落在 PARSE_META 的前 7 行里（自洽）。')
    A('//')
    A('// 已知边界（与 Python 的细微口径差，详见生成器 docstring）：')
    A('//   · 正则 \\w / \\s 为 ASCII-only；值两端只保证 ASCII 空白的 strip 一致。')
    A('//   · 单独 \\r 不切行（SPLIT_LINES 按 \\n 切）；测试用 \\n 与 \\r\\n。')
    A('')
    A('IMPORT("wlwl:std.str", ["SPLIT_LINES", "CAT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_SEARCH", "RE_REPLACE"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('')
    A('// 头部注释正则 —— 逐字复刻 Python')
    A('//   re.match(r"<!--\\s*(\\w+):\\s*(.*)\\s*-->", line.strip())')
    A('// `(?m)` 使 RE_SEARCH 的 ^ 按行锚定：行已 strip ⇒ 与 re.match 等价。')
    A('// ⚠ 文件里必须写 `\\\\s`（WLWL 字符串 `\\s` → 正则 \\s；写 \\s 会 E0001）。')
    A('LET(META_RE, RE("(?m)^<!--\\\\s*(\\\\w+):\\\\s*(.*)\\\\s*-->"));')
    A('')
    A('// meta_value 的 _UNSAFE_META = re.compile(r"[\\r\\n]+")：')
    A('// 连续 \\r/\\n 序列压成**一个**空格（"a\\n\\n\\nb" → "a b"，不是三个空格）。')
    A('LET(UNSAFE_META_RE, RE("[\\\\r\\\\n]+"));')
    A('')

    # ── 白名单判定 ────────────────────────────────────────────
    src += fn('is_allowed_key', 'key', [
        _allowed_chain(),
    ], '// 键是否在 8 键白名单里（白名单外静默忽略）')

    # ── META_VALUE ────────────────────────────────────────────
    src += fn('META_VALUE', 'v', [
        '// 顺序必须是：STR(v) → 压连续换行 → ESCAPE_HTML → TRIM',
        '// （TRIM 放最后：html.escape 不动两端空白，压完换行才轮到 trim 收口）',
        'TRIM(ESCAPE_HTML(RE_REPLACE(UNSAFE_META_RE, STR(v), " ")))',
    ], '// 元数据值 → 单行安全串（对齐 meta_value）')

    # ── PARSE_META ────────────────────────────────────────────
    src += fn('PARSE_META', 'text', [
        'LET(lines, SPLIT_LINES(text))',
        '// 只读前 7 行（Python: for i, line in enumerate(f): if i >= 7: break）',
        'LET(limit, IF(>(LEN(lines), 7), 7, LEN(lines)))',
        'LET MUT(meta, DICT())',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, limit)', [
            'LET(line, TRIM(lines[i]))',
            'LET(m, RE_SEARCH(META_RE, line))',
            C('IF', '==(TYPE(m), "NULL")', 'NULL', [
                '// groups = [整体匹配, key, val]（RE_SEARCH 形状）',
                'LET(g, m["groups"])',
                'LET(key, g[1])',
                'LET(val, TRIM(g[2]))',
                C('IF', 'is_allowed_key(key)', [
                    '// 白名单内才记录；INDEX_SET 同键后写覆盖先写（与 setattr 一致）',
                    'SET(meta, INDEX_SET(meta, key, val))',
                    'NULL',
                ], 'NULL'),
            ]),
            'SET(i, +(i, 1))',
        ]),
        '// if not meta.status: meta.status = "published"（缺省或空串都兜底）',
        'IF(==(AT_K(meta, "status", ""), ""), '
        '(SET(meta, INDEX_SET(meta, "status", "published")); NULL), NULL)',
        'meta',
    ], '// 读 .html 头部元数据 → DICT（对齐 parse_meta 的头部读取部分）')

    # ── META_HEADER ───────────────────────────────────────────
    src += fn('META_HEADER', 'title, date, slug, tags, summary, category, status', [
        '// 7 字段固定顺序，每行 `<!-- {k}: {META_VALUE(v)} -->` 以 \\n 结尾、',
        '// 各行无额外分隔直接相连 ⇒ 正好 7 行，落在 PARSE_META 的前 7 行里',
        _header_call(),
    ], '// 元数据注释头（对齐 _meta_header）')

    A('EXPORT(["PARSE_META", "META_VALUE", "META_HEADER"]);')
    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
