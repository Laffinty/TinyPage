"""生成 tp/lib/search_index.wll —— 搜索索引（卡 S2-4 的 search-index.json）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出；
WLWL 的括号诊断只说「expected ')' got X」，不告诉你缺了几层）。

**对齐目标（真 Python 源码树）**：

  · `SEARCH_INDEX(opts)` == tinypage/generator.py:599 `generate_search_index`

**接口形态**：WLWL 没有关键字参数与默认参数 ⇒ 收一个 DICT：
  · `articles`    ARRAY[DICT]   （对齐 Python 的 `articles: list[ArticleMeta]`）
  · `standalones` ARRAY[DICT]   （对齐 `standalones: list[ArticleMeta] | None`，缺省/`NULL` ⇒ 空）
  记录字段（与 `ArticleMeta` 同名）：`title` / `date` / `slug` / `tags` /
  `summary` / `category` / `file`（`status` 与 `date_obj` 本模块**不读** ——
  草稿过滤不在这一层，见下）。

**⚠ 本卡的核心：JSON 的字节口径（全部本机实测，不是读文档推的）**

  Python 侧（generator.py:625）：
    `json.dumps(data, ensure_ascii=False)` ⇒ **插入序** + 分隔符 `", "` / `": "`，
    **紧凑**（不是 `indent=2`），键序 = `title, summary, url, date, tags, category`。

  WLWL 侧（实测探针）：
    · `STRINGIFY(容器)` 是**紧凑分隔符 + 键名字典序**
      （`STRINGIFY(INDEX_SET(INDEX_SET(DICT(),"z",1),"a",2))` ⇒ `{"a":2,"z":1}`）
      ⇒ **整体序列化必然与 Python 逐字节不同**，不能用。
    · `STRINGIFY(单个字符串)` 与 Python 对单字符串的转义**逐字一致**：
      `"`→`\\"`、`\\`→`\\\\`、`\\n`/`\\t`/`\\r`/`\\b`/`\\f` 同名，
      控制字符走 `\\u00XX`（`\\x01`→`"\\u0001"`、`\\x1f`→`"\\u001f"`、
      `\\x0b`→`"\\u000b"`），而 `\\x7f`、`/`、中文、emoji **原样保留**。

  ⇒ 结论：**骨架手工拼装 + 标量走 `STRINGIFY`**，做到逐字节相同。
     （与 `tp/lib/page_common.wll` 的 `JSON_STR` 是同一套路；这里不 IMPORT 它，
      因为它没有 EXPORT 那个辅助函数，而本模块只需它一行。）

**草稿：本模块不过滤（分层，与 Python 的函数一一对应）**

  `generate_search_index` **本身不过滤草稿**（generator.py:604-624 是对 `articles`
  的无条件推导式）；排除发生在**调用方的上一层**：`cli.py:139` 调
  `list_articles(include_drafts=False)`，过滤点在 content.py:187-189。
  同族的 `generate_rss` 也一样（不过滤，`generator.py:730` 的调用方过滤）。
  ⇒ 本项目约定「一个 WLWL 模块 = 一个 Python 函数」⇒ 本模块**原样**遍历
    `articles`，过滤留给调用方。这样「连草稿一起写进索引做预览」也表达得出来。
  ⇒ 反向守卫 `guard/drafts_pass_through` 钉住这条：草稿**会**出现在产物里，
    将来谁「顺手加个过滤」就会红。

**逐字节对照基准**：tp/test/fixtures/search_index_baseline.json
    （由 tp/test/gen_search_index_baseline.py 用**真 Python** 生成）

用法：python gen_search_index.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'search_index.wll')

# 索引里的键序（与 generator.py:606-612 的字典构造顺序**逐字一致**）
FIELDS = ['title', 'summary', 'url', 'date', 'tags', 'category']
ARTICLE_URL_PREFIX = '/article/'
STANDALONE_URL_PREFIX = '/standalone/'


def wl(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 转义白名单只有 `\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`
      ⇒ `\\n` 等必须转成两字符转义；`$` 必须写成 `\\$`（否则是插值，坑 #32）。
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
        elif ch == '$':
            out.append('\\$')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def main():
    src = []
    A = src.append
    A('// tp/lib/search_index.wll —— 搜索索引（卡 S2-4 的 search-index.json）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_search_index.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（真 Python 源码树）：')
    A('//   SEARCH_INDEX(opts) == tinypage/generator.py:599 generate_search_index')
    A('//')
    A('// opts 键：articles（ARRAY[DICT]）/ standalones（ARRAY[DICT]，缺省 ⇒ 空）')
    A('// 记录字段：title / date / slug / tags / summary / category / status / file')
    A('// 索引字段：' + ' / '.join(FIELDS) + '（**不含正文**）')
    A('//')
    A('// ⚠ JSON 的字节口径（本机实测）：')
    A('//   Python 用 json.dumps(data, ensure_ascii=False) ⇒ 插入序 + ", " / ": "，')
    A('//   **紧凑**（不是 indent=2），键序 title, summary, url, date, tags, category。')
    A('//   而 STRINGIFY 对**容器**是紧凑分隔符 + **键名字典序** ⇒ 整体序列化必然不同；')
    A('//   对**单个字符串**却与 Python 的转义逐字一致 ⇒ 本模块「骨架手工拼装 +')
    A('//   标量走 JSON_STR」。')
    A('//')
    A('// 草稿：**本模块不过滤**（与 generate_search_index 一一对应）。')
    A('//   Python 的函数不对 articles 做任何过滤（generator.py:604-624）；')
    A('//   排除在调用方上一层完成（cli.py:139 → list_articles(include_drafts=False)，')
    A('//   过滤点在 content.py:187-189）。generate_rss 同此（generator.py:730 调用方过滤）。')
    A('//   ⇒ 本模块原样遍历 ⇒ 反向守卫 guard/drafts_pass_through 钉住这条。')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/search_index_baseline.json')
    A('')
    A('IMPORT("wlwl:std.json", ["STRINGIFY"]);')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_REPLACE"]);')
    A('IMPORT("wlwl:std.encode", ["UTF8_DECODE"]);')
    A('')
    A('// ── Python str.strip() 的复刻（D1 修正，2026-11-02）────────────────')
    A('// ⚠ 内建 TRIM **只剥 ASCII 空白**（实测 TRIM(U+3000/U+00A0) 原样返回），')
    A('//   而 Python 的 str.strip() 按 str.isspace() 剥 Unicode 空白')
    A('//   （NBSP U+00A0、全角空格 U+3000 都算）⇒ 必须自己构造空白集合。')
    A('// ⚠ UTF8_DECODE 的实参是**字节**（0-255），不是码点（见 tp/README.md 坑 42）。')
    A('LET(PY_WS, FUN((), (')
    A('    UTF8_DECODE([9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 194, 133, 194, 160, 225, 154, 128, 226, 128, 128, 226, 128, 129, 226, 128, 130, 226, 128, 131, 226, 128, 132, 226, 128, 133, 226, 128, 134, 226, 128, 135, 226, 128, 136, 226, 128, 137, 226, 128, 138, 226, 128, 168, 226, 128, 169, 226, 128, 175, 226, 129, 159, 227, 128, 128])')
    A(')));')
    A('// 首尾空白模式：字符类里放**字面**字符，无转义问题；')
    A('// ⚠ 结尾锚 `$` 要写成 `\\$`（裸 `$` 在 WLWL 字面量里是插值，见坑 32）。')
    A('LET(WS_LEAD_RE, RE(CAT("^[", PY_WS(), "]+")));')
    A('LET(WS_TRAIL_RE, RE(CAT("[", PY_WS(), "]+\\$")));')
    A('LET(PY_STRIP, FUN((s), (')
    A('    RE_REPLACE(WS_TRAIL_RE, RE_REPLACE(WS_LEAD_RE, s, ""), "")')
    A(')));')
    A('')

    # ── JSON 标量 ─────────────────────────────────────────────────
    src += fn('JSON_STR', 's', [
        '// JSON 字符串标量 —— 复用 STRINGIFY：实测它对**单个字符串**的转义与',
        '// Python 的 json.dumps(ensure_ascii=False) 逐字一致（含 \\u00XX 控制字符）。',
        '// ⚠ 不要拿它序列化**容器**：那会变成紧凑分隔符 + 键名字典序。',
        'STRINGIFY(s)',
    ], '// JSON 字符串标量（复用 STRINGIFY 的单字符串转义）')

    # ── tags 切分 ─────────────────────────────────────────────────
    # Python（models.py:25）：
    #   if not self.tags: return []
    #   return [t.strip() for t in self.tags.split(",") if t.strip()]
    # ⚠ `SPLIT("", ",")` 实测返回 `[""]`（1 个空串），不是 `[]`；
    #   `SPLIT` **不**剥空白 ⇒ 必须自己 TRIM 再丢空串。
    src += fn('TAG_LIST', 's', [
        '// 对齐 ArticleMeta.tag_list：按 "," 切、逐个 strip、丢掉空串',
        'LET(parts, SPLIT(s, ","))',
        'LET MUT(out, [])',
        'LET MUT(n, LEN(parts))',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, n)', [
            'LET(t, PY_STRIP(AT(parts, i, "")))',
            C('IF', '!=(t, "")', [
                'SET(out, PUSH(out, t))',
            ], [
                'NULL',
            ]),
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// String[] ← tags 串（对齐 ArticleMeta.tag_list）')

    # ── JSON 字符串数组 ───────────────────────────────────────────
    # Python 的 json.dumps 对 list 用 ", " 分隔（与对象成员同一个分隔符）
    src += fn('JSON_ARRAY', 'items', [
        '// JSON 字符串数组：["a", "b"]；空数组 "[]"',
        '// ⚠ 分隔符是 ", "（Python json.dumps 的默认 item separator），不是 ","',
        'LET MUT(out, "")',
        'LET MUT(n, LEN(items))',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, n)', [
            C('IF', '>(i, 0)', [
                'SET(out, CAT(out, ", "))',
            ], [
                'NULL',
            ]),
            'SET(out, CAT(out, JSON_STR(AT(items, i, ""))))',
            'SET(i, +(i, 1))',
        ]),
        'CAT("[", out, "]")',
    ], '// JSON 字符串数组（分隔符 ", "）')

    # ── 单条记录 ──────────────────────────────────────────────────
    # Python（generator.py:604-624）：
    #   articles    : {"title": art.title, "summary": art.summary,
    #                  "url": f"/article/{art.file}", "date": art.date,
    #                  "tags": art.tag_list, "category": art.category}
    #   standalones : {"title": page.title, "summary": page.summary,
    #                  "url": f"/standalone/{page.file}", "date": "",
    #                  "tags": [], "category": ""}
    #                  ⚠ standalone 的 date/tags/category 是**硬编码**的，
    #                    即使 meta 里有值也不进产物。
    kind_article = wl('article')
    body = [
        '// kind == "standalone" ⇒ url 用 /standalone/、date/tags/category 硬编码空',
        'LET(is_sa, ==(kind, ' + wl('standalone') + '))',
        'LET(title, AT_K(art, "title", ""))',
        'LET(summary, AT_K(art, "summary", ""))',
        'LET(file, AT_K(art, "file", ""))',
        'LET(url, CAT(IF(is_sa, ' + wl(STANDALONE_URL_PREFIX) + ', '
        + wl(ARTICLE_URL_PREFIX) + '), file))',
        'LET(date, IF(is_sa, "", AT_K(art, "date", "")))',
        'LET(tags, IF(is_sa, [], TAG_LIST(AT_K(art, "tags", ""))))',
        'LET(cat, IF(is_sa, "", AT_K(art, "category", "")))',
    ]
    # 骨架：键序与分隔符照 Python json.dumps 的默认值。
    # ⚠ tags 在 Python 侧是 **list** ⇒ 走 JSON_ARRAY，其余是字符串 ⇒ 走 JSON_STR。
    cat_args = []
    for i, f in enumerate(FIELDS):
        if i > 0:
            cat_args.append(wl(', "%s": ' % f))
        else:
            cat_args.append(wl('{"%s": ' % f))
        if f == 'tags':
            cat_args.append('JSON_ARRAY(tags)')
        else:
            cat_args.append('JSON_STR(%s)' % ('cat' if f == 'category' else f))
    cat_args.append(wl('}'))
    body.append('CAT(' + ', '.join(cat_args) + ')')
    src += fn('RECORD', 'art, kind', body,
              '// 单条索引记录（对齐 generator.py:604-624）')

    # ── 空值兜底 ──────────────────────────────────────────────────
    src += fn('AS_LIST', 'v', [
        '// 缺省 / NULL ⇒ 空数组（Python 的 `standalones=None` 等价于"没有"）',
        '// ⚠ AT_K(NULL, k, d) 是运行时 E0030 ⇒ 默认值兜不住 NULL 基值（坑 #35），',
        '//   这里兜的是**值**本身为 NULL 的情况',
        'IF(==(TYPE(v), "NULL"), [], v)',
    ], '// 非 NULL 的数组（NULL/缺省 ⇒ []）')

    # ── 主函数 ────────────────────────────────────────────────────
    src += fn('SEARCH_INDEX', 'opts', [
        '// opts 键：articles（ARRAY[DICT]）/ standalones（ARRAY[DICT]）',
        'LET(arts, AS_LIST(AT_K(opts, "articles", [])))',
        'LET(pages, AS_LIST(AT_K(opts, "standalones", [])))',
        '// 记录之间的分隔符是 ", "（Python json.dumps 的默认值）',
        'LET MUT(out, "")',
        'LET MUT(k, 0)',
        '// ① 文章：**原样**遍历（不过滤草稿 —— 与 generator.py:604-614 的推导式一致）',
        'LET MUT(na, LEN(arts))',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, na)', [
            'LET(art, AT(arts, i, DICT()))',
            C('IF', '>(k, 0)', [
                'SET(out, CAT(out, ", "))',
            ], [
                'NULL',
            ]),
            'SET(out, CAT(out, RECORD(art, ' + kind_article + ')))',
            'SET(k, +(k, 1))',
            'SET(i, +(i, 1))',
        ]),
        '// ② 独立页：同样原样 append（generator.py:615-624）',
        'LET MUT(np, LEN(pages))',
        'LET MUT(j, 0)',
        C('WHILE', '<(j, np)', [
            'LET(p, AT(pages, j, DICT()))',
            C('IF', '>(k, 0)', [
                'SET(out, CAT(out, ", "))',
            ], [
                'NULL',
            ]),
            'SET(out, CAT(out, RECORD(p, ' + wl('standalone') + ')))',
            'SET(k, +(k, 1))',
            'SET(j, +(j, 1))',
        ]),
        'CAT("[", out, "]")',
    ], '// 搜索索引 JSON（对齐 generator.py:599 generate_search_index）')

    A('EXPORT(["SEARCH_INDEX"]);')

    # ⚠ wllgen.fn(comment=…) 会自己补 `// ` 前缀，而本文件的 comment 已经带 `//`
    #   ⇒ 产物里会冒出 `// // `。写盘前收一下（纯注释行，不影响语义）。
    src = [ln.replace('// // ', '// ') for ln in src]

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
