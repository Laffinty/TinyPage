"""生成 tp/lib/admin_actions.wll —— 文章/独立页 CRUD + 上传（卡 S4-4）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**对齐目标（真 Python 源码树，tinypage/admin/actions.py）**：

| 导出 | Python 函数 | 位置 |
|---|---|---|
| `CREATE_ARTICLE(opts)` | `create_article` | actions.py:37 |
| `SAVE_ARTICLE(opts)`   | `save_article`   | actions.py:67 |
| `DELETE_ARTICLE(opts)` | `delete_article_action` | actions.py:96 |
| `CREATE_PAGE(opts)`    | `create_page`    | actions.py:117 |
| `SAVE_PAGE(opts)`      | `save_page`      | actions.py:143 |
| `DELETE_PAGE(opts)`    | `delete_page_action` | actions.py:171 |
| `UPLOAD_IMAGE(opts)`   | `upload_image`   | actions.py:194 |
| `REGEN(opts)`          | `regenerate`     | actions.py:268 |
| `PREVIEW(opts)`        | `live_preview`   | actions.py:285 |
| `SET_THEME(opts)`      | `set_theme` + `_save_theme_config` | actions.py:348 / :367 |

**不覆盖**（本卡范围外）：`ai_assist`（actions.py:296，依赖外部 AI 服务）、
`translate_article_action`（:332，依赖 `content.translate_article`）、
`login_handler` / `logout_handler`（:382 / :426，会话与 CSRF 中间件）。

**失败映射（WLWL 没有异常）**：

Python 侧有两种对外表现 ——
  · 表单级校验 ⇒ `error_response(400/409, "<msg>")`（HTTP 层，带状态码）；
  · 写盘层 ⇒ `raise ValueError("<msg>")`（被 WSGI 兜成 500）。
WLWL 侧统一成 `{"ok": FALSE, "error": "<同一句 msg>"}`，**消息文本逐字照抄**，
状态码只在这里登记（调用方要 400/409 时按下面这张表）：

| error 前缀 | Python 状态码 | 出处 |
|---|---|---|
| `Missing fields` / `Invalid filename` / `Invalid slug` / `Missing theme name` / `Theme not found` | 400 | actions.py:49/82/130/155/177/351 |
| `Page already exists` | 409 | actions.py:132 |
| `Missing filename or data` / `File type not allowed: ` / `Invalid base64 data` / `File too large (max 10MB)` / `Invalid image format` | 400（JSON） | actions.py:201/210/222/225/246 |
| `Invalid filename: ` / `Title invalid or too long: ` / `Content validation failed: length=` / `Invalid date format: ` / `Invalid page filename: ` | ValueError ⇒ 500 | content.py:269/271/273/275/714/716/718 |

**与 Python 的已知差异**（每条都在 `tp/test/gen_admin_actions_baseline.py` 里有实测依据）：

  D1  `BASE64_DECODE` **不能搬二进制**：它返回 `RESULT<STRING>`，非 UTF-8 字节
      ⇒ `ERR[kind: DecodeError, reason: decoded bytes are not valid UTF-8]`（本机实测）。
      ⇒ 上传路径**自己解码**成 `ARRAY[INTEGER]`，再用 `WRITE_BYTES` 落盘。
      （Python: `base64.b64decode` 返回 `bytes`，没有这层「必须是文本」的限制。）
  D2  重名后缀：Python 用 `secrets.token_urlsafe(4)`（6 字符 base64url）。
      WLWL 用 `opts["suffix"]`，缺省 `RANDOM_HEX(4)`（8 个十六进制字符）——
      两者都是「URL 安全 + 随机」，**长度与字母表不同**。测试里给确定的 suffix。
  D3  `slugify` 的 `\\w`：Python 的 `\\w` 是 **Unicode**（`ü` 保留），WLWL 侧只认
      ASCII + CJK ⇒ `ü` 被换成 `-`。纯 ASCII / 纯 CJK 输入**无差异**。
  D4  `slugify` 兜底 `untitled-{int(time.time())}`：WLWL 用 `NOW()/1000`（秒）。
      两者都是「秒级时间戳」，但时区/取值不同 ⇒ 只保证**形状**相同
      （`^untitled-[0-9]+$`），不保证数值相同。
  D5  写盘口径：`create_article` / `save_article` 在 Python 里是
      `skip_html_generation=True`（actions.py:58/87）⇒ 文章 `.html` 只有 7 行
      meta 头、正文在兄弟 `.md` 里。本模块照抄。
      独立页 Python 会**当场**渲染整页（`write_standalone`），本模块只写
      2 行 meta 头（`title`/`summary`）+ `.md`：**整页由 REGEN/BUILD 生成**，
      否则本模块要拉进 theme/template 全套上下文（超出本卡职责边界）。
  D6  `.tinypage/config.json`：Python 用 `json.dumps(ensure_ascii=False, indent=2)`
      ⇒ 插入序 + 缩进；WLWL 用 `STRINGIFY` ⇒ **紧凑 + 键名排序**。
      **语义相同、字节不同**（测试按语义比）。
  D7  换行：Python 在 Windows 上文本模式写 **CRLF**；本模块（`WRITE_FILE_ATOMIC`
      / `WRITE_SOURCE`）写 **LF** ⇒ 比对时两侧都归一化成 LF（陷阱表 #55）。
  D8  上传目录的 `YYYY-MM`：Python 取 `datetime.now()`（**本地时区**）；
      本模块取 `opts["year"]`/`opts["month"]`，缺省从 `NOW()`（epoch 毫秒，**UTC**）
      推出来 ⇒ 只在「跨时区且跨月边界」时才可能差一个月。
  D9  `delete_article` 的回滚：Python 用 `shutil.move(backup, path)` 直接**覆盖**；
      本模块在「目标仍存在」时只删掉多余备份、目标不存在时才 `MOVE` 回去
      ⇒ 落盘效果相同（文章仍在），且能处理「COPY 当场失败、目标根本没被删」。
  D10 `upload_image` 的两处**源码原样照抄的怪癖**（不是本模块引入的）：
      · `.jpeg` 在扩展名白名单里，但 magic 表里 JPEG 的 expected_ext 是 `.jpg`
        ⇒ **`.jpeg` 永远被 "Invalid image format" 拒掉**（actions.py:207-243）。
      · WEBP 的 `raw_data[8:12] == b"WEBP"` 分支是**死代码**：外层 `ext == expected_ext`
        已经先命中 ⇒ 只要前 4 字节是 `RIFF` 就通过（actions.py:237-243）。
  D11 文件大小上限（10MB）与 `MAX_WRITE_BYTES`（64MiB）无关；本模块先解码再判
      `LEN(bytes) > 10485760`，与 Python 的 `len(raw_data) > 10*1024*1024` 一致。

**取的是 Python 的哪个口径**：`validate_*` 一律复用 `tp/lib/article_store.wll`
（S2-1 已交付、已与 security.py 逐字对齐）；markdown 复用 `tp/lib/md.wll`
（S2-3，对齐 mistune）；meta 头复用 `tp/lib/frontmatter.wll::META_HEADER`。

用法：python gen_admin_actions.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn as _wfn, write  # noqa: E402


def _strip_semis(node):
    """递归去掉语句串**结尾**的 `;`。

    `wllgen.render_group` 自己会在「非最后一条」语句后补 `;`，而**最后一条**不补
    （它后面紧跟分组的 `)`）。手写语句串时若自己带了 `;`，非末条会变成 `;;`
    （`E0010: expected expression, got Semicolon`）、末条会变成 `SET(…);)`
    ⇒ 统一在生成期剥掉，让渲染器独占「补分号」这件事。
    """
    if isinstance(node, str):
        return node[:-1] if node.endswith(';') else node
    if isinstance(node, list):
        if node and node[0] == 'call':
            return [node[0], node[1]] + [_strip_semis(a) for a in node[2:]]
        return [_strip_semis(x) for x in node]
    return node


def fn(name, params, body, comment=None):
    """包一层：先剥语句串尾部的 `;`，再交给 wllgen.fn。"""
    return _wfn(name, params, _strip_semis(body), comment)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'admin_actions.wll')

# 顶层名一律 ADM_ 前缀：陷阱表 #52（顶层绑定跨模块共享，会顶掉被 import 模块的私有名）
EXPORTS = [
    'CREATE_ARTICLE', 'SAVE_ARTICLE', 'DELETE_ARTICLE',
    'CREATE_PAGE', 'SAVE_PAGE', 'DELETE_PAGE',
    'SET_THEME', 'PREVIEW', 'REGEN', 'UPLOAD_IMAGE',
]


def main():
    src = []
    A = src.append

    # ── 文件头 ────────────────────────────────────────────────────
    A('// tp/lib/admin_actions.wll —— 文章/独立页 CRUD + 上传（卡 S4-4）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_admin_actions.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标（tinypage/admin/actions.py）：')
    A('//   CREATE_ARTICLE(opts) == actions.py:37   create_article')
    A('//   SAVE_ARTICLE(opts)   == actions.py:67   save_article')
    A('//   DELETE_ARTICLE(opts) == actions.py:96   delete_article_action')
    A('//   CREATE_PAGE(opts)    == actions.py:117  create_page')
    A('//   SAVE_PAGE(opts)      == actions.py:143  save_page')
    A('//   DELETE_PAGE(opts)    == actions.py:171  delete_page_action')
    A('//   UPLOAD_IMAGE(opts)   == actions.py:194  upload_image')
    A('//   REGEN(opts)          == actions.py:268  regenerate')
    A('//   PREVIEW(opts)        == actions.py:285  live_preview')
    A('//   SET_THEME(opts)      == actions.py:348  set_theme (+ :367 _save_theme_config)')
    A('//')
    A('// 返回值统一 `{"ok": TRUE, ...}` / `{"ok": FALSE, "error": "<msg>"}`。')
    A('// 映射规则与 HTTP 状态码对照表见生成器 docstring（消息文本逐字照抄 Python）。')
    A('//')
    A('// ⚠ 与 Python 的 11 条已知差异（D1–D11）同样见生成器 docstring；')
    A('//   其中 D1 是硬约束：BASE64_DECODE 只能产出**文本**，二进制必须自己解码。')
    A('//')
    A('// 逐字节/逐字对照基准：tp/test/fixtures/admin_actions_baseline.json')
    A('')

    # ── import ────────────────────────────────────────────────────
    A('IMPORT("wlwl:std.str", ["CAT", "INDEX_OF"]);')
    A('IMPORT("wlwl:std.text", ["TO_LOWER", "TO_INT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_TEST", "RE_REPLACE"]);')
    A('IMPORT("wlwl:std.json", ["STRINGIFY", "PARSE", "JSON_VALIDATE"]);')
    A('IMPORT("wlwl:std.time", ["NOW"]);')
    A('IMPORT("wlwl:std.encode", ["RANDOM_HEX"]);')
    A('IMPORT("wlwl:std.fs", ["PATH_JOIN", "PATH_BASE", "PATH_EXT", "MKDIRS",')
    A('     "EXISTS", "READ_FILE", "FILE_META", "COPY", "MOVE", "REMOVE",')
    A('     "WRITE_BYTES", "WRITE_FILE_ATOMIC"]);')
    A('IMPORT("./article_store.wll", ["VALIDATE_FILENAME", "VALIDATE_CONTENT",')
    A('     "VALIDATE_DATE_FORMAT", "VALIDATE_TITLE", "SOURCE_PATH", "WRITE_SOURCE"]);')
    A('IMPORT("./frontmatter.wll", ["META_VALUE", "META_HEADER"]);')
    A('IMPORT("./md.wll", ["RENDER_MD"]);')
    A('')

    # ── 常量 ──────────────────────────────────────────────────────
    A('// 独立页文件名模式 —— Python: content.py:662 SAFE_PAGE_FILENAME')
    A('// ⚠ WLWL 正则**不支持反斜杠转义** ⇒ 字面点写 `[.]`（本仓库既有写法）。')
    A('LET(ADM_PAGE_RE, RE("^[a-zA-Z0-9一-龥_-]+[.]html$"));')
    A('')
    A('// slugify 的两个模式（security.py:368-369）')
    A('// ⚠ Python 的 `\\w` 是 Unicode；这里只认 ASCII + CJK ⇒ 见差异 D3。')
    A('LET(ADM_SLUG_BAD_RE, RE("[^A-Za-z0-9_一-龥-]"));')
    A('LET(ADM_SLUG_MULTI_RE, RE("[-][-]+"));')
    A('')
    A('// 上传文件名净化 —— Python: actions.py:203 re.sub(r"[^a-zA-Z0-9._-]", "_", filename)')
    A('LET(ADM_FN_JUNK_RE, RE("[^a-zA-Z0-9._-]"));')
    A('')
    A('// base64 字母表（RFC 4648 标准表，与 Python base64.b64decode 同一张）')
    A('LET(ADM_B64_ALPHA, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");')
    A('// Python 的 b64decode(validate=False) **丢弃**字母表外的字符（含换行/空白）')
    A('LET(ADM_B64_JUNK_RE, RE("[^A-Za-z0-9+/=]"));')
    A('')
    A('// 扩展名白名单 —— Python: actions.py:207 ALLOWED_EXTENSIONS（不带点，PATH_EXT 无前导点）')
    A('LET(ADM_IMG_EXTS_RE, RE("^(jpg|jpeg|png|gif|webp)$"));')
    A('')
    A('// 10MB —— Python: actions.py:224 len(raw_data) > 10 * 1024 * 1024')
    A('LET(ADM_MAX_IMAGE_BYTES, 10485760);')
    A('')
    A('// 预览空内容占位 —— Python: actions.py:290（整串照抄）')
    A('LET(ADM_PREVIEW_PLACEHOLDER, "<p class=\\"preview-placeholder\\">（无内容）</p>");')
    A('')

    # ── 小工具 ────────────────────────────────────────────────────
    src += fn('ADM_AS', 'v', [
        '// 非 STRING 一律当空串（对齐 Python 的 `post_data.get(k, [""])[0]`）',
        'IF(==(TYPE(v), "STRING"), (v), (""))',
    ], '// 取 opts 里的字符串值')

    src += fn('ADM_ERR', 'msg', [
        '// 统一失败形状',
        'INDEX_SET(INDEX_SET(DICT(), "ok", FALSE), "error", msg)',
    ], '// {"ok": FALSE, "error": msg}')

    src += fn('ADM_OK', 'key, val', [
        '// 统一成功形状：{"ok": TRUE, <key>: <val>}',
        'INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), key, val)',
    ], '// {"ok": TRUE, key: val}')

    src += fn('ADM_OK0', '', [
        '// 无附加字段的成功',
        'INDEX_SET(DICT(), "ok", TRUE)',
    ], '// {"ok": TRUE}')

    src += fn('ADM_IS_FILE', 'p', [
        '// 对齐 Python 的 `path.is_file()`（同名的目录不算）',
        '// ⚠ FILE_META 可能返 ERR（权限）⇒ 必须先 IS_ERR 消费（陷阱 #25）',
        'IF(IS_ERR(FILE_META(p)), (FALSE), (LET(m, FILE_META(p)); &&(AT_K(m, "exists", FALSE), !(AT_K(m, "is_dir", TRUE)))))',
    ], '// path.is_file()')

    src += fn('ADM_MKDIRS_OK', 'p', [
        '// mkdir -p；已存在即成功（std 规范）',
        'IF(IS_ERR(MKDIRS(p)), (FALSE), (TRUE))',
    ], '// mkdirs → 成功与否')

    src += fn('ADM_WRITE_ATOMIC', 'p, text', [
        '// ⚠ WRITE_FILE_ATOMIC 成功返 NULL、失败返 ERR（陷阱表；本仓库既有先例）',
        '// ⚠ 它**不建父目录** ⇒ 调用方负责 MKDIRS',
        'IF(IS_ERR(WRITE_FILE_ATOMIC(p, text)), (FALSE), (TRUE))',
    ], '// 原子写文本 → 成功与否')

    src += fn('ADM_READ_TEXT', 'p', [
        '// 读文本；读不到返 NULL（不抛）',
        'IF(IS_ERR(READ_FILE(p)), (NULL), (READ_FILE(p)))',
    ], '// 读文本或 NULL')

    src += fn('ADM_STRIP_DASH_L', 's', [
        '// Python: .strip("-") 的左半边',
        'LET MUT(out, s);',
        'LET MUT(done, FALSE);',
        C('WHILE', '!done', [
            C('IF', '&&(>(LEN(out), 0), ==(SUB(out, 0, 1), "-"))', [
                'SET(out, SUB(out, 1))',
            ], [
                'SET(done, TRUE)',
            ]),
        ]),
        'out',
    ], '// 去掉开头的 -')

    src += fn('ADM_STRIP_DASH_R', 's', [
        '// Python: .rstrip("-")（也用于 .strip("-") 的右半边）',
        'LET MUT(out, s);',
        'LET MUT(done, FALSE);',
        C('WHILE', '!done', [
            C('IF', '&&(>(LEN(out), 0), ==(SUB(out, -(LEN(out), 1), 1), "-"))', [
                'SET(out, SUB(out, 0, -(LEN(out), 1)))',
            ], [
                'SET(done, TRUE)',
            ]),
        ]),
        'out',
    ], '// 去掉结尾的 -')

    # slugify —— security.py:357
    src += fn('ADM_SLUGIFY', 'title, fallback', [
        '// Python: slugify(text, max_length=80, fallback="")',
        '//   slug = re.sub(r"[^\\w\\u4e00-\\u9fa5-]", "-", text.lower()).strip("-")',
        '//   slug = re.sub(r"-{2,}", "-", slug)',
        '//   if max_length: slug = slug[:max_length].rstrip("-")',
        '//   return slug or fallback or f"untitled-{int(time.time())}"',
        'LET(low, TO_LOWER(title));',
        'LET(rep, RE_REPLACE(ADM_SLUG_BAD_RE, low, "-"));',
        'LET(stripped, ADM_STRIP_DASH_L(rep));',
        'LET(stripped2, ADM_STRIP_DASH_R(stripped));',
        'LET(collapsed, RE_REPLACE(ADM_SLUG_MULTI_RE, stripped2, "-"));',
        'LET(cut, IF(>(LEN(collapsed), 80), (SUB(collapsed, 0, 80)), (collapsed)));',
        'LET(trunc, ADM_STRIP_DASH_R(cut));',
        '// 兜底：Python 用 int(time.time())（秒）——见差异 D4',
        'IF(!=(trunc, ""), (trunc), (IF(!=(ADM_AS(fallback), ""), (fallback), (CAT("untitled-", STR(/(NOW(), 1000)))))))',
    ], '// security.py:357 slugify（D3/D4 见 docstring）')

    # 独立页文件名校验 —— content.py:665
    src += fn('ADM_VALIDATE_PAGE_FILENAME', 'fname', [
        '// Python: SAFE_PAGE_FILENAME.match 且不含 ".." / "/" / "\\\\"',
        '&&(RE_TEST(ADM_PAGE_RE, fname), &&(==(INDEX_OF(fname, ".."), -1), &&(==(INDEX_OF(fname, "/"), -1), ==(INDEX_OF(fname, "\\\\"), -1))))',
    ], '// content.py:665 validate_page_filename')

    # ── 写文章 ────────────────────────────────────────────────────
    src += fn('ADM_WRITE_ARTICLE', 'd', [
        '// 对齐 content.py:241 write_article（调用方传 skip_html_generation=True）',
        '// d 的键：dir / fname / title / date / slug / content / tags / summary /',
        '//           category / status',
        '// ⚠ 校验顺序与 Python **逐行一致**（content.py:268-275）：',
        '//   文件名 → 标题长度 → 正文 → 日期格式',
        'LET(dirx, ADM_AS(AT_K(d, "dir", "")));',
        'LET(fname, ADM_AS(AT_K(d, "fname", "")));',
        'LET(title, ADM_AS(AT_K(d, "title", "")));',
        'LET(date, ADM_AS(AT_K(d, "date", "")));',
        'LET(slug, ADM_AS(AT_K(d, "slug", "")));',
        'LET(content, ADM_AS(AT_K(d, "content", "")));',
        'LET(tags, ADM_AS(AT_K(d, "tags", "")));',
        'LET(summary, ADM_AS(AT_K(d, "summary", "")));',
        'LET(category, ADM_AS(AT_K(d, "category", "")));',
        'LET(status, ADM_AS(AT_K(d, "status", "")));',
        'LET(path, PATH_JOIN(dirx, fname));',
        C('IF', '!VALIDATE_FILENAME(fname)', [
            'ADM_ERR(CAT("Invalid filename: ", fname))',
        ], [C('IF', '!VALIDATE_TITLE(title)', [
            'ADM_ERR(CAT("Title invalid or too long: ", STR(LEN(title))))',
        ], [C('IF', '!VALIDATE_CONTENT(content)', [
            'ADM_ERR(CAT("Content validation failed: length=", STR(LEN(content))))',
        ], [C('IF', '!VALIDATE_DATE_FORMAT(date)', [
            'ADM_ERR(CAT("Invalid date format: ", date))',
        ], [
            '// ① .md 源（Python: write_source(path, content)）',
            C('IF', '!AT_K(WRITE_SOURCE(path, content), "ok", FALSE)', [
                'ADM_ERR(CAT("Write failed: ", path))',
            ], [
                '// ② .html = 7 行 meta 头（skip_html_generation ⇒ full_html=""）',
                C('IF', '!ADM_WRITE_ATOMIC(path, META_HEADER(title, date, slug, tags, summary, category, status))', [
                    'ADM_ERR(CAT("Write failed: ", path))',
                ], [
                    'ADM_OK("file", fname)',
                ]),
            ]),
        ])])])]),
    ], '// 对齐 content.py:241 write_article')

    # ── 写独立页 ──────────────────────────────────────────────────
    src += fn('ADM_WRITE_STANDALONE', 'd', [
        '// 对齐 content.py:702 write_standalone 的**校验**部分；',
        '// 整页渲染交给 REGEN/BUILD（差异 D5）。',
        '// d 的键：dir / fname / title / content / summary',
        'LET(dirx, ADM_AS(AT_K(d, "dir", "")));',
        'LET(fname, ADM_AS(AT_K(d, "fname", "")));',
        'LET(title, ADM_AS(AT_K(d, "title", "")));',
        'LET(content, ADM_AS(AT_K(d, "content", "")));',
        'LET(summary, ADM_AS(AT_K(d, "summary", "")));',
        'LET(path, PATH_JOIN(dirx, fname));',
        C('IF', '!ADM_VALIDATE_PAGE_FILENAME(fname)', [
            'ADM_ERR(CAT("Invalid page filename: ", fname))',
        ], [C('IF', '!VALIDATE_TITLE(title)', [
            'ADM_ERR(CAT("Title invalid or too long: ", STR(LEN(title))))',
        ], [C('IF', '!VALIDATE_CONTENT(content)', [
            'ADM_ERR(CAT("Content validation failed: length=", STR(LEN(content))))',
        ], [
            C('IF', '!AT_K(WRITE_SOURCE(path, content), "ok", FALSE)', [
                'ADM_ERR(CAT("Write failed: ", path))',
            ], [
                '// Python: `<!-- title: … -->\\n<!-- summary: … -->\\n` + full_html',
                C('IF', '!ADM_WRITE_ATOMIC(path, CAT("<!-- title: ", META_VALUE(title), " -->\\n", "<!-- summary: ", META_VALUE(summary), " -->\\n"))', [
                    'ADM_ERR(CAT("Write failed: ", path))',
                ], [
                    'ADM_OK("file", fname)',
                ]),
            ]),
        ])])]),
    ], '// 对齐 content.py:702 write_standalone 的校验')

    # ── 删除的回滚 ────────────────────────────────────────────────
    src += fn('ADM_RESTORE', 'path, backup, src, src_backup, had_src, msg', [
        '// 对齐 content.py:145-150 的 `except` 分支：把备份移回。',
        '// ⚠ 与 Python 的唯一差别（差异 D9）：目标**还在**时只删掉多余备份，',
        '//   不盲目 MOVE 覆盖（WLWL 的 MOVE 不保证覆盖语义）。',
        C('IF', 'EXISTS(backup)', [
            C('IF', 'EXISTS(path)', [
                'IF(IS_ERR(REMOVE(backup)), (NULL), (NULL))',
            ], [
                'IF(IS_ERR(MOVE(backup, path)), (NULL), (NULL))',
            ]),
        ], [
            'NULL',
        ]),
        C('IF', '&&(had_src, EXISTS(src_backup))', [
            C('IF', 'EXISTS(src)', [
                'IF(IS_ERR(REMOVE(src_backup)), (NULL), (NULL))',
            ], [
                'IF(IS_ERR(MOVE(src_backup, src)), (NULL), (NULL))',
            ]),
        ], [
            'NULL',
        ]),
        'ADM_ERR(msg)',
    ], '// 删除失败的恢复（备份移回）')

    src += fn('ADM_DELETE_FILE', 'path', [
        '// 对齐 content.py:122 delete_article 的备份-校验-回滚顺序：',
        '//   ① copy 到 .html.backup  ② **有 .md 时** copy 到 .md.backup',
        '//   ③ 删 .html  ④ 删 .md  ⑤ 校验 .html 不存在  ⑥ 删两个 backup',
        '//   任何一步失败 ⇒ 走 ADM_RESTORE（文章仍在）',
        '// ⚠ Python 的 with_suffix(".html.backup") 对 "a.html" 就是 "a.html.backup"',
        '//   ⇒ 直接拼串等价（本函数只接受 .html 名）。',
        'LET(backup, CAT(path, ".backup"));',
        'LET(src, SOURCE_PATH(path));',
        'LET(src_backup, CAT(src, ".backup"));',
        'LET(had_src, ADM_IS_FILE(src));',
        C('IF', 'IS_ERR(COPY(path, backup))', [
            'ADM_ERR(CAT("Backup failed: ", path))',
        ], [
            C('IF', '&&(had_src, IS_ERR(COPY(src, src_backup)))', [
                'ADM_RESTORE(path, backup, src, src_backup, had_src, CAT("Backup failed: ", src))',
            ], [
                C('IF', 'IS_ERR(REMOVE(path))', [
                    'ADM_RESTORE(path, backup, src, src_backup, had_src, CAT("Delete failed: ", path))',
                ], [
                    C('IF', '&&(had_src, &&(EXISTS(src), IS_ERR(REMOVE(src))))', [
                        'ADM_RESTORE(path, backup, src, src_backup, had_src, CAT("Delete failed: ", src))',
                    ], [
                        C('IF', 'EXISTS(path)', [
                            'ADM_RESTORE(path, backup, src, src_backup, had_src, "File deletion verification failed")',
                        ], [
                            C('IF', 'IS_ERR(REMOVE(backup))', [
                                'ADM_RESTORE(path, backup, src, src_backup, had_src, CAT("Cleanup failed: ", backup))',
                            ], [
                                C('IF', '&&(had_src, &&(EXISTS(src_backup), IS_ERR(REMOVE(src_backup))))', [
                                    'ADM_RESTORE(path, backup, src, src_backup, had_src, CAT("Cleanup failed: ", src_backup))',
                                ], [
                                    'ADM_OK0()',
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ], '// content.py:122 delete_article（含回滚）')

    # ── base64 → 字节 ─────────────────────────────────────────────
    src += fn('ADM_B64_BYTES', 's', [
        '// Python: base64.b64decode(s)（validate=False）⇒ bytes。',
        '// ⚠⚠ 不能用 `std.encode::BASE64_DECODE`：它返回 RESULT<STRING>，',
        '//   非 UTF-8 字节直接 ERR（差异 D1，实测报文 "decoded bytes are not valid UTF-8"）',
        '//   ⇒ 图片永远进不了这条 API。这里按 RFC 4648 自己解成 ARRAY[INTEGER]。',
        '// 失败用**空 DICT** 当哨兵（正常结果必然是 ARRAY）⇒ 调用方判 TYPE。',
        'LET(clean, RE_REPLACE(ADM_B64_JUNK_RE, s, ""));',
        'LET(n, LEN(clean));',
        C('IF', '==(n, 0)', [
            '// Python: b64decode("") == b""（不是错误）',
            '[]',
        ], [
            C('IF', '!=(%(n, 4), 0)', [
                '// 长度必须是 4 的倍数（Python: "number of data characters cannot be 1 more than a multiple of 4"；',
                '//   n % 4 ∈ {1,2,3} 在 Python 侧是 Incorrect padding / 1-more 错 —— 本模块一律拒）',
                'DICT()',
            ], [
                'LET(pad, IF(==(SUB(clean, -1, 1), "="), (1), (0)));',
                'LET(pad2, IF(&&(==(pad, 1), ==(SUB(clean, -(n, 1), 1), "=")), (2), (pad)));',
                'LET(body, SUB(clean, 0, -(n, pad2)));',
                C('IF', '||(>(INDEX_OF(body, "="), -1), &&(>(pad2, 0), ==(%(LEN(body), 4), 0)))', [
                    '// "=" 只能出现在结尾，且补位后必须补齐一组',
                    'DICT()',
                ], [
                    'LET MUT(out, []);',
                    'LET MUT(i, 0);',
                    'LET MUT(ok, TRUE);',
                    'LET MUT(bl, LEN(body));',
                    C('WHILE', '&&(ok, <(i, bl))', [
                        'LET(rem, -(bl, i));',
                        'LET(g, IF(>=(rem, 4), (4), (rem)));',
                        'LET(s0, INDEX_OF(ADM_B64_ALPHA, SUB(body, i, 1)));',
                        'LET(s1, INDEX_OF(ADM_B64_ALPHA, SUB(body, +(i, 1), 1)));',
                        C('IF', '||(<(s0, 0), <(s1, 0))', [
                            'SET(ok, FALSE)',
                        ], [
                            '// b0 = s0*4 + s1/16',
                            'SET(out, PUSH(out, +(*(s0, 4), /(s1, 16))))',
                        ]),
                        C('IF', '&&(ok, >=(g, 3))', [
                            'LET(s2, INDEX_OF(ADM_B64_ALPHA, SUB(body, +(i, 2), 1)));',
                            C('IF', '<(s2, 0)', [
                                'SET(ok, FALSE)',
                            ], [
                                '// b1 = (s1%16)*16 + s2/4',
                                'SET(out, PUSH(out, +(*(-(s1, *(/(s1, 16), 16)), 16), /(s2, 4))))',
                            ]),
                        ], [
                            'NULL',
                        ]),
                        C('IF', '&&(ok, >=(g, 4))', [
                            'LET(s2b, INDEX_OF(ADM_B64_ALPHA, SUB(body, +(i, 2), 1)));',
                            'LET(s3, INDEX_OF(ADM_B64_ALPHA, SUB(body, +(i, 3), 1)));',
                            C('IF', '||(<(s2b, 0), <(s3, 0))', [
                                'SET(ok, FALSE)',
                            ], [
                                '// b2 = (s2%4)*64 + s3',
                                'SET(out, PUSH(out, +(*(-(s2b, *(/(s2b, 4), 4)), 64), s3)))',
                            ]),
                        ], [
                            'NULL',
                        ]),
                        'SET(i, +(i, g))',
                    ]),
                    C('IF', 'ok', [
                        'out',
                    ], [
                        'DICT()',
                    ]),
                ]),
            ]),
        ]),
    ], '// base64 → ARRAY[INTEGER]（D1）')

    # ── magic bytes ───────────────────────────────────────────────
    src += fn('ADM_MAGIC_OK', 'b, ext', [
        '// Python: actions.py:227-246 MAGIC_BYTES 表 + `ext == expected_ext` 判定。',
        '// ⚠ 字节值按 Python 的 b"…" 字面量逐字节照抄（不是 4 字节简称）：',
        '//   PNG  = 89 50 4E 47 0D 0A 1A 0A（8 字节，actions.py:228）',
        '//   JPEG = FF D8 FF（3 字节，:229）',
        '//   GIF  = "GIF87a" / "GIF89a"（6 字节，:230-231）',
        '//   WEBP = "RIFF"（4 字节，:232；12 字节处的 "WEBP" 分支是死代码，见 D10）',
        '// ⚠ expected_ext 是 `.jpg` ⇒ `.jpeg` 永远过不了（D10，Python 原样如此）',
        'LET(n, LEN(b));',
        C('IF', '==(ext, "png")', [
            C('IF', '<(n, 8)', [
                'FALSE',
            ], [
                '&&(==(AT(b, 0, -1), 137), &&(==(AT(b, 1, -1), 80), &&(==(AT(b, 2, -1), 78), &&(==(AT(b, 3, -1), 71), &&(==(AT(b, 4, -1), 13), &&(==(AT(b, 5, -1), 10), &&(==(AT(b, 6, -1), 26), ==(AT(b, 7, -1), 10))))))))',
            ]),
        ], [
            C('IF', '==(ext, "jpg")', [
                C('IF', '<(n, 3)', [
                    'FALSE',
                ], [
                    '&&(==(AT(b, 0, -1), 255), &&(==(AT(b, 1, -1), 216), ==(AT(b, 2, -1), 255)))',
                ]),
            ], [
                C('IF', '==(ext, "gif")', [
                    C('IF', '<(n, 6)', [
                        'FALSE',
                    ], [
                        '// Python: MAGIC_BYTES 里 GIF 有**两个**前缀 b"GIF87a" / b"GIF89a"',
                        '&&(&&(==(AT(b, 0, -1), 71), &&(==(AT(b, 1, -1), 73), ==(AT(b, 2, -1), 70))), &&(==(AT(b, 3, -1), 56), &&(||(==(AT(b, 4, -1), 55), ==(AT(b, 4, -1), 57)), ==(AT(b, 5, -1), 97))))',
                    ]),
                ], [
                    C('IF', '==(ext, "webp")', [
                        C('IF', '<(n, 4)', [
                            'FALSE',
                        ], [
                            '&&(==(AT(b, 0, -1), 82), &&(==(AT(b, 1, -1), 73), &&(==(AT(b, 2, -1), 70), ==(AT(b, 3, -1), 70))))',
                        ]),
                    ], [
                        'FALSE',
                    ]),
                ]),
            ]),
        ]),
    ], '// actions.py:227-246 magic bytes')

    # ── 年月（从 epoch 毫秒推）────────────────────────────────────
    src += fn('ADM_IS_LEAP', 'y', [
        '// 公历闰年：能被 4 整除且（不能被 100 整除 或 能被 400 整除）',
        '&&(==(%(y, 4), 0), ||(!=(%(y, 100), 0), ==(%(y, 400), 0)))',
    ], '// 闰年判定')

    src += fn('ADM_MONTH_LEN', 'y, m', [
        '// 1..12 月的天数（二月按闰年）',
        C('IF', '==(m, 2)', [
            'IF(ADM_IS_LEAP(y), (29), (28))',
        ], [
            C('IF', '||(||(==(m, 4), ==(m, 6)), ||(==(m, 9), ==(m, 11)))', [
                '30',
            ], [
                '31',
            ]),
        ]),
    ], '// 某年某月的天数')

    src += fn('ADM_YM', 'ms', [
        '// epoch 毫秒 → {year, month}（UTC；差异 D8）',
        '// Python 侧是 datetime.now()（本地时区）⇒ 只在跨时区且跨月边界时不同。',
        'LET(days, /(ms, 86400000));',
        'LET MUT(y, 1970);',
        'LET MUT(d, days);',
        'LET MUT(done, FALSE);',
        C('WHILE', '!done', [
            'LET(yl, IF(ADM_IS_LEAP(y), (366), (365)));',
            C('IF', '<(d, yl)', [
                'SET(done, TRUE)',
            ], [
                'SET(d, -(d, yl));',
                'SET(y, +(y, 1))',
            ]),
        ]),
        'LET MUT(m, 1);',
        'LET MUT(mdone, FALSE);',
        C('WHILE', '!mdone', [
            'LET(ml, ADM_MONTH_LEN(y, m));',
            C('IF', '<(d, ml)', [
                'SET(mdone, TRUE)',
            ], [
                'SET(d, -(d, ml));',
                'SET(m, +(m, 1))',
            ]),
        ]),
        'INDEX_SET(INDEX_SET(DICT(), "year", y), "month", m)',
    ], '// epoch ms → UTC 年月')

    # ── 主题配置持久化 ────────────────────────────────────────────
    src += fn('ADM_SAVE_THEME_CONFIG', 'config_dir, cfg_path, theme', [
        '// 对齐 actions.py:367 _save_theme_config',
        '// ⚠ Python 的 except (OSError, JSONDecodeError) ⇒ **只 warning、不写**',
        '//   ⇒ 读失败 / 解析失败时返回 FALSE（"未持久化"，但 set_theme 仍成功）',
        'LET(merged, INDEX_SET(DICT(), "theme_name", theme));',
        C('IF', '!ADM_MKDIRS_OK(config_dir)', [
            'FALSE',
        ], [
            C('IF', 'EXISTS(cfg_path)', [
                'LET(txt, ADM_READ_TEXT(cfg_path));',
                C('IF', '==(TYPE(txt), "NULL")', [
                    'FALSE',
                ], [
                    C('IF', 'IS_ERR(JSON_VALIDATE(txt))', [
                        '// 现有文件不是合法 JSON ⇒ Python 抛 JSONDecodeError ⇒ 不写',
                        'FALSE',
                    ], [
                        'LET(parsed, PARSE(txt));',
                        C('IF', '!=(TYPE(parsed), "DICT")', [
                            'FALSE',
                        ], [
                            '// D6：STRINGIFY 是紧凑 + 键名排序，Python 是 indent=2 + 插入序',
                            'ADM_WRITE_ATOMIC(cfg_path, STRINGIFY(INDEX_SET(parsed, "theme_name", theme)))',
                        ]),
                    ]),
                ]),
            ], [
                'ADM_WRITE_ATOMIC(cfg_path, STRINGIFY(merged))',
            ]),
        ]),
    ], '// actions.py:367 _save_theme_config')

    # ── 公开：CREATE_ARTICLE ──────────────────────────────────────
    src += fn('CREATE_ARTICLE', 'opts', [
        '// actions.py:37 create_article',
        '// opts：article_dir / title / date / content / tags / category / status',
        '//       + suffix（**本实现新增**，替代 secrets.token_urlsafe(4)，见 D2）',
        '//       + fallback（透传给 slugify 的 fallback）',
        'LET(dirx, ADM_AS(AT_K(opts, "article_dir", "")));',
        'LET(title, ADM_AS(AT_K(opts, "title", "")));',
        'LET(date, ADM_AS(AT_K(opts, "date", "")));',
        'LET(content, ADM_AS(AT_K(opts, "content", "")));',
        'LET(tags, ADM_AS(AT_K(opts, "tags", "")));',
        'LET(category, ADM_AS(AT_K(opts, "category", "")));',
        '// Python: status 不在 (published, draft) ⇒ 落回 published（:44-45）',
        'LET(status0, ADM_AS(AT_K(opts, "status", "published")));',
        'LET(status, IF(||(==(status0, "published"), ==(status0, "draft")), (status0), ("published")));',
        'LET(s, ADM_SLUGIFY(title, AT_K(opts, "fallback", "")));',
        C('IF', '||(==(title, ""), ||(==(date, ""), ==(content, "")))', [
            '// Python: if not all([title, date, content]) ⇒ 400 "Missing fields"（:48）',
            'ADM_ERR("Missing fields")',
        ], [
            '// Python: fname = f"{date[:10]}-{s}.html"（:52）',
            'LET(base_name, CAT(SUB(date, 0, 10), "-", s, ".html"));',
            'LET(suffix, ADM_AS(AT_K(opts, "suffix", "")));',
            '// 重名：Python 换成 date-slug-<token>.html（:53-54；token 见 D2）',
            'LET(use_suffix, IF(!EXISTS(PATH_JOIN(dirx, base_name)), (""), IF(!=(suffix, ""), (suffix), (RANDOM_HEX(4)))));',
            'LET(fname, IF(==(use_suffix, ""), (base_name), (CAT(SUB(date, 0, 10), "-", s, "-", use_suffix, ".html"))));',
            'ADM_WRITE_ARTICLE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "dir", dirx), "fname", fname), "title", title), "date", date), "slug", s), "content", content), "tags", tags), "summary", ""), "category", category), "status", status))',
        ]),
    ], '// actions.py:37 create_article')

    src += fn('SAVE_ARTICLE', 'opts', [
        '// actions.py:67 save_article',
        '// opts：article_dir / file / title / date / content / tags / category / status',
        'LET(dirx, ADM_AS(AT_K(opts, "article_dir", "")));',
        'LET(fname, ADM_AS(AT_K(opts, "file", "")));',
        'LET(title, ADM_AS(AT_K(opts, "title", "")));',
        'LET(date, ADM_AS(AT_K(opts, "date", "")));',
        'LET(content, ADM_AS(AT_K(opts, "content", "")));',
        'LET(tags, ADM_AS(AT_K(opts, "tags", "")));',
        'LET(category, ADM_AS(AT_K(opts, "category", "")));',
        'LET(status0, ADM_AS(AT_K(opts, "status", "published")));',
        'LET(status, IF(||(==(status0, "published"), ==(status0, "draft")), (status0), ("published")));',
        C('IF', '||(||(==(fname, ""), ==(title, "")), ||(==(date, ""), ==(content, "")))', [
            'ADM_ERR("Missing fields")',
        ], [
            C('IF', '!VALIDATE_FILENAME(fname)', [
                '// :81-82',
                'ADM_ERR("Invalid filename")',
            ], [
                'LET(s, ADM_SLUGIFY(title, AT_K(opts, "fallback", "")));',
                'ADM_WRITE_ARTICLE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "dir", dirx), "fname", fname), "title", title), "date", date), "slug", s), "content", content), "tags", tags), "summary", ""), "category", category), "status", status))',
            ]),
        ]),
    ], '// actions.py:67 save_article')

    src += fn('DELETE_ARTICLE', 'opts', [
        '// actions.py:96 delete_article_action',
        '// opts：article_dir / file',
        'LET(dirx, ADM_AS(AT_K(opts, "article_dir", "")));',
        'LET(fname, ADM_AS(AT_K(opts, "file", "")));',
        C('IF', '!VALIDATE_FILENAME(fname)', [
            'ADM_ERR("Invalid filename")',
        ], [
            'LET(path, PATH_JOIN(dirx, fname));',
            C('IF', '!ADM_IS_FILE(path)', [
                '// Python: `if path.is_file()` 不成立 ⇒ 什么都不做，仍重定向（:102）',
                'ADM_OK("deleted", FALSE)',
            ], [
                '// Python: delete_article(path) 内部抛异常 ⇒ 冒到 WSGI',
                'LET(dres, ADM_DELETE_FILE(path));',
                C('IF', 'AT_K(dres, "ok", FALSE)', [
                    'ADM_OK("deleted", TRUE)',
                ], [
                    'dres',
                ]),
            ]),
        ]),
    ], '// actions.py:96 delete_article_action')

    # ── 公开：独立页 ──────────────────────────────────────────────
    src += fn('CREATE_PAGE', 'opts', [
        '// actions.py:117 create_page',
        '// opts：standalone_dir / title / slug / content',
        'LET(dirx, ADM_AS(AT_K(opts, "standalone_dir", "")));',
        'LET(title, ADM_AS(AT_K(opts, "title", "")));',
        'LET(slug, ADM_AS(AT_K(opts, "slug", "")));',
        'LET(content, ADM_AS(AT_K(opts, "content", "")));',
        C('IF', '||(==(title, ""), ||(==(slug, ""), ==(content, "")))', [
            'ADM_ERR("Missing fields")',
        ], [
            'LET(fname, CAT(slug, ".html"));',
            C('IF', '!ADM_VALIDATE_PAGE_FILENAME(fname)', [
                '// :129-130 "Invalid slug"',
                'ADM_ERR("Invalid slug")',
            ], [
                C('IF', 'EXISTS(PATH_JOIN(dirx, fname))', [
                    '// :131-132 409',
                    'ADM_ERR("Page already exists")',
                ], [
                    '// :134 cfg.standalone_dir.mkdir(parents=True, exist_ok=True)',
                    C('IF', '!ADM_MKDIRS_OK(dirx)', [
                        'ADM_ERR(CAT("Cannot create directory: ", dirx))',
                    ], [
                        'ADM_WRITE_STANDALONE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "dir", dirx), "fname", fname), "title", title), "content", content), "summary", ""))',
                    ]),
                ]),
            ]),
        ]),
    ], '// actions.py:117 create_page')

    src += fn('SAVE_PAGE', 'opts', [
        '// actions.py:143 save_page',
        '// opts：standalone_dir / file / title / slug / content',
        'LET(dirx, ADM_AS(AT_K(opts, "standalone_dir", "")));',
        'LET(fname, ADM_AS(AT_K(opts, "file", "")));',
        'LET(title, ADM_AS(AT_K(opts, "title", "")));',
        'LET(slug, ADM_AS(AT_K(opts, "slug", "")));',
        'LET(content, ADM_AS(AT_K(opts, "content", "")));',
        C('IF', '||(||(==(fname, ""), ==(title, "")), ||(==(slug, ""), ==(content, "")))', [
            'ADM_ERR("Missing fields")',
        ], [
            C('IF', '!ADM_VALIDATE_PAGE_FILENAME(fname)', [
                'ADM_ERR("Invalid filename")',
            ], [
                'LET(new_fname, CAT(slug, ".html"));',
                '// :158-161 slug 变了 ⇒ 先删旧文件（delete_standalone 含回滚）',
                C('IF', '!=(new_fname, fname)', [
                    'LET(old_path, PATH_JOIN(dirx, fname));',
                    C('IF', 'ADM_IS_FILE(old_path)', [
                        'LET(dres, ADM_DELETE_FILE(old_path));',
                        C('IF', 'AT_K(dres, "ok", TRUE)', [
                            'ADM_WRITE_STANDALONE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "dir", dirx), "fname", new_fname), "title", title), "content", content), "summary", ""))',
                        ], [
                            'dres',
                        ]),
                    ], [
                        'ADM_WRITE_STANDALONE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "dir", dirx), "fname", new_fname), "title", title), "content", content), "summary", ""))',
                    ]),
                ], [
                    'ADM_WRITE_STANDALONE(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "dir", dirx), "fname", new_fname), "title", title), "content", content), "summary", ""))',
                ]),
            ]),
        ]),
    ], '// actions.py:143 save_page')

    src += fn('DELETE_PAGE', 'opts', [
        '// actions.py:171 delete_page_action',
        '// opts：standalone_dir / file',
        'LET(dirx, ADM_AS(AT_K(opts, "standalone_dir", "")));',
        'LET(fname, ADM_AS(AT_K(opts, "file", "")));',
        C('IF', '!ADM_VALIDATE_PAGE_FILENAME(fname)', [
            'ADM_ERR("Invalid filename")',
        ], [
            'LET(path, PATH_JOIN(dirx, fname));',
            C('IF', '!ADM_IS_FILE(path)', [
                'ADM_OK("deleted", FALSE)',
            ], [
                'LET(dres, ADM_DELETE_FILE(path));',
                C('IF', 'AT_K(dres, "ok", FALSE)', [
                    'ADM_OK("deleted", TRUE)',
                ], [
                    'dres',
                ]),
            ]),
        ]),
    ], '// actions.py:171 delete_page_action')

    # ── 公开：主题 / 预览 / 重建 ──────────────────────────────────
    src += fn('SET_THEME', 'opts', [
        '// actions.py:348 set_theme（+ :367 _save_theme_config）',
        '// opts：theme / themes_dir（默认 "themes"）/ config_dir（默认 ".tinypage"）',
        '// ⚠ Python 不校验主题名（只判 manifest 是否存在）⇒ 这里也不校验（含 ".." 的情形',
        '//   与 Python 一致地交给「文件不存在」兜住）。',
        'LET(theme, ADM_AS(AT_K(opts, "theme", "")));',
        'LET(themes_dir, ADM_AS(AT_K(opts, "themes_dir", "themes")));',
        'LET(config_dir, ADM_AS(AT_K(opts, "config_dir", ".tinypage")));',
        'LET(manifest, PATH_JOIN(themes_dir, theme, "manifest.json"));',
        C('IF', '==(theme, "")', [
            'ADM_ERR("Missing theme name")',
        ], [
            C('IF', '!ADM_IS_FILE(manifest)', [
                'ADM_ERR("Theme not found")',
            ], [
                'LET(persisted, ADM_SAVE_THEME_CONFIG(config_dir, PATH_JOIN(config_dir, "config.json"), theme));',
                '// Python 随后 list_articles + generate_static_pages ⇒ 本模块把重建交给 REGEN/BUILD',
                'INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "ok", TRUE), "theme", theme), "persisted", persisted)',
            ]),
        ]),
    ], '// actions.py:348 set_theme')

    src += fn('PREVIEW', 'opts', [
        '// actions.py:285 live_preview —— **只做 Markdown 渲染**：',
        '// 不加代码高亮、不加 TOC、不加脚注（Python 用的是 parsers.render_markdown，',
        '// 它只做 mistune 那一趟；高亮/TOC/脚注是在 generator.write_article 里另加的）。',
        'LET(content, ADM_AS(AT_K(opts, "content", "")));',
        'IF(==(content, ""), (ADM_OK("html", ADM_PREVIEW_PLACEHOLDER)), (ADM_OK("html", RENDER_MD(content))))',
    ], '// actions.py:285 live_preview')

    src += fn('REGEN', '_opts', [
        '// actions.py:268 regenerate',
        '// Python：list_articles + list_standalones + generate_static_pages。',
        '// 职责边界：**全站构建的入口在 tp/bin/build.wll::BUILD(opts)**，本模块不 import 它',
        '// （否则 lib → bin 反向依赖，且构建要 theme/template 全量上下文）。',
        '// ⇒ 这里只回报「该重建了」+ 把目录原样带回给调用方。',
        'ADM_OK("regen", TRUE)',
    ], '// actions.py:268 regenerate')

    # ── 公开：上传 ────────────────────────────────────────────────
    src += fn('UPLOAD_IMAGE', 'opts', [
        '// actions.py:194 upload_image',
        '// opts：filename / data（base64 或 data URL）/ static_dir',
        '//       + year / month（**本实现新增**，替代 datetime.now()，见 D8）',
        '//       + now_ms（可注入的时钟，便于测试）',
        'LET(filename0, ADM_AS(AT_K(opts, "filename", "")));',
        'LET(data, ADM_AS(AT_K(opts, "data", "")));',
        C('IF', '||(==(filename0, ""), ==(data, ""))', [
            '// :200-201',
            'ADM_ERR("Missing filename or data")',
        ], [
            '// :203 净化文件名（字母/数字/点/下划线/连字符之外一律 "_"）',
            'LET(filename, RE_REPLACE(ADM_FN_JUNK_RE, filename0, "_"));',
            C('IF', '||(==(filename, ""), >(INDEX_OF(filename, ".."), -1))', [
                '// :204-205',
                'ADM_ERR("Invalid filename")',
            ], [
                'LET(ext, TO_LOWER(PATH_EXT(filename)));',
                C('IF', '!RE_TEST(ADM_IMG_EXTS_RE, ext)', [
                    '// :207-210 消息里带**前导点**（Python 的 Path.suffix 含点）',
                    'ADM_ERR(CAT("File type not allowed: ", IF(==(ext, ""), ("<none>"), (CAT(".", ext)))))',
                ], [
                    '// :212-213 images/YYYY-MM',
                    'LET(now_ms, IF(==(TYPE(AT_K(opts, "now_ms", NULL)), "NULL"), (NOW()), (AT_K(opts, "now_ms", 0))));',
                    'LET(ym, ADM_YM(now_ms));',
                    'LET(year, IF(==(TYPE(AT_K(opts, "year", NULL)), "NULL"), (AT_K(ym, "year", 1970)), (AT_K(opts, "year", 1970))));',
                    'LET(month, IF(==(TYPE(AT_K(opts, "month", NULL)), "NULL"), (AT_K(ym, "month", 1)), (AT_K(opts, "month", 1))));',
                    'LET(ym_str, CAT(STR(year), "-", IF(<(month, 10), (CAT("0", STR(month))), (STR(month)))));',
                    'LET(subdir, PATH_JOIN(ADM_AS(AT_K(opts, "static_dir", "")), "images", ym_str));',
                    C('IF', '!ADM_MKDIRS_OK(subdir)', [
                        'ADM_ERR(CAT("Cannot create directory: ", subdir))',
                    ], [
                        '// :216-217 data URL 前缀（只在**第一个**逗号处切）',
                        'LET(comma, INDEX_OF(data, ","));',
                        'LET(payload, IF(>(comma, -1), (SUB(data, +(comma, 1))), (data)));',
                        'LET(raw, ADM_B64_BYTES(payload));',
                        C('IF', '==(TYPE(raw), "DICT")', [
                            '// :219-222',
                            'ADM_ERR("Invalid base64 data")',
                        ], [
                            C('IF', '>(LEN(raw), ADM_MAX_IMAGE_BYTES)', [
                                '// :224-225',
                                'ADM_ERR("File too large (max 10MB)")',
                            ], [
                                C('IF', '!ADM_MAGIC_OK(raw, ext)', [
                                    '// :245-246',
                                    'ADM_ERR("Invalid image format")',
                                ], [
                                    '// :248-255 重名加 -1 / -2 …（stem 不含扩展名）',
                                    'LET(base, PATH_BASE(filename));',
                                    'LET(stem, SUB(base, 0, -(LEN(base), +(LEN(ext), 1))));',
                                    'LET MUT(target, PATH_JOIN(subdir, filename));',
                                    'LET MUT(counter, 1);',
                                    'LET MUT(name, filename);',
                                    C('WHILE', 'EXISTS(target)', [
                                        'SET(name, CAT(stem, "-", STR(counter), ".", ext));',
                                        'SET(target, PATH_JOIN(subdir, name));',
                                        'SET(counter, +(counter, 1))',
                                    ]),
                                    C('IF', 'IS_ERR(WRITE_BYTES(target, raw))', [
                                        'ADM_ERR(CAT("Write failed: ", target))',
                                    ], [
                                        '// :258 rel_path',
                                        'ADM_OK("url", CAT("/static/images/", ym_str, "/", name))',
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ], '// actions.py:194 upload_image')

    A('')
    A('EXPORT(["' + '", "'.join(EXPORTS) + '"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
