"""生成 tp/test/test_admin_actions.wll —— 卡 S4-4 的对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例的期望值来自**真 Python** 产出的基准
`tp/test/fixtures/admin_actions_baseline.json`（由 `gen_admin_actions_baseline.py` 生成），
WLWL 侧逐用例 `ASSERT_EQ`。

**基准组 → WLWL 调用 → 断言**：

| 基准组 | WLWL 调用 | 断言 |
|---|---|---|
| `slugify`（14 例） | `CREATE_ARTICLE`（文件名里的 slug 就是 slugify 的输出） | `file` == `2026-01-02-<want>.html` |
| `article.create/save` | `CREATE_ARTICLE` / `SAVE_ARTICLE` | `file` / 兄弟 `.md` 正文 / `.html` meta 头 |
| `article.delete/delete_missing` | `DELETE_ARTICLE` | `ok` / `deleted` / 文件是否还在 / 备份是否清干净 |
| `article.rollback` | `DELETE_ARTICLE`（让备份目标不可写） | 失败 + `.html`/`.md` 都还在且内容未变 |
| `article.collision` | `CREATE_ARTICLE` + `suffix` | 新文件名 `<date>-<slug>-<suffix>.html`，旧文件不动 |
| `page.create/save/delete` | `CREATE_PAGE` / `SAVE_PAGE` / `DELETE_PAGE` | 文件增删 + 两个文件内容 |
| `errors`（20 例） | 8 个动作 | `ok`==FALSE + `error` 逐字 + 文档的状态码映射 |
| `uploads`（13 例） | `UPLOAD_IMAGE` | `ok` / `error` / `url` / 落盘字节逐字节 |
| `theme` | `SET_THEME` | `persisted` + `.tinypage/config.json` 语义 |
| `preview`（4 例） | `PREVIEW` | `html` 逐字 |
| `deviations` | 见下 | 两条已登记差异**照样钉住**（钉的是 WLWL 侧口径） |

**三条已登记差异在测试里怎么处理**（不许让它们悄悄漂走）：

* `slug_unicode`（D3）：Python 得 `ünïcode`，WLWL 得 `n-code` ⇒ 断言 WLWL 的
  `n-code`，注释指向 `deviations.slug_unicode`。
* `b64_lenient_pad`（D1b）：`AAAA=` Python 解得 3 字节，WLWL 报
  `Invalid base64 data` ⇒ 作为**独立用例**钉住 WLWL 口径。
* `slugify` 的 `title=""`（基准第 12 例）：**公开面不可达** ——
  `CREATE_ARTICLE` 先判 `Missing fields`（与 Python `actions.py:48` 同序），
  slugify 根本不会被调用 ⇒ 本文件断言「`Missing fields`」并在注释里登记。

**反向守卫（卡 S4-4 点名三条 + 补四条）**：
  ① 上传 `.php` / `.html` ⇒ 扩展名白名单拒（内容再合法也不行）
  ② 扩展名 `.png` 但内容是 PHP ⇒ magic bytes 拒
  ③ 删除失败 ⇒ 回滚：`.html` 与 `.md` 都还在、内容未变
  ④ 删除文件名带 `..` ⇒ 拒，且目录外文件不受影响
  ⑤ 上传文件名带 `..` ⇒ 净化后仍含 `..` ⇒ 拒，且不落盘
  ⑥ 独立页 slug 带 `../` ⇒ 拒，目录外无文件
  ⑦ `SAVE_PAGE` 改 slug ⇒ 旧文件必须消失（不留双份）

用法：python gen_test_admin_actions.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn as _wfn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_admin_actions.wll')

ARTICLES = 'articles'
PAGES = 'pages'

# 上传目录的 YYYY-MM：基准把 actions.datetime 钉成 2026-11 ⇒ 这里显式传 year/month
# （差异 D8：WLWL 侧取 opts["year"]/opts["month"]，否则从 NOW() 推 UTC 年月）。
UP_YEAR = 2026
UP_MONTH = 11

# 1×1 PNG 的 base64（与基准 uplodas 用例同一份字节）
PNG_B64 = ('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAF'
           'AAH/q842iQAAAABJRU5ErkJggg==')


# ── 渲染小工具（与 gen_admin_actions.py 同源：先剥语句串尾部的 `;`）──
def _strip_semis(node):
    if isinstance(node, str):
        return node[:-1] if node.endswith(';') else node
    if isinstance(node, list):
        if node and node[0] == 'call':
            return [node[0], node[1]] + [_strip_semis(a) for a in node[2:]]
        return [_strip_semis(x) for x in node]
    return node


def fn(name, params, body, comment=None):
    return _wfn(name, params, _strip_semis(body), comment)


def wl_string(s):
    """Python 字符串 → WLWL 字面量。

    ⚠ 转义白名单：`\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`（README #7）。
    ⚠ `$` 必须写成 `\\$`：否则 `${...}` / `$var` 会被当插值（README #32）。
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


def wl_value(v):
    """Python 值 → WLWL 字面量（dict 用 `["k": v]` 字面量）。"""
    if isinstance(v, str):
        return wl_string(v)
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return '[' + ', '.join(wl_value(x) for x in v) + ']'
    if isinstance(v, dict):
        return '[' + ', '.join('%s: %s' % (wl_string(k), wl_value(x))
                               for k, x in v.items()) + ']'
    raise TypeError('bad value: %r' % (v,))


# 值占位符 → 测试文件里的顶层变量名（避免在 .wll 里硬编码工作区路径）
OPTVARS = {
    '__ERR__': '_TAA_ERR_',
    '__ART__': '_TAA_ART_',
    '__PG__': '_TAA_PG_',
    '__RB__': '_TAA_RB_',
    '__COL__': '_TAA_COL_',
    '__TH__': '_TAA_THEMES_',
    '__GST__': '_TAA_GST_',
    '__ROOT__': '_TAA_ROOT_',
    '__CFG1__': '_TAA_CFG1_',
    '__CFG2__': '_TAA_CFG2_',
    '__CFG3__': '_TAA_CFG3_',
    '__T201__': '_TAA_T201_',
    '__C50001__': '_TAA_C50001_',
}


def wl_opt_value(v):
    """单个 opts 值：占位符（`__X__` 或 `_TAA_X_`）渲染成**变量引用**，其余按字面量。"""
    if isinstance(v, str):
        if v in OPTVARS:
            return OPTVARS[v]
        if v.startswith('_TAA_') and v.endswith('_'):
            return v
    return wl_value(v)


def wl_opts(opts):
    """opts 字典 → WLWL 字典字面量（值走 wl_opt_value）。"""
    return '[' + ', '.join('%s: %s' % (wl_string(k), wl_opt_value(x))
                           for k, x in opts.items()) + ']'


def emit_test(src, A, name, asserts, comment=None):
    """一个 TEST：断言行每条行首带 `(`（README #46），末尾 `TRUE`。"""
    if comment:
        A('// ' + comment)
    A('TEST(%s, FUN(() ,' % wl_string(name))
    for a in asserts:
        A('    (%s);' % a)
    A('    TRUE));')


def main():
    with open(os.path.join(FIXTURES, 'admin_actions_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)

    src = []
    A = src.append
    A('// tp/test/test_admin_actions.wll —— 卡 S4-4：文章/独立页 CRUD + 上传 + 主题 + 预览')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_admin_actions.py 生成 —— 请勿手改。')
    A('//')
    A('// 期望值全部来自 tp/test/fixtures/admin_actions_baseline.json')
    A('//   （gen_admin_actions_baseline.py 用**真 Python** action 产出）。')
    A('//')
    A('// ⚠ 与 Python 的已登记差异（D1–D11）见 tp/test/gen_admin_actions.py 的 docstring；')
    A('//   本文件把其中**可观察**的三条也钉住（D3 slug unicode / D1b base64 补位 /')
    A('//   title="" 走不到 slugify），钉的是 WLWL 侧自己的口径。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS", "TEMP_DIR"]);')
    A('IMPORT("wlwl:std.fs", ["MKDIRS", "WRITE_FILE", "WRITE_BYTES", "READ_FILE",')
    A('     "READ_BYTES", "EXISTS", "PATH_JOIN", "FILE_META"]);')
    A('IMPORT("wlwl:std.json", ["PARSE"%s]);' % (', "STRINGIFY"' if os.environ.get('TAA_DEBUG') else ''))
    A('IMPORT("wlwl:std.str", ["CAT", "INDEX_OF"]);')
    A('IMPORT("./../lib/admin_actions.wll", ["CREATE_ARTICLE", "SAVE_ARTICLE",')
    A('     "DELETE_ARTICLE", "CREATE_PAGE", "SAVE_PAGE", "DELETE_PAGE",')
    A('     "SET_THEME", "PREVIEW", "REGEN", "UPLOAD_IMAGE"]);')
    A('')

    # ── 测试侧的小工具 ────────────────────────────────────────────
    A('// ── 测试侧工具（顶层名一律 TAA_ 前缀：陷阱 #52 顶层绑定跨模块共享）──')

    # 字节数组逐元素比较（不依赖 `==` 对 ARRAY 的语义）
    src += fn('_TAA_ARR_EQ_', 'a, b', [
        '// 字节数组逐元素比较（避免依赖 `==` 对 ARRAY 的语义）',
        C('IF', '||(!=(TYPE(a), "ARRAY"), !=(TYPE(b), "ARRAY"))', [
            'FALSE',
        ], [
            'LET(na, LEN(a));',
            'LET(nb, LEN(b));',
            C('IF', '!=(na, nb)', [
                'FALSE',
            ], [
                'LET MUT(i, 0);',
                'LET MUT(same, TRUE);',
                C('WHILE', '&&(same, <(i, na))', [
                    C('IF', '!=(AT(a, i, -1), AT(b, i, -1))', [
                        'SET(same, FALSE)',
                    ], [
                        'NULL',
                    ]),
                    'SET(i, +(i, 1))',
                ]),
                'same',
            ]),
        ]),
    ], '// _TAA_ARR_EQ_(a, b) -> BOOLEAN')

    # 字符串按 unit 倍增（造 201 / 50001 字符的输入；WLWL 没有 REPEAT 内建）
    src += fn('_TAA_DBL_', 'unit, times', [
        '// 反复自拼 n 次：1 → 2 → 4 → … ⇒ O(n) 步；用来造超长输入',
        'LET MUT(s, unit);',
        'LET MUT(i, 0);',
        C('WHILE', '<(i, times)', [
            'SET(s, +(s, s))',
            'SET(i, +(i, 1))',
        ]),
        's',
    ], '// _TAA_DBL_(unit, times) -> STRING')

    A('// 读文件；不存在时给哨兵（避免 LET 直接绑 ERR ⇒ E0103，陷阱 #25）')
    src += fn('_TAA_READ_', 'p', [
        'IF(EXISTS(p), (READ_FILE(p)), ("<missing>"))',
    ], '// _TAA_READ_(p) -> STRING')

    # 错误文本 → HTTP 状态码（映射表逐字来自 gen_admin_actions.py docstring：
    # 表单级校验 400/409，写盘层 ValueError 被 WSGI 兜成 500）
    src += fn('_TAA_STATUS_', 'msg', [
        '// 错误文本 → Python 侧会给出的 HTTP 状态码（见生成器 docstring 的对照表）',
        'LET(map, _TAA_STATUS_MAP_);',
        'LET MUT(i, 0);',
        'LET MUT(done, FALSE);',
        'LET MUT(out, "500");',
        C('WHILE', '&&(!done, <(i, LEN(map)))', [
            'LET(row, AT(map, i, []));',
            'LET(pfx, AT(row, 0, ""));',
            C('IF', '==(INDEX_OF(msg, pfx), 0)', [
                'SET(out, AT(row, 1, "500"))',
                'SET(done, TRUE)',
            ], [
                'NULL',
            ]),
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// _TAA_STATUS_(msg) -> "400"/"409"/"500"')

    A('// 状态码映射表：**先 409、再 500 专属前缀、最后 400**。')
    A('// ⚠ 顺序有意义：`Invalid filename: x`（500）以 `Invalid filename`（400）开头。')
    A('LET(_TAA_STATUS_MAP_, [')
    A('    ["Page already exists", "409"],')
    A('    ["Invalid filename: ", "500"],')
    A('    ["Title invalid or too long: ", "500"],')
    A('    ["Content validation failed: ", "500"],')
    A('    ["Invalid date format: ", "500"],')
    A('    ["Invalid page filename: ", "500"],')
    A('    ["Missing fields", "400"],')
    A('    ["Invalid filename", "400"],')
    A('    ["Invalid slug", "400"],')
    A('    ["Missing theme name", "400"],')
    A('    ["Theme not found", "400"],')
    A('    ["Missing filename or data", "400"],')
    A('    ["File type not allowed: ", "400"],')
    A('    ["Invalid base64 data", "400"],')
    A('    ["Invalid image format", "400"],')
    A('    ["File too large", "400"]')
    A(']);')
    A('')

    # ── 工作区 ────────────────────────────────────────────────────
    A('// ── 工作区（TEMP_DIR ⇒ 绝不出现机器相关路径）────────────────────')
    A('LET(_TAA_ROOT_, TEMP_DIR());')
    A('LET(_TAA_ART_, PATH_JOIN(_TAA_ROOT_, %s));' % wl_string(ARTICLES))
    A('LET(_TAA_PG_, PATH_JOIN(_TAA_ROOT_, %s));' % wl_string(PAGES))
    A('LET(_TAA_GST_, PATH_JOIN(_TAA_ROOT_, "guard_static"));')
    A('MKDIRS(_TAA_ART_);')
    A('MKDIRS(_TAA_PG_);')
    A('MKDIRS(_TAA_GST_);')
    A('')

    # 长输入（201 / 50001 字符）——倍增后裁切
    A('// 201 / 50001 字符的输入：倍增到 ≥ 长度再 SUB 裁切（WLWL 没有 REPEAT 内建）')
    A('LET(_TAA_T201_, SUB(_TAA_DBL_("T", 8), 0, 201));')
    A('LET(_TAA_C50001_, SUB(_TAA_DBL_("x", 16), 0, 50001));')
    A('')

    # ── ① slugify（经 CREATE_ARTICLE 的文件名观察）─────────────────
    A('// ── ① slugify：基准 14 例（slugify 不导出 ⇒ 用 CREATE_ARTICLE 的文件名观察）──')
    A('//   日期固定 2026-01-02 ⇒ 文件名 = "2026-01-02-" + slug + ".html"')
    dev = base['deviations']['slug_unicode']
    slug_cases = []
    for i, e in enumerate(base['slugify']):
        title, fb, want = e['title'], e['fallback'], e['want']
        note = None
        if title == dev['title']:
            want = dev['wlwl']
            note = ('D3：Python 得 %r，WLWL 正则只认 ASCII+CJK ⇒ 断言 WLWL 侧 %r'
                    % (dev['python'], dev['wlwl']))
        if title == '':
            note = ('基准该例 title="" 在**公开面不可达**：CREATE_ARTICLE 先判'
                    ' Missing fields（与 actions.py:48 同序）⇒ 断言 Missing fields')
        U = 'SL_%02d' % i
        A('LET(_TAA_%s_D_, PATH_JOIN(_TAA_ROOT_, %s));' % (U, wl_string('sd_%02d' % i)))
        A('MKDIRS(_TAA_%s_D_);' % U)
        A('LET(_TAA_%s_R_, CREATE_ARTICLE(%s));' % (U, wl_opts({
            'article_dir': '_TAA_%s_D_' % U,
            'title': title, 'date': '2026-01-02 10:30', 'content': 'c',
            'fallback': fb,
        })))
        slug_cases.append((U, '2026-01-02-' + want + '.html', note, title))
    A('')

    for U, want_file, note, title in slug_cases:
        if title == '':
            asserts = ['ASSERT_EQ(AT_K(_TAA_%s_R_, "ok", TRUE), FALSE)' % U,
                       'ASSERT_EQ(AT_K(_TAA_%s_R_, "error", ""), "Missing fields")' % U]
        elif '_' in want_file:
            # slug 里的 `_` 会让 SAFE_FILENAME_PATTERN 不匹配（基准 meta.findings F1）
            # ⇒ 写盘层拒。这条**本身就是 F1 的实证**：slug 对了，但文件名规则不允许。
            asserts = ['ASSERT_EQ(AT_K(_TAA_%s_R_, "ok", TRUE), FALSE)' % U,
                       'ASSERT_EQ(AT_K(_TAA_%s_R_, "error", ""), %s)'
                       % (U, wl_string('Invalid filename: ' + want_file))]
            note = ((note + '；') if note else '') + (
                '文件名校验不许 `_`（SAFE_FILENAME_PATTERN）⇒ 落盘被拒；'
                '错误消息里带出的正是 slug=%r，等价于断言 slug 本身' % want_file[11:-5])
        else:
            asserts = ['ASSERT_EQ(AT_K(_TAA_%s_R_, "ok", FALSE), TRUE)' % U,
                       'ASSERT_EQ(AT_K(_TAA_%s_R_, "file", ""), %s)' % (U, wl_string(want_file))]
        emit_test(src, A, 'slugify/%02d' % int(U[-2:]), asserts, note)

    # ── ② 文章 create / save / delete ─────────────────────────────
    art = base['article']
    A('// ── ② 文章：create → save → delete ──────────────────────────')
    A('// ⚠ 测试体在 RUN_TESTS() 里才跑（晚于全部顶层 LET）⇒ create 与 save 必须')
    A('//   用**两个目录**，否则 save 覆盖同文件后 create 的断言比的是 save 的产物。')
    A('//   基准里两者共用一条路径、按时间顺序各读一次；这里用 `art_create` /')
    A('//   `art_save` 两个目录复现同一序列（save 目录先 create 再 save）。')
    A('LET(_TAA_ARTD_C_, PATH_JOIN(_TAA_ROOT_, "art_create"));')
    A('LET(_TAA_ARTD_S_, PATH_JOIN(_TAA_ROOT_, "art_save"));')
    A('MKDIRS(_TAA_ARTD_C_);')
    A('MKDIRS(_TAA_ARTD_S_);')
    cp = dict(art['create']['post'])
    A('LET(_TAA_ART_C_, CREATE_ARTICLE(%s));' % wl_opts(
        dict([('article_dir', '_TAA_ARTD_C_')] + list(cp.items()))))
    A('LET(_TAA_ART_HTML_, PATH_JOIN(_TAA_ARTD_C_, %s));'
      % wl_string(art['create']['want_file']))
    A('LET(_TAA_ART_MD_, PATH_JOIN(_TAA_ARTD_C_, %s));'
      % wl_string(art['create']['want_file'][:-5] + '.md'))
    emit_test(src, A, 'article/create_ok',
              ['ASSERT_EQ(AT_K(_TAA_ART_C_, "ok", FALSE), TRUE)'], None)
    emit_test(src, A, 'article/create_file',
              ['ASSERT_EQ(AT_K(_TAA_ART_C_, "file", ""), %s)'
               % wl_string(art['create']['want_file'])], None)
    emit_test(src, A, 'article/create_md',
              ['ASSERT_EQ(READ_FILE(_TAA_ART_MD_), %s)' % wl_string(art['create']['md'])],
              '正文在兄弟 .md 里（skip_html_generation，差异 D5）')
    emit_test(src, A, 'article/create_html',
              ['ASSERT_EQ(READ_FILE(_TAA_ART_HTML_), %s)' % wl_string(art['create']['html'])],
              '文章 .html = 7 行 meta 头（基准 create.html）')

    sp = dict(art['save']['post'])
    A('// save 目录：先 create 出同一份文件，再 save 覆盖（与基准同起点）')
    A('LET(_TAA_ART_S0_, CREATE_ARTICLE(%s));' % wl_opts(
        dict([('article_dir', '_TAA_ARTD_S_')] + list(cp.items()))))
    A('LET(_TAA_ART_S_, SAVE_ARTICLE(%s));' % wl_opts(
        dict([('article_dir', '_TAA_ARTD_S_')] + list(sp.items()))))
    A('LET(_TAA_ART_SHTML_, PATH_JOIN(_TAA_ARTD_S_, %s));'
      % wl_string(art['save']['post']['file']))
    A('LET(_TAA_ART_SMD_, PATH_JOIN(_TAA_ARTD_S_, %s));'
      % wl_string(art['save']['post']['file'][:-5] + '.md'))
    A('// 快照：后面的 delete 会删掉这两个文件，而测试体要晚于全部顶层 LET 才跑')
    A('LET(_TAA_ART_SMD_TXT_, _TAA_READ_(_TAA_ART_SMD_));')
    A('LET(_TAA_ART_SHTML_TXT_, _TAA_READ_(_TAA_ART_SHTML_));')
    emit_test(src, A, 'article/save_ok',
              ['ASSERT_EQ(AT_K(_TAA_ART_S_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_ART_S_, "file", ""), %s)'
               % wl_string(art['save']['post']['file'])], None)
    emit_test(src, A, 'article/save_md',
              ['ASSERT_EQ(_TAA_ART_SMD_TXT_, %s)' % wl_string(art['save']['md'])], None)
    emit_test(src, A, 'article/save_html',
              ['ASSERT_EQ(_TAA_ART_SHTML_TXT_, %s)' % wl_string(art['save']['html'])],
              '改标题后 slug 变 hello-world-v2，但**文件名不变** —— 与 Python 同')

    dl = art['delete']
    A('LET(_TAA_ART_D_, DELETE_ARTICLE(%s));' % wl_opts(
        {'article_dir': '_TAA_ARTD_S_', 'file': dl['file']}))
    emit_test(src, A, 'article/delete_ok',
              ['ASSERT_EQ(AT_K(_TAA_ART_D_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_ART_D_, "deleted", FALSE), TRUE)'], None)
    emit_test(src, A, 'article/delete_files_gone',
              ['ASSERT(!EXISTS(_TAA_ART_SHTML_))',
               'ASSERT(!EXISTS(_TAA_ART_SMD_))'], None)
    emit_test(src, A, 'article/delete_no_backup_left',
              ['ASSERT(!EXISTS(CAT(_TAA_ART_SHTML_, ".backup")))',
               'ASSERT(!EXISTS(CAT(_TAA_ART_SMD_, ".backup")))'],
              '基准 backup_left == []（备份必须清干净）')

    dm = art['delete_missing']
    A('LET(_TAA_ART_DM_, DELETE_ARTICLE(%s));' % wl_opts(
        {'article_dir': '_TAA_ARTD_S_', 'file': dm['file']}))
    emit_test(src, A, 'article/delete_missing_ok',
              ['ASSERT_EQ(AT_K(_TAA_ART_DM_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_ART_DM_, "deleted", TRUE), FALSE)'],
              'Python: `if path.is_file()` 不成立 ⇒ 什么都不做、仍重定向（actions.py:102）')
    A('')

    # ── ③ 文章删除失败 ⇒ 回滚 ─────────────────────────────────────
    rb = art['rollback']
    A('// ── ③ 删除失败 ⇒ 回滚（卡点名守卫 ③）────────────────────────────')
    A('// Python 侧靠 monkeypatch `shutil.copy2` 第二次调用抛 OSError 造失败；')
    A('// WLWL 没有注入点 ⇒ 用**同义的失败源**：把备份目标 `<file>.html.backup`')
    A('// 先造成一个**目录** ⇒ COPY 必然失败（Python 的 copy2 到目录同样抛）。')
    A('// 断言的可观察结果与基准一致：失败 + 文章与 .md 都还在、内容未变。')
    A('LET(_TAA_RB_, PATH_JOIN(_TAA_ROOT_, "rollback"));')
    A('MKDIRS(_TAA_RB_);')
    A('LET(_TAA_RB_HTML_, PATH_JOIN(_TAA_RB_, %s));' % wl_string(rb['file']))
    A('LET(_TAA_RB_MD_, PATH_JOIN(_TAA_RB_, %s));' % wl_string(rb['file'][:-5] + '.md'))
    A('WRITE_FILE(_TAA_RB_HTML_, %s);' % wl_string(rb['html_text']))
    A('WRITE_FILE(_TAA_RB_MD_, %s);' % wl_string(rb['md_text']))
    A('MKDIRS(CAT(_TAA_RB_HTML_, ".backup"));')
    A('LET(_TAA_RB_R_, DELETE_ARTICLE(%s));' % wl_opts(
        {'article_dir': '__RB__', 'file': rb['file']}))
    emit_test(src, A, 'guard/delete_failure_reports_error',
              ['ASSERT_EQ(AT_K(_TAA_RB_R_, "ok", TRUE), FALSE)',
               'ASSERT_EQ(_TAA_STATUS_(AT_K(_TAA_RB_R_, "error", "")), "500")'], None)
    emit_test(src, A, 'guard/delete_failure_html_kept',
              ['ASSERT(EXISTS(_TAA_RB_HTML_))',
               'ASSERT_EQ(READ_FILE(_TAA_RB_HTML_), %s)' % wl_string(rb['html_text'])],
              '基准 html_still_there == True 且内容未变')
    emit_test(src, A, 'guard/delete_failure_md_kept',
              ['ASSERT(EXISTS(_TAA_RB_MD_))',
               'ASSERT_EQ(READ_FILE(_TAA_RB_MD_), %s)' % wl_string(rb['md_text'])],
              '基准 md_still_there == True 且内容未变')
    A('')

    # ── ④ 重名 ⇒ suffix ──────────────────────────────────────────
    col = art['collision']
    A('// ── ④ 重名创建：改用 `<date>-<slug>-<suffix>.html`（差异 D2）────')
    A('LET(_TAA_COL_, PATH_JOIN(_TAA_ROOT_, "collision"));')
    A('MKDIRS(_TAA_COL_);')
    A('WRITE_FILE(PATH_JOIN(_TAA_COL_, %s), "<!-- title: old -->\\n");'
      % wl_string(col['existing']))
    col_opts = dict(cp)
    col_opts['suffix'] = col['want_suffix']
    A('LET(_TAA_COL_R_, CREATE_ARTICLE(%s));' % wl_opts(
        dict([('article_dir', '__COL__')] + list(col_opts.items()))))
    emit_test(src, A, 'article/collision_new_name',
              ['ASSERT_EQ(AT_K(_TAA_COL_R_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_COL_R_, "file", ""), %s)' % wl_string(col['want_file'])],
              '基准 names_after 里新文件是 %s' % col['want_file'])
    emit_test(src, A, 'article/collision_both_exist',
              ['ASSERT(EXISTS(PATH_JOIN(_TAA_COL_, %s)))' % wl_string(col['want_file']),
               'ASSERT(EXISTS(PATH_JOIN(_TAA_COL_, %s)))' % wl_string(col['existing']),
               'ASSERT_EQ(READ_FILE(PATH_JOIN(_TAA_COL_, %s)), "<!-- title: old -->\\n")'
               % wl_string(col['existing'])],
              '旧文件必须原样保留（不能被覆盖）')
    A('')

    # ── ⑤ 独立页 ─────────────────────────────────────────────────
    pg = base['page']
    A('// ── ⑤ 独立页：create → save（改 slug）→ delete ────────────────')
    A('// ⚠ 同 ②：create 与 save 用两个目录（save 会删掉旧 slug 的文件）。')
    A('LET(_TAA_PGD_C_, PATH_JOIN(_TAA_ROOT_, "pg_create"));')
    A('LET(_TAA_PGD_S_, PATH_JOIN(_TAA_ROOT_, "pg_save"));')
    A('MKDIRS(_TAA_PGD_C_);')
    A('MKDIRS(_TAA_PGD_S_);')
    pc = dict(pg['create']['post'])
    A('LET(_TAA_PG_C_, CREATE_PAGE(%s));' % wl_opts(
        dict([('standalone_dir', '_TAA_PGD_C_')] + list(pc.items()))))
    give = pg['create']['want_file']
    A('LET(_TAA_PG_OLD_, PATH_JOIN(_TAA_PGD_C_, %s));' % wl_string(give))
    A('LET(_TAA_PG_OLDM_, PATH_JOIN(_TAA_PGD_C_, %s));' % wl_string(give[:-5] + '.md'))
    emit_test(src, A, 'page/create_ok',
              ['ASSERT_EQ(AT_K(_TAA_PG_C_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_PG_C_, "file", ""), %s)' % wl_string(give)], None)
    emit_test(src, A, 'page/create_md',
              ['ASSERT_EQ(READ_FILE(_TAA_PG_OLDM_), %s)' % wl_string(pg['create']['md'])], None)
    emit_test(src, A, 'page/create_html',
              ['ASSERT_EQ(READ_FILE(_TAA_PG_OLD_), %s)' % wl_string(pg['create']['html'])],
              'D5：整页渲染交给 REGEN ⇒ 只剩 title/summary 两行 meta 头')

    ps = dict(pg['save']['post'])
    A('// save 目录：先 create 出 about.html，再 save 成 contact.html')
    A('LET(_TAA_PG_C0_, CREATE_PAGE(%s));' % wl_opts(
        dict([('standalone_dir', '_TAA_PGD_S_')] + list(pc.items()))))
    A('LET(_TAA_PG_OLD2_, PATH_JOIN(_TAA_PGD_S_, %s));' % wl_string(give))
    A('LET(_TAA_PG_OLD2M_, PATH_JOIN(_TAA_PGD_S_, %s));' % wl_string(give[:-5] + '.md'))
    A('LET(_TAA_PG_S_, SAVE_PAGE(%s));' % wl_opts(
        dict([('standalone_dir', '_TAA_PGD_S_')] + list(ps.items()))))
    newf = pg['save']['new_file']
    A('LET(_TAA_PG_NEW_, PATH_JOIN(_TAA_PGD_S_, %s));' % wl_string(newf))
    A('LET(_TAA_PG_NEWM_, PATH_JOIN(_TAA_PGD_S_, %s));' % wl_string(newf[:-5] + '.md'))
    A('// 快照（后面的 delete 会删掉这两个文件；测试体跑得更晚）')
    A('LET(_TAA_PG_NEWM_TXT_, _TAA_READ_(_TAA_PG_NEWM_));')
    A('LET(_TAA_PG_NEW_TXT_, _TAA_READ_(_TAA_PG_NEW_));')
    emit_test(src, A, 'page/save_ok',
              ['ASSERT_EQ(AT_K(_TAA_PG_S_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_PG_S_, "file", ""), %s)' % wl_string(newf)], None)
    emit_test(src, A, 'page/save_old_removed',
              ['ASSERT(!EXISTS(_TAA_PG_OLD2_))',
               'ASSERT(!EXISTS(_TAA_PG_OLD2M_))'],
              '基准 save.left == [contact.html, contact.md] ⇒ about.* 必须消失（守卫⑦）')
    emit_test(src, A, 'page/save_new_content',
              ['ASSERT_EQ(_TAA_PG_NEWM_TXT_, %s)' % wl_string(pg['save']['md']),
               'ASSERT_EQ(_TAA_PG_NEW_TXT_, %s)' % wl_string(pg['save']['html'])], None)

    pd = pg['delete']
    A('LET(_TAA_PG_D_, DELETE_PAGE(%s));' % wl_opts(
        {'standalone_dir': '_TAA_PGD_S_', 'file': pd['file']}))
    emit_test(src, A, 'page/delete_ok',
              ['ASSERT_EQ(AT_K(_TAA_PG_D_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_PG_D_, "deleted", FALSE), TRUE)'], None)
    emit_test(src, A, 'page/delete_files_gone',
              ['ASSERT(!EXISTS(_TAA_PG_NEW_))',
               'ASSERT(!EXISTS(_TAA_PG_NEWM_))'], '基准 delete.left == []')
    A('')

    # ── ⑥ 上传 ───────────────────────────────────────────────────
    A('// ── ⑥ 上传：13 例逐字节对照（D8：year/month 显式钉成 2026-11）──')
    up_cases = []
    for i, e in enumerate(base['uploads']):
        U = 'UP_%02d' % i
        A('LET(_TAA_%s_ST_, PATH_JOIN(_TAA_ROOT_, %s));' % (U, wl_string('up_%02d' % i)))
        A('MKDIRS(_TAA_%s_ST_);' % U)
        # 重名用例：先把第一个文件摆进去
        for pre in e.get('precreate', []):
            A('MKDIRS(PATH_JOIN(_TAA_%s_ST_, "images/%d-%02d"));' % (U, UP_YEAR, UP_MONTH))
            A('WRITE_BYTES(PATH_JOIN(_TAA_%s_ST_, %s), %s);'
              % (U, wl_string('images/%d-%02d/%s' % (UP_YEAR, UP_MONTH, pre['file'])),
                 wl_value(pre['bytes'])))
        opts = {
            'static_dir': '_TAA_%s_ST_' % U,
            'filename': e['filename'],
            'data': e['data'],
            'year': UP_YEAR,
            'month': UP_MONTH,
        }
        A('LET(_TAA_%s_R_, UPLOAD_IMAGE(%s));' % (U, wl_opts(opts)))
        up_cases.append((U, e))

    for U, e in up_cases:
        name = 'upload/%s' % e['name']
        if e['want_ok']:
            p = 'PATH_JOIN(_TAA_%s_ST_, %s)' % (U, wl_string(e['file']))
            emit_test(src, A, name + '_ok',
                      ['ASSERT_EQ(AT_K(_TAA_%s_R_, "ok", FALSE), TRUE)' % U,
                       'ASSERT_EQ(AT_K(_TAA_%s_R_, "url", ""), %s)'
                       % (U, wl_string(e['want_url']))],
                      None)
            emit_test(src, A, name + '_file',
                      ['ASSERT(EXISTS(%s))' % p,
                       'ASSERT(&&(EXISTS(%s), ==(AT_K(FILE_META(%s), "size", -1), %d)))'
                       % (p, p, len(e['bytes']))],
                      '落盘路径 = static/%s（%d 字节）' % (e['file'], len(e['bytes'])))
            emit_test(src, A, name + '_bytes',
                      ['ASSERT(&&(EXISTS(%s), _TAA_ARR_EQ_(READ_BYTES(%s), %s)))'
                       % (p, p, wl_value(e['bytes']))],
                      '逐字节对照基准的 bytes')
        else:
            tgt = 'PATH_JOIN(_TAA_%s_ST_, %s)' % (
                U, wl_string('images/%d-%02d/%s' % (UP_YEAR, UP_MONTH, e['filename'])))
            emit_test(src, A, name + '_error',
                      ['ASSERT_EQ(AT_K(_TAA_%s_R_, "ok", TRUE), FALSE)' % U,
                       'ASSERT_EQ(_TAA_STATUS_(AT_K(_TAA_%s_R_, "error", "")), "400")' % U,
                       'ASSERT_EQ(AT_K(_TAA_%s_R_, "error", ""), %s)'
                       % (U, wl_string(e['want_error_prefix']))],
                      '基准 files == []（拒了就不能落盘）')
            emit_test(src, A, name + '_not_written',
                      ['ASSERT(!EXISTS(%s))' % tgt], None)
    A('')
    A('// ── 已登记差异 D1b：base64 尾部多一个 "="（Python 宽容、本模块拒）────')
    A('// 基准 deviations.b64_lenient_pad：Python 把 "AAAA=" 解成 3 字节，')
    A('// 本模块要求「= 只在结尾且补位后恰好补齐一组」⇒ 报 Invalid base64 data。')
    A('// 两种口径下都过不了 magic bytes，对外差别只在错误码。')
    dpad = base['deviations']['b64_lenient_pad']
    A('LET(_TAA_DEV_PAD_D_, PATH_JOIN(_TAA_ROOT_, "dev_pad"));')
    A('MKDIRS(_TAA_DEV_PAD_D_);')
    A('LET(_TAA_DEV_PAD_, UPLOAD_IMAGE(%s));' % wl_opts(
        {'filename': 'p.png', 'data': dpad['data'], 'static_dir': '_TAA_DEV_PAD_D_',
         'year': UP_YEAR, 'month': UP_MONTH}))
    emit_test(src, A, 'deviation/b64_lenient_pad',
              ['ASSERT_EQ(AT_K(_TAA_DEV_PAD_, "ok", TRUE), FALSE)',
               'ASSERT_EQ(AT_K(_TAA_DEV_PAD_, "error", ""), %s)'
               % wl_string(dpad['wlwl'])],
              'Python 侧 base64.b64decode(%r) == %r（3 字节）；这里钉 WLWL 口径'
              % (dpad['data'], bytes(dpad['python_bytes'])))
    A('')

    # ── ⑦ 主题 ───────────────────────────────────────────────────
    th = base['theme']
    A('// ── ⑦ 主题：SET_THEME 只做「选中 + 落 config」；重建交给 REGEN ─────')
    A('LET(_TAA_THEMES_, PATH_JOIN(_TAA_ROOT_, "themes"));')
    A('LET(_TAA_MANIFEST_, PATH_JOIN(_TAA_THEMES_, "default/manifest.json"));')
    A('MKDIRS(PATH_JOIN(_TAA_THEMES_, "default"));')
    A('WRITE_FILE(_TAA_MANIFEST_, "{}");')
    A('// ① 全新：目录里没有 config.json')
    A('LET(_TAA_CFG1_, PATH_JOIN(_TAA_ROOT_, "cfg_fresh"));')
    A('MKDIRS(_TAA_CFG1_);')
    A('LET(_TAA_CFG1_F_, PATH_JOIN(_TAA_CFG1_, "config.json"));')
    A('LET(_TAA_T1_, SET_THEME(%s));' % wl_opts(
        {'theme': th['theme'], 'themes_dir': '__TH__', 'config_dir': '_TAA_CFG1_'}
    ))
    emit_test(src, A, 'theme/set_ok',
              ['ASSERT_EQ(AT_K(_TAA_T1_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_T1_, "theme", ""), %s)' % wl_string(th['theme']),
               'ASSERT_EQ(AT_K(_TAA_T1_, "persisted", FALSE), TRUE)'], None)
    emit_test(src, A, 'theme/fresh_config',
              ['ASSERT(EXISTS(_TAA_CFG1_F_))',
               'ASSERT_EQ(AT_K(PARSE(READ_FILE(_TAA_CFG1_F_)), "theme_name", ""), %s)'
               % wl_string(th['theme'])],
              '基准 fresh_config = %s（D6：WLWL 紧凑+排序，按语义比）' % th['fresh_config'])

    A('// ② 已有 config.json（含 locale）⇒ 合并，其余键保留')
    A('LET(_TAA_CFG2_, PATH_JOIN(_TAA_ROOT_, "cfg_merge"));')
    A('MKDIRS(_TAA_CFG2_);')
    A('LET(_TAA_CFG2_F_, PATH_JOIN(_TAA_CFG2_, "config.json"));')
    A('WRITE_FILE(_TAA_CFG2_F_, "{\\"locale\\": \\"zh\\"}");')
    A('LET(_TAA_T2_, SET_THEME(%s));' % wl_opts(
        {'theme': th['theme'], 'themes_dir': '__TH__', 'config_dir': '_TAA_CFG2_'}
    ))
    emit_test(src, A, 'theme/merged_config',
              ['ASSERT_EQ(AT_K(_TAA_T2_, "persisted", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(PARSE(READ_FILE(_TAA_CFG2_F_)), "theme_name", ""), %s)'
               % wl_string(th['theme']),
               'ASSERT_EQ(AT_K(PARSE(READ_FILE(_TAA_CFG2_F_)), "locale", ""), "zh")'],
              '基准 merged_config = %s' % th['merged_config'])

    A('// ③ 现有 config.json 不是合法 JSON ⇒ Python 抛 JSONDecodeError ⇒ 只 warning、不写')
    A('LET(_TAA_CFG3_, PATH_JOIN(_TAA_ROOT_, "cfg_broken"));')
    A('MKDIRS(_TAA_CFG3_);')
    A('LET(_TAA_CFG3_F_, PATH_JOIN(_TAA_CFG3_, "config.json"));')
    A('WRITE_FILE(_TAA_CFG3_F_, %s);' % wl_string(th['broken_input']))
    A('LET(_TAA_T3_, SET_THEME(%s));' % wl_opts(
        {'theme': th['theme'], 'themes_dir': '__TH__', 'config_dir': '_TAA_CFG3_'}
    ))
    emit_test(src, A, 'theme/broken_config_not_overwritten',
              ['ASSERT_EQ(AT_K(_TAA_T3_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_T3_, "persisted", TRUE), FALSE)',
               'ASSERT_EQ(READ_FILE(_TAA_CFG3_F_), %s)' % wl_string(th['broken_input'])],
              '读失败/解析失败 ⇒ set_theme 仍成功，但不持久化（actions.py:367）')
    A('')

    # ── ⑧ 预览 / 重建 ─────────────────────────────────────────────
    A('// ── ⑧ 预览（只做 Markdown 渲染）+ 重建（只回报「该重建了」）──────')
    for i, e in enumerate(base['preview']):
        A('LET(_TAA_PV_%02d_R_, PREVIEW(%s));' % (i, wl_value({'content': e['content']})))
    for i, e in enumerate(base['preview']):
        label = (e['content'].split('\n')[0][:24] if e['content'] else '<empty>')
        emit_test(src, A, 'preview/%02d' % i,
                  ['ASSERT_EQ(AT_K(_TAA_PV_%02d_R_, "ok", FALSE), TRUE)' % i,
                   'ASSERT_EQ(AT_K(_TAA_PV_%02d_R_, "html", ""), %s)'
                   % (i, wl_string(e['want_html']))],
                  '输入 %r' % label)
    A('LET(_TAA_REGEN_, REGEN(DICT()));')
    emit_test(src, A, 'regen/ok',
              ['ASSERT_EQ(AT_K(_TAA_REGEN_, "ok", FALSE), TRUE)',
               'ASSERT_EQ(AT_K(_TAA_REGEN_, "regen", FALSE), TRUE)'],
              '全站构建在 tp/bin/build.wll::BUILD，本模块只回报「该重建了」')
    A('')

    # ── ⑨ errors 组 ──────────────────────────────────────────────
    A('// ── ⑨ 错误路径：20 例（消息逐字 + 状态码映射）───────────────────')
    A('LET(_TAA_ERR_, PATH_JOIN(_TAA_ROOT_, "err"));')
    A('MKDIRS(_TAA_ERR_);')
    A('WRITE_FILE(PATH_JOIN(_TAA_ERR_, "dup.html"), "<!-- title: d -->\\n");')

    # (名字, 调用表达式, 期望消息, 说明)
    err_cases = [
        ('create_missing_title',
         'CREATE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__', 'title': '',
                                         'date': '2026-01-02 10:30', 'content': 'c'}),
         'Missing fields', None),
        ('create_missing_date',
         'CREATE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__', 'title': 'T',
                                         'date': '', 'content': 'c'}),
         'Missing fields', None),
        ('write_invalid_filename',
         'CREATE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__', 'title': 'T',
                                         'date': 'abcdefghij', 'content': 'c'}),
         'Invalid filename: abcdefghij-t.html',
         '基准诱因是 content.write_article("bad-name.html")，该入口 WLWL 未导出；'
         '这里用等价诱因（日期前 10 位不是日期 ⇒ 拼出的文件名非法）打同一条校验分支，'
         '消息模板 `Invalid filename: <fname>` 逐字断言'),
        ('write_title_201',
         'CREATE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__', 'title': '__T201__',
                                         'date': '2026-01-02 10:30', 'content': 'c'}),
         'Title invalid or too long: 201', '校验顺序：文件名 → 标题 → 正文 → 日期'),
        ('write_content_50001',
         'CREATE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__', 'title': 'T',
                                         'date': '2026-01-02 10:30',
                                         'content': '__C50001__'}),
         'Content validation failed: length=50001', None),
        ('write_bad_date',
         'SAVE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__',
                                       'file': '2026-01-02-t.html', 'title': 'T',
                                       'date': '2026-13-01 10:00', 'content': 'c'}),
         'Invalid date format: 2026-13-01 10:00',
         '基准是 write_article("2026-01-02-t.html", date="2026-13-01 10:00")：'
         '文件名合法、日期非法。CREATE_ARTICLE 的文件名由 date[:10] 拼出，'
         '2026-13 会先被文件名校验拦掉 ⇒ 改用 SAVE_ARTICLE 传显式 file 复现同一条分支'),
        ('save_missing_file',
         'SAVE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__', 'file': '', 'title': 'T',
                                       'date': '2026-01-02 10:30', 'content': 'c'}),
         'Missing fields', None),
        ('save_invalid_filename',
         'SAVE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__', 'file': 'bad.html',
                                       'title': 'T', 'date': '2026-01-02 10:30',
                                       'content': 'c'}),
         'Invalid filename', None),
        ('delete_invalid_filename',
         'DELETE_ARTICLE(%s)' % wl_opts({'article_dir': '__ERR__', 'file': '/etc/passwd'}),
         'Invalid filename', None),
        ('page_missing_slug',
         'CREATE_PAGE(%s)' % wl_opts({'standalone_dir': '__ERR__', 'title': 'T',
                                      'slug': '', 'content': 'c'}),
         'Missing fields', None),
        ('page_invalid_slug',
         'CREATE_PAGE(%s)' % wl_opts({'standalone_dir': '__ERR__', 'title': 'T',
                                      'slug': 'a/b', 'content': 'c'}),
         'Invalid slug', None),
        ('page_exists',
         'CREATE_PAGE(%s)' % wl_opts({'standalone_dir': '__ERR__', 'title': 'T',
                                      'slug': 'dup', 'content': 'c'}),
         'Page already exists', 'dup.html 已存在 ⇒ 409'),
        ('save_page_invalid_filename',
         'SAVE_PAGE(%s)' % wl_opts({'standalone_dir': '__ERR__', 'file': 'a b.html',
                                    'title': 'T', 'slug': 's', 'content': 'c'}),
         'Invalid filename', None),
        ('delete_page_invalid_filename',
         'DELETE_PAGE(%s)' % wl_opts({'standalone_dir': '__ERR__', 'file': 'x.txt'}),
         'Invalid filename', None),
        ('theme_missing_name',
         'SET_THEME(%s)' % wl_opts({'theme': '', 'themes_dir': '__TH__',
                                    'config_dir': '__ERR__'}),
         'Missing theme name', None),
        ('theme_not_found',
         'SET_THEME(%s)' % wl_opts({'theme': 'nope', 'themes_dir': '__TH__',
                                    'config_dir': '__ERR__'}),
         'Theme not found', None),
        ('upload_missing',
         'UPLOAD_IMAGE(%s)' % wl_opts({'filename': '', 'data': 'x',
                                       'static_dir': '__ERR__'}),
         'Missing filename or data', None),
        ('upload_bad_ext',
         'UPLOAD_IMAGE(%s)' % wl_opts({'filename': 'shell.php', 'data': 'PD9waHA=',
                                       'static_dir': '__ERR__', 'year': UP_YEAR,
                                       'month': UP_MONTH}),
         'File type not allowed: .php', '内容本身合法也无用 ⇒ 扩展名白名单先拦'),
        ('upload_bad_b64',
         'UPLOAD_IMAGE(%s)' % wl_opts({'filename': 'a.png', 'data': 'AAAAA',
                                       'static_dir': '__ERR__', 'year': UP_YEAR,
                                       'month': UP_MONTH}),
         'Invalid base64 data', '长度 % 4 == 1（Python 同样报错）'),
        ('upload_wrong_magic',
         'UPLOAD_IMAGE(%s)' % wl_opts({'filename': 'a.png',
                                       'data': 'PD9waHAgZWNobyAxOyA/Pg==',
                                       'static_dir': '__ERR__', 'year': UP_YEAR,
                                       'month': UP_MONTH}),
         'Invalid image format', '内容 = `<?php echo 1; ?>`（与基准同一份 base64）'),
    ]
    want_status = {e['name']: e['want_status'] for e in base['errors']}
    for i, (nm, call, want_err, note) in enumerate(err_cases):
        A('LET(_TAA_E%02d_R_, %s);' % (i, call))
    A('')
    for i, (nm, call, want_err, note) in enumerate(err_cases):
        U = 'E%02d' % i
        st = want_status[nm]
        want_st = st.split(' ')[0] if st else '500'
        lines = ['ASSERT_EQ(AT_K(_TAA_%s_R_, "ok", TRUE), FALSE)' % U,
                 'ASSERT_EQ(AT_K(_TAA_%s_R_, "error", ""), %s)' % (U, wl_string(want_err)),
                 'ASSERT_EQ(_TAA_STATUS_(AT_K(_TAA_%s_R_, "error", "")), "%s")' % (U, want_st)]
        if st is None:
            hdr = ((note + '；') if note else '') + \
                '基准 want_status = None（ValueError ⇒ WSGI 兜成 500）'
        else:
            hdr = ((note + '；') if note else '') + '基准 want_status = %s' % st
        emit_test(src, A, 'errors/%s' % nm, lines, hdr)
    A('')

    # ── ⑩ 反向守卫 ───────────────────────────────────────────────
    A('// ── ⑩ 反向守卫（卡点名 ①②③ + 补 ④⑤⑥⑦）──────────────────────')
    A('// ① 扩展名白名单：.php / .html 即使内容是合法 PNG 也必须拒')
    A('LET(_TAA_G_PHP_, UPLOAD_IMAGE(%s));' % wl_opts(
        {'filename': 'x.php', 'data': PNG_B64, 'static_dir': '_TAA_GST_',
         'year': UP_YEAR, 'month': UP_MONTH}))
    A('LET(_TAA_G_HTML_, UPLOAD_IMAGE(%s));' % wl_opts(
        {'filename': 'x.html', 'data': PNG_B64, 'static_dir': '_TAA_GST_',
         'year': UP_YEAR, 'month': UP_MONTH}))
    emit_test(src, A, 'guard/upload_php_rejected',
              ['ASSERT_EQ(AT_K(_TAA_G_PHP_, "ok", TRUE), FALSE)',
               'ASSERT_EQ(AT_K(_TAA_G_PHP_, "error", ""), "File type not allowed: .php")'],
              '内容 = 合法 1×1 PNG 的 base64')
    emit_test(src, A, 'guard/upload_html_rejected',
              ['ASSERT_EQ(AT_K(_TAA_G_HTML_, "ok", TRUE), FALSE)',
               'ASSERT_EQ(AT_K(_TAA_G_HTML_, "error", ""), "File type not allowed: .html")'],
              None)
    emit_test(src, A, 'guard/upload_php_html_not_on_disk',
              ['ASSERT(!EXISTS(PATH_JOIN(_TAA_GST_, "images/2026-11/x.php")))',
               'ASSERT(!EXISTS(PATH_JOIN(_TAA_GST_, "images/2026-11/x.html")))'], None)

    A('// ② 扩展名合法但内容不是图片 ⇒ magic bytes 必须拒')
    A('LET(_TAA_G_MAGIC_, UPLOAD_IMAGE(%s));' % wl_opts(
        {'filename': 'shell.png', 'data': 'PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=',
         'static_dir': '_TAA_GST_', 'year': UP_YEAR, 'month': UP_MONTH}))
    emit_test(src, A, 'guard/upload_php_as_png_rejected',
              ['ASSERT_EQ(AT_K(_TAA_G_MAGIC_, "ok", TRUE), FALSE)',
               'ASSERT_EQ(AT_K(_TAA_G_MAGIC_, "error", ""), "Invalid image format")',
               'ASSERT(!EXISTS(PATH_JOIN(_TAA_GST_, "images/2026-11/shell.png")))'],
              'data = base64("<?php system($_GET[c]); ?>")')

    A('// ③（见上：guard/delete_failure_*）')
    A('// ④ 删除文件名带 `..` ⇒ 拒，且目录外文件不受影响')
    A('WRITE_FILE(PATH_JOIN(_TAA_ROOT_, "outside.txt"), "keep");')
    A('LET(_TAA_G_TRAV_, DELETE_ARTICLE(%s));' % wl_opts(
        {'article_dir': '__ART__', 'file': '../outside.txt'}))
    emit_test(src, A, 'guard/delete_traversal_rejected',
              ['ASSERT_EQ(AT_K(_TAA_G_TRAV_, "ok", TRUE), FALSE)',
               'ASSERT(EXISTS(PATH_JOIN(_TAA_ROOT_, "outside.txt")))',
               'ASSERT_EQ(READ_FILE(PATH_JOIN(_TAA_ROOT_, "outside.txt")), "keep")'], None)

    A('// ⑤ 上传文件名带 `..` ⇒ 净化后仍含 `..` ⇒ 拒，且不落盘')
    A('LET(_TAA_G_UPTRAV_, UPLOAD_IMAGE(%s));' % wl_opts(
        {'filename': '../x.png', 'data': PNG_B64, 'static_dir': '_TAA_GST_',
         'year': UP_YEAR, 'month': UP_MONTH}))
    emit_test(src, A, 'guard/upload_traversal_rejected',
              ['ASSERT_EQ(AT_K(_TAA_G_UPTRAV_, "ok", TRUE), FALSE)',
               'ASSERT_EQ(AT_K(_TAA_G_UPTRAV_, "error", ""), "Invalid filename")',
               'ASSERT(!EXISTS(PATH_JOIN(_TAA_ROOT_, "x.png")))',
               'ASSERT(!EXISTS(PATH_JOIN(_TAA_GST_, "images/2026-11/.._x.png")))'],
              '净化把 `/` 换成 `_` ⇒ ".._x.png"；`..` 仍在 ⇒ 拒')

    A('// ⑥ 独立页 slug 带 `../` ⇒ 拒，且目录外无文件')
    A('LET(_TAA_G_SLUG_, CREATE_PAGE(%s));' % wl_opts(
        {'standalone_dir': '__PG__', 'title': 'T', 'slug': '../evil', 'content': 'c'}))
    emit_test(src, A, 'guard/page_slug_traversal_rejected',
              ['ASSERT_EQ(AT_K(_TAA_G_SLUG_, "ok", TRUE), FALSE)',
               'ASSERT_EQ(AT_K(_TAA_G_SLUG_, "error", ""), "Invalid slug")',
               'ASSERT(!EXISTS(PATH_JOIN(_TAA_ROOT_, "evil.html")))'], None)

    A('// ⑦ SAVE_PAGE 改 slug ⇒ 旧文件必须消失 —— 见 page/save_old_removed')
    A('')

    # ── 跑测试 ───────────────────────────────────────────────────
    A('// ── 跑测试 ────────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_admin_actions: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_admin_actions: failed=", failed);')
    if os.environ.get('TAA_DEBUG'):
        # 调试用（TAA_DEBUG=1）：把失败记录的 payload 与关键读数打出来，不进默认产物
        A('')
        A('PRINT("=== DEBUG ===");')
        A('FOR(rec, records,')
        A('    IF(AT_K(rec, "passed", TRUE), NULL,')
        A('        PRINT("FAILREC ", AT_K(rec, "name", "?"), " :: ",'
          ' STRINGIFY(AT_K(rec, "error", "?")))));')
        A('PRINT("err00:", STRINGIFY(_TAA_E00_R_));')
        A('PRINT("status00:", _TAA_STATUS_(AT_K(_TAA_E00_R_, "error", "")));')
        A('PRINT("statusmap0:", STRINGIFY(AT(_TAA_STATUS_MAP_, 0, "?")));')
        A('PRINT("art_md:", READ_FILE(_TAA_ART_MD_));')
        A('PRINT("art_html:", READ_FILE(_TAA_ART_HTML_));')
        A('PRINT("up00:", STRINGIFY(_TAA_UP_00_R_));')
        A('PRINT("up02:", STRINGIFY(_TAA_UP_02_R_));')
        A('PRINT("saveS:", STRINGIFY(_TAA_ART_S_));')
        A('IF(EXISTS(_TAA_ART_SMD_), (PRINT("smd:", READ_FILE(_TAA_ART_SMD_))), '
          '(PRINT("smd MISSING")));')
        A('IF(EXISTS(_TAA_ART_SHTML_), (PRINT("shtml:", READ_FILE(_TAA_ART_SHTML_))), '
          '(PRINT("shtml MISSING")));')
        A('PRINT("e04:", STRINGIFY(_TAA_E04_R_));')
        A('PRINT("e05:", STRINGIFY(_TAA_E05_R_));')
        A('PRINT("sl06:", STRINGIFY(_TAA_SL_06_R_));')
        A('PRINT("pgsave:", STRINGIFY(_TAA_PG_S_));')
        A('IF(EXISTS(_TAA_PG_NEWM_), (PRINT("pgnm:", READ_FILE(_TAA_PG_NEWM_))), '
          '(PRINT("pgnm MISSING")));')
    A('IF(>(failed, 0), (PRINT_ERR("test_admin_actions: FAILED"); '
      'PANIC("admin_actions tests failed")), NULL);')
    A('PRINT("test_admin_actions: OK");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines, %d slugify + %d errors 用例)'
          % (OUT, chars, lines, len(slug_cases), len(err_cases)))


if __name__ == '__main__':
    main()
