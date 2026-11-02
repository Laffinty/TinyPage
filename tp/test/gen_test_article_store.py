"""生成 tp/test/test_article_store.wll —— 文章存储的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的结果**逐字节对照**。
基准：tp/test/fixtures/article_store_baseline.json
    （由 tp/test/gen_article_store_baseline.py 用真 Python 生成）。

**分组与各自的断言形态**：
  | 基准组 | WLWL 调用 | 断言 |
  |---|---|---|
  | validate_filename | `VALIDATE_FILENAME(s)` | == want（BOOLEAN） |
  | validate_content | `VALIDATE_CONTENT(s)` | == want（BOOLEAN） |
  | validate_date_format | `VALIDATE_DATE_FORMAT(s)` | == want（BOOLEAN） |
  | validate_title | `VALIDATE_TITLE(s)` | == want（BOOLEAN） |
  | safe_path_check | `SAFE_PATH_CHECK(s, base)` | ok / rel 分别断言 |
  | source_path | `SOURCE_PATH(s)` | == want（STRING） |
  | write_source | `WRITE_SOURCE(html, content)` | md_name / content 分别断言 |
  | decode_content | `DECODE_CONTENT(s)` | == want（STRING|NULL） |
  | decode_legacy_body | `DECODE_LEGACY_BODY(s)` | == want（STRING|NULL） |
  | unescape_to_fixpoint | `UNESCAPE_TO_FIXPOINT(s)` | == want（STRING） |
  | meta_value | `META_VALUE(s)` | == want（STRING） |

**两个需要真实文件系统的组**（基准生成器与本文件必须用**同一份布局**）：
  · `safe_path_check`：`base` 目录下要有 `ok.html` / `bad.exe` / `sub/a.txt`
    三个文件与 `sub` 目录（扩展名白名单分支依赖目标**是否真实存在**），
    还要有**兄弟目录** `pages-evil`（前缀绕过用例）。
    ⇒ 本文件在 WLWL 侧用 `TEMP_DIR()` + `MKDIRS` + `WRITE_FILE` 重建同一布局。
  · `write_source`：真的写文件、再读回来比对字节。

**反向守卫**（卡 S2-1 的要求）：
  · `../etc/passwd` 形态的路径 ⇒ 必须被拒
  · `pages-evil/x.html` 形态（同前缀兄弟目录）⇒ 必须被拒
  · 写入中途失败 ⇒ 不得留下半截 `.html`

用法：python gen_test_article_store.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_article_store.wll')

# safe_path_check 的夹具布局 —— 必须与 gen_article_store_baseline.py 的
# SAFE_PATH_FIXTURE **逐字一致**
SAFE_PATH_FILES = ['ok.html', 'bad.exe', 'sub/a.txt']
SAFE_PATH_DIRS = ['sub']
SAFE_PATH_SIBLING = 'pages-evil'


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ WLWL 的转义白名单只有：\" \\ / \\n \\r \\t \\b \\f \\0 \\
      ⇒ 其余控制字符**无法**写进字面量（必须用 UTF8_DECODE 运行时造）。
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
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def wl_value(v):
    """Python 值（str / bool / None / int / float / dict / list）→ WLWL 字面量。"""
    if isinstance(v, str):
        return wl_string(v)
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        s = repr(v)
        if '.' not in s and 'e' not in s and 'E' not in s:
            s += '.0'
        return s
    if isinstance(v, dict):
        return '[' + ', '.join('%s: %s' % (wl_string(k), wl_value(x))
                               for k, x in v.items()) + ']'
    if isinstance(v, list):
        return '[' + ', '.join(wl_value(x) for x in v) + ']'
    raise TypeError('bad fixture value: %r' % (v,))


def materialize(spec):
    """把基准的三种输入形态还原成 Python 字符串。

    形态（见 gen_article_store_baseline.py）：
      {'input': '字面量'} / {'repeat': {'unit': 'a', 'count': 50000}} /
      {'codepoints': [1, 2, 97]}
    """
    if 'input' in spec:
        return spec['input']
    if 'repeat' in spec:
        r = spec['repeat']
        return r['unit'] * r['count']
    if 'codepoints' in spec:
        return ''.join(chr(c) for c in spec['codepoints'])
    raise ValueError('bad input spec: %r' % (spec,))


def wl_input_expr(spec):
    """把输入形态渲染成 WLWL 表达式。

    ⚠ 输入有两种形态：
      · **裸字符串**（多数组）⇒ 直接字面量；
      · **spec 字典**（`{'input': …}` / `{'repeat': …}` / `{'codepoints': …}`）
        ⇒ 按形态分别渲染。
    ⚠ 含控制字符（ord<32 且非 \\t\\n\\r）的字符串**无法**写成字面量
      （WLWL 的转义白名单不含它们）⇒ 运行时用 `UTF8_DECODE([...])` 造。
      ⇒ 输入里含控制字符时，返回一个**表达式**而不是字面量。
    """
    if isinstance(spec, str):
        s = spec
        if any(ord(c) < 32 and c not in '\t\n\r' for c in s):
            return _utf8_expr(s)
        return wl_string(s)
    if 'input' in spec:
        return wl_input_expr(spec['input'])
    if 'repeat' in spec:
        r = spec['repeat']
        unit = r['unit']
        if any(ord(c) < 32 and c not in '\t\n\r' for c in unit):
            return _utf8_expr(unit * r['count'])
        # 重复构造：WLWL 没有 REPEAT 内建 ⇒ 用本文件定义的 _REPEAT_
        return '_REPEAT_(%s, %d)' % (wl_string(unit), r['count'])
    if 'codepoints' in spec:
        return _utf8_expr(''.join(chr(c) for c in spec['codepoints']))
    raise ValueError('bad input spec: %r' % (spec,))


def _utf8_expr(s):
    """字符串 → UTF8_DECODE([...]) 表达式（码点序列）。"""
    return 'UTF8_DECODE([%s])' % ', '.join(str(ord(c)) for c in s)


def _replace_base_placeholder(expr):
    """把 WLWL 字面量里的 `{BASE}` 占位符替换成 `_BASE_` 表达式。

    输入形如 `"{BASE}/ok.html"`（WLWL 字符串字面量）；
    输出形如 `_BASE_ + "/ok.html"`（拼接表达式）。
    ⚠ `_BASE_` 是本测试文件在 TEMP_DIR 下建的 pages 目录。
    """
    # 去掉外层引号，按 {BASE} 切分
    assert expr.startswith('"') and expr.endswith('"'), expr
    inner = expr[1:-1]
    parts = inner.split('{BASE}')
    pieces = []
    for i, part in enumerate(parts):
        if i > 0:
            pieces.append('_BASE_')
        if part:
            pieces.append(wl_string(part))
    if not pieces:
        return '_BASE_'
    out = pieces[0]
    for p in pieces[1:]:
        out = '+(' + out + ', ' + p + ')'
    return out


def main():
    with open(os.path.join(FIXTURES, 'article_store_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']

    src = []
    A = src.append
    A('// tp/test/test_article_store.wll —— 文章存储的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_article_store.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的结果逐字节对照。')
    A('// 基准：tp/test/fixtures/article_store_baseline.json')
    A('//   （由 tp/test/gen_article_store_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS", '
      '"TEMP_DIR"]);')
    A('IMPORT("wlwl:std.fs", ["MKDIRS", "WRITE_FILE", "READ_FILE", "PATH_JOIN", '
      '"PATH_DIR", "PATH_BASE", "PATH_CANONICAL", "EXISTS"]);')
    A('IMPORT("wlwl:std.encode", ["UTF8_DECODE"]);')
    A('IMPORT("./../lib/article_store.wll", ["DECODE_CONTENT", '
      '"DECODE_LEGACY_BODY", "META_VALUE", "SAFE_PATH_CHECK", "SOURCE_PATH", '
      '"UNESCAPE_TO_FIXPOINT", "VALIDATE_CONTENT", "VALIDATE_DATE_FORMAT", '
      '"VALIDATE_FILENAME", "VALIDATE_TITLE", "WRITE_SOURCE"]);')
    A('')
    A('// ── 工具：重复构造字符串（基准里的大用例靠它展开）────────────────')
    src += fn('_REPEAT_', 'unit, n', [
        'LET MUT(out, "")',
        'LET MUT(i, 0)',
        C('WHILE', '<(i, n)', [
            'SET(out, +(out, unit))',
            'SET(i, +(i, 1))',
        ]),
        'out',
    ], '// 把 unit 重复 n 次（WLWL 没有 REPEAT 内建）')
    A('')

    # ── safe_path_check 的夹具目录 ─────────────────────────────────
    A('// ── safe_path_check 的夹具（与基准生成器的 SAFE_PATH_FIXTURE 同一份）──')
    A('//   base 下有 ok.html / bad.exe / sub/a.txt 与 sub 目录；')
    A('//   另有**兄弟目录** pages-evil（前缀绕过用例用）。')
    A('LET(_TD_, TEMP_DIR());')
    A('LET(_BASE_, PATH_JOIN(_TD_, "pages"));')
    A('LET(_SIBLING_, PATH_JOIN(_TD_, "pages-evil"));')
    A('MKDIRS(PATH_JOIN(_BASE_, "sub"));')
    A('MKDIRS(_SIBLING_);')
    A('WRITE_FILE(PATH_JOIN(_BASE_, "ok.html"), "x");')
    A('WRITE_FILE(PATH_JOIN(_BASE_, "bad.exe"), "x");')
    A('WRITE_FILE(PATH_JOIN(_BASE_, "sub/a.txt"), "x");')
    A('')

    # ── 用例数据 ──────────────────────────────────────────────────
    A('// ── 用例数据（逐字节来自基准）─────────────────────────────────')

    # ① 布尔型四组
    for group, fn_name in [
            ('validate_filename', 'VALIDATE_FILENAME'),
            ('validate_content', 'VALIDATE_CONTENT'),
            ('validate_date_format', 'VALIDATE_DATE_FORMAT'),
            ('validate_title', 'VALIDATE_TITLE'),
    ]:
        for key in sorted(cases[group]):
            e = cases[group][key]
            name = '%s_%s' % (group, key)
            expr = wl_input_expr(e['input'])
            A('LET(in_%s, %s);' % (name, expr))
            A('LET(want_%s, %s);' % (name, wl_value(e['want'])))

    # ② 纯字符串返回的三组
    for group, fn_name in [
            ('source_path', 'SOURCE_PATH'),
            ('decode_content', 'DECODE_CONTENT'),
            ('decode_legacy_body', 'DECODE_LEGACY_BODY'),
            ('unescape_to_fixpoint', 'UNESCAPE_TO_FIXPOINT'),
            ('meta_value', 'META_VALUE'),
    ]:
        for key in sorted(cases[group]):
            e = cases[group][key]
            name = '%s_%s' % (group, key)
            expr = wl_input_expr(e['input'])
            A('LET(in_%s, %s);' % (name, expr))
            A('LET(want_%s, %s);' % (name, wl_value(e['want'])))

    # ③ safe_path_check（两个返回值分别断言）
    A('// safe_path_check 的 want 是 {ok, rel} ⇒ 分开断言')
    A('// ⚠ 基准里的 `{BASE}` 是**占位符**（Python 侧 substitute 成真实临时目录）')
    A('//   ⇒ 测试侧要替换成 `_BASE_` 表达式，否则绝对路径用例（p16/p17）对不上。')
    for key in sorted(cases['safe_path_check']):
        e = cases['safe_path_check'][key]
        name = 'safe_path_check_%s' % key
        want = e['want']
        expr = wl_input_expr(e['input'])
        if '{BASE}' in expr:
            # 字面量里含占位符 ⇒ 用 + 拼接（"前缀" + _BASE_ + "后缀"）
            expr = _replace_base_placeholder(expr)
        A('LET(in_%s, %s);' % (name, expr))
        A('LET(want_%s_ok, %s);' % (name, wl_value(want['ok'])))
        A('LET(want_%s_rel, %s);' % (name, wl_value(want['rel'])))

    # ④ write_source（真写文件 ⇒ 需要 html_path 与 content）
    A('// write_source 真写文件 ⇒ 每个用例用独立目录，避免互相覆盖')
    for key in sorted(cases['write_source']):
        e = cases['write_source'][key]
        name = 'write_source_%s' % key
        spec = e['input']
        want = e['want']
        A('LET(dir_%s, PATH_JOIN(_TD_, "ws_%s"));' % (name, key))
        A('MKDIRS(dir_%s);' % name)
        A('LET(html_%s, PATH_JOIN(dir_%s, %s));' % (name, name, wl_string(spec['html_path'])))
        A('LET(content_%s, %s);' % (name, wl_input_expr(
            {'input': spec['content']})))
        A('LET(want_%s_md, %s);' % (name, wl_value(want['md_name'])))
        A('LET(want_%s_content, %s);' % (name, wl_value(want['content'])))

    A('')

    # ── 用例 ──────────────────────────────────────────────────────
    A('// ── 用例 ──────────────────────────────────────────────────────')
    for group, fn_name in [
            ('validate_filename', 'VALIDATE_FILENAME'),
            ('validate_content', 'VALIDATE_CONTENT'),
            ('validate_date_format', 'VALIDATE_DATE_FORMAT'),
            ('validate_title', 'VALIDATE_TITLE'),
    ]:
        for key in sorted(cases[group]):
            name = '%s_%s' % (group, key)
            e = cases[group][key]
            note = e.get('note')
            if note:
                A('// ⚠ %s：%s' % (name, note))
            A('TEST("%s", FUN(() ,' % name)
            A('    (ASSERT_EQ(%s(in_%s), want_%s));' % (fn_name, name, name))
            A('    TRUE));')

    for group, fn_name in [
            ('source_path', 'SOURCE_PATH'),
            ('decode_content', 'DECODE_CONTENT'),
            ('decode_legacy_body', 'DECODE_LEGACY_BODY'),
            ('unescape_to_fixpoint', 'UNESCAPE_TO_FIXPOINT'),
            ('meta_value', 'META_VALUE'),
    ]:
        for key in sorted(cases[group]):
            name = '%s_%s' % (group, key)
            e = cases[group][key]
            note = e.get('note')
            if note:
                A('// ⚠ %s：%s' % (name, note))
            A('TEST("%s", FUN(() ,' % name)
            A('    (ASSERT_EQ(%s(in_%s), want_%s));' % (fn_name, name, name))
            A('    TRUE));')

    # safe_path_check：ok 与 rel 分别断言
    for key in sorted(cases['safe_path_check']):
        name = 'safe_path_check_%s' % key
        e = cases['safe_path_check'][key]
        note = e.get('note')
        if note:
            A('// ⚠ %s：%s' % (name, note))
        A('LET(res_%s, SAFE_PATH_CHECK(in_%s, _BASE_));' % (name, name))
        A('TEST("%s_ok", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(res_%s, "ok", FALSE), want_%s_ok));' % (name, name))
        A('    TRUE));')
        A('TEST("%s_rel", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(res_%s, "rel", NULL), want_%s_rel));' % (name, name))
        A('    TRUE));')

    # write_source：写成功后读回比对
    for key in sorted(cases['write_source']):
        name = 'write_source_%s' % key
        e = cases['write_source'][key]
        note = e.get('note')
        if note:
            A('// ⚠ %s：%s' % (name, note))
        A('LET(res_%s, WRITE_SOURCE(html_%s, content_%s));' % (name, name, name))
        A('TEST("%s_ok", FUN(() ,' % name)
        A('    (ASSERT(AT_K(res_%s, "ok", FALSE)));' % name)
        A('    TRUE));')
        A('TEST("%s_md_name", FUN(() ,' % name)
        A('    (ASSERT_EQ(PATH_BASE(AT_K(res_%s, "path", "")), want_%s_md));' % (name, name))
        A('    TRUE));')
        A('TEST("%s_content", FUN(() ,' % name)
        A('    (ASSERT_EQ(READ_FILE(AT_K(res_%s, "path", "")), want_%s_content));' % (name, name))
        A('    TRUE));')

    A('')

    # ── 反向守卫 ──────────────────────────────────────────────────
    A('// ── 反向守卫（卡 S2-1 的要求）─────────────────────────────────')
    A('// ① 路径穿越形态必须被拒')
    A('TEST("guard/traversal_rejected", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(SAFE_PATH_CHECK("../etc/passwd", _BASE_), "ok", TRUE), FALSE));')
    A('    TRUE));')
    A('// ② 同前缀兄弟目录（pages-evil）必须被拒')
    A('//    ⚠ 基准 p13 的输入是 `../pages-evil/x.html`（含 `..` ⇒ D3 拒）。')
    A('//    单独的 `pages-evil/x.html` 不含 `..`，Python 视为 base 内的子目录 ⇒ 允许，')
    A('//    所以这里用**与基准相同的形态**，而不是裸的 pages-evil/x.html。')
    A('TEST("guard/sibling_prefix_rejected", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(SAFE_PATH_CHECK("../pages-evil/x.html", _BASE_), "ok", TRUE), FALSE));')
    A('    TRUE));')
    A('// ③ 含 `..` 的输入即使落在 base 内也必须被拒（D3：词法判定不解析符号链接）')
    A('TEST("guard/dotdot_inside_base_rejected", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(SAFE_PATH_CHECK("sub/../ok.html", _BASE_), "ok", TRUE), FALSE));')
    A('    TRUE));')
    A('// ④ 写入失败 ⇒ 不得留下半截文件（父目录不存在 ⇒ 原子写失败）')
    A('//    ⚠ 实现**不** MKDIRS（Python 的 write_source 也不建目录）')
    A('//    ⇒ 父目录不存在时 WRITE_FILE_ATOMIC 返回 ERR ⇒ ok=FALSE 且无残留。')
    A('LET(_BADPATH_, PATH_JOIN(_TD_, "no_such_dir/deep/x.html"));')
    A('LET(_BADR_, WRITE_SOURCE(_BADPATH_, "partial"));')
    A('TEST("guard/atomic_write_no_partial", FUN(() ,')
    A('    (ASSERT_EQ(AT_K(_BADR_, "ok", TRUE), FALSE));')
    A('    (ASSERT(!EXISTS(PATH_JOIN(_TD_, "no_such_dir/deep/x.md"))));')
    A('    TRUE));')
    A('// ⑤ 原子写成功后不留 .tmp 残留')
    A('MKDIRS(PATH_JOIN(_TD_, "tmpx"));')
    A('LET(_TMPR_, WRITE_SOURCE(PATH_JOIN(_TD_, "tmpx/x.html"), "body"));')
    A('TEST("guard/atomic_write_no_tmp_left", FUN(() ,')
    A('    (ASSERT(AT_K(_TMPR_, "ok", FALSE)));')
    A('    (ASSERT(!EXISTS(PATH_JOIN(_TD_, "tmpx/x.md.tmp"))));')
    A('    TRUE));')
    A('')

    # ── 跑测试 ────────────────────────────────────────────────────
    A('// ── 跑测试 ────────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_article_store: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_article_store: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_article_store: FAILED"); '
      'PANIC("article_store tests failed")), NULL);')
    A('PRINT("test_article_store: OK");')

    chars, lines = write(OUT, src)
    n_cases = sum(len(v) for v in cases.values())
    print(f'wrote {OUT} ({chars} chars, {lines} lines, {n_cases} baseline cases)')


if __name__ == '__main__':
    main()
