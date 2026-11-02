"""生成 tp/test/test_theme.wll —— 主题模块的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的结果**逐字节对照**。
基准：tp/test/fixtures/theme_baseline.json
    （由 tp/test/gen_theme_baseline.py 用真 Python 生成）。

**分组与各自的断言形态**：
  | 基准组 | WLWL 调用 | 断言 |
  |---|---|---|
  | validate_theme_name | `VALIDATE_THEME_NAME(s)` | `== want`（BOOLEAN） |
  | load_theme_css | `LOAD_THEME_CSS(dir)` | `css` / `dark_css` / `has_dark` 分别断言 |
  | load_theme_manifest | `LOAD_THEME_MANIFEST(n, dir)` | `want` 为 NULL ⇒ 判 TYPE；为字典 ⇒ `STRINGIFY` 比对 |
  | list_themes | `LIST_THEMES(dir)` | 先断 `LEN`，再逐项断 5 个字段 |

**需要真实文件系统的三组**：`input` 是一棵**相对布局**（`root` / `dirs` / `files`），
本文件在 `TEMP_DIR()` 下按**同一份 spec** 逐字节重建：
  · 目录用 `MKDIRS`；
  · 文件用 `WRITE_BYTES(UTF8_ENCODE(...))` —— ⚠ **不能用 `WRITE_FILE`**：
    必须字节级写入，否则 CRLF 用例根本测不到东西。
  · 用例之间用**独立根目录**（`TEMP_DIR()/<group>_<id>`），互不干扰。

**反向守卫**（卡 S2-3 的要求）：
  · `../etc` 形态的主题名 ⇒ `VALIDATE_THEME_NAME` 必须拒
  · `../etc` ⇒ `LOAD_THEME_MANIFEST` 必须返 NULL（不得读到 themes 之外）
  · CRLF 文件读出的 CSS **不得**含 `\\r`
  · 主题列表必须**目录名升序**（目录按**逆序**创建，证明顺序不是创建序）

**为什么要 `IF(failed > 0)` 收尾**：`RUN_TESTS()` 的失败**不影响进程退出码**
（规范明载）⇒ 本文件自己 `PANIC` 把关，否则 CI 的「exit 0」是假的。

用法：python gen_test_theme.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_theme.wll')

ESCAPES = {
    '\\': '\\\\', '"': '\\"', '\n': '\\n', '\r': '\\r',
    '\t': '\\t', '\b': '\\b', '\f': '\\f', '\0': '\\0', '$': '\\$',
}


def wl_str(s):
    """Python 字符串 → WLWL 字符串字面量（转义白名单内）。"""
    return '"' + ''.join(ESCAPES.get(ch, ch) for ch in s) + '"'


def wl_value(v):
    """标量 → WLWL 字面量（只需要 str / bool / None / int）。"""
    if isinstance(v, str):
        return wl_str(v)
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    raise TypeError('bad fixture value: %r' % (v,))


def case_root_expr(case_name):
    """本用例自己的临时根目录表达式。"""
    return 'PATH_JOIN(_TD_, %s)' % wl_str(case_name)


def emit_tree(A, case_name, spec):
    """把相对布局落成真实目录与文件（字节级）。

    ⚠ `WRITE_BYTES` **不建父目录**（实测：父目录不存在 ⇒ ERR「系统找不到指定的路径」）
      ⇒ 父目录从文件路径**反推**出来一起 MKDIRS，不依赖用例作者写全 `dirs`。
    ⚠ `WRITE_BYTES` 失败返 **ERR**（实测），裸用一条语句就是 `E0103`（discarded ERR）
      ⇒ 必须放进 `IS_ERR(...)` 消费。⚠ 注意 `WRITE_FILE` **不**是这个形状
      （既有 test_article_store 里裸用 `WRITE_FILE(...)` 是绿的）——
      「同一个命名空间里，不同成员的失败形态不一样」。
    """
    root = case_root_expr(case_name)
    A('LET(root_%s, %s);' % (case_name, root))
    A('MKDIRS(root_%s);' % case_name)
    dirs = set(spec.get('dirs', []))
    for rel in spec.get('files', {}):
        if '/' in rel:
            dirs.add(rel.rsplit('/', 1)[0])
        if '\\' in rel:
            dirs.add(rel.rsplit('\\', 1)[0])
    for rel in sorted(d for d in dirs if d):
        A('MKDIRS(PATH_JOIN(root_%s, %s));' % (case_name, wl_str(rel)))
    for rel in sorted(spec.get('files', {})):
        A('IF(IS_ERR(WRITE_BYTES(PATH_JOIN(root_%s, %s), UTF8_ENCODE(%s))), '
          'PRINT_ERR("setup: WRITE_BYTES failed for %s"), NULL);'
          % (case_name, wl_str(rel), wl_str(spec['files'][rel]), rel))


def main():
    with open(os.path.join(FIXTURES, 'theme_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']

    src = []
    A = src.append
    A('// tp/test/test_theme.wll —— 主题模块的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_theme.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的结果逐字节对照。')
    A('// 基准：tp/test/fixtures/theme_baseline.json')
    A('//   （由 tp/test/gen_theme_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关（见尾段）。')
    A('// ⚠ 文件内容一律 `WRITE_BYTES(UTF8_ENCODE(...))` 写入 —— 必须字节级，')
    A('//   否则 CRLF 用例测不到东西。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS", '
      '"TEMP_DIR"]);')
    A('IMPORT("wlwl:std.fs", ["MKDIRS", "WRITE_BYTES", "PATH_JOIN"]);')
    A('IMPORT("wlwl:std.encode", ["UTF8_ENCODE"]);')
    A('IMPORT("wlwl:std.json", ["PARSE", "STRINGIFY"]);')
    A('IMPORT("wlwl:std.str", ["CONTAINS_SUB", "JOIN"]);')
    A('IMPORT("./../lib/theme.wll", ["VALIDATE_THEME_NAME", "LOAD_THEME_CSS", '
      '"LOAD_THEME_MANIFEST", "LIST_THEMES"]);')
    A('')
    A('// 所有用例共用的临时根（每个用例再在其下开自己的子目录）')
    A('LET(_TD_, TEMP_DIR());')
    A('')

    # ── ① validate_theme_name：数据 ────────────────────────────────
    A('// ── validate_theme_name：数据 ─────────────────────────────────')
    for key in sorted(cases['validate_theme_name']):
        e = cases['validate_theme_name'][key]
        n = 'vtn_%s' % key
        A('LET(in_%s, %s);' % (n, wl_str(e['input'])))
        A('LET(want_%s, %s);' % (n, wl_value(e['want'])))
    A('')

    # ── ② load_theme_css：目录树 + 数据 ───────────────────────────
    A('// ── load_theme_css：真实目录树 + 数据 ─────────────────────────')
    for key in sorted(cases['load_theme_css']):
        e = cases['load_theme_css'][key]
        n = 'css_%s' % key
        emit_tree(A, n, e['input'])
        A('LET(dir_%s, PATH_JOIN(root_%s, %s));'
          % (n, n, wl_str(e['input']['root'])))
        A('LET(want_%s_css, %s);' % (n, wl_str(e['want']['css'])))
        A('LET(want_%s_dark, %s);' % (n, wl_str(e['want']['dark_css'])))
        A('LET(want_%s_has_dark, %s);' % (n, wl_value(e['want']['has_dark'])))
    A('')

    # ── ③ load_theme_manifest：目录树 + 数据 ──────────────────────
    A('// ── load_theme_manifest：真实目录树 + 数据 ────────────────────')
    for key in sorted(cases['load_theme_manifest']):
        e = cases['load_theme_manifest'][key]
        n = 'man_%s' % key
        emit_tree(A, n, e['input'])
        A('LET(dir_%s, PATH_JOIN(root_%s, %s));'
          % (n, n, wl_str(e['input']['root'])))
        A('LET(name_%s, %s);' % (n, wl_str(e['input']['theme'])))
        want = e['want']
        if want is None:
            A('LET(want_%s, NULL);' % n)
            A('LET(want_%s_is_null, TRUE);' % n)
        else:
            # 期望值走 PARSE 再 STRINGIFY ⇒ 比较的是**语言自己的** JSON 形态
            A('LET(want_%s, STRINGIFY(PARSE(%s)));'
              % (n, wl_str(json.dumps(want, ensure_ascii=False,
                                      sort_keys=True))))
            A('LET(want_%s_is_null, FALSE);' % n)
    A('')

    # ── ④ list_themes：目录树 + 数据 ──────────────────────────────
    A('// ── list_themes：真实目录树 + 数据 ────────────────────────────')
    for key in sorted(cases['list_themes']):
        e = cases['list_themes'][key]
        n = 'lst_%s' % key
        emit_tree(A, n, e['input'])
        A('LET(dir_%s, PATH_JOIN(root_%s, %s));'
          % (n, n, wl_str(e['input']['root'])))
        A('LET(want_%s_n, %d);' % (n, len(e['want'])))
        for i, item in enumerate(e['want']):
            A('LET(want_%s_%d_name, %s);' % (n, i, wl_str(item['name'])))
            A('LET(want_%s_%d_disp, %s);'
              % (n, i, wl_str(item['display_name'])))
            A('LET(want_%s_%d_desc, %s);'
              % (n, i, wl_str(item['description'])))
            A('LET(want_%s_%d_dlay, %s);'
              % (n, i, wl_str(item['default_layout'])))
            # layouts 是数组 ⇒ 用 JOIN 拍平成串（避免依赖数组深比较的细节）
            A('LET(want_%s_%d_layouts, %s);'
              % (n, i, wl_str(','.join(item['layouts']))))
    A('')

    # ── 用例：validate_theme_name ─────────────────────────────────
    A('// ── 用例：validate_theme_name ─────────────────────────────────')
    for key in sorted(cases['validate_theme_name']):
        e = cases['validate_theme_name'][key]
        n = 'vtn_%s' % key
        if e.get('note'):
            A('// ⚠ %s：%s' % (n, e['note']))
        A('TEST("validate_theme_name/%s", FUN(() ,' % key)
        A('    (ASSERT_EQ(VALIDATE_THEME_NAME(in_%s), want_%s));' % (n, n))
        A('    TRUE));')
    A('')

    # ── 用例：load_theme_css ─────────────────────────────────────
    A('// ── 用例：load_theme_css（三个键分别断言）─────────────────────')
    for key in sorted(cases['load_theme_css']):
        e = cases['load_theme_css'][key]
        n = 'css_%s' % key
        if e.get('note'):
            A('// ⚠ %s：%s' % (n, e['note']))
        A('LET(res_%s, LOAD_THEME_CSS(dir_%s));' % (n, n))
        A('TEST("load_theme_css/%s_css", FUN(() ,' % key)
        A('    (ASSERT_EQ(AT_K(res_%s, "css", NULL), want_%s_css));' % (n, n))
        A('    TRUE));')
        A('TEST("load_theme_css/%s_dark_css", FUN(() ,' % key)
        A('    (ASSERT_EQ(AT_K(res_%s, "dark_css", NULL), want_%s_dark));'
          % (n, n))
        A('    TRUE));')
        A('TEST("load_theme_css/%s_has_dark", FUN(() ,' % key)
        A('    (ASSERT_EQ(AT_K(res_%s, "has_dark", NULL), want_%s_has_dark));'
          % (n, n))
        A('    TRUE));')
    A('')

    # ── 用例：load_theme_manifest ────────────────────────────────
    A('// ── 用例：load_theme_manifest ────────────────────────────────')
    for key in sorted(cases['load_theme_manifest']):
        e = cases['load_theme_manifest'][key]
        n = 'man_%s' % key
        if e.get('note'):
            A('// ⚠ %s：%s' % (n, e['note']))
        A('LET(res_%s, LOAD_THEME_MANIFEST(name_%s, dir_%s));'
          % (n, n, n))
        A('TEST("load_theme_manifest/%s", FUN(() ,' % key)
        A('    (IF(want_%s_is_null,' % n)
        A('        (ASSERT_EQ(TYPE(res_%s), "NULL")),' % n)
        A('        (ASSERT_EQ(STRINGIFY(res_%s), want_%s))));' % (n, n))
        A('    TRUE));')
    A('')

    # ── 用例：list_themes ────────────────────────────────────────
    A('// ── 用例：list_themes（先断条数，再逐项断 5 个字段）───────────')
    for key in sorted(cases['list_themes']):
        e = cases['list_themes'][key]
        n = 'lst_%s' % key
        if e.get('note'):
            A('// ⚠ %s：%s' % (n, e['note']))
        A('LET(res_%s, LIST_THEMES(dir_%s));' % (n, n))
        A('TEST("list_themes/%s_len", FUN(() ,' % key)
        A('    (ASSERT_EQ(LEN(res_%s), want_%s_n));' % (n, n))
        A('    TRUE));')
        for i, item in enumerate(e['want']):
            A('LET(e_%s_%d, AT(res_%s, %d, DICT()));' % (n, i, n, i))
            A('TEST("list_themes/%s_%d_name", FUN(() ,' % (key, i))
            A('    (ASSERT_EQ(AT_K(e_%s_%d, "name", NULL), want_%s_%d_name));'
              % (n, i, n, i))
            A('    TRUE));')
            A('TEST("list_themes/%s_%d_display_name", FUN(() ,' % (key, i))
            A('    (ASSERT_EQ(AT_K(e_%s_%d, "display_name", NULL), '
              'want_%s_%d_disp));' % (n, i, n, i))
            A('    TRUE));')
            A('TEST("list_themes/%s_%d_description", FUN(() ,' % (key, i))
            A('    (ASSERT_EQ(AT_K(e_%s_%d, "description", NULL), '
              'want_%s_%d_desc));' % (n, i, n, i))
            A('    TRUE));')
            A('TEST("list_themes/%s_%d_default_layout", FUN(() ,' % (key, i))
            A('    (ASSERT_EQ(AT_K(e_%s_%d, "default_layout", NULL), '
              'want_%s_%d_dlay));' % (n, i, n, i))
            A('    TRUE));')
            A('TEST("list_themes/%s_%d_layouts", FUN(() ,' % (key, i))
            A('    (ASSERT_EQ(JOIN(AT_K(e_%s_%d, "layouts", []), ","), '
              'want_%s_%d_layouts));' % (n, i, n, i))
            A('    TRUE));')
    A('')

    # ── 反向守卫 ─────────────────────────────────────────────────
    A('// ── 反向守卫（卡 S2-3 的要求）─────────────────────────────────')
    A('// ① ../etc 形态的主题名必须被拒（D5）')
    A('TEST("guard/traversal_theme_name_rejected", FUN(() ,')
    A('    (ASSERT_EQ(VALIDATE_THEME_NAME("../etc"), FALSE));')
    A('    (ASSERT_EQ(VALIDATE_THEME_NAME(".."), FALSE));')
    A('    (ASSERT_EQ(VALIDATE_THEME_NAME("a/b"), FALSE));')
    A('    (ASSERT_EQ(VALIDATE_THEME_NAME("a\\\\b"), FALSE));')
    A('    (ASSERT_EQ(VALIDATE_THEME_NAME(""), FALSE));')
    A('    TRUE));')
    A('// ② 即使目录里**真的**存在 themes 之外的 etc/manifest.json，')
    A('//    恶意主题名也必须拿到 NULL —— 这是 D5 的可执行形态。')
    A('LET(_GUARD_ROOT_, PATH_JOIN(_TD_, "guard_manifest"));')
    A('MKDIRS(PATH_JOIN(_GUARD_ROOT_, "themes/alpha"));')
    A('MKDIRS(PATH_JOIN(_GUARD_ROOT_, "etc"));')
    A('WRITE_BYTES(PATH_JOIN(_GUARD_ROOT_, "etc/manifest.json"), '
      'UTF8_ENCODE("{\\"name\\": \\"evil\\"}"));')
    A('LET(_GUARD_THEMES_, PATH_JOIN(_GUARD_ROOT_, "themes"));')
    A('TEST("guard/traversal_manifest_is_null", FUN(() ,')
    A('    (ASSERT_EQ(TYPE(LOAD_THEME_MANIFEST("../etc", _GUARD_THEMES_)), '
      '"NULL"));')
    A('    TRUE));')
    A('// ③ CRLF 文件读出的 CSS **不得**含 \\r（D7 之外的另一半：换行归一）')
    A('//    ⚠ 这条与 load_theme_css/c04 的逐字节对照互补：那条断「等于什么」，')
    A('//      这条断「不得含什么」，防的是「两边一起错成 CRLF」。')
    A('LET(_CRLF_DIR_, PATH_JOIN(_TD_, "guard_crlf"));')
    A('MKDIRS(_CRLF_DIR_);')
    A('WRITE_BYTES(PATH_JOIN(_CRLF_DIR_, "theme.css"), '
      'UTF8_ENCODE("a\\r\\nb\\r\\n"));')
    A('LET(_CRLF_CSS_, AT_K(LOAD_THEME_CSS(_CRLF_DIR_), "css", NULL));')
    A('TEST("guard/crlf_css_has_no_cr", FUN(() ,')
    A('    (ASSERT(!CONTAINS_SUB(_CRLF_CSS_, "\\r")));')
    A('    (ASSERT_EQ(_CRLF_CSS_, "a\\nb\\n"));')
    A('    TRUE));')
    A('// ④ 主题列表必须**目录名升序** —— 目录按**逆序**创建（zeta, mm, alpha）')
    A('//    ⇒ 若实现跟随文件系统/创建顺序，这里必红。这是 D6 的可执行形态。')
    A('LET(_ORD_DIR_, PATH_JOIN(_TD_, "guard_order"));')
    A('MKDIRS(_ORD_DIR_);')
    A('MKDIRS(PATH_JOIN(_ORD_DIR_, "zeta"));')
    A('MKDIRS(PATH_JOIN(_ORD_DIR_, "mm"));')
    A('MKDIRS(PATH_JOIN(_ORD_DIR_, "alpha"));')
    A('LET(_ORD_, LIST_THEMES(_ORD_DIR_));')
    A('TEST("guard/themes_sorted_ascending", FUN(() ,')
    A('    (ASSERT_EQ(LEN(_ORD_), 3));')
    A('    (ASSERT_EQ(AT_K(AT(_ORD_, 0, DICT()), "name", NULL), "alpha"));')
    A('    (ASSERT_EQ(AT_K(AT(_ORD_, 1, DICT()), "name", NULL), "mm"));')
    A('    (ASSERT_EQ(AT_K(AT(_ORD_, 2, DICT()), "name", NULL), "zeta"));')
    A('    TRUE));')
    A('')

    # ── 跑测试 ───────────────────────────────────────────────────
    A('// ── 跑测试 ────────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_theme: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_theme: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_theme: FAILED"); '
      'PANIC("theme tests failed")), NULL);')
    A('PRINT("test_theme: OK");')

    chars, lines = write(OUT, src)
    n_cases = sum(len(v) for v in cases.values())
    print(f'wrote {OUT} ({chars} chars, {lines} lines, {n_cases} baseline cases)')


if __name__ == '__main__':
    main()
