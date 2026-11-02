"""生成 tp/test/test_template.wll —— 模板模块的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的结果逐字节对照。
基准：tp/test/fixtures/template_baseline.json
    （由 tp/test/gen_template_baseline.py 用真 Python 生成）。

**分组与各自的断言形态**：
  | 基准组 | WLWL 调用 | 断言 |
  |---|---|---|
  | substitute | `SUBSTITUTE(tmpl, mapping)` | 期望字符串 ⇒ 相等；期望错误 ⇒ 载荷字典**整体相等** |
  | safe_substitute | `SAFE_SUBSTITUTE(tmpl, mapping)` | 相等（且必须**不是** ERR） |
  | render_skeleton | `RENDER_SKELETON(page_type, opts)` | **逐字节**相等（含首尾换行） |

**为什么错误用例能整体比字典**：`ERR` 的载荷是本模块自定的形状
（见 gen_template.py 的 docstring），基准里的 `want` 就是**同一个形状的字典**
⇒ `ASSERT_EQ(TAKE_ERR(...), want)` 一条断言同时钉住 kind / key / pos，
多一个或少一个键都会红（形状本身就是契约）。

**WLWL 侧的两条硬约束（决定了下面的写法）**：
  ① `LET(r, <ERR>)` **绑定不算消费**（§8.6.3）⇒ 绝不把 `SUBSTITUTE(...)` 直接 LET 住。
     统一用「`IS_ERR(...)` 判别 + 取字符串时再算一次」与「`TAKE_ERR(...)` 一步取载荷」
     两种形态 —— `TAKE_ERR` 是取走型消费者，用完就不再有未消费 ERR。
  ② `UNWRAP_OR` **只吃 OK/ERR**（实测 `E0030: expected OK/ERR, got string`），
     不能拿它给「STRING | ERR」接地 ⇒ 只能走 ① 的两种形态。

**反向守卫（卡 S2-3 的要求）**：
  · 缺占位符时 **前台 `SUBSTITUTE` 必须返回 `ERR`** —— 不得静默留下 `$var`。
  · `RENDER_SKELETON` 的产物必须与真 Python 的 `render_skeleton` **逐字节相等**
    （含首尾换行：首行 `<!DOCTYPE html>`、末行 `</html>` 后面**没有**换行）。
  · 代入值里含 `$` ⇒ **不得**被二次扫描（Python 的 `str.replace` 语义）。

用法：python gen_test_template.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_template.wll')


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 白名单：`\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`。
    ⚠⚠ `$` **必须**写成 `\\$`：WLWL 的字符串字面量支持 `${...}` **插值**
      （实测 `PRINT("a${d}b")` 在 `d="k"` 时输出 `akb`）⇒ 夹具里全是
      `$a` / `${a}` 形态，原样写进去会被当插值、直接 E0002 或语义跑偏。
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
    """Python 值（str / bool / None / int / float / dict）→ WLWL 字面量 / 表达式。"""
    if isinstance(v, str):
        return wl_string(v)
    if isinstance(v, bool):
        # ⚠ 必须在 int 之前判（Python 的 bool 是 int 的子类）
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
        # ⚠ 字典**字面量** `["k": v]` 会触发 wllgen 的逗号表达式守卫
        #   ⇒ 一律用 INDEX_SET 逐层套。
        expr = 'DICT()'
        for k in sorted(v):
            expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl_string(k), wl_value(v[k]))
        return expr
    raise TypeError('bad fixture value: %r' % (v,))


def is_err_want(want):
    """基准里的 `want` 是不是「期望的错误载荷」形态。"""
    return isinstance(want, dict)


def main():
    with open(os.path.join(FIXTURES, 'template_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']

    src = []
    A = src.append
    A('// tp/test/test_template.wll —— 模板模块的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_template.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的结果逐字节对照。')
    A('// 基准：tp/test/fixtures/template_baseline.json')
    A('//   （由 tp/test/gen_template_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关（见尾段）。')
    A('//')
    A('// ⚠ `LET(r, <ERR>)` 绑定**不算**消费（§8.6.3）⇒ 这里只有两种形态：')
    A('//   ① 期望字符串：`IS_ERR(...)` 判别 + 分支里再算一次；')
    A('//   ② 期望错误：`TAKE_ERR(...)`（一步取载荷、并消费掉那个 ERR）。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.result", ["TAKE_ERR"]);')
    A('IMPORT("./../lib/template.wll", ["SUBSTITUTE", "SAFE_SUBSTITUTE", '
      '"RENDER_SKELETON"]);')
    A('')

    # ── substitute / safe_substitute：数据 ────────────────────────
    A('// ── substitute / safe_substitute 的用例数据（逐字节来自基准）──────')
    for group, prefix in (('substitute', 'sub'), ('safe_substitute', 'safe')):
        for key in sorted(cases[group]):
            e = cases[group][key]
            name = '%s_%s' % (prefix, key)
            spec = e['input']
            A('LET(in_%s, %s);' % (name, wl_string(spec['tmpl'])))
            A('LET(map_%s, %s);' % (name, wl_value(spec['mapping'])))
            if is_err_want(e['want']):
                A('LET(want_%s, %s);' % (name, wl_value(e['want'])))
            else:
                A('LET(want_%s, %s);' % (name, wl_string(e['want'])))
    A('')

    # ── substitute / safe_substitute：判定变量 ────────────────────
    A('// ── 判定变量（⚠ 会返回 ERR 的调用一律**不**直接 LET 住）─────────')
    for group, prefix in (('substitute', 'sub'), ('safe_substitute', 'safe')):
        for key in sorted(cases[group]):
            e = cases[group][key]
            name = '%s_%s' % (prefix, key)
            fn_name = 'SUBSTITUTE' if group == 'substitute' else 'SAFE_SUBSTITUTE'
            if is_err_want(e['want']):
                # 取走型：拿到载荷字典（非 ERR 时是 NULL）
                A('LET(pay_%s, TAKE_ERR(%s(in_%s, map_%s)));'
                  % (name, fn_name, name, name))
            else:
                A('LET(iserr_%s, IS_ERR(%s(in_%s, map_%s)));'
                  % (name, fn_name, name, name))
                A('LET(out_%s, IF(iserr_%s, "", %s(in_%s, map_%s)));'
                  % (name, name, fn_name, name, name))
    A('')

    # ── render_skeleton：数据 + 判定变量 ─────────────────────────
    A('// ── render_skeleton 的用例数据 ────────────────────────────────')
    render_ids = sorted(cases['render_skeleton'])
    for i, key in enumerate(render_ids):
        e = cases['render_skeleton'][key]
        name = 'r%02d' % i
        spec = e['input']
        A('// %s' % key)
        A('LET MUT(opt_%s, DICT());' % name)
        for k in sorted(spec['opts']):
            A('SET(opt_%s, INDEX_SET(opt_%s, %s, %s));'
              % (name, name, wl_string(k), wl_value(spec['opts'][k])))
        A('LET(want_%s, %s);' % (name, wl_string(e['want'])))
        A('LET(iserr_%s, IS_ERR(RENDER_SKELETON(%s, opt_%s)));'
          % (name, wl_string(spec['page_type']), name))
        A('LET(out_%s, IF(iserr_%s, "", RENDER_SKELETON(%s, opt_%s)));'
          % (name, name, wl_string(spec['page_type']), name))
    A('')

    # ── 用例 ──────────────────────────────────────────────────────
    A('// ── 用例 ──────────────────────────────────────────────────────')
    for group, prefix in (('substitute', 'sub'), ('safe_substitute', 'safe')):
        for key in sorted(cases[group]):
            e = cases[group][key]
            name = '%s_%s' % (prefix, key)
            note = e.get('note')
            if note:
                A('// ⚠ %s：%s' % (name, note))
            A('TEST("%s/%s", FUN(() ,' % (group, key))
            if is_err_want(e['want']):
                A('    (ASSERT_EQ(pay_%s, want_%s));' % (name, name))
            else:
                A('    (ASSERT(!iserr_%s);' % name)
                A('     ASSERT_EQ(out_%s, want_%s));' % (name, name))
            A('    TRUE));')

    for i, key in enumerate(render_ids):
        e = cases['render_skeleton'][key]
        name = 'r%02d' % i
        note = e.get('note')
        if note:
            A('// ⚠ %s：%s' % (key, note))
        A('TEST("render_skeleton/%s", FUN(() ,' % key)
        A('    (ASSERT(!iserr_%s);' % name)
        A('     ASSERT_EQ(out_%s, want_%s));' % (name, name))
        A('    TRUE));')
    A('')

    # ── 反向守卫 ──────────────────────────────────────────────────
    A('// ── 反向守卫（卡 S2-3 的要求）─────────────────────────────────')
    A('// ① 缺占位符 ⇒ 严格版**必须**返回 ERR，且**不得**静默留下 `$var`')
    A('LET(_G_TMPL_, "hi \\$missing there");')
    A('LET(_G_MAP_, DICT());')
    A('LET(_G_PAY_, TAKE_ERR(SUBSTITUTE(_G_TMPL_, _G_MAP_)));')
    A('LET(_G_STR_, IF(IS_ERR(SUBSTITUTE(_G_TMPL_, _G_MAP_)), "<ERR>", '
      'SUBSTITUTE(_G_TMPL_, _G_MAP_)));')
    A('TEST("guard/strict_missing_returns_err", FUN(() ,')
    A('    (ASSERT_EQ(TYPE(_G_PAY_), "DICT"));')
    A('    (ASSERT_EQ(AT_K(_G_PAY_, "kind", ""), "KeyError"));')
    A('    (ASSERT_EQ(AT_K(_G_PAY_, "key", ""), "missing"));')
    A('    TRUE));')
    A('TEST("guard/strict_missing_not_silently_kept", FUN(() ,')
    A('    (ASSERT(!= (_G_STR_, _G_TMPL_)));')
    A('    TRUE));')
    A('')
    A('// ② 宽容版对**同一个**输入必须原样保留（与严格版分叉的证据）')
    A('TEST("guard/safe_missing_keeps_placeholder", FUN(() ,')
    A('    (ASSERT_EQ(SAFE_SUBSTITUTE(_G_TMPL_, _G_MAP_), _G_TMPL_));')
    A('    TRUE));')
    A('')
    A('// ③ 代入值里的 `$` **不得**被二次扫描（Python 侧是一次性扫描）')
    A('LET(_G_DOLLAR_, INDEX_SET(DICT(), "a", "\\$b \\${c}"));')
    A('TEST("guard/no_rescan_of_values", FUN(() ,')
    A('    (ASSERT_EQ(SUBSTITUTE("\\$a!", _G_DOLLAR_), "\\$b \\${c}!"));')
    A('    TRUE));')
    A('')
    A('// ④ 骨架产物的**首尾**逐字节判定（首行无前导空白、末行 `</html>` 后无换行）')
    A('TEST("guard/skeleton_edge_bytes", FUN(() ,')
    A('    (ASSERT_EQ(SUB(out_r00, 0, 15), "<!DOCTYPE html>"));')
    A('    (ASSERT_EQ(SUB(out_r00, -(LEN(out_r00), 7)), "</html>"));')
    A('    TRUE));')
    A('')
    A('// ⑤ 渲染**不得**残留任何占位符（19 个 `$name` 必须全被替换）')
    A('TEST("guard/skeleton_no_leftover_placeholder", FUN(() ,')
    A('    (ASSERT(!CONTAINS(out_r04, "\\$lang")));')
    A('    (ASSERT(!CONTAINS(out_r04, "\\$site_title")));')
    A('    (ASSERT(!CONTAINS(out_r04, "\\$nav_links")));')
    A('    (ASSERT(!CONTAINS(out_r04, "\\$theme_toggle")));')
    A('    TRUE));')
    A('')

    # ── 跑测试 + 自己把关退出码 ──────────────────────────────────
    A('// ── 跑测试 ────────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_template: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));')
    A('PRINT("test_template: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_template: FAILED"); '
      'PANIC("template tests failed")), NULL);')
    A('PRINT("test_template: OK");')

    chars, lines = write(OUT, src)
    n_cases = sum(len(v) for v in cases.values())
    print(f'wrote {OUT} ({chars} chars, {lines} lines, {n_cases} baseline cases)')


if __name__ == '__main__':
    main()
