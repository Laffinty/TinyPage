"""生成 tp/test/test_admin_views.wll —— admin 视图层的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例都与**真 Python** 的结果逐字节对照。
基准：tp/test/fixtures/admin_views_baseline.json
    （由 tp/test/gen_admin_views_baseline.py 用真 Python 生成）。

**分组与调用**（8 个导出全部覆盖）：

| 基准组 | WLWL 调用 |
|---|---|
| dashboard | `DASHBOARD_VIEW(opts)` |
| article_form | `ARTICLE_FORM_VIEW(opts)` |
| page_form | `PAGE_FORM_VIEW(opts)` |
| pages_dashboard | `PAGES_DASHBOARD_VIEW(opts)` |
| theme_selector | `THEME_SELECTOR_VIEW(opts)` |
| login | `LOGIN_VIEW(opts)` |
| ai_panel | `AI_PANEL(opts)` |
| nav_html | `NAV_HTML(opts)` |

**反向守卫**（不只比字节，还钉住「语义特征」）：
  · 渲染结果**不得残留占位符**（`$total` / `$rows` / `$content` …）——
    这条能抓到「SAFE_SUBSTITUTE 的 mapping 漏了键」而逐字节对照仍偶然通过的情形
    （缺键时 safe_substitute 原样保留，所以逐字节对照本来也抓得到；这里额外
    钉一条**独立**断言）。
  · 正文/标题里的 `<tag>` 必须**被转义**成 `&lt;tag&gt;`（vs 片段字段不转义）。
  · `locked` 覆盖 `error`（views.py:279-282 的顺序）。
  · `current_path` 不匹配时**不得**出现 `nav-active` / `aria-current`。

用法：python gen_test_admin_views.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_admin_views.wll')

# 基准组 → (导出名, 用例名前缀)
GROUPS = [
    ('dashboard', 'DASHBOARD_VIEW', 'd'),
    ('article_form', 'ARTICLE_FORM_VIEW', 'af'),
    ('page_form', 'PAGE_FORM_VIEW', 'pf'),
    ('pages_dashboard', 'PAGES_DASHBOARD_VIEW', 'pd'),
    ('theme_selector', 'THEME_SELECTOR_VIEW', 'ts'),
    ('login', 'LOGIN_VIEW', 'lg'),
    ('ai_panel', 'AI_PANEL', 'ai'),
    ('nav_html', 'NAV_HTML', 'nv'),
]


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量。

    ⚠ 白名单：`\\" \\\\ \\/ \\n \\r \\t \\b \\f \\0 \\$`（README #7）。
    ⚠⚠ `$` **必须**写 `\\$`：夹具里的 HTML 含大量 `$`（有的来自模板占位符、
       有的来自 `<script>` 里的 `$`），原样写进去会被 WLWL 当插值（README #32）。
       实测 `"\\$a"` ⇒ 字面 `$a`。
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
    """Python 值（str / bool / None / int / float / list / dict）→ WLWL 表达式。"""
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
    if isinstance(v, list):
        # 数组字面量：`[` 在 wllgen 的逗号守卫里算「调用形态」⇒ 内部逗号合法
        return '[' + ', '.join(wl_value(x) for x in v) + ']'
    if isinstance(v, dict):
        # ⚠ 字典**字面量** `["k": v]` 会触发逗号表达式守卫 ⇒ 一律 INDEX_SET 逐层套
        expr = 'DICT()'
        for k in sorted(v):
            expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl_string(k), wl_value(v[k]))
        return expr
    raise TypeError('bad fixture value: %r' % (v,))


def main():
    with open(os.path.join(FIXTURES, 'admin_views_baseline.json'),
              encoding='utf-8') as f:
        base = json.load(f)
    cases = base['cases']

    src = []
    A = src.append
    A('// tp/test/test_admin_views.wll —— admin 视图层的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_admin_views.py 生成 —— 请勿手改。')
    A('//')
    A('// 验收方式：每个用例都与**真 Python** 的结果逐字节对照。')
    A('// 基准：tp/test/fixtures/admin_views_baseline.json')
    A('//   （由 tp/test/gen_admin_views_baseline.py 用真 Python 生成）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关（见尾段）。')
    A('// ⚠ 模板替换是 safe_substitute ⇒ 缺键**不报错、原样保留**，所以每条都')
    A('//   逐字节比对整段 HTML（少一个键就会在对应位置露 `$key`）。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["CONTAINS_SUB"]);')
    A('IMPORT("./../lib/admin_views.wll", ["DASHBOARD_VIEW", "ARTICLE_FORM_VIEW", '
      '"PAGE_FORM_VIEW", "PAGES_DASHBOARD_VIEW", "THEME_SELECTOR_VIEW", '
      '"LOGIN_VIEW", "AI_PANEL", "NAV_HTML"]);')
    A('')

    # ── 用例数据 + 判定变量 ─────────────────────────────────────
    ids = {}   # (group, case) → 变量后缀
    for group, fn_name, prefix in GROUPS:
        A('// ── %s ─────────────────────────────────────────────' % group)
        for i, key in enumerate(sorted(cases[group])):
            e = cases[group][key]
            name = '%s_%02d' % (prefix, i)
            ids[(group, key)] = name
            note = e.get('note')
            map_note = e.get('map_note')
            A('// %s' % key)
            if note:
                A('// ⚠ 已知差异：%s' % note)
            if map_note:
                A('// ⚠ 输入改映射（输出相同）：%s' % map_note)
            A('LET(_TAV_OPT_%s, %s);' % (name, wl_value(e['input']['opts'])))
            A('LET(_TAV_OUT_%s, %s(_TAV_OPT_%s));' % (name, fn_name, name))
            A('LET(_TAV_WANT_%s, %s);' % (name, wl_string(e['want'])))
        A('')

    # ── 用例：逐字节对照 ────────────────────────────────────────
    A('// ── 用例：逐字节对照 ──────────────────────────────────────────')
    for group, fn_name, prefix in GROUPS:
        for key in sorted(cases[group]):
            name = ids[(group, key)]
            A('TEST("%s/%s", FUN(() ,' % (group, key))
            A('    (ASSERT_EQ(_TAV_OUT_%s, _TAV_WANT_%s));' % (name, name))
            A('    TRUE));')
    A('')

    # ── 反向守卫 ────────────────────────────────────────────────
    # ⚠ 多断言形态照 gen_test_template 的**范本**：首行 `(ASSERT…;`、
    #   后续行只写 `ASSERT…`、末行 `ASSERT…));`、再 `TRUE));`。
    #   手写这种括号极易多/少一个（README #46）⇒ 这里**程序化**生成。
    def test(name, stmts):
        """stmts：完整断言语句（如 `ASSERT_EQ(a, b)`），一条或多条。"""
        A('TEST("%s", FUN(() ,' % name)
        if len(stmts) == 1:
            A('    (%s);' % stmts[0])
        else:
            A('    (%s;' % stmts[0])
            for s in stmts[1:-1]:
                A('     %s;' % s)
            A('     %s);' % stmts[-1])
        A('    TRUE));')

    def not_has(var, needle):
        return 'ASSERT(!CONTAINS_SUB(%s, %s))' % (var, wl_string(needle))

    def has(var, needle):
        return 'ASSERT(CONTAINS_SUB(%s, %s))' % (var, wl_string(needle))

    A('// ── 反向守卫 ──────────────────────────────────────────────────')
    A('// ① 渲染结果**不得**残留占位符（safe_substitute 缺键时会原样留下 `$key`）')
    test('guard/dashboard_no_leftover_placeholder',
         [not_has('_TAV_OUT_d_09', '$total'),
          not_has('_TAV_OUT_d_09', '$draft_count'),
          not_has('_TAV_OUT_d_09', '$page_count'),
          not_has('_TAV_OUT_d_09', '$rows'),
          not_has('_TAV_OUT_d_09', '$nav_html'),
          not_has('_TAV_OUT_d_09', '$csrf_token'),
          not_has('_TAV_OUT_d_09', '$pages')])
    A('')
    A('// ② 表单里的正文必须是**转义后**的（`<tag>` ⇒ `&lt;tag&gt;`），且占位符全被替换')
    test('guard/article_form_content_escaped',
         [has('_TAV_OUT_af_03', '&lt;tag&gt;'),
          not_has('_TAV_OUT_af_03', '<tag>'),
          not_has('_TAV_OUT_af_03', '$content'),
          not_has('_TAV_OUT_af_03', '$datalist')])
    A('')
    A('// ③ locked **覆盖** error（views.py:279-282 的赋值顺序）')
    test('guard/login_locked_overrides_error',
         ['ASSERT_EQ(_TAV_OUT_lg_03, _TAV_OUT_lg_02)',
          'ASSERT(!= (_TAV_OUT_lg_03, _TAV_OUT_lg_01))'])
    A('')
    A('// ④ current_path 不匹配 ⇒ 不得有高亮（templates.py:52-53）')
    test('guard/nav_no_active_when_no_match',
         [not_has('_TAV_OUT_nv_02', 'nav-active'),
          not_has('_TAV_OUT_nv_02', 'aria-current')])
    A('')
    A('// ⑤ 未知 icon_name ⇒ 回落 "•"；标签原样（不转义，因为 Python 也不转）')
    test('guard/nav_icon_fallback_and_raw_label',
         [has('_TAV_OUT_nv_03', '•'),
          has('_TAV_OUT_nv_03', '<未&转义>'),
          has('_TAV_OUT_nv_03', 'nav-active')])
    A('')
    A('// ⑥ not-found 分支是**短路**的：不套模板（输出就是那一段 <p>）')
    test('guard/article_form_not_found_short_circuits',
         ['ASSERT_EQ(_TAV_OUT_af_05, "<p>Article not found</p>")'])
    A('')
    A('// ⑦ 空输入 ⇒ 空串（不得留下分隔符残渣）')
    test('guard/nav_empty_is_empty',
         ['ASSERT_EQ(_TAV_OUT_nv_04, "")'])
    A('')

    # ── 跑测试 + 自己把关退出码 ──────────────────────────────────
    A('// ── 跑测试 ────────────────────────────────────────────────────')
    A('LET(_TAV_RECORDS, RUN_TESTS());')
    A('PRINT("test_admin_views: ", LEN(_TAV_RECORDS), " test(s) run");')
    A('')
    A('LET MUT(_TAV_FAILED, 0);')
    A('FOR(_TAV_REC, _TAV_RECORDS,')
    A('    (IF(AT_K(_TAV_REC, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(_TAV_REC, "name", "?")),')
    A('        (SET(_TAV_FAILED, +(_TAV_FAILED, 1));')
    A('         PRINT("  FAIL ", AT_K(_TAV_REC, "name", "?"))))));')
    A('PRINT("test_admin_views: failed=", _TAV_FAILED);')
    A('IF(>(_TAV_FAILED, 0), (PRINT_ERR("test_admin_views: FAILED"); '
      'PANIC("admin views tests failed")), NULL);')
    A('PRINT("test_admin_views: OK");')

    chars, lines = write(OUT, src)
    total = sum(len(cases[g]) for g, _, _ in GROUPS)
    print('wrote %s (%d chars, %d lines, %d cases)'
          % (OUT, chars, lines, total))


if __name__ == '__main__':
    main()
