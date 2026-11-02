"""生成 tp/test/test_incremental.wll —— 增量构建的逐字节对照测试 + 反向守卫。

⚠ 输出的 .wll 由本文件生成，不要手改。

**验收方式**：每个用例的期望值都来自 **tp/test/fixtures/incremental_baseline.json**
（由 `gen_incremental_baseline.py` 用**真 Python** `tinypage/core/incremental.py` 跑出来的）。

**两层期望值**（为什么必须分两层）：
  · 第一层（**字面量**，逐字节对照）：凡是**与运行期 mtime 无关**的用例，期望值直接是
    Python 的输出 —— `SHOULD_USE_INCREMENTAL` 全部用例、`BUILD_CACHE_KEY` 的
    `nonexistent_dir` / `existing_empty_dir`、`GET_UNCHANGED` 的「命中 / 不命中 / 无 cache /
    空目录 / 部分变更」判定（判词本身与 mtime 的**绝对值**无关，只与「相等/不等」有关）。
  · 第二层（**运行期观察值**）：`BUILD_CACHE_KEY` 的绝对摘要是 (名字, 秒) 的函数，
    而 WLWL **无法设置文件 mtime**（`std.fs` 没有 utime/touch；全表查过）⇒ 运行期目录的
    秒数在生成期不可知。⇒ 测试侧**独立重算** preimage（用 `FILE_META` 取毫秒再 `/1000`，
    与 lib 走 `DIR_ENTRIES` 的取数路径**不同源**），再与本模块的 key 对照。
    这仍然抓得住：名字取法（PATH_BASE 还是全路径）、秒级截断、`:`/`|` 分隔符、
    12 位切片、小写 hex、目录项是否参与 —— 都会在两侧不一致时立刻红。
  · 生成期再补一道：`verify_rule_against_fixture()` 用夹具里**固定 mtime** 的
    `python_key` 校验这条重算规则本身与 Python 一致（规则错 ⇒ 生成器直接抛错，不产出测试）。

**反向守卫（本文件共 4 条，2 条静态 + 2 条运行期）**：
  ① 静态：`tp/lib/incremental.wll` **不得**出现 `READ_FILE` / `READ_BYTES` / `BYTE_LEN`
     —— 判据必须是 mtime，**不许读内容**（不做内容 hash）。
  ② 静态：`tp/lib/incremental.wll` 里必须有「毫秒 ÷ 1000」这一步 —— 秒级截断不能丢。
  ③ 运行期：每个运行期目录的 key 必须**不等于**「按毫秒拼」算出的 digest
     ⇒ 一旦有人把 `/1000` 去掉，立刻红。
  ④ 运行期：`cache` 为 NULL 时 `modified` 必须是**全部**文件 —— 即**不得**复现
     Python 兜底路径「恒判未变」的缺陷（夹具 `known_differences[0]`）。

**⚠ RUN_TESTS() 的失败不影响退出码**（规范明载）⇒ 本文件自己在末尾把关。

用法：python gen_test_incremental.py
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402
from paren_check import strip_comments  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, '..', 'lib')
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_incremental.wll')
LIB_FILE = os.path.join(LIB, 'incremental.wll')

# 守卫 ①：判据必须是 mtime ⇒ 模块里不许出现任何「读文件内容」的成员
FORBIDDEN_RED_CONTENT = re.compile(r'\bREAD_FILE\b|\bREAD_BYTES\b|\bBYTE_LEN\b')
# 守卫 ②：秒级截断那一步
SEC_TRUNC = re.compile(r'_ENTRY_MS.*/\(.*1000|/\(_ENTRY_MS.*1000')


def wl_string(s):
    """Python 字符串 → WLWL 字符串字面量（转义白名单见 tp/README.md 坑 7）。"""
    out = s.replace('\\', '\\\\').replace('"', '\\"')
    out = out.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    # ⚠ 字面美元符必须写 \$（坑 32）
    out = out.replace('$', '\\$')
    return '"' + out + '"'


def wl_value(v):
    """Python 值（str / dict / list / bool / int / None）→ WLWL 字面量。"""
    if isinstance(v, str):
        return wl_string(v)
    if isinstance(v, dict):
        return '[' + ', '.join('%s: %s' % (wl_string(k), wl_value(x))
                               for k, x in v.items()) + ']'
    if isinstance(v, list):
        return '[' + ', '.join(wl_value(x) for x in v) + ']'
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    raise TypeError('bad fixture value: %r' % (v,))


def guard_no_content_read():
    """守卫 ①：判据仍是 mtime ⇒ lib 里不得读文件内容（不做内容 hash）。"""
    with open(LIB_FILE, encoding='utf-8') as f:
        raw = f.read()
    code, _ = strip_comments(raw)
    problems = []
    for i, line in enumerate(code.split('\n'), 1):
        if FORBIDDEN_RED_CONTENT.search(line):
            problems.append('incremental.wll:%d: %s' % (i, line.strip()[:100]))
    if problems:
        raise SystemExit(
            'incremental 静态守卫失败：判据必须是 mtime，不得读文件内容（不做内容 hash）\n  '
            + '\n  '.join(problems))


def guard_seconds_truncation():
    """守卫 ②：毫秒 → 秒的截断那一步必须在。"""
    with open(LIB_FILE, encoding='utf-8') as f:
        raw = f.read()
    code, _ = strip_comments(raw)
    if not SEC_TRUNC.search(code):
        raise SystemExit(
            'incremental 静态守卫失败：找不到「毫秒 / 1000」的秒级截断\n'
            '  （== Python 的 int(st_mtime)；少了这一步 key 会变，且与 Python 对不上）')


def verify_rule_against_fixture(base):
    """生成期自检：测试侧的重算规则必须与夹具里**固定 mtime** 的 Python key 一致。

    规则 = 「名字以 .html 结尾的项（含同名目录）按名升序，拼 "name:<秒>" 用 | 连接，
    sha256 前 12 位」；秒 = int(mtime)。任何一处口径写错 ⇒ 这里直接抛错。
    """
    import hashlib
    for case in base['cache_key']['fixed']:
        if case['name'] == 'nonexistent_dir':
            continue
        entries = [e for e in case['entries'] if e['name'].endswith('.html')]
        entries.sort(key=lambda e: e['name'])
        pre = '|'.join('%s:%d' % (e['name'], e['sec']) for e in entries)
        got = hashlib.sha256(pre.encode()).hexdigest()[:12]
        if got != case['expected']:
            raise SystemExit(
                '重算规则与真 Python 不一致（%s）：rule=%r python=%r preimage=%r'
                % (case['name'], got, case['expected'], pre))
        if pre != case['preimage']:
            raise SystemExit('preimage 口径与真 Python 不一致（%s）：rule=%r python=%r'
                             % (case['name'], pre, case['preimage']))


def main():
    guard_no_content_read()
    guard_seconds_truncation()

    with open(os.path.join(FIXTURES, 'incremental_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)
    verify_rule_against_fixture(base)

    src = []
    A = src.append

    # ── 文件头 ──────────────────────────────────────────────────────────
    A('// tp/test/test_incremental.wll —— 增量构建的逐字节对照测试 + 反向守卫')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_incremental.py 生成 —— 请勿手改。')
    A('//')
    A('// 基准：tp/test/fixtures/incremental_baseline.json')
    A('//   （由 tp/test/gen_incremental_baseline.py 用**真 Python** 跑')
    A('//     tinypage/core/incremental.py 产出）')
    A('//')
    A('// 期望值分两层（理由见生成器 docstring）：')
    A('//   ① 字面量：与运行期 mtime 无关的用例 —— Python 的输出逐字节写死；')
    A('//   ② 运行期重算：绝对摘要依赖文件 mtime，而 WLWL 无法设置 mtime（std.fs 无 utime）')
    A('//      ⇒ 测试侧用 FILE_META 独立重算 preimage（与 lib 的 DIR_ENTRIES 路径不同源）。')
    A('//')
    A('// 反向守卫：① 静态禁 READ_FILE/READ_BYTES/BYTE_LEN（判据是 mtime，不做内容 hash）')
    A('//           ② 静态要求「毫秒 / 1000」这一步在')
    A('//           ③ 运行期：key 必须**不等于**按毫秒算的 digest（秒级截断可见）')
    A('//              ⇒ key == 秒版 digest 且 != 毫秒版 digest，等价于「key 只是秒的函数」')
    A('//              ⇒ 「同一秒内改 mtime 而 key 不变」是它的直接推论（WLWL 无法设 mtime，')
    A('//                所以不另造一条需要改 mtime 的用例 —— 那会是时序相关、CI 会 flaky）')
    A('//           ④ 运行期：cache 为 NULL ⇒ 全部 modified（不得复现 Python 兜底缺陷）')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "ASSERT_NEQ", '
      '"RUN_TESTS", "TEMP_DIR"]);')
    A('IMPORT("wlwl:std.fs", ["DIR_ENTRIES", "FILE_META", "MKDIRS", "PATH_EXT", '
      '"PATH_JOIN", "WRITE_FILE"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "JOIN"]);')
    A('IMPORT("wlwl:std.encode", ["SHA256"]);')
    A('IMPORT("./../lib/incremental.wll", ["BUILD_CACHE_KEY", "GET_UNCHANGED", '
      '"SHOULD_USE_INCREMENTAL"]);')
    A('')

    # ── 测试侧的重算（独立于 lib 的取数路径）───────────────────────────
    A('// ── 测试侧重算：**只**读 FILE_META（毫秒），不碰 DIR_ENTRIES 的 mtime ──')
    A('LET(_SEC_OF_, FUN((dir, nm), (')
    A('    // 一个目录项的秒级 mtime（== Python int(st_mtime)）。')
    A('    // ⚠ FILE_META 可能返 ERR（坑 25）⇒ 直接内联进 IS_ERR。')
    A('    IF(IS_ERR(FILE_META(PATH_JOIN(dir, nm))), 0,')
    A('       /(AT_K(FILE_META(PATH_JOIN(dir, nm)), "mtime", 0), 1000))')
    A(')));')
    A('')
    A('LET(_PREIMAGE_, FUN((dir, use_ms), (')
    A('    // preimage：名字以 .html 结尾的项（**含同名目录**，对齐 glob）按名升序，')
    A('    // 拼 "<名>:<秒>" 用 | 连接。use_ms = TRUE ⇒ 故意用毫秒（守卫 ③ 的判据）。')
    A('    LET MUT(lines, []);')
    A('    FOR(e, DIR_ENTRIES(dir), (')
    A('        IF(==(PATH_EXT(AT_K(e, "name", "")), "html"), (')
    A('            LET(nm, AT_K(e, "name", ""));')
    A('            LET(sec, IF(use_ms,')
    A('                AT_K(FILE_META(PATH_JOIN(dir, nm)), "mtime", 0),')
    A('                _SEC_OF_(dir, nm)));')
    A('            SET(lines, PUSH(lines, CAT(nm, ":", STR(sec))))')
    A('        ), (NULL))')
    A('    ));')
    A('    JOIN(lines, "|")')
    A(')));')
    A('')
    A('LET(_KEY_OF_, FUN((dir), (')
    A('    SUB(SHA256(_PREIMAGE_(dir, FALSE)), 0, 12)')
    A(')));')
    A('')
    A('LET(_KEY_OF_MS_, FUN((dir), (')
    A('    // 守卫 ③：若把 /1000 去掉，key 就会长成这样 ⇒ 必须**不等**。')
    A('    SUB(SHA256(_PREIMAGE_(dir, TRUE)), 0, 12)')
    A(')));')
    A('')
    A('LET(_CACHE_OF_, FUN((dir), (')
    A('    // cache 的形态：DICT 名 → **秒**（与 BUILD_CACHE_KEY 的 int(mtime) 同口径）。')
    A('    LET MUT(c, DICT());')
    A('    FOR(e, DIR_ENTRIES(dir), (')
    A('        IF(AT_K(e, "is_dir", FALSE), (NULL), (')
    A('            IF(==(PATH_EXT(AT_K(e, "name", "")), "html"), (')
    A('                SET(c, INDEX_SET(c, AT_K(e, "name", ""),')
    A('                    _SEC_OF_(dir, AT_K(e, "name", ""))))')
    A('            ), (NULL))')
    A('        ))')
    A('    ));')
    A('    c')
    A(')));')
    A('')
    A('LET(_CACHE_PARTIAL_, FUN((dir), (')
    A('    // 「部分变更」：b.html 的 cache 秒故意少 1 秒；d.html 从 cache 里删掉（新增）。')
    A('    LET MUT(c, _CACHE_OF_(dir));')
    A('    SET(c, INDEX_SET(c, "b.html", -(AT_K(c, "b.html", 0), 1)));')
    A('    SET(c, REMOVE_KEY(c, "d.html"));')
    A('    c')
    A(')));')
    A('')

    # ── 夹具目录（运行期）────────────────────────────────────────────────
    A('// ── 运行期夹具：TEMP_DIR 下真造目录/文件（mtime 由文件系统给，不可设）──')
    A('LET(_TD_, TEMP_DIR());')
    A('// 缓存 key：不存在 / 存在但空')
    A('LET(_CK_NONE_, PATH_JOIN(_TD_, "ck_none"));')
    A('LET(_CK_EMPTY_, PATH_JOIN(_TD_, "ck_empty"));')
    A('MKDIRS(_CK_EMPTY_);')
    A('')

    rt = base['cache_key']['runtime']
    for case in rt:
        d = '_CK_%s_' % case['name'].upper()
        A('// %s：%s' % (case['name'], case['note']))
        A('LET(%s, PATH_JOIN(_TD_, "%s"));' % (d, case['name']))
        A('MKDIRS(%s);' % d)
        for dn in case['dirs']:
            A('MKDIRS(PATH_JOIN(%s, %s));' % (d, wl_string(dn)))
        for fn in case['files']:
            A('WRITE_FILE(PATH_JOIN(%s, %s), "x");' % (d, wl_string(fn)))
        A('')

    A('// ── 运行期期望值（观察到的 mtime 重算；生成期不可知）──────────────')
    for case in rt:
        d = '_CK_%s_' % case['name'].upper()
        A('LET(_K_%s_, _KEY_OF_(%s));' % (case['name'].upper(), d))
    A('')

    # ── GET_UNCHANGED 夹具目录 ──────────────────────────────────────────
    A('// ── GET_UNCHANGED 夹具（每个用例一个独立目录：实现会**回写** cache）──')
    gu = base['get_unchanged']
    for case in gu:
        d = '_GU_%s_' % case['name'].upper()
        A('// %s：%s' % (case['name'], case['note']))
        A('LET(%s, PATH_JOIN(_TD_, "gu_%s"));' % (d, case['name']))
        A('MKDIRS(%s);' % d)
        for fn in case['files']:
            A('WRITE_FILE(PATH_JOIN(%s, %s), "x");' % (d, wl_string(fn)))
        A('')

    A('// ── cache 形态（按夹具的 cache_mode 造）───────────────────────────')
    def cache_expr_for(mode, d):
        if mode in ('exact', 'wrong_type', 'extra_name'):
            return '_CACHE_OF_(%s)' % d
        if mode == 'partial':
            return '_CACHE_PARTIAL_(%s)' % d
        if mode == 'stale':
            # 「cache 来自别处」⇒ 一个条目都对不上（Python 侧对应「key 不匹配」）
            return 'DICT()'
        if mode == 'none':
            return 'NULL'
        raise SystemExit('unknown cache_mode: %r' % (mode,))

    for case in gu:
        d = '_GU_%s_' % case['name'].upper()
        mode = case['cache_mode']
        expr = cache_expr_for(mode, d)
        if mode == 'wrong_type':
            # 值不是 INTEGER ⇒ 必须判 modified（类型守卫，坑 35 的近亲）
            expr = 'INDEX_SET(%s, "a.html", "abc")' % expr
            A('LET(_C_%s_, %s);' % (case['name'].upper(), expr))
        elif mode == 'extra_name':
            # cache 里有、目录里已无的名字 ⇒ 两组都不出现
            expr = 'INDEX_SET(%s, "gone.html", 5)' % expr
            A('LET(_C_%s_, %s);' % (case['name'].upper(), expr))
        else:
            A('LET(_C_%s_, %s);' % (case['name'].upper(), expr))
    A('')

    # ── SHOULD_USE_INCREMENTAL ─────────────────────────────────────────
    A('// ── SHOULD_USE_INCREMENTAL（期望值 = 真 Python incremental.py:131）──')
    for case in base['should_use_incremental']:
        opts = {'article_count': case['article_count'],
                'modified_count': case['modified_count']}
        if case['threshold'] is not None:
            opts['threshold'] = case['threshold']
        A('// %s：%s' % (case['name'], case['note']))
        A('LET(_SU_%s_, %s);' % (case['name'].upper(), wl_value(opts)))
        A('TEST("should/%s", FUN(() ,' % case['name'])
        A('    (ASSERT_EQ(SHOULD_USE_INCREMENTAL(_SU_%s_), %s));'
          % (case['name'].upper(), wl_value(case['expected'])))
        A('    TRUE));')
    A('')

    # ── BUILD_CACHE_KEY：字面量用例 ─────────────────────────────────────
    A('// ── BUILD_CACHE_KEY：与 mtime 无关的字面量用例（Python 输出）──────')
    for case in base['cache_key']['fixed']:
        if case['name'] == 'existing_empty_dir':
            d = '_CK_EMPTY_'
        elif case['name'] == 'nonexistent_dir':
            d = '_CK_NONE_'
        else:
            continue          # 固定 mtime 的用例走 verify_rule_against_fixture()
        A('// %s：%s' % (case['name'], case['note']))
        A('TEST("cache_key/%s", FUN(() ,' % case['name'])
        A('    (ASSERT_EQ(BUILD_CACHE_KEY(["article_dir": %s]), %s));'
          % (d, wl_string(case['expected'])))
        A('    TRUE));')
    A('')

    A('')
    A('// ── BUILD_CACHE_KEY：把**文件**当目录传入（Python 给 sha256("")[:12]，不是 "empty"）')
    fid = base['cache_key']['file_instead_of_dir']
    A('// %s' % fid['note'])
    A('TEST("cache_key/file_instead_of_dir", FUN(() ,')
    A('    (ASSERT_EQ(BUILD_CACHE_KEY(["article_dir": PATH_JOIN(_CK_RT_SINGLE_, "a.html")]), '
      '%s));' % wl_string(fid['expected']))
    A('    TRUE));')
    A('')

    # ── BUILD_CACHE_KEY：运行期用例 ────────────────────────────────────
    A('// ── BUILD_CACHE_KEY：运行期目录（期望 = 测试侧用 FILE_META 重算）───')
    for case in rt:
        u = case['name'].upper()
        A('// %s：%s' % (case['name'], case['note']))
        A('TEST("cache_key/%s", FUN(() ,' % case['name'])
        A('    (ASSERT_EQ(BUILD_CACHE_KEY(["article_dir": _CK_%s_]), _K_%s_));' % (u, u))
        A('    TRUE));')
        A('// 守卫 ③：同一目录的 key 必须**不等于**按毫秒算的 digest（秒级截断可见）')
        A('TEST("guard/truncation_%s", FUN(() ,' % case['name'])
        A('    (ASSERT_NEQ(BUILD_CACHE_KEY(["article_dir": _CK_%s_]), _KEY_OF_MS_(_CK_%s_)));'
          % (u, u))
        A('    TRUE));')
    A('// 守卫 ③ 的补充：同一目录两次调用必须一致（无隐藏状态）')
    A('TEST("guard/cache_key_idempotent", FUN(() ,')
    A('    (ASSERT_EQ(BUILD_CACHE_KEY(["article_dir": _CK_RT_MULTI_]), '
      'BUILD_CACHE_KEY(["article_dir": _CK_RT_MULTI_])));')
    A('    TRUE));')
    A('')

    # ── GET_UNCHANGED ─────────────────────────────────────────────────
    A('// ── GET_UNCHANGED（期望 = 夹具 expected_wlwl）─────────────────────')
    for case in gu:
        u = case['name'].upper()
        A('// %s：%s' % (case['name'], case['note']))
        A('TEST("unchanged/%s", FUN(() ,' % case['name'])
        A('    (ASSERT_EQ(GET_UNCHANGED(["article_dir": _GU_%s_, "cache": _C_%s_]), %s));'
          % (u, u, wl_value(case['expected_wlwl'])))
        A('    TRUE));')

    A('')
    A('// ── 反向守卫 ④：不得复现 Python 兜底路径的缺陷（恒判「未变」）─────')
    A('// Python 的 cache 未命中 ⇒ get_modified_files(article_dir, article_dir) ⇒ 恒空')
    A('// ⇒ 全部判未变（实测见夹具 known_differences[0].evidence）。')
    A('// WLWL 侧：cache 缺失 ⇒ 全部进 modified ⇒ 退化为**全量重建**（安全侧）。')
    stale = [c for c in gu if c['cache_mode'] == 'stale' and len(c['files']) == 2][0]
    u = stale['name'].upper()
    A('TEST("guard/not_python_defect_all_modified", FUN(() ,')
    A('    (ASSERT_EQ(LEN(AT_K(GET_UNCHANGED(["article_dir": _GU_%s_, "cache": DICT()]), '
      '"modified", [])), 2));' % u)
    A('    TRUE));')
    A('TEST("guard/not_python_defect_not_equal", FUN(() ,')
    A('    // 也不能恰好等于 Python 的（缺陷）返回值。')
    A('    (ASSERT_NEQ(GET_UNCHANGED(["article_dir": _GU_%s_, "cache": DICT()]), %s));'
      % (u, wl_value(stale['expected_python'])))
    A('    TRUE));')
    A('// 新增文件也必须被抓到（Python 漏判的那条）')
    newf = [c for c in gu if c['name'] == 'stale_new_file'][0]
    un = newf['name'].upper()
    A('TEST("guard/new_file_is_modified", FUN(() ,')
    A('    (ASSERT_EQ(LEN(AT_K(GET_UNCHANGED(["article_dir": _GU_%s_, "cache": DICT()]), '
      '"modified", [])), 3));' % un)
    A('    TRUE));')
    A('')

    # ── 跑测试并把失败转成非零退出码 ────────────────────────────────────
    A('// ── 跑测试 ────────────────────────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_incremental: ", LEN(records), " test(s) run");')
    A('')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"), " error=", '
      'STR(AT_K(rec, "error", "")))))));')
    A('PRINT("test_incremental: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_incremental: FAILED"); '
      'PANIC("incremental tests failed")), NULL);')
    A('PRINT("test_incremental: OK");')

    chars, lines = write(OUT, src)
    n_tests = len(base['should_use_incremental']) + 2 * len(rt) + 1 + len(gu) + 3
    print('wrote %s (%d chars, %d lines, ~%d tests)'
          % (OUT, chars, lines, n_tests))


if __name__ == '__main__':
    main()
