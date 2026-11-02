"""生成 tp/test/fixtures/incremental_baseline.json —— 增量构建的**真 Python** 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**验收纪律**（业主裁决）：基准必须**直接 import 真 Python 实现**产出期望值，
不许「照抄规则重写一遍」—— 照抄的基准只是你的第二种读法，逐字节对照会失去意义。
⇒ 本文件的每一个 `expected` 都是调 `tinypage/core/incremental.py` 的**真函数**跑出来的，
   文件系统状态也在临时目录里**真造**（`write_text` + `os.utime` 定死 mtime）。

对齐的三个函数（`tinypage/core/incremental.py`）：

  ① `should_use_incremental(source_dir, output_dir, threshold=100) -> bool`（:131）
       · `article_count = len(list(source_dir.glob("*.html")))`
       · `if article_count < threshold: return False`
       · `modified_ratio = len(modified) / article_count if article_count > 0 else 1.0`
       · `return modified_ratio < 0.1`          ← **严格小于**，恰好 0.1 ⇒ FALSE
     ⚠ threshold 的默认值就写在**签名**里（:134 `threshold: int = 100`），不是配置文件。
     ⚠ `glob("*.html")` 在 Windows **大小写敏感**（实测：目录里的 `A.HTML` 不被匹配），
       且**会把名字以 `.html` 结尾的目录也算进去**（实测：`dir.html/` 被 `glob` 匹配）。
     ⇒ 基准用**真目录**驱动它：造 `article_count` 个 `.html`，输出目录里缺
       `modified_count` 个（缺的就算「已改」，因为 `out.exists()` 为假）。

  ② `build_cache_key(article_dir) -> str`（:159）
       · `if not article_dir.exists(): return "empty"`
       · 对 `sorted(article_dir.glob("*.html"))` 取 `f"{f.name}:{int(f.stat().st_mtime)}"`
         用 `|` 拼接 ⇒ `sha256(...).hexdigest()[:12]`
     ⚠ `int(st_mtime)` 是**秒级截断**（`FILE_META`/`DIR_ENTRIES` 的 `mtime` 是**毫秒**
       ⇒ WLWL 侧必须自己 `/1000`）。
     ⚠ 「存在但为空」的目录**不是** `"empty"`：内容是空串 ⇒ `sha256("")[:12]` =
       `e3b0c44298fc`。两者必须分开（实测）。
     ⚠ `sorted()` 对 `WindowsPath` 按 **lower** 比较（实测：`a.html` 排在 `B.html` 前）。

  ③ `get_unchanged_articles(articles, article_dir, cache_file=None)`（:182）
       · cache 命中（`cached_key == build_cache_key(article_dir)`）⇒ 返回 `(articles, [])`
       · 否则**兜底路径**：`modified_files = get_modified_files(article_dir, article_dir)`
         ⚠⚠ **这就是本卡要修的缺陷**：把 `article_dir` **同时**当 source 与 output
           传进去 ⇒ `out = article_dir / src.name` 就是 `src` 自己
           ⇒ `src.stat().st_mtime > out.stat().st_mtime` **恒假**
           ⇒ `modified_files` **恒空** ⇒ 每篇都被判「未变」。
         实测证据见本文件 `evidence.defect`：key 变了（说明内容确实变了），
         但 `changed` 仍是 `[]`；**新增**文件也照样 `changed == []`。
         ⇒ 后果：调用方按 `changed` 决定重建 ⇒ **该重建的全被漏掉**；
           若调用方另把「key 变了但 changed 为空」当异常，就只能退回**全量重建**
           （卡面描述的「恒全量重建」就是这条链的下游表现）。

**本文件同时是「无机器相关路径」的守卫**（本仓踩过：CI 临时目录是 8.3 短名
`RUNNER~1`，被测函数 `resolve()` 给长名 ⇒ 相对路径算出 `..\\..\\runneradmin\\...`
写进夹具，本地永远复现不出来、只有 CI 红）：
  · 进临时目录后**先** `os.path.realpath(td)`；
  · 夹具里**只记文件名**，绝不记目录；
  · `_record_rel()` 一旦拿到以 `..` 开头的相对路径就**当场抛错**；
  · 落盘前再过一遍 `guard_no_machine_paths()`（盘符 / 临时目录 / `~1` 短名）。

用法：python gen_incremental_baseline.py
"""
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))          # ← 仓库根（含 tinypage/）
OUT = os.path.join(HERE, 'fixtures', 'incremental_baseline.json')

sys.path.insert(0, REPO)
from tinypage.core.incremental import (  # noqa: E402  ← 真项目实现
    build_cache_key,
    get_unchanged_articles,
    should_use_incremental,
)

# 固定的 mtime（Unix 秒）。**不用真实写盘时间** —— 否则基准不可复现。
T0 = 1_700_000_000


# ── 临时目录 / 路径守卫 ────────────────────────────────────────────────────
def new_tmp(prefix):
    """造一个临时目录并**先 realpath**（8.3 短名陷阱：必须拿到长名）。"""
    td = tempfile.mkdtemp(prefix=prefix)
    td = os.path.realpath(td)          # ← CI 上是 RUNNER~1 ⇒ 展开成长名
    return td


def _record_rel(path, base):
    """把路径折成**相对**形式；以 `..` 开头 ⇒ 当场抛错（绝不进夹具）。"""
    rel = os.path.relpath(path, base).replace('\\', '/')
    if rel.startswith('..'):
        raise SystemExit(
            'refusing to record a path that escapes the temp dir: %r '
            '(base=%r, path=%r) —— 夹具只许记文件名' % (rel, base, path))
    return rel


def guard_no_machine_paths(text, tmp_dirs):
    """落盘前的最后一道守卫：夹具里不得出现任何机器相关路径。"""
    problems = []
    for td in tmp_dirs:
        if td and (td in text or td.replace('\\', '/') in text):
            problems.append('temporary directory leaked: %s' % td)
    if re.search(r'[A-Za-z]:[\\/]', text):
        problems.append('drive-letter path found')
    if '~1' in text:
        problems.append('8.3 short name (~1) found')
    if re.search(r'\\\\', text):
        problems.append('UNC / windows separator found')
    if problems:
        raise SystemExit('incremental fixture is machine-dependent:\n  '
                         + '\n  '.join(problems))
    return text


# ── 造文件 / 造目录（mtime 定死）──────────────────────────────────────────
def put_file(root, name, sec, content='x'):
    """写一个文件并把 mtime 定成 `sec`（整数秒）。"""
    p = Path(root) / name
    p.write_text(content, encoding='utf-8')
    os.utime(p, (sec, sec))
    assert int(p.stat().st_mtime) == sec, (name, p.stat().st_mtime, sec)
    return p


def put_file_ms(root, name, ms, content='x'):
    """写一个文件并把 mtime 定成 `ms`（**毫秒**；用 ns 设，避开浮点误差）。"""
    p = Path(root) / name
    p.write_text(content, encoding='utf-8')
    os.utime(p, ns=(ms * 1_000_000, ms * 1_000_000))
    st = int(p.stat().st_mtime)
    assert st == ms // 1000, (name, p.stat().st_mtime, ms)
    return p


def put_dir(root, name, sec):
    """建一个**目录**并把 mtime 定成 `sec`（`dir.html/` 这种形态要用）。"""
    p = Path(root) / name
    p.mkdir()
    os.utime(p, (sec, sec))
    return p


class _Art:
    """`get_unchanged_articles` 只用 `art.file` ⇒ 鸭子类型就够（不必造 ArticleMeta）。"""

    def __init__(self, name):
        self.file = name


# ── ① should_use_incremental ───────────────────────────────────────────────
def case_should(tmp, article_count, modified_count, threshold=None):
    """真造两个目录，然后调**真函数** `should_use_incremental`。

    输出目录里只写前 `article_count - modified_count` 个 ⇒ 其余「缺输出」⇒
    `get_modified_files` 判它们已改 ⇒ `len(modified) == modified_count`。
    ⚠ 输出文件在源文件**之后**写 ⇒ 输出更「新」⇒ 已写的那些**不算**修改
      （`src.st_mtime > out.st_mtime` 为假）。
    """
    src = Path(new_tmp('tp_inc_src_'))
    out = Path(new_tmp('tp_inc_out_'))
    names = ['%04d.html' % i for i in range(article_count)]
    for i, nm in enumerate(names):
        put_file(src, nm, T0 + i)
    for nm in names[:article_count - modified_count]:
        (out / nm).write_text('x', encoding='utf-8')
    kwargs = {} if threshold is None else {'threshold': threshold}
    got = should_use_incremental(src, out, **kwargs)
    real_count = len(list(src.glob('*.html')))
    assert real_count == article_count, (real_count, article_count)
    # 独立复核：真函数算出的 modified 个数必须就是传进来的那个数
    from tinypage.core.incremental import get_modified_files
    real_mod = len(get_modified_files(src, out))
    assert real_mod == modified_count, (real_mod, modified_count)
    return got


def build_should_cases(tmp_dirs):
    spec = [
        ('default_below_threshold', 99, 0, None,
         '默认 threshold=100：99 篇 < 100 ⇒ 不用增量（与修改比例无关）'),
        ('default_at_threshold_no_change', 100, 0, None,
         '篇数恰好等于阈值 ⇒ 通过第一条；零修改 ⇒ 比值 0 < 0.1 ⇒ TRUE'),
        ('boundary_ratio_exactly_0_1', 100, 10, None,
         '比值**恰好 0.1**（10/100）⇒ 严格小于不成立 ⇒ FALSE'),
        ('boundary_ratio_just_below', 101, 10, None,
         '10/101 ≈ 0.099 < 0.1 ⇒ TRUE（比值的下边界，仅超一篇文章）'),
        ('boundary_ratio_just_above', 100, 11, None,
         '11/100 = 0.11 > 0.1 ⇒ FALSE'),
        ('ratio_9_of_100', 100, 9, None,
         '9/100 = 0.09 < 0.1 ⇒ TRUE'),
        ('zero_articles_default', 0, 0, None,
         '0 篇 ⇒ 0 < 100 ⇒ FALSE（Python 连比值都不算）'),
        ('zero_articles_threshold_0', 0, 0, 0,
         '0 篇 + threshold=0 ⇒ 越过第一条；`article_count > 0` 为假 ⇒ 比值取 1.0 ⇒ FALSE'),
        ('threshold_0_one_article', 1, 0, 0,
         'threshold=0 + 1 篇零修改 ⇒ 比值 0 < 0.1 ⇒ TRUE'),
        ('all_modified', 200, 200, None,
         '全改 ⇒ 比值 1.0 ⇒ FALSE'),
        ('custom_threshold_high', 50, 1, 10,
         'threshold=10 且 50 篇 ⇒ 1/50 = 0.02 < 0.1 ⇒ TRUE'),
        ('custom_threshold_blocks', 5, 0, 10,
         'threshold=10 且 5 篇 ⇒ 5 < 10 ⇒ FALSE（篇数不足，比值再小也没用）'),
        ('big_at_boundary', 1000, 100, None,
         '1000 篇里 100 篇改 ⇒ 比值恰好 0.1 ⇒ FALSE（大数上的同一把尺）'),
        ('big_just_below', 1001, 100, None,
         '100/1001 ≈ 0.09990 < 0.1 ⇒ TRUE'),
    ]
    cases = []
    for name, ac, mc, th, note in spec:
        got = case_should(new_tmp('tp_inc_c_'), ac, mc, th)
        cases.append({
            'name': name,
            'note': note,
            'article_count': ac,
            'modified_count': mc,
            'threshold': th,          # None ⇒ 不传该键（验默认值）
            'expected': bool(got),
        })
    return cases


# ── ② build_cache_key ─────────────────────────────────────────────────────
def python_preimage(entries):
    """把 `(名字, 秒)` 列表拼成 Python 侧的那条 preimage 串（**只用于自检/留证**）。

    ⚠ 排序用 Python 自己的 `sorted`（`WindowsPath` 比较 = lower 比较）。
    ⚠ 只有名字以 `.html` 结尾的参与（对齐 `glob("*.html")`；目录也算，见 dir_named_html）。
    """
    keep = [(n, sec) for n, sec in entries if n.endswith('.html')]
    return '|'.join('%s:%d' % (n, sec) for n, sec in sorted(keep, key=lambda e: e[0]))


def build_cache_fixed(tmp_dirs):
    """固定 mtime 的目录状态 ⇒ 真 `build_cache_key` 的返回值（逐字节可复现）。"""
    spec = [
        ('nonexistent_dir', 'empty', [],
         '不存在 ⇒ 字面量 "empty"（:171 的提前返回）'),
        ('existing_empty_dir', None, [],
         '存在但为空 ⇒ 不是 "empty"，是 sha256("")[:12] = e3b0c44298fc'),
        ('single_file', None, [('a.html', T0, False)],
         '单文件：preimage = "a.html:1700000000"'),
        ('three_files', None,
         [('b.html', T0 + 1, False), ('a.html', T0 + 2, False), ('中文.html', T0 + 3, False)],
         '多文件 ⇒ 按名排序后拼接（创建顺序与结果无关）；含中文文件名'),
        ('dir_named_html', None,
         [('a.html', T0, False), ('dir.html', T0 + 5, True)],
         '⚠ glob("*.html") **会把目录也算进去** ⇒ 目录的真实 mtime 参与 key'),
        ('non_html_ignored', None,
         [('a.html', T0, False), ('notes.txt', T0 + 9, False)],
         '非 .html 后缀不参与'),
    ]
    out = []
    for name, literal, entries, note in spec:
        case = {'name': name, 'note': note}
        if name == 'nonexistent_dir':
            case['expected'] = build_cache_key(Path(new_tmp('tp_inc_k_')) / 'nope')
            case['entries'] = []
            case['preimage'] = ''
            out.append(case)
            continue
        d = new_tmp('tp_inc_k_')
        tmp_dirs.append(d)
        rec = []
        for fname, sec, is_dir in entries:
            if is_dir:
                put_dir(d, fname, sec)
            else:
                put_file(d, fname, sec)
            rec.append({'name': fname, 'sec': sec, 'is_dir': is_dir})
        key = build_cache_key(Path(d))
        pre = python_preimage([(r['name'], r['sec']) for r in rec])
        # 复核：真函数的结果必须等于「按规则重算 preimage 再 hash」
        expect = hashlib.sha256(pre.encode()).hexdigest()[:12]
        if key != expect:
            raise AssertionError('%s: build_cache_key=%r but recomputed=%r (preimage=%r)'
                                 % (name, key, expect, pre))
        case['entries'] = rec
        case['preimage'] = pre
        case['expected'] = key
        out.append(case)
    return out


def build_cache_file_instead_of_dir(tmp_dirs):
    """把**文件**当目录传进来：Python 的 `exists()` 为真、`glob` 给空集 ⇒ sha256("")[:12]。

    ⚠ 这条**不是** "empty"（那是目录不存在）；两个分支必须分开。
    """
    d = new_tmp('tp_inc_f_')
    tmp_dirs.append(d)
    f = put_file(d, 'a.html', T0)
    key = build_cache_key(f)
    expect = hashlib.sha256(b'').hexdigest()[:12]
    if key != expect:
        raise AssertionError('文件当目录传入：预期 %r，实际 %r' % (expect, key))
    return {
        'name': 'file_instead_of_dir',
        'note': '传入的是**文件**（exists 为真、glob 为空）⇒ sha256("")[:12]；'
                '与「目录不存在 ⇒ "empty"」是两条不同分支（实测）',
        'expected': key,
    }


def build_cache_truncation(tmp_dirs):
    """秒级截断的**Python 证据**：同秒内 ms 不同 ⇒ key 必须相同。

    另外给一份「若用毫秒」会得到的 key ⇒ 两者不同 ⇒ 反向守卫的判据。
    """
    d1 = new_tmp('tp_inc_t_')
    d2 = new_tmp('tp_inc_t_')
    tmp_dirs += [d1, d2]
    put_file_ms(d1, 'a.html', T0 * 1000 + 123)
    put_file_ms(d1, 'b.html', T0 * 1000 + 987)
    put_file(d2, 'a.html', T0)
    put_file(d2, 'b.html', T0)
    ms_key = build_cache_key(Path(d1))
    sec_key = build_cache_key(Path(d2))
    if ms_key != sec_key:
        raise AssertionError('秒级截断不成立？ms_key=%r sec_key=%r' % (ms_key, sec_key))
    # 「若按毫秒拼」会得到的 digest —— 与正确的 key 必须不同（守卫判据）
    wrong = hashlib.sha256(('%s:%d|%s:%d' % (
        'a.html', T0 * 1000 + 123, 'b.html', T0 * 1000 + 987)).encode()).hexdigest()[:12]
    if wrong == ms_key:
        raise AssertionError('毫秒版 digest 竟然等于正确 key ⇒ 守卫失效')
    return {
        'name': 'subsecond_same_second',
        'note': '同一秒内 ms 不同（123 / 987）⇒ 秒级截断 ⇒ key 与整秒版相同；'
                '若改用毫秒拼接会得到另一个 key（守卫判据）',
        'ms_key': ms_key,
        'sec_key': sec_key,
        'would_be_key_with_ms': wrong,
        'equal': True,
    }


def build_cache_runtime(tmp_dirs):
    """运行期用例：.wll 侧在 TEMP_DIR 下真造这些文件/目录。

    期望值**不能**预生成（运行期 mtime 未知）⇒ .wll 侧用「观察到的 mtime 重建 preimage」
    得到期望值；本文件只提供布局。两条 mtime 无关的用例（`nonexistent` / `empty`）
    已在上面的 `fixed` 里给出 Python 的**字面量**期望值。
    """
    return [
        {'name': 'rt_single', 'note': '单文件（运行期 mtime）', 'files': ['a.html'], 'dirs': []},
        {'name': 'rt_multi', 'note': '多文件 + 中文名（运行期 mtime）',
         'files': ['b.html', 'a.html', '中文.html'], 'dirs': []},
        {'name': 'rt_dir_named_html', 'note': '含一个名为 dir.html 的**目录**（运行期 mtime）',
         'files': ['a.html'], 'dirs': ['dir.html']},
        {'name': 'rt_non_html', 'note': '含非 .html 后缀（必须被忽略）',
         'files': ['a.html', 'notes.txt'], 'dirs': []},
    ]


# ── ③ get_unchanged_articles ───────────────────────────────────────────────
def build_gu_cases(tmp_dirs):
    """每个用例一个独立目录（真函数会**回写** cache 文件 ⇒ 不能共用）。

    `cache_mode` 决定 cache 文件的初始内容（None ⇒ 不传 cache_file）：
      · exact      —— 写当前 key（⇒ hit 路径）
      · stale      —— 写一个**别处的** key（cache_dir 与 article_dir 不匹配的形态）
      · none       —— 不传 cache_file
    期望值两栏：
      · expected_python —— 真函数实际返回（**含缺陷**）
      · expected_wlwl   —— WLWL 侧**修好之后**的口径（见 known_differences）
    """
    spec = [
        ('hit_all_unchanged', ['a.html', 'b.html'], 'exact',
         'cache 全命中 ⇒ 全部未变（Python 走的正是这条 hit 路径）',
         None),
        ('stale_mtimes_changed', ['a.html', 'b.html'], 'stale',
         'cache 来自别处（不匹配）⇒ 兜底路径 ⇒ Python 误判「全部未变」；'
         'WLWL 侧逐文件比 mtime ⇒ 两篇都进 modified',
         ['a.html', 'b.html']),
        ('stale_new_file', ['a.html', 'b.html', 'c.html'], 'stale',
         '新增文件 c.html 也走兜底路径 ⇒ Python 漏判；WLWL 侧进 modified',
         ['a.html', 'b.html', 'c.html']),
        ('no_cache', ['a.html', 'b.html'], 'none',
         '完全没有 cache ⇒ 无从证明未变 ⇒ WLWL 全部进 modified（安全侧）；'
         'Python 仍返回「全部未变」',
         ['a.html', 'b.html']),
        ('empty_dir', [], 'none',
         '空目录 ⇒ 两组都空（两侧一致）',
         None),
    ]
    cases = []
    for name, files, mode, note, wlwl_modified in spec:
        d = new_tmp('tp_inc_gu_')
        tmp_dirs.append(d)
        for i, fname in enumerate(files):
            put_file(d, fname, T0 + i)
        arts = [_Art(f) for f in sorted(files)]
        cache_file = Path(d) / 'cache.txt'
        if mode == 'exact':
            cache_file.write_text(build_cache_key(Path(d)), encoding='utf-8')
        elif mode == 'stale':
            # 「cache 在别的目录里」⇒ 它的 key 是那个目录的 key ⇒ 与当前目录不匹配
            other = new_tmp('tp_inc_other_')
            tmp_dirs.append(other)
            put_file(other, 'zzz.html', T0 + 99)
            cache_file.write_text(build_cache_key(Path(other)), encoding='utf-8')
        kwargs = {} if mode == 'none' else {'cache_file': cache_file}
        unchanged, changed = get_unchanged_articles(arts, Path(d), **kwargs)
        py = {
            'unchanged': [a.file for a in unchanged],
            'modified': [a.file for a in changed],
        }
        if wlwl_modified is None:
            # 无差异：WLWL 侧与 Python 同口径
            wlwl = dict(py)
        else:
            wlwl = {'unchanged': sorted(n for n in files if n not in wlwl_modified),
                    'modified': sorted(wlwl_modified)}
        cases.append({
            'name': name,
            'note': note,
            'files': sorted(files),
            'cache_mode': mode,
            'expected_python': py,
            'expected_wlwl': wlwl,
            'agrees_with_python': py == wlwl,
        })
    # hit 用例必须与 Python 完全一致（这是「没有差异」的锚点）
    hit = [c for c in cases if c['name'] == 'hit_all_unchanged'][0]
    if not hit['agrees_with_python']:
        raise AssertionError('cache 命中用例两侧不一致：%r' % (hit,))
    return cases


def build_gu_partial(tmp_dirs):
    """「部分变更 / 新增文件 / 删除文件」的**真 Python** 期望值。

    ⚠ 这里**不**用 `get_unchanged_articles`（它的兜底路径恒空 = 缺陷），而是用
      `get_modified_files(source_dir, output_dir)` —— **同一个函数**在参数正确时
      才是「按 mtime 判已改」的参考实现。缓存（cache）在 WLWL 侧记录的就是
      「产物目录里那份文件的 mtime」，所以本用例的 verdict 与 WLWL 口径等价：
        · `b.html` 的产物**缺**  ⇒ 已改（= cache 里 b 的秒与当前不符）
        · `d.html` **新增**（无产物）⇒ 已改（= cache 里没有 d）
        · 产物里的 `gone.html` 在源里**已删** ⇒ 两组都不出现
    """
    from tinypage.core.incremental import get_modified_files

    src = new_tmp('tp_inc_p_')
    out = new_tmp('tp_inc_p_')
    tmp_dirs += [src, out]
    files = ['a.html', 'b.html', 'c.html', 'd.html']
    for i, nm in enumerate(files):
        put_file(src, nm, T0 + i)
    # 产物：a / c 有且更「新」；b 缺；d 没有；另有一个源里已删的 gone.html
    for i, nm in ((0, 'a.html'), (2, 'c.html')):
        put_file(out, nm, T0 + 10 + i)
    put_file(out, 'gone.html', T0 + 20)
    modified = sorted(p.name for p in get_modified_files(Path(src), Path(out)))
    if modified != ['b.html', 'd.html']:
        raise AssertionError('预期 modified=[b.html, d.html]，实际 %r' % (modified,))
    deleted = sorted(set(p.name for p in Path(out).glob('*.html'))
                     - set(p.name for p in Path(src).glob('*.html')))
    if deleted != ['gone.html']:
        raise AssertionError('预期删除集为 [gone.html]，实际 %r' % (deleted,))
    unchanged = sorted(set(files) - set(modified))
    return {
        'name': 'partial_change_via_get_modified_files',
        'note': '真 Python 的 get_modified_files（参数正确时才是对的参考实现）：'
                'b.html 产物缺失 ⇒ 已改；d.html 新增 ⇒ 已改；gone.html 源里已删 ⇒ 两组都不出现',
        'files': files,
        'cache_mode': 'partial',
        'expected_python': {'unchanged': unchanged, 'modified': modified},
        'expected_wlwl': {'unchanged': unchanged, 'modified': modified},
        'agrees_with_python': True,
        'derived_via': 'tinypage/core/incremental.py:17 get_modified_files(src, out)',
        'deleted': deleted,
    }


def build_gu_extra_cases():
    """两个 **WLWL 专有** 的 cache 形态（Python 侧没有「cache 是 DICT」这个形态）。

    `expected_python` 记 None（不是「同意」，是**无从对照**）。
    """
    return [
        {
            'name': 'cache_extra_name_deleted',
            'note': '删除文件：cache 里有 gone.html、目录里已无 ⇒ 两组都不出现'
                    '（Python 同口径：文章列表里本来就没有它）',
            'files': ['a.html', 'b.html'],
            'cache_mode': 'extra_name',
            'expected_python': None,
            'expected_wlwl': {'unchanged': ['a.html', 'b.html'], 'modified': []},
            'agrees_with_python': None,
        },
        {
            'name': 'cache_wrong_value_type',
            'note': 'WLWL 专有：cache 的值不是 INTEGER ⇒ 判 modified'
                    '（Python 没有 DICT cache 这个形态）',
            'files': ['a.html', 'b.html'],
            'cache_mode': 'wrong_type',
            'expected_python': None,
            'expected_wlwl': {'unchanged': ['b.html'], 'modified': ['a.html']},
            'agrees_with_python': None,
        },
    ]


def build_defect_evidence(tmp_dirs):
    """把「判定目录不匹配」的缺陷**当场测出来**（不是从文档抄的）。"""
    d = new_tmp('tp_inc_ev_')
    tmp_dirs.append(d)
    put_file(d, 'a.html', T0)
    put_file(d, 'b.html', T0 + 1)
    cache_file = Path(d) / 'cache.txt'
    cache_file.write_text(build_cache_key(Path(d)), encoding='utf-8')
    key_before = cache_file.read_text().strip()

    # ① 改 a.html 的 mtime（内容确实变了）⇒ key 变
    put_file(d, 'a.html', T0 + 60)
    key_after = build_cache_key(Path(d))
    unchanged1, changed1 = get_unchanged_articles(
        [_Art('a.html'), _Art('b.html')], Path(d), cache_file=cache_file)

    # ② 新增文件 c.html ⇒ 仍判「全部未变」
    put_file(d, 'c.html', T0 + 120)
    unchanged2, changed2 = get_unchanged_articles(
        [_Art('a.html'), _Art('b.html'), _Art('c.html')], Path(d), cache_file=cache_file)

    if key_before == key_after:
        raise AssertionError('mtime 改了 key 却没变？')
    if changed1:
        raise AssertionError('缺陷已消失？预期 changed 为空，实际 %r'
                             % [a.file for a in changed1])
    return {
        'site': 'tinypage/core/incremental.py:207',
        'code': 'modified_files = get_modified_files(article_dir, article_dir)',
        'why': '把 article_dir 同时当 source 与 output ⇒ out 就是 src 自己 ⇒ '
               'src.st_mtime > out.st_mtime 恒假 ⇒ modified_files 恒空',
        'key_before': key_before,
        'key_after': key_after,
        'changed_after_mtime_edit': [a.file for a in changed1],
        'unchanged_after_mtime_edit': [a.file for a in unchanged1],
        'changed_after_new_file': [a.file for a in changed2],
        'unchanged_after_new_file': [a.file for a in unchanged2],
        'measured': True,
    }


def build_limitations(tmp_dirs):
    """**已知没做到**的口径（诚实登记；不是本卡的「故意差异」）。"""
    # 大小写交错时的排序差异：Python 按 lower 比较，DIR_ENTRIES 按码点
    d = new_tmp('tp_inc_lim_')
    tmp_dirs.append(d)
    put_file(d, 'B.html', T0)
    put_file(d, 'a.html', T0 + 1)
    globs = [p.name for p in Path(d).glob('*.html')]
    sorted_names = [p.name for p in sorted(Path(d).glob('*.html'))]
    return [{
        'name': 'case_interleaved_order',
        'what': '仅大小写不同的多个 .html 名字交错时（如 B.html 与 a.html），'
                'Python 的 sorted() 按 lower 比较 ⇒ [a.html, B.html]；'
                'WLWL 侧用 DIR_ENTRIES 的**码点序** ⇒ [B.html, a.html] ⇒ 两者的 key 不同',
        'python_sorted': sorted_names,
        'python_glob': globs,
        'python_key': build_cache_key(Path(d)),
        'not_tested': 'WLWL 侧未按 lower 重排（要做得多一遍带键的排序，'
                      '而 lower 相同的名字在 Python 侧本身按文件系统枚举序稳定排序 ⇒ '
                      '那一档本来不可复现）；其余名字集合（全小写 ASCII / 含 CJK）两侧一致',
    }, {
        'name': 'permission_denied_dir',
        'what': '目录不可读时 FILE_META / DIR_ENTRIES 返 ERR；Python 的 exists() 吞掉 OSError',
        'not_tested': '本机（Windows + 管理员）造不出稳定的权限失败 ⇒ 未实测；'
                      'WLWL 侧选择「FILE_META 是 ERR ⇒ 当作不存在 ⇒ "empty"」',
    }, {
        'name': 'glob_case_sensitivity',
        'what': 'Python 的 glob("*.html") 在本机**不匹配** A.HTML（大小写敏感，实测）',
        'not_tested': 'WLWL 侧按 PATH_EXT == "html" 精确比较 ⇒ 与实测口径同向；'
                      '若在大小写不敏感的文件系统上 Python 行为不同，本夹具不覆盖',
    }]


def main():
    tmp_dirs = []
    for d in [new_tmp('tp_inc_warm_')]:
        tmp_dirs.append(d)

    should = build_should_cases(tmp_dirs)
    cache_fixed = build_cache_fixed(tmp_dirs)
    cache_file_path = build_cache_file_instead_of_dir(tmp_dirs)
    trunc = build_cache_truncation(tmp_dirs)
    cache_runtime = build_cache_runtime(tmp_dirs)
    gu = build_gu_cases(tmp_dirs)
    gu.append(build_gu_partial(tmp_dirs))
    gu += build_gu_extra_cases()
    evidence = build_defect_evidence(tmp_dirs)
    limitations = build_limitations(tmp_dirs)

    data = {
        'schema': 1,
        'generated_by': 'tp/test/gen_incremental_baseline.py',
        'source': 'tinypage/core/incremental.py',
        'rules': {
            'should_use_incremental': 'article_count < threshold ⇒ FALSE；'
                                      'modified_ratio = modified_count / article_count '
                                      '（article_count == 0 时取 1.0）；'
                                      'ratio < 0.1（严格小于）⇒ TRUE；threshold 默认 100',
            'build_cache_key': 'sorted(glob("*.html")) 取 "name:int(st_mtime)"（秒级截断）'
                               '用 "|" 拼接 ⇒ sha256 hexdigest 前 12 位；'
                               '目录不存在 ⇒ "empty"',
            'get_unchanged': 'WLWL 口径：逐文件比 cache 里的秒级 mtime；'
                             'cache 缺失/不是 DICT ⇒ 全部 modified',
        },
        'should_use_incremental': should,
        'cache_key': {
            'fixed': cache_fixed,
            'file_instead_of_dir': cache_file_path,
            'truncation': trunc,
            'runtime': cache_runtime,
        },
        'get_unchanged': gu,
        'known_differences': [{
            'name': 'get_unchanged_fallback_dir_mismatch',
            'function': 'GET_UNCHANGED',
            'python_behaviour': 'cache 未命中时走 get_modified_files(article_dir, article_dir) '
                                '⇒ 恒空 ⇒ 全部判「未变」',
            'wlwl_behaviour': '不再与目录比较：逐文件比 cache 里记录的秒级 mtime；'
                              'cache 缺失/不是 DICT ⇒ 全部判 modified',
            'reason': 'Python 的兜底路径把同一目录既当源又当产物 ⇒ mtime 比较恒假 ⇒ '
                      '该重建的全被漏掉（新增文件也漏）。WLWL 侧改成「与 cache 比」，'
                      '缺失即视为已变 ⇒ 退化为全量重建（安全侧），而不是静默不重建。'
                      '判据仍是 mtime（秒级截断），**不引入内容 hash**',
            'evidence': evidence,
        }],
        'limitations': limitations,
    }

    text = json.dumps(data, ensure_ascii=False, indent=2) + '\n'
    text = guard_no_machine_paths(text, tmp_dirs)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    for d in tmp_dirs:
        shutil.rmtree(d, ignore_errors=True)
    n_fixed = len(cache_fixed)
    print('wrote %s (%d should_use cases, %d cache-key fixed, %d runtime, %d get_unchanged)'
          % (OUT, len(should), n_fixed, len(cache_runtime), len(gu)))
    print('  defect evidence: key %s -> %s, changed=%r'
          % (evidence['key_before'], evidence['key_after'],
             evidence['changed_after_mtime_edit']))


if __name__ == '__main__':
    main()
