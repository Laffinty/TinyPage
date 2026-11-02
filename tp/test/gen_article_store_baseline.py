"""生成 tp/test/fixtures/article_store_baseline.json —— 文章存储模块的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标**（全部**直接 import 真 Python 实现**，不重写规则）：

| 基准段 | 对齐的 Python 函数 | 位置 |
|---|---|---|
| `validate_filename` | `tinypage.security.validate_filename` | security.py:228 |
| `validate_title` | `tinypage.content.write_article` 的内联判定 | content.py:270 |
| `validate_content` | `tinypage.security.validate_content` | security.py:256 |
| `validate_date_format` | `tinypage.security.validate_date_format` | security.py:243 |
| `safe_path_check` | `tinypage.security.safe_path_check` | security.py:269 |
| `source_path` | `tinypage.core.article_store.source_path` | article_store.py:67 |
| `write_source` | `tinypage.core.article_store.write_source` | article_store.py:72 |
| `decode_content` | `tinypage.core.article_store.decode_content` | article_store.py:104 |
| `decode_legacy_body` | `tinypage.core.article_store.decode_legacy_body` | article_store.py:121 |
| `unescape_to_fixpoint` | `tinypage.core.article_store._unescape_to_fixpoint` | article_store.py:132 |
| `meta_value` | `tinypage.core.article_store.meta_value` | article_store.py:90 |

**唯一的「复刻」**：`validate_title`。Python 侧**没有独立函数** —— 规则内联在
`tinypage/content.py:270`（`if not isinstance(title, str) or len(title) > 200: raise`）。
本文件按该行逐字复刻，并在 `TITLE_RULE_SOURCE` 里标注出处。

**路径分隔符**：基准里路径一律用 `PurePosixPath` 渲染（Windows 上 `Path` 会渲染成
`\\`），保证夹具跨机器稳定；`source_path`/`safe_path_check` 调用的仍是**真函数**，
只是喂了 POSIX 风格的 Path 对象（`with_suffix` 语义与平台无关）。

**已知差异**（`want` ≠ `python` 的用例，必须带 `note`）：
  D1 `validate_filename` 接受尾随换行（Python `re` 的 `$` 语义）—— WLWL 侧
     `RE_TEST` 是整串锚定，不接受 ⇒ 两边**都接受**（WLWL 显式复刻了尾随 `\n`），
     故 **无差异**；真正的差异见下。
  D2 `validate_filename` 的 `\\d`：Python 的 `re` 匹配 Unicode 数字（`٢٠٢٦`），
     WLWL 的 `\d` 只认 ASCII ⇒ WLWL 拒绝，Python 接受。
  D3 `safe_path_check` 拒绝含 `..` 的输入（卡片 S2-1 路径安全要求，WLWL 侧
     **故意更严**）⇒ Python 允许 `sub/../ok.html`，WLWL 拒绝。
  D4 `validate_date_format` 的**年位置**：Python 的 `re` 的 `\d` 匹配 Unicode
     数字，且 `strptime` 的 `%Y` 用 `int()` 解析 ⇒ Python 接受 `٢٠٢٦-01-01 10:00`；
     WLWL 的 `TO_INT` 拒绝 Unicode 数字（返回 ERR）、`NFKC` 也不归一它
     ⇒ WLWL 侧**无法复刻** ⇒ WLWL 拒绝、Python 接受。
     （实测：WLWL `TO_INT("٢٠٢٦")` 返回 ERR；`NFKC("٢٠٢٦")` 原样不变。）

用法：python gen_article_store_baseline.py
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.security import (  # noqa: E402
    validate_filename, validate_date_format, validate_content, safe_path_check,
)
from tinypage.core.article_store import (  # noqa: E402
    source_path, write_source, meta_value, decode_content, decode_legacy_body,
    _unescape_to_fixpoint,
)

OUT = os.path.join(HERE, 'fixtures', 'article_store_baseline.json')

# ── 文件 IO 基准用的真函数（写文件） ───────────────────────────────
from pathlib import Path, PurePosixPath  # noqa: E402

TITLE_RULE_SOURCE = (
    '复刻自 tinypage/content.py:270 —— `if not isinstance(title, str) or '
    'len(title) > 200: raise ValueError(...)`（Python 侧无独立函数）'
)

# safe_path_check 的夹具布局（相对 base 目录）——两边必须一致
SAFE_PATH_FIXTURE = {
    'files': ['ok.html', 'bad.exe', 'sub/a.txt'],
    'dirs': ['sub'],
    'note': 'safe_path_check 的扩展名白名单分支依赖目标是否**真实存在**；'
            '故基准与测试用同一份相对布局。',
}


def validate_title_rule(title):
    """复刻 content.py:270 的标题长度判定（见 TITLE_RULE_SOURCE）。"""
    return isinstance(title, str) and len(title) <= 200


# ── 用例表 ────────────────────────────────────────────────────────
# 输入可以写成三种形态（生成器按形态分别渲染到 .wll）：
#   {'input': '字面量'}
#   {'repeat': {'unit': 'a', 'count': 50000}}
#   {'codepoints': [1, 2, 97]}

FILENAME_CASES = [
    '2026-01-01-x.html',
    '2026-01-01-中文.html',
    '2026-01-01-x-y.html',
    '2026-01-01--.html',
    '2026-01-01-.html',
    '2026-01-01-x.HTML',
    '2026-01-01-x_y.html',
    '2026-01-01-x h.html',
    '2026-01-01-x.md',
    '2026-01-01-x.html.md',
    '2100-12-31-x.html',
    '2000-01-01-x.html',
    '2101-01-01-x.html',
    '1999-12-31-x.html',
    '2026-00-01-x.html',
    '2026-13-01-x.html',
    '2026-01-00-x.html',
    '2026-01-32-x.html',
    '2026-02-31-x.html',
    '02026-01-01-x.html',
    '2026-1-01-x.html',
    '../etc/passwd',
    'pages-evil/x.html',
    '',
    '2026-01-01-x.html\n',
    '2026-01-01-中文-x.html',
    '2026-01-01-x-龥.html',      # 龥 = U+9FA5（CJK 区上界）
    '2026-01-01-x-龦.html',      # 龦 = U+9FA6（区间外）
    '2026-01-01-x-一.html',      # 一 = U+4E00（CJK 区下界）
    '2026-01-01-x-〇.html',      # 〇 = U+3007（区间外）
    '\u0662\u0660\u0662\u0666-01-01-x.html',   # 阿拉伯数字（Unicode \d）
]

TITLE_CASES = [
    {'input': ''},
    {'input': 'x'},
    {'repeat': {'unit': 'x', 'count': 199}},
    {'repeat': {'unit': 'x', 'count': 200}},
    {'repeat': {'unit': 'x', 'count': 201}},
    {'repeat': {'unit': '\u4e2d', 'count': 200}},
    {'repeat': {'unit': '\u4e2d', 'count': 201}},
]

CONTENT_CASES = [
    {'input': ''},
    {'input': 'hello'},
    {'repeat': {'unit': 'a', 'count': 50000}},
    {'repeat': {'unit': 'a', 'count': 50001}},
    {'repeat': {'unit': '\u4e2d', 'count': 16667}},
    {'repeat': {'unit': '\u4e2d', 'count': 16668}},
    {'repeat': {'unit': '\u4e2d', 'count': 50001}},
    {'codepoints': [97, 9, 98, 10, 99, 13]},               # \t \n \r 放行
    {'codepoints': [97] * 9 + [1]},                        # 恰好 10%
    {'codepoints': [97] * 9 + [1, 2]},                     # 超过 10%
    {'codepoints': [1] * 10},                              # 全是控制字符
    {'codepoints': [1] * 11},
    {'codepoints': [0] * 5 + [97] * 95},                  # NUL 也算控制字符
]

DATE_CASES = [
    '2026-01-01 10:00',
    '2026-12-31 23:59',
    '2000-01-01 00:00',
    '2100-12-31 23:59',
    '2101-01-01 00:00',
    '1999-12-31 23:59',
    '2026-02-30 10:00',
    '2026-02-29 10:00',
    '2024-02-29 10:00',
    '2000-02-29 10:00',
    '2100-02-29 10:00',
    '2026-00-01 10:00',
    '2026-13-01 10:00',
    '2026-01-00 10:00',
    '2026-01-32 10:00',
    '2026-04-31 10:00',
    '2026-01-01 24:00',
    '2026-01-01 10:60',
    '2026-01-01 10:00\n',
    '2026-1-01 10:00',
    '2026-01-01T10:00',
    '0000-01-01 00:00',
    '\u0662\u0660\u0662\u0666-01-01 10:00',
]

SAFE_PATH_CASES = [
    'ok.html',
    'sub/a.txt',
    'bad.exe',
    'missing.exe',
    'sub',
    '',
    '.',
    'ok.txt',
    'X.HTML',
    'dir/',
    'a//b',
    '../etc/passwd',
    '/../etc/passwd',
    '../pages-evil/x.html',
    '/../pages-evil/secret.txt',
    'sub/../ok.html',          # ← 已知差异 D3（Python 允许，WLWL 拒绝）
    '{BASE}/ok.html',          # 绝对路径（落在 base 内）
    '{BASE}/../pages-evil/x.html',   # 绝对路径（落在 base 外）
]

SOURCE_PATH_CASES = [
    'pages/article/2026-01-01-x.html',
    'x.html',
    'a.b.html',
    'foo.',
    'noext',
    'dir.with.dot/file.html',
    '.bashrc',
    'x.tar.gz',
    '2026-01-01-x.md',
]

WRITE_SOURCE_CASES = [
    {'html_path': '2026-01-01-x.html', 'content': 'body\r\nline2\n'},
    {'html_path': '2026-01-01-y.html', 'content': ''},
    {'html_path': '2026-01-01-z.html', 'content': '\u4e2d\u6587\n\u4e2d\u6587'},
    {'html_path': '2026-01-01-w.html', 'content': 'no trailing newline'},
]

DECODE_CASES = [
    '<!-- tinypage:markdown 5 -->\nhello',
    '<!-- tinypage:markdown 100 -->\nhello',
    '<!-- tinypage:markdown 5 -->\r\nhello',
    '<!-- tinypage:markdown 0 -->\n',
    '<!-- tinypage:markdown 3 -->\nabc',
    '<!-- tinypage:markdown 5 -->\nhello world',
    'no body',
    '',
    '<!-- markdown: hello -->',
    '<!--markdown:hello-->',
    '<!-- markdown: a --> tail <!-- markdown: b -->',
    '<!-- markdown: a &amp; b -->',
    '<!-- markdown: &amp;amp; -->',
    '<!--  markdown :  spaced  -->',
    '<!-- markdown: multi\nline -->',
    '<!-- markdown: no close',
    'x <!-- markdown: mid --> y',
    '<!-- markdown: -->',
    '<!-- markdown:&#x27;-->',
    '<!--markdown:x--><!-- markdown: y -->',
    '<!-- markdown: a--> b <!-- markdown: c -->',
    '<!-- tinypage:markdown 12 -->\nhello world!',
]

UNESCAPE_CASES = [
    '&amp;', '&amp;amp;', 'a &lt;b&gt;', '&quot;x&quot;', '&#39;', '&#x27;', '&apos;',
    '&nbsp;', '&copy;', '&hellip;', '&mdash;', '&ldquo;', '&notit;', '&unknown;',
    '&#65;&#x42;', '&#00065;', '&#x1F600;', '&#1114112;', '&#xZZ;', '&euro;',
    '&Chi;', '&reg;', '&trade;', '&bull;', '&deg;', '&times;', '&laquo;', '&middot;',
    '&dagger;', '&prime;', '&larr;', '&infin;', '&ne;', '&le;', '&gt;', '&frac12;',
    '&hearts;', '&spades;', '&alpha;', '&Omega;', '&sigma;', '&pound;', '&yen;',
    '&sect;', '&para;', '&micro;', '&plusmn;', '&divide;', '&not;', '&macr;', '&sup2;',
    '&frac14;', '&frac34;', '&iexcl;', '&iquest;', '&brvbar;', '&curren;', '&uml;',
    '&ordf;', '&ordm;', '&sbquo;', '&bdquo;', '&Dagger;', '&permil;', '&lsaquo;',
    '&rsaquo;', '&scaron;', '&Scaron;', '&Yuml;', '&fnof;', '&circ;', '&tilde;',
    '&Alpha;', '&beta;', '&zeta;', '&theta;', '&iota;', '&kappa;', '&lambda;', '&mu;',
    '&amp', '&lt', '&AMP;', '&amp;x', '&#38;', '&#x26;', 'plain', '',
    'a&amp;b&lt;c&quot;d&#39;e', '&amp;amp;amp;',
]

META_VALUE_CASES = [
    "T & 'x'",
    'a\n\n\nb',
    '  pad  ',
    '',
    '\u4e2d\u6587',
    'line1\nline2',
    'tab\there',
]


# ── 把输入形态展开成真字符串 ──────────────────────────────────────
def materialize(spec):
    if 'input' in spec:
        return spec['input']
    if 'repeat' in spec:
        r = spec['repeat']
        return r['unit'] * r['count']
    if 'codepoints' in spec:
        return ''.join(chr(c) for c in spec['codepoints'])
    raise ValueError('bad input spec: %r' % (spec,))


def main():
    cases = {}

    # ── validate_filename ─────────────────────────────────────────
    vf = {}
    for s in FILENAME_CASES:
        py = validate_filename(s)
        name = 'f%02d' % len(vf)
        vf[name] = {'input': s, 'python': py, 'want': py, 'note': None}
    # 已知差异 D2：Unicode 数字（Python 的 \d 匹配 Unicode）
    for name, case in vf.items():
        if case['input'].startswith('\u0662'):
            case['note'] = ('已知差异 D2：Python `re` 的 `\\d` 匹配 Unicode 数字'
                            '（`int()` 也能解析），WLWL 的 `\\d` 只认 ASCII '
                            '⇒ WLWL 拒绝、Python 接受。')
            case['want'] = False
    cases['validate_filename'] = vf

    # ── validate_title ───────────────────────────────────────────
    vt = {}
    for spec in TITLE_CASES:
        s = materialize(spec)
        py = validate_title_rule(s)
        name = 't%02d' % len(vt)
        vt[name] = {'input': spec, 'python': py, 'want': py, 'note': None}
    cases['validate_title'] = vt

    # ── validate_content ─────────────────────────────────────────
    vc = {}
    for spec in CONTENT_CASES:
        s = materialize(spec)
        py = validate_content(s)
        name = 'c%02d' % len(vc)
        vc[name] = {'input': spec, 'python': py, 'want': py, 'note': None}
    cases['validate_content'] = vc

    # ── validate_date_format ─────────────────────────────────────
    vd = {}
    for s in DATE_CASES:
        py = validate_date_format(s)
        name = 'd%02d' % len(vd)
        case = {'input': s, 'python': py, 'want': py, 'note': None}
        # D4：Python 的 `re` 的 `\d` 匹配 Unicode 数字，且 `strptime` 的 `%Y`
        #     用 `int()` 解析 ⇒ **年位置接受 Unicode 数字**
        #     （实测 '٢٠٢٦-01-01 10:00' 在 Python 侧为真）。
        #     WLWL 的 `TO_INT` 拒绝 Unicode 数字（返回 ERR）、`NFKC` 也不归一它
        #     ⇒ WLWL 侧**无法复刻** ⇒ 登记为差异（WLWL 拒绝、Python 接受）。
        if py and s[:4] and not all(ch in '0123456789' for ch in s[:4]):
            case['want'] = False
            case['note'] = (
                '已知差异 D4：Python 的 `re` 的 `\\d` 匹配 Unicode 数字，'
                '且 `strptime` 的 `%Y` 用 `int()` 解析 ⇒ **年位置接受 Unicode 数字**；'
                'WLWL 的 `TO_INT` 拒绝 Unicode 数字（返回 ERR）、`NFKC` 也不归一它 '
                '⇒ WLWL 侧无法复刻 ⇒ WLWL 拒绝、Python 接受。')
        vd[name] = case
    cases['validate_date_format'] = vd

    # ── safe_path_check（需要真实目录 ⇒ 用夹具建出来） ─────────────
    sp = {}
    with tempfile.TemporaryDirectory() as _td:
        # ⚠ 必须先把临时目录归一到**规范长路径**再往下算。
        # gettempdir() 在 GitHub Windows runner 上返回 8.3 短名
        # （实测 `C:\Users\RUNNER~1\AppData\Local\Temp\tmpXXXX`），而
        # safe_path_check 内部的 resolve() 返回长名（`runneradmin`）⇒
        # relpath(长, 短) 会算出 `..\..\..\runneradmin\AppData\...` 这种
        # **机器相关**的相对路径，让夹具在本机与 CI 之间漂移
        # （wf run #6 实测：本机生成 → CI 重生成，该 JSON 差 23 行）。
        # realpath 走 GetFinalPathNameByHandle，在同一个卷上给出与
        # resolve() 同形的规范路径，两边于是可比。
        td = os.path.realpath(_td)
        base = os.path.join(td, 'pages')
        os.makedirs(base)
        for rel in SAFE_PATH_FIXTURE['files']:
            full = os.path.join(base, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'w', encoding='utf-8') as f:
                f.write('x')
        for rel in SAFE_PATH_FIXTURE['dirs']:
            os.makedirs(os.path.join(base, rel), exist_ok=True)
        # 兄弟目录（用于 pages-evil 前缀绕过用例）
        os.makedirs(os.path.join(td, 'pages-evil'), exist_ok=True)

        for s in SAFE_PATH_CASES:
            probe = s.replace('{BASE}', base.replace(os.sep, '/'))
            ok, target = safe_path_check(probe, Path(base))
            rel_out = None
            if ok and target is not None:
                rel_out = os.path.relpath(str(target), str(base)).replace(os.sep, '/')
                # 守卫：rel 若能跳出 base，说明 base 与 resolve() 的路径形态仍不一致
                # （典型原因就是上面的 8.3 短名没被 realpath 归一）⇒ 此时写进夹具的
                # 期望值必然是机器相关的。宁可在生成阶段炸掉，也不要让它悄悄漂移到 CI。
                if rel_out == '..' or rel_out.startswith('../'):
                    raise RuntimeError(
                        'safe_path_check 基准夹具出现机器相关路径：input=%r rel=%r\n'
                        'base=%r\ntarget=%r\n'
                        'base 与 resolve() 的形态不一致（多半是 8.3 短名）⇒ '
                        '先把它归一到规范长路径再生成。'
                        % (s, rel_out, base, str(target)))
            py = {'ok': bool(ok), 'rel': rel_out}
            name = 'p%02d' % len(sp)
            entry = {'input': s, 'python': py, 'want': dict(py), 'note': None}
            if s == 'sub/../ok.html':
                entry['want'] = {'ok': False, 'rel': None}
                entry['note'] = ('已知差异 D3：卡片 S2-1 要求「拒绝路径中含 `..` 的输入」'
                                 '（WLWL 的 PATH_CANONICAL 是词法判定、不解析符号链接）'
                                 '⇒ WLWL 拒绝、Python 允许（Python 的 resolve() 会消解 `..`）。')
            sp[name] = entry
    cases['safe_path_check'] = sp

    # ── source_path ──────────────────────────────────────────────
    sx = {}
    for s in SOURCE_PATH_CASES:
        py = str(source_path(PurePosixPath(s)))
        name = 's%02d' % len(sx)
        sx[name] = {'input': s, 'python': py, 'want': py, 'note': None}
    cases['source_path'] = sx

    # ── write_source（真函数写文件 ⇒ 期望值 = 落盘字节） ──────────
    ws = {}
    with tempfile.TemporaryDirectory() as td:
        for spec in WRITE_SOURCE_CASES:
            html_path = os.path.join(td, spec['html_path'])
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write('old')
            written = write_source(Path(html_path), spec['content'])
            with open(written, 'rb') as f:
                raw = f.read()
            py = {'md_name': os.path.basename(str(written)),
                  'content': raw.decode('utf-8')}
            name = 'w%02d' % len(ws)
            ws[name] = {'input': spec, 'python': py, 'want': dict(py), 'note': None}
    cases['write_source'] = ws

    # ── decode_content / decode_legacy_body / unescape_to_fixpoint ─
    dc = {}
    for s in DECODE_CASES:
        py = decode_content(s)
        name = 'c%02d' % len(dc)
        dc[name] = {'input': s, 'python': py, 'want': py, 'note': None}
    cases['decode_content'] = dc

    dl = {}
    for s in DECODE_CASES:
        py = decode_legacy_body(s)
        name = 'l%02d' % len(dl)
        dl[name] = {'input': s, 'python': py, 'want': py, 'note': None}
    cases['decode_legacy_body'] = dl

    ue = {}
    for s in UNESCAPE_CASES:
        py = _unescape_to_fixpoint(s)
        name = 'u%02d' % len(ue)
        ue[name] = {'input': s, 'python': py, 'want': py, 'note': None}
    cases['unescape_to_fixpoint'] = ue

    mv = {}
    for s in META_VALUE_CASES:
        py = meta_value(s)
        name = 'm%02d' % len(mv)
        mv[name] = {'input': s, 'python': py, 'want': py, 'note': None}
    cases['meta_value'] = mv

    # ── 自检：python 与 want 一致 ⇔ 无 note ────────────────────────
    for group, entries in cases.items():
        for name, entry in entries.items():
            same = entry['python'] == entry['want']
            if same and entry['note']:
                raise SystemExit(
                    '%s/%s: note 存在但 python==want（应删 note）' % (group, name))
            if not same and not entry['note']:
                raise SystemExit(
                    '%s/%s: python!=want 但缺 note（必须登记已知差异）'
                    % (group, name))

    doc = {
        '_meta': {
            'generated_by': 'tp/test/gen_article_store_baseline.py',
            'python_functions': {
                'validate_filename': 'tinypage.security.validate_filename (security.py:228)',
                'validate_title': TITLE_RULE_SOURCE,
                'validate_content': 'tinypage.security.validate_content (security.py:256)',
                'validate_date_format': 'tinypage.security.validate_date_format (security.py:243)',
                'safe_path_check': 'tinypage.security.safe_path_check (security.py:269)',
                'source_path': 'tinypage.core.article_store.source_path (article_store.py:67)',
                'write_source': 'tinypage.core.article_store.write_source (article_store.py:72)',
                'decode_content': 'tinypage.core.article_store.decode_content (article_store.py:104)',
                'decode_legacy_body': 'tinypage.core.article_store.decode_legacy_body (article_store.py:121)',
                'unescape_to_fixpoint': 'tinypage.core.article_store._unescape_to_fixpoint (article_store.py:132)',
                'meta_value': 'tinypage.core.article_store.meta_value (article_store.py:90)',
            },
            'safe_path_fixture': SAFE_PATH_FIXTURE,
            'known_difference_count': sum(
                1 for entries in cases.values() for e in entries.values()
                if e['note']),
        },
        'cases': cases,
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    n_diff = doc['_meta']['known_difference_count']
    total = sum(len(e) for e in cases.values())
    print('wrote %s (%d cases, %d known differences)'
          % (OUT, total, n_diff))


if __name__ == '__main__':
    main()
