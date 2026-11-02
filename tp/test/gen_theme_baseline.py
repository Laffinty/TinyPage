"""生成 tp/test/fixtures/theme_baseline.json —— 主题模块的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标**（全部**直接 import 真 Python 实现**，不重写规则）：

| 基准段 | 对齐的 Python 函数 | 位置 |
|---|---|---|
| `validate_theme_name` | **无对应**（Python 不做校验）⇒ 见 D5 | — |
| `load_theme_css` | `tinypage.generator.load_theme_css` | generator.py:134 |
| `load_theme_manifest` | `tinypage.core.template.load_theme_manifest` | template.py:133 |
| `list_themes` | `tinypage.core.template.list_themes` | template.py:144 |

**`validate_theme_name` 的 `python` 列为何一律 `true`**：Python 侧没有这个函数，
`themes_dir / name / "manifest.json"` 对任何字符串都**不抛异常**（连 `""` 也合法，
它退化成 `themes_dir/manifest.json`）⇒ 「Python 不做校验」最忠实的记法就是
`python=true`。`want` 才是 WLWL 的（更严的）契约 ⇒ 被拒的用例必然 `python!=want`，
按 D5 登记 note。

**需要真实文件系统的三组**（`load_theme_css` / `load_theme_manifest` / `list_themes`）：
`input` 是**一棵相对布局**（`root` / `dirs` / `files`，全部 POSIX 相对路径），
所有路径都相对「本用例自己的临时根」——
  · **本文件**在 `tempfile.mkdtemp()` 里真造出这棵树，再调**真 Python 函数**取期望值；
  · **生成测试的 `gen_test_theme.py`** 用**同一份 spec** 在 `TEMP_DIR()` 里重建。
⇒ 夹具里**不含任何临时目录绝对路径**，跨机器/跨运行可复现。

**Pygments 占位（D7 的记录方式，务必读）**：
Python 的 `load_theme_css` 会在 `base_css` 后追加
`"\n/* Pygments syntax highlighting */\n" + pygments_css`。
Pygments 是**可选依赖**（`pyproject.toml` 的 `syntax` extra），样式表内容随其版本变化，
把它整段写进夹具会让夹具随环境漂移（CI 第 3 步「重生成后 git diff 为空」会红）。
⇒ 本文件的记法：
  · `want["css"]`   = **去掉**追加段后的内容（= WLWL 的返回值）；
  · `python["css"]` = 同上内容 + 标记行 + **字面占位** `<PYGMENTS_CSS>`。
    即 Python 的真实输出，只把「版本相关的那部分」换成显式占位标记。
生成时若 Pygments **确实可用**，会先校验真实输出与「去追加段」能精确对上
（`endswith` + 标记行都在），对不上直接 `SystemExit` —— 绝不悄悄算错。

**已知差异**（`want` ≠ `python` 的用例必须带 `note`）：
  · **D5** 主题名校验：Python 不校验 ⇒ WLWL 拒、Python 放行。
    （`load_theme_manifest` 的 `../etc` 用例是 D5 的**实证**：
    Python 真读到了 themes 目录外的 `etc/manifest.json`。）
  · **D7** `load_theme_css`：Python 追加 Pygments、WLWL 不追加。
  · **D6** `list_themes` 顺序：Python 用 `iterdir()`，顺序随文件系统变化、
    **不可复现** ⇒ 本夹具把 Python 侧结果**按名称排序后**登记（`want` 也是名称升序）。
    故本组 `python == want`，D6 由 note（逐例）+ `_meta.known_differences` 登记，
    不制造一个会随文件系统漂移的 `python` 值。
    ⚠ 因此本文件的「有 note ⇒ python!=want」自检只在**除 list_themes 外**严格成立，
    `list_themes` 的 note 属显式声明的例外（生成时会打印出来）。

用法：python gen_theme_baseline.py
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from pathlib import Path  # noqa: E402

from tinypage.generator import load_theme_css  # noqa: E402
from tinypage.core.template import (  # noqa: E402
    load_theme_manifest, list_themes,
)

OUT = os.path.join(HERE, 'fixtures', 'theme_baseline.json')

# ── D7：Pygments 追加段的记录方式 ────────────────────────────────────
PYG_MARK = '\n/* Pygments syntax highlighting */\n'   # generator.py 里的原样常量
PYG_PLACEHOLDER = '<PYGMENTS_CSS>'


def _pygments_css():
    """已安装的 Pygments 样式表；不可用（可选依赖）⇒ ""。"""
    try:
        from tinypage.parsers.syntax import has_syntax_highlighting, get_pygments_css
    except Exception:          # pragma: no cover - 依赖缺失
        return ''
    if not has_syntax_highlighting():
        return ''
    return get_pygments_css() or ''


def strip_pygments(base_css):
    """去掉 `load_theme_css` 追加的 Pygments 段，得到 WLWL 侧的期望值。"""
    py = _pygments_css()
    if not py:
        # Pygments 未安装 ⇒ Python 侧本来就没追加
        return base_css
    if not base_css.endswith(py) or PYG_MARK not in base_css:
        raise SystemExit(
            'load_theme_css 的追加段形态与预期不符（generator.py 改过？）\n'
            '  base_css 尾部=%r\n  期望尾部=%r'
            % (base_css[-120:], (PYG_MARK + py)[:120]))
    return base_css[:len(base_css) - len(py) - len(PYG_MARK)]


# ── 用例表 ────────────────────────────────────────────────────────
# 单字符串组：validate_theme_name
THEME_NAME_CASES = [
    # 合法
    'default',
    'my-theme',
    '主题',
    'theme_2',
    'Dark',
    # 非法（D5：WLWL 新增的校验）
    '',
    '.',
    '..',
    '../etc',
    'a/b',
    'a\\b',
    'a..b',
    '...',
    'themes/..',
]

# 需要真实文件系统的三组：input 是**相对布局**
CSS_CASES = [
    ('c00', {'dirs': ['themes/t'],
             'files': {'themes/t/theme.css': 'body{color:red}\n',
                       'themes/t/theme.dark.css': 'body{color:#fff}\n'}}),
    ('c01', {'dirs': ['themes/t'],
             'files': {'themes/t/theme.css': 'a{color:blue}\n'}}),
    ('c02', {'dirs': ['themes/t'],
             'files': {'themes/t/theme.dark.css': 'b{color:#000}\n'}}),
    ('c03', {'dirs': ['themes/t'], 'files': {}}),
    # CRLF 文件：Python 的 read_text() 归一成 LF（坑 23）
    ('c04', {'dirs': ['themes/t'],
             'files': {'themes/t/theme.css': 'a\r\nb\r\n',
                       'themes/t/theme.dark.css': 'c\r\nd\r\n'}}),
    # 孤立 CR：通用换行的**第二条**规则（只替 CRLF 会算错）
    ('c05', {'dirs': ['themes/t'],
             'files': {'themes/t/theme.css': 'a\rb\rc'}}),
    # 文件存在但为空 ⇒ ""、has_dark FALSE
    ('c06', {'dirs': ['themes/t'],
             'files': {'themes/t/theme.css': '',
                       'themes/t/theme.dark.css': ''}}),
    # 空行 + 多行 CSS（确认归一不影响正文）
    ('c07', {'dirs': ['themes/t'],
             'files': {'themes/t/theme.css': 'a{}\n\nb{}\n'}}),
]

MANIFEST_CASES = [
    ('m00', {'root': 'themes', 'theme': 'alpha',
             'dirs': ['themes/alpha'],
             'files': {'themes/alpha/manifest.json': json.dumps(
                 {'name': 'Alpha Theme', 'description': 'desc',
                  'layouts': ['blog', 'doc'], 'default_layout': 'doc'},
                 ensure_ascii=False)}}),
    ('m01', {'root': 'themes', 'theme': 'alpha',
             'dirs': ['themes/alpha'], 'files': {}}),
    ('m02', {'root': 'themes', 'theme': 'alpha',
             'dirs': ['themes/alpha'],
             'files': {'themes/alpha/manifest.json': '{"name": '}}),
    ('m03', {'root': 'themes', 'theme': 'alpha',
             'dirs': ['themes/alpha'],
             'files': {'themes/alpha/manifest.json': ''}}),
    ('m04', {'root': 'themes', 'theme': 'alpha',
             'dirs': ['themes/alpha'],
             'files': {'themes/alpha/manifest.json': 'null'}}),
    # D5 实证：Python 真读到了 themes 之外的文件
    ('m05', {'root': 'themes', 'theme': '../etc',
             'dirs': ['themes/alpha'],
             'files': {'etc/manifest.json': '{"name": "evil"}'}}),
    # manifest.json 是**目录** ⇒ Python 的 is_file() 为假
    ('m06', {'root': 'themes', 'theme': 'alpha',
             'dirs': ['themes/alpha/manifest.json'],
             'files': {}}),
]

LIST_CASES = [
    # 正常：三个主题（全清单 / 只有 name / 无清单）+ 一个游离文件
    ('t00', {'root': 'themes',
             'dirs': ['themes/alpha', 'themes/beta', 'themes/zeta'],
             'files': {
                 'themes/alpha/manifest.json': json.dumps(
                     {'name': 'Alpha', 'description': 'A theme',
                      'layouts': ['blog', 'doc'], 'default_layout': 'doc'},
                     ensure_ascii=False),
                 'themes/beta/manifest.json': '{"name": "Beta"}',
                 'themes/stray.txt': 'not a theme',
             }}),
    # themes_dir 是**文件**
    ('t01', {'root': 'themes', 'dirs': [],
             'files': {'themes': 'i am a file'}}),
    # 空目录
    ('t02', {'root': 'themes', 'dirs': ['themes'], 'files': {}}),
    # 目录不存在
    ('t03', {'root': 'themes', 'dirs': [], 'files': {}}),
]


def build_tree(root, spec):
    """按 spec 在 root 下真造目录与文件（字节级：不做换行转换）。"""
    for rel in spec.get('dirs', []):
        os.makedirs(os.path.join(root, rel), exist_ok=True)
    for rel, content in spec.get('files', {}).items():
        full = os.path.join(root, rel)
        parent = os.path.dirname(full)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(full, 'wb') as f:
            f.write(content.encode('utf-8'))


def main():
    cases = {}

    # ── validate_theme_name ───────────────────────────────────────
    vn = {}
    for s in THEME_NAME_CASES:
        valid_py = True          # Python 侧不做校验（见模块 docstring）
        # WLWL 的契约（与 gen_theme.py 的 VALIDATE_THEME_NAME 逐条对应）
        want = (s != ''
                and s != '.'
                and s != '..'
                and '/' not in s
                and '\\' not in s
                and '..' not in s)
        note = None
        if want != valid_py:
            note = ('已知差异 D5：Python **没有**主题名校验（它直接 '
                    '`themes_dir / name / "manifest.json"`）⇒ WLWL **故意更严**。')
        vn['n%02d' % len(vn)] = {'input': s, 'python': valid_py,
                                 'want': want, 'note': note}
    cases['validate_theme_name'] = vn

    # ── load_theme_css ───────────────────────────────────────────
    cc = {}
    tmp = tempfile.mkdtemp(prefix='theme_css_')
    try:
        for cid, spec in CSS_CASES:
            root = os.path.join(tmp, cid)
            os.makedirs(root)
            build_tree(root, spec)
            base_css, dark_css, has_dark = load_theme_css(
                Path(root) / 'themes' / 't')
            orig = strip_pygments(base_css)
            want = {'css': orig, 'dark_css': dark_css, 'has_dark': bool(has_dark)}
            py = {'css': orig + PYG_MARK + PYG_PLACEHOLDER,
                  'dark_css': dark_css, 'has_dark': bool(has_dark)}
            cc[cid] = {
                'input': {'root': 'themes/t', 'dirs': spec['dirs'],
                          'files': spec['files']},
                'python': py,
                'want': want,
                'note': ('已知差异 D7：Python 在 `base_css` 后追加 '
                         '`"\\n/* Pygments syntax highlighting */\\n" + '
                         'pygments_css`（本夹具用 `<PYGMENTS_CSS>` 占位该段），'
                         'WLWL **不追加**（业主裁决：代码高亮改前端 highlight.js）。'),
            }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    cases['load_theme_css'] = cc

    # ── load_theme_manifest ──────────────────────────────────────
    mm = {}
    tmp = tempfile.mkdtemp(prefix='theme_manifest_')
    try:
        for cid, spec in MANIFEST_CASES:
            root = os.path.join(tmp, cid)
            os.makedirs(root)
            build_tree(root, spec)
            py = load_theme_manifest(spec['theme'], Path(root) / spec['root'])
            want = py
            note = None
            if spec['theme'] == '../etc':
                # D5 实证：WLWL 直接 NULL；Python 读到了 themes 目录外的清单
                want = None
                note = ('已知差异 D5：Python 没有主题名校验 ⇒ `"../etc"` 真的拼出 '
                        '`themes/../etc/manifest.json` 并把内容读了出来；'
                        'WLWL 先做 VALIDATE_THEME_NAME ⇒ 直接 NULL。')
            mm[cid] = {
                'input': {'root': spec['root'], 'theme': spec['theme'],
                          'dirs': spec['dirs'], 'files': spec['files']},
                'python': py, 'want': want, 'note': note,
            }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    cases['load_theme_manifest'] = mm

    # ── list_themes ──────────────────────────────────────────────
    tt = {}
    tmp = tempfile.mkdtemp(prefix='theme_list_')
    try:
        for cid, spec in LIST_CASES:
            root = os.path.join(tmp, cid)
            os.makedirs(root)
            build_tree(root, spec)
            raw = list_themes(Path(root) / spec['root'])
            # ⚠ D6：Python 的 iterdir() 顺序不可复现 ⇒ **按名称排序后**登记
            py = sorted(raw, key=lambda d: d['name'])
            tt[cid] = {
                'input': {'root': spec['root'], 'dirs': spec['dirs'],
                          'files': spec['files']},
                'python': py,
                'want': [dict(d) for d in py],
                'note': ('已知差异 D6（本组固定带 note）：Python 用 `iterdir()` 顺序 '
                         '（随文件系统变化：NTFS 近似名称序、ext4 是哈希序）⇒ **不可复现**，'
                         '故 `python` 列已**按名称排序后**登记；WLWL 固定**目录名升序**。'),
            }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    cases['list_themes'] = tt

    # ── 自检 ───────────────────────────────────────────────────────
    # differ ⇒ 必须带 note；带 note 但 python==want 只允许出现在 list_themes（D6 声明）。
    for group, entries in cases.items():
        for name, entry in entries.items():
            same = entry['python'] == entry['want']
            if not same and not entry['note']:
                raise SystemExit(
                    '%s/%s: python!=want 但缺 note（必须登记已知差异）'
                    % (group, name))
            if same and entry['note'] and group != 'list_themes':
                raise SystemExit(
                    '%s/%s: note 存在但 python==want（应删 note）' % (group, name))
            if same and entry['note']:
                print('note on equal case (declared D6 exception): %s/%s'
                      % (group, name))

    doc = {
        '_meta': {
            'generated_by': 'tp/test/gen_theme_baseline.py',
            'python_functions': {
                'validate_theme_name': '**无对应** —— Python 不做主题名校验（D5）',
                'load_theme_css': 'tinypage.generator.load_theme_css (generator.py:134)',
                'load_theme_manifest':
                    'tinypage.core.template.load_theme_manifest (template.py:133)',
                'list_themes': 'tinypage.core.template.list_themes (template.py:144)',
            },
            'known_differences': {
                'D5': '主题名校验：Python 没有 ⇒ WLWL 故意更严'
                      '（"../etc" / "" / "." / ".." / 含 "/" 或 "\\" 或 ".." 直接拒）。',
                'D6': 'LIST_THEMES 顺序：WLWL 固定目录名升序；Python 用 iterdir() 顺序'
                      '（不可复现）⇒ 本夹具的 python 列已按名称排序后登记。',
                'D7': 'LOAD_THEME_CSS：Python 追加 Pygments CSS，WLWL 不追加'
                      '（业主裁决：高亮改前端 highlight.js）；'
                      'python 列用字面占位 <PYGMENTS_CSS> 表示被省略的那一段。',
            },
            'fixture_rule': '需要真实文件系统的三组（load_theme_css / '
                            'load_theme_manifest / list_themes）：input 是一棵**相对布局**'
                            '（root / dirs / files，POSIX 相对路径，相对本用例自己的临时根）；'
                            '基线在 mkdtemp 里真造，测试在 TEMP_DIR() 里用同一份 spec 重建'
                            '⇒ 夹具不含绝对路径。',
            'files_are_bytes': 'files 的值是**字面内容**，生成器按 UTF-8 **字节**写入'
                               '（不做换行转换），否则 CRLF 用例测不到东西。',
            'pygments_placeholder': PYG_PLACEHOLDER,
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
    total = sum(len(e) for e in cases.values())
    print('wrote %s (%d cases, %d noted differences)'
          % (OUT, total, doc['_meta']['known_difference_count']))


if __name__ == '__main__':
    main()
