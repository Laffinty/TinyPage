"""生成 tp/test/fixtures/template_baseline.json —— 模板模块的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标（全部**直接 import 真 Python 实现**，不照抄规则）**：

| 基准段 | 对齐的 Python 实现 |
|---|---|
| `substitute` | `string.Template(tmpl).substitute(mapping)`（CPython `Lib/string.py`） |
| `safe_substitute` | `string.Template(tmpl).safe_substitute(mapping)`（CPython `Lib/string.py`） |
| `render_skeleton` | `tinypage.core.template.render_skeleton`（core/template.py:52） |

⚠ **不许**把 `string.Template` 的规则在这里重写一遍当基准 —— 照抄的基准只是
「我的第二种读法」，与 WLWL 实现同错就失去对照意义。这里一律**调用真方法**。

**`ERR` 载荷的期望形状**（本模块自己的约定，与 WLWL 侧的构造逐键对齐）：
  · 缺键      ⇒ `{"kind": "KeyError", "key": <缺失的键名>}`
  · 非法占位符 ⇒ `{"kind": "ValueError", "what": "invalid_placeholder", "pos": <`$` 的码点下标>}`

  Python 侧抛的是**异常**，所以这里把异常**翻译成同一形状**再落盘：
    - `KeyError(k)` 的 `k` 取自 `e.args[0]`（CPython 在 `convert()` 里用
      `mapping[named]` 触发，参数就是那个键名）。
    - `ValueError` 的 `pos` 由 CPython 的消息
      `Invalid placeholder in string: line L, col C` **反推**成绝对码点下标
      （CPython `_invalid()` 的 colno 是**行内 1 基**列号）。反推公式是
      `sum(len(l) for l in tmpl.splitlines(keepends=True)[:L-1]) + C - 1`，
      并且**逐条自检** `tmpl[pos] == '$'` —— 反推出错就直接炸掉生成器，
      不让错误期望值悄悄落盘。

**已知差异**：本模块的语义**应当**与 Python 完全一致（`string.Template` 的行为
可以逐字节复刻），所以这里预期 `python == want`、`note` 全为 `null`。若实测撞到
WLWL 无法复刻的形态，**在本文件里显式改写 `want` 并写 `note`**，不要放宽断言。

**漂移守卫**：本文件断言 `gen_template.SKELETON == tinypage.core.template._PAGE_SKELETON`
—— 页面骨架抄错/上游改了骨架，生成期立刻炸。

用法：python gen_template_baseline.py
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, HERE)

from string import Template  # noqa: E402

from tinypage.core.template import render_skeleton, _PAGE_SKELETON  # noqa: E402

from gen_template import SKELETON  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'template_baseline.json')

ERR_SHAPE = {
    'key_error': {'kind': 'KeyError', 'key': '<缺失的键名>'},
    'invalid_placeholder': {
        'kind': 'ValueError',
        'what': 'invalid_placeholder',
        'pos': '<`$` 的码点下标（0 基）>',
    },
}

# ── 用例表 ────────────────────────────────────────────────────────
# (模板串, mapping)。⚠ 每个单元都在 Python 侧**真跑**，不靠人脑推。
SUBSTITUTE_CASES = [
    # ── 没有占位符 / 空串 ────────────────────────────────────────
    ('hello world', {}),
    ('', {}),
    # ── 裸形态 `$var` ────────────────────────────────────────────
    ('$a', {'a': 'X'}),
    ('a $a b', {'a': 'X'}),
    ('$a$b', {'a': 'X', 'b': 'Y'}),
    ('$a$a', {'a': 'X'}),
    ('$a1', {'a1': 'one'}),
    ('$a_1', {'a_1': 'under'}),
    ('$_a', {'_a': 'us'}),
    ('$_', {'_': 'u'}),
    ('$_1', {'_1': 'u1'}),
    ('$A', {'A': 'up'}),
    ('$aB', {'aB': 'mixed'}),
    ('$a-b', {'a': 'X'}),
    ('$a.b', {'a': 'X'}),
    ('$a}', {'a': 'X'}),
    ('中文$var中文', {'var': 'V'}),
    # ── 花括号形态 `${var}` ──────────────────────────────────────
    ('${a}', {'a': 'X'}),
    ('$a${b}', {'a': 'X', 'b': 'Y'}),
    ('${a}${b}', {'a': 'X', 'b': 'Y'}),
    ('${_}', {'_': 'u'}),
    ('${A}', {'A': 'up'}),
    ('${A_b1}', {'A_b1': 'z'}),
    ('${a}x', {'a': 'X'}),
    ('${a}{b}', {'a': 'X'}),
    ('x${a}y$b', {'a': '1', 'b': '2'}),
    ('$a${a}', {'a': 'X'}),
    # ── 转义 `$$` ────────────────────────────────────────────────
    ('$$', {}),
    ('$$a', {'a': 'X'}),
    ('a$$b', {'a': 'X'}),
    ('$$$a', {'a': 'X'}),
    ('$$$$', {}),
    ('$$${a}', {'a': 'X'}),
    ('$${', {'a': 'X'}),
    # ── 非法占位符 ⇒ ValueError ──────────────────────────────────
    ('$1x', {}),
    ('$-', {}),
    ('$ ', {}),
    ('$\t', {}),
    ('$(x)', {}),
    ('${}', {'a': 'X'}),
    ('${a b}', {'a': 'X'}),
    ('${a', {'a': 'X'}),
    ('a${b', {}),
    ('$', {}),
    ('x$', {}),
    ('ab$1x', {}),
    ('$b$1', {}),
    ('cost $5.00', {}),
    ('$中文', {}),
    ('$é', {}),
    ('$$$', {}),
    ('$a$', {'a': 'X'}),
    ('${a}$', {'a': 'X'}),
    ('$ a', {}),
    # ── 缺键 ⇒ KeyError ─────────────────────────────────────────
    ('$zz', {'a': 'X'}),
    ('${missing}', {}),
    ('$b', {'a': 'X'}),
    ('$aa', {'a': 'A'}),
    ('pre $nope mid $also_nope', {}),
    # ── 值本身含 `$` ⇒ **不**重扫 ───────────────────────────────
    ('$a', {'a': '$b'}),
    ('$a', {'a': '${b}'}),
    ('${a}$a', {'a': '$$'}),
    # ── mapping 的值**不是**字符串 ───────────────────────────────
    # Python 的 convert() 是 `str(mapping[named])` ⇒ 会强制转串。
    # WLWL 侧用 `STR(...)` 对齐；整数/浮点的渲染两边逐字相同，
    # NULL / 布尔 / 容器的渲染口径不同 ⇒ 那几条**显式登记差异**（见 want + note）。
    ('$a', {'a': 42}),
    ('$a', {'a': -7}),
    ('$a', {'a': 1.5}),
    ('$a', {'a': ''}),
    {'tmpl': '$a', 'mapping': {'a': None}, 'want': 'NULL',
     'note': ('已知差异（值类型渲染）：Python 的 `str(None)` 是 "None"，'
              'WLWL 的 `STR(NULL)` 渲染成 "NULL" ⇒ 文本不同。'
              '根因：`str()` 的容器/空值渲染是**宿主语言**的口径，'
              '与 `string.Template` 的语义无关，WLWL 侧无法逐字复刻。')},
    {'tmpl': '$a', 'mapping': {'a': True}, 'want': 'TRUE',
     'note': ('已知差异（值类型渲染）：Python 的 `str(True)` 是 "True"，'
              'WLWL 的 `STR(TRUE)` 是 "TRUE"（布尔的字面量口径不同）。')},
    {'tmpl': '$a', 'mapping': {'a': {'k': 1}}, 'want': '[k: 1]',
     'note': ('已知差异（值类型渲染）：Python 的 `str({"k": 1})` 是 "{\'k\': 1}"，'
              'WLWL 的 `STR(字典)` 是 "[k: 1]"（字典的渲染语法不同）。')},
]

# render_skeleton 的用例：{'page_type': …, 'opts': {…}}
# 前 5 个参数（site_title / page_title / description / body_content / theme_css）
# 在 Python 侧**必填** ⇒ 每个用例都带上；其余走缺省值。
_BASE = {
    'site_title': 'Site',
    'page_title': 'Page',
    'description': 'Desc',
    'body_content': '<p>body</p>',
    'theme_css': 'body{margin:0}',
}

RENDER_CASES = [
    ('r00/minimal', 'article', dict(_BASE)),
    ('r01/dark_css', 'article', dict(_BASE, dark_css='a{color:#000}')),
    ('r02/dark_css_empty', 'article', dict(_BASE, dark_css='')),
    ('r03/dark_css_quote', 'article', dict(_BASE, dark_css='a::after{content:"x"}')),
    ('r04/all_opts', 'list', dict(
        _BASE,
        dark_css='a{color:#111}',
        has_dark=True,
        nav_links='<a href="/">home</a>',
        footer_text='© 2026 Site',
        lang='en',
        dark_mode_meta='<meta name="color-scheme" content="dark light">',
        pwa_meta='<meta name="theme-color" content="#fff">',
        vt_meta='<meta name="view-transition" content="same-origin">',
        og_html='<meta property="og:title" content="T">',
        pwa_manifest='<link rel="manifest" href="/m.webmanifest">',
        dark_mode_script='<script>void 0;</script>',
        search_script='<script src="/s.js"></script>',
        mermaid_script='<script>mermaid.init();</script>',
        json_ld_html='<script type="application/ld+json">{}</script>',
        theme_toggle='<button id="t">T</button>',
    )),
    ('r05/escape_specials', 'article', dict(
        _BASE,
        site_title='A & B < C > D " E \' F',
        page_title='<b>&amp;</b>',
        description='x"y\'z&<>',
        lang='en"q"',
        footer_text='& < > " \'',
    )),
    ('r06/footer_empty', 'article', dict(_BASE, footer_text='')),
    ('r07/footer_special', 'article', dict(_BASE, footer_text='f & < > " \'')),
    ('r08/body_has_dollar', 'standalone',
     dict(_BASE, body_content='<p>cost: $x and ${y}</p>')),
    ('r09/nav_and_toggle', 'category', dict(
        _BASE,
        nav_links='<a href="/a">a</a>',
        theme_toggle='<button>d</button>',
    )),
    ('r10/has_dark_true', 'article', dict(_BASE, has_dark=True)),
    ('r11/has_dark_false', 'article', dict(_BASE, has_dark=False)),
    ('r12/empty_titles', 'search', dict(_BASE, site_title='', page_title='',
                                        description='')),
    ('r13/description_newline', 'article', dict(_BASE, description='line1\nline2')),
    ('r14/lang_custom', 'article', dict(_BASE, lang='ja')),
    ('r15/css_with_dollar', 'article', dict(_BASE, theme_css='a::after{content:"$x"}')),
    ('r16/cjk_everything', 'article', dict(
        _BASE,
        site_title='站点名',
        page_title='文章标题',
        description='描述',
        body_content='<p>中文正文</p>',
        footer_text='页脚',
        nav_links='<a href="/">首页</a>',
    )),
    ('r17/dark_css_and_meta', 'article', dict(
        _BASE,
        dark_css='@media (prefers-color-scheme: dark){body{background:#000}}',
        dark_mode_meta='<meta name="color-scheme" content="dark light">',
        dark_mode_script='<script>document.documentElement.classList.add("dark");</script>',
    )),
]

_ERR_RE = re.compile(r'^Invalid placeholder in string: line (\d+), col (\d+)$')


def pos_from_value_error(tmpl, exc):
    """把 CPython 的 `Invalid placeholder …: line L, col C` 反推成绝对码点下标。

    ⚠ 只做**坐标换算**（CPython `_invalid()` 的 colno 是行内 1 基列号），
      不复刻「哪一处算非法」的判定 —— 那是 Python 自己算的。
    ⚠ 逐条自检 `tmpl[pos] == '$'`：反推出错就炸掉生成器。
    """
    m = _ERR_RE.match(str(exc))
    if not m:
        raise SystemExit('无法解析 ValueError 消息：%r' % (str(exc),))
    lineno = int(m.group(1))
    colno = int(m.group(2))
    lines = tmpl.splitlines(keepends=True)
    idx = sum(len(l) for l in lines[:max(lineno - 1, 0)]) + (colno - 1)
    if idx >= len(tmpl) or tmpl[idx] != '$':
        raise SystemExit(
            'pos 反推失败：tmpl=%r line=%d col=%d ⇒ idx=%d（该位置不是 `$`）'
            % (tmpl, lineno, colno, idx))
    return idx


def run_strict(tmpl, mapping):
    """真 Python 的 substitute ⇒ 字符串或错误描述字典。"""
    try:
        return Template(tmpl).substitute(mapping)
    except KeyError as exc:
        return {'kind': 'KeyError', 'key': exc.args[0]}
    except ValueError as exc:
        return {'kind': 'ValueError', 'what': 'invalid_placeholder',
                'pos': pos_from_value_error(tmpl, exc)}


def run_safe(tmpl, mapping):
    """真 Python 的 safe_substitute ⇒ 字符串。"""
    return Template(tmpl).safe_substitute(mapping)


def _norm(case):
    """用例有两种写法：`(tmpl, mapping)` 或
    `{'tmpl': …, 'mapping': …, 'want': <覆盖>, 'note': <登记差异>}`。"""
    if isinstance(case, tuple):
        return {'tmpl': case[0], 'mapping': case[1]}
    return case


def main():
    if SKELETON != _PAGE_SKELETON:
        raise SystemExit(
            'gen_template.SKELETON 与 tinypage.core.template._PAGE_SKELETON 不一致'
            '（页面骨架抄错了，或上游改了骨架）—— 先修 gen_template.py 的副本。\n'
            '  gen_template 长度=%d / tinypage 长度=%d'
            % (len(SKELETON), len(_PAGE_SKELETON)))

    cases = {}

    sub = {}
    for i, case in enumerate(SUBSTITUTE_CASES):
        spec = _norm(case)
        py = run_strict(spec['tmpl'], spec['mapping'])
        want = spec['want'] if spec.get('want') is not None else py
        sub['s%02d' % i] = {
            'input': {'tmpl': spec['tmpl'], 'mapping': spec['mapping']},
            'python': py,
            'want': want,
            'note': spec.get('note'),
        }
    cases['substitute'] = sub

    safe = {}
    for i, case in enumerate(SUBSTITUTE_CASES):
        spec = _norm(case)
        py = run_safe(spec['tmpl'], spec['mapping'])
        # safe 侧「缺键 ⇒ 原样保留」⇒ 那几种值类型**根本不参与**（键在才取值）
        # ⇒ want 覆盖同样适用于 safe（只有值真的被代入的用例才有差异）。
        want = spec['want'] if spec.get('want') is not None else py
        safe['s%02d' % i] = {
            'input': {'tmpl': spec['tmpl'], 'mapping': spec['mapping']},
            'python': py,
            'want': want,
            'note': spec.get('note'),
        }
    cases['safe_substitute'] = safe

    ren = {}
    for name, page_type, opts in RENDER_CASES:
        py = render_skeleton(page_type, **opts)
        ren[name] = {
            'input': {'page_type': page_type, 'opts': opts},
            'python': py,
            'want': py,
            'note': None,
        }
    cases['render_skeleton'] = ren

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
            'generated_by': 'tp/test/gen_template_baseline.py',
            'python_functions': {
                'substitute':
                    'string.Template.substitute (CPython Lib/string.py；'
                    'idpattern 为 (?a:[_a-z][_a-z0-9]*)，IGNORECASE ⇒ ASCII only)',
                'safe_substitute':
                    'string.Template.safe_substitute (CPython Lib/string.py)',
                'render_skeleton':
                    'tinypage.core.template.render_skeleton (core/template.py:52)',
            },
            'err_shape': ERR_SHAPE,
            'skeleton': {
                'chars': len(_PAGE_SKELETON),
                'lines': _PAGE_SKELETON.count('\n') + 1,
                'trailing_newline': _PAGE_SKELETON.endswith('\n'),
                'note': 'Python 侧 _PAGE_SKELETON（core/template.py:11-49）；'
                        'gen_template.py 的副本已在生成期逐字比对。',
            },
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
    print('wrote %s (%d cases, %d known differences, skeleton %d chars)'
          % (OUT, total, doc['_meta']['known_difference_count'], len(_PAGE_SKELETON)))


if __name__ == '__main__':
    main()
