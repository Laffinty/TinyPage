"""生成 tp/lib/footnotes.wll —— 脚注模块。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出；
WLWL 的括号诊断只说「expected ')' got X」，不告诉你缺了几层）。

对齐目标：`tinypage.parsers.footnotes` 的四个函数（真 Python 源码树）
    PARSE_FOOTNOTES(text)  -> [cleaned, footnotes]   == parse_footnotes
    RENDER_FOOTNOTE_REFS(text) -> STRING             == render_footnote_refs
    BUILD_FOOTNOTES_HTML(footnotes) -> STRING        == build_footnotes_html
    PROCESS_FOOTNOTES(text) -> [rendered, html]      == process_footnotes
  footnotes 每项是 {"key": ..., "text": ...} DICT（ARRAY 顺序 = 定义出现顺序）。

两条**刻意差异**（测试与基准已同步处理，逐字节可比）：
  1. 顺序：Python 用 `set` 收集 key ⇒ footnotes 顺序跨进程不确定（父进程实测
     5 次运行 4 种顺序）；本模块取**定义出现顺序**（插入序，确定性）。
     基准生成器（gen_footnotes_baseline.py）序列化前同样按定义出现顺序重排。
  2. 前瞻：Python 的 REF 模式带 `(?!:)`；WLWL 正则**不支持前瞻**（E0030
     "lookahead is not supported"）⇒ RENDER_FOOTNOTE_REFS 用
     「RE_SEARCH 循环 + 检查匹配末位后一字符是否为 ':'」的等价实现
     （等价性论证见函数内注释）。

基准：tp/test/fixtures/footnotes_baseline.json（由 gen_footnotes_baseline.py
用真 Python 生成）。用法：python gen_footnotes.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'footnotes.wll')

# .wll 文件里的字面文本（正则反斜杠在 .wll 字符串里要写成 \\，见 README 坑 7）
DEF_FIND = r'RE("(?m)\\[\\^([^\\]]+)\\]:\\s*(.+)")'
DEF_REPLACE = r'RE("(?m)\\[\\^([^\\]]+)\\]:\\s*(.+)$")'
REF_RE = r'RE("\\[\\^([^\\]]+)\\]")'


def main():
    src = []
    A = src.append
    A('// tp/lib/footnotes.wll —— 脚注模块')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_footnotes.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 对齐目标：tinypage.parsers.footnotes（真 Python 实现）：')
    A('//   PARSE_FOOTNOTES(text) -> [cleaned, footnotes]   == parse_footnotes')
    A('//   RENDER_FOOTNOTE_REFS(text) -> STRING             == render_footnote_refs')
    A('//   BUILD_FOOTNOTES_HTML(footnotes) -> STRING        == build_footnotes_html')
    A('//   PROCESS_FOOTNOTES(text) -> [rendered, html]      == process_footnotes')
    A('//   footnotes 每项 = {"key": ..., "text": ...} DICT。')
    A('//')
    A('// 两条刻意差异（基准已同步处理 ⇒ 逐字节可比）：')
    A('//   ① 顺序：Python 用 set 收集 key ⇒ footnotes 顺序跨进程不确定；')
    A('//      本模块取**定义出现顺序**（插入序，确定性）。')
    A('//   ② 前瞻：Python REF 模式带 (?!:)，WLWL 正则不支持前瞻（E0030）⇒')
    A('//      RENDER_FOOTNOTE_REFS 用 RE_SEARCH 循环 + 逐字符检查等价实现。')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/footnotes_baseline.json')
    A('//   （由 tp/test/gen_footnotes_baseline.py 用真 Python 生成）')
    A('')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_SEARCH", "RE_FIND_ALL", "RE_REPLACE"]);')
    A('IMPORT("./esc.wll", ["ESCAPE_HTML"]);')
    A('')

    # ── PARSE_FOOTNOTES ─────────────────────────────────────
    src += fn('PARSE_FOOTNOTES', 'text', [
        '// 对齐 Python parse_footnotes：',
        '//  · DEF 模式与 Python FOOTNOTE_DEF_PATTERN **逐字相同**（含 (?m)）：',
        '//    无行首锚定 ⇒ 行中间的 [^k]: v 也被匹配删除（实测 "def at mid [^z]: value"',
        '//    ⇒ "def at mid "）；\\s* 在 : 之后、(.+) 不跨行、$ 是行尾 ⇒ 定义值',
        '//    只取到本行行尾（实测 "before [^x]: first line\\nsecond" ⇒ "first line"）。',
        '//  · RE_FIND_ALL（取值）与 RE_REPLACE（删除）用同一模式 ⇒ 零漂移；',
        '//    RE_REPLACE 删**全部**匹配（含重复定义行），值取**第一个**（先出现者赢）。',
        '//  · ⚠ 顺序：Python 用 set 收集 key ⇒ 跨进程不确定；这里取**定义出现',
        '//    顺序**（插入序）—— 刻意的确定性选择，基准生成器同步重排。',
        'LET(matches, RE_FIND_ALL(' + DEF_FIND + ', text))',
        'LET MUT(defs, DICT())',
        'LET MUT(keys, [])',
        C('FOR', 'm, matches', [
            'LET(g, AT_K(m, "groups", []))',
            'LET(k, g[1])',
            '// 只有首个定义进 defs（对齐 Python dict 先出现者赢）；值 = (.+) 后 TRIM',
            'IF(==(TYPE(AT_K(defs, k, NULL)), "NULL"), '
            '(SET(defs, INDEX_SET(defs, k, TRIM(g[2]))); SET(keys, PUSH(keys, k))), NULL)',
        ]),
        'LET MUT(footnotes, [])',
        C('FOR', 'k, keys', [
            'SET(footnotes, PUSH(footnotes, ["key": k, "text": AT_K(defs, k, "")]))',
        ]),
        '// 删除**全部**定义匹配（含重复定义）',
        'LET(cleaned, RE_REPLACE(' + DEF_REPLACE + ', text, ""))',
        '[cleaned, footnotes]',
    ], '// 解析脚注定义：[cleaned_text, footnotes]（定义出现顺序）')

    # ── RENDER_FOOTNOTE_REFS ────────────────────────────────
    src += fn('RENDER_FOOTNOTE_REFS', 'text', [
        '// 对齐 Python render_footnote_refs。Python REF 模式带前瞻 (?!:)，',
        '// WLWL 正则**不支持前瞻**（E0030: lookahead is not supported）⇒ 等价改写：',
        '//  RE_SEARCH 逐段扫描；每次取匹配的 start/end（码点坐标，相对剩余串），',
        '//  检查匹配末位**之后一个字符**是否为 ":" —— 是则原样保留 [^n] 片段',
        '//  （定义形态，从 end 续扫），否则替换为 <sup>…</sup>（引用形态）。',
        '// 等价性：Python 匹配被前瞻否掉后从 start+1 重试；但任何「更内层」的',
        '//  候选都必须以 [^ 开头且吞到**同一个** "]"（[^\\]]+ 不跨 ]）⇒ 它的',
        '//  下一字符同样是 ":" ⇒ 同样被否掉 ⇒ 从 end 续扫与 Python 完全等价。',
        '// （process_footnotes 先 parse 后 render ⇒ 正常路径上定义行已被删；',
        '//  本函数被直接调用（未先 parse）时仍须跳过 [^n]: —— 即本段逻辑。）',
        'LET MUT(out, "")',
        'LET MUT(pos, 0)',
        'LET MUT(run, TRUE)',
        C('WHILE', 'run', [
            'LET(rest, SUB(text, pos, -(LEN(text), pos)))',
            'LET(hit, RE_SEARCH(' + REF_RE + ', rest))',
            C('IF', '==(TYPE(hit), "NULL")', [
                'SET(out, CAT(out, rest))',
                'SET(run, FALSE)',
            ], [
                'LET(st, AT_K(hit, "start", 0))',
                'LET(en, AT_K(hit, "end", 0))',
                'LET(gs, AT_K(hit, "groups", []))',
                'LET(key, gs[1])',
                'LET(abs_end, +(pos, en))',
                'LET(nxt, IF(<(abs_end, LEN(text)), SUB(text, abs_end, 1), ""))',
                'SET(out, CAT(out, SUB(text, pos, st)))',
                C('IF', '==(nxt, ":")', [
                    # 定义形态 [^n]: —— 原样保留；冒号由下一段前缀复制
                    'SET(out, CAT(out, SUB(rest, st, -(en, st))))',
                ], [
                    C('SET', 'out',
                      'CAT(out, "<sup><a href=\\"#fn-", key, "\\" id=\\"fnref-", '
                      'key, "\\">[", key, "]</a></sup>")'),
                ]),
                'SET(pos, abs_end)',
            ]),
        ]),
        'out',
    ], '// 把引用 [^n] 转成 <sup><a …>[n]</a></sup>（无前瞻等价实现）')

    # ── BUILD_FOOTNOTES_HTML ────────────────────────────────
    src += fn('BUILD_FOOTNOTES_HTML', 'footnotes', [
        '// 对齐 Python build_footnotes_html：空列表 ⇒ ""',
        'IF(==(LEN(footnotes), 0), (RETURN("")), NULL)',
        'LET MUT(items, "")',
        C('FOR', 'item, footnotes', [
            # {escape_html(text)} <a …> —— 转义后紧跟**一个空格**再接 <a
            C('SET', 'items',
              'CAT(items, "<li id=\\"fn-", AT_K(item, "key", ""), "\\">", '
              'ESCAPE_HTML(AT_K(item, "text", "")), '
              '" <a href=\\"#fnref-", AT_K(item, "key", ""), "\\\">↩</a></li>")'),
        ]),
        '// 模板逐字节对齐 Python f-string：\\n 开头、</section> 后**没有**换行',
        C('CAT', '"\\n<section class=\\"footnotes\\">\\n  <hr>\\n  <ol>\\n    "',
          'items', '"\\n  </ol>\\n</section>"'),
    ], '// 生成脚注区 HTML（空列表返回 ""）')

    # ── PROCESS_FOOTNOTES ───────────────────────────────────
    src += fn('PROCESS_FOOTNOTES', 'text', [
        '// 对齐 Python process_footnotes：先 parse（删定义行），再在 cleaned 上转引用',
        'LET(parsed, PARSE_FOOTNOTES(text))',
        'LET(cleaned, parsed[0])',
        'LET(footnotes, parsed[1])',
        '[RENDER_FOOTNOTE_REFS(cleaned), BUILD_FOOTNOTES_HTML(footnotes)]',
    ], '// 全流程：[rendered_text, footnotes_html]')

    A('EXPORT(["PARSE_FOOTNOTES", "RENDER_FOOTNOTE_REFS", '
      '"BUILD_FOOTNOTES_HTML", "PROCESS_FOOTNOTES"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
