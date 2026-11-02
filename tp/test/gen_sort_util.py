"""生成 tp/lib/sort_util.wll —— 手写排序（归并排序），替代内建 SORT / SORT_BY。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出；
WLWL 的括号诊断只说「expected ')' got X」，不告诉你缺了几层）。

**为什么必须手写**（计划 §2.3 / C2，已裁决）：
    std.collection::SORT 是**二次复杂度** —— 实测 200 元素 850ms、500 元素 6.1s、
    1000 元素 28.2s ⇒ 500 篇以上文章的一次构建会卡到**分钟级**。
    ⇒ 本模块用**归并排序**（O(n log n) 次比较，稳定）。

**对齐的 Python 行为**（真 Python 源码树）：
  · `SORT_STRINGS(items)`
      == Python `sorted(list_of_str)` —— 升序、**码点序**、稳定。
      对应 tinypage/content.py:698（页面按标题）、generator.py:684（分类）、
      admin/views.py:133（分类）、core/incremental.py:175（文件名）。
  · `SORT_BY_DATE(items)`
      == Python `tinypage/content.py:196`
         `arts.sort(key=lambda x: x.date_obj or datetime.min, reverse=True)`
      —— **按日期倒序**（新→旧）、稳定。
      键的口径与 content.py:185 一致：`datetime.strptime(meta.date[:16],
      "%Y-%m-%d %H:%M")` ⇒ 只取日期串**前 16 个字符**（分钟精度）。
      ⚠ 只取 16 字符不是偷懒：Python 侧就是 `meta.date[:16]`，
      若 WLWL 比较整串（可能带秒），同一分钟内、带秒的两篇文章在两侧的
      先后顺序会不同 ⇒ 逐字节对照会红。
  · `SORT_BY_TITLE_OR_FILE(items)`（**本轮新增，缺口 A**）
      == Python `tinypage/content.py:698`
         `pages.sort(key=lambda x: x.title or x.file)`
      —— **按「标题优先、空标题回落文件名」升序**、稳定。
      ⚠ Python 的 `or` 对**空串**也回落（不只是 None）：`""` 是 falsy ⇒
      键取 `file`。基准用**真 `list_standalones()`** 的返回顺序锁定这一点。
  · `SORT_BY_NUM(items)`（**本轮新增，缺口 B**）
      == Python `tinypage/content.py:237`
         `related.sort(key=lambda x: x[1], reverse=True)`
      —— 元素是**二元组** `(article, jaccard)` ⇒ WLWL 侧用
      **两元素数组** `[payload, number]`，键 = `元素[1]`。
      **倒序**、稳定（Python 的 `reverse=True` **保持稳定**：
      相等键的元素保持输入次序 ⇒ 归并时相等取左半）。
      ⚠ 同一形态也覆盖 `core/ai_assistance.py:258`
      `sorted(word_freq.items(), key=lambda x: x[1], reverse=True)`
      （`(word, count)` ⇒ count 是 INTEGER）⇒ 键必须同时吃 INTEGER/FLOAT。

**数据形态**（与 Python 侧真实用法对齐，见 gen_sort_util_baseline.py）：
  · `SORT_BY_DATE(items)`  items = ARRAY[DICT{"date": STRING}] 或 ARRAY[STRING]
      —— DICT 形态对齐 `ArticleMeta`（Python 的 dataclass 在 WLWL 侧对应 DICT）；
      STRING 形态是「日期串数组」（计划 §4 卡 S2-2 的验收口径就是它）。
  · `SORT_STRINGS(items)`  items = ARRAY[STRING]

**实现要点（都是本机实测出来的，不是猜的）**：
  ① WLWL 的 `<` 对字符串是**码点序**（规范 §4.3 + 实测）⇒ 与 Python `sorted`
     的码点序一致，可逐字节对照。
  ② 归并排序的**稳定性**：相等时**取左半**（升序 `<=`、降序 `>=` 都取左边）
     ⇒ 与 Python `sorted`（含 `reverse=True`）一致。
  ③ **本解释器读数组变量时会深拷贝整个数组**（实测：读一个 2000 元素的
     数组 ≈ 92µs ⇒ 每次下标访问都是 O(n)）⇒ 归并的热循环里**每输出一个
     元素只做一次下标访问**（把左右两半的「当前front」缓存成局部变量，
     用完再刷新），否则复杂度会退化成 O(n²)。
  ④ 函数调用的解释器开销实测 ≈ 0.7µs/次 ⇒ 热循环里的**调用次数**是第二瓶颈，
     所以：键只算一次（缓存 ka/kb）、不把「取键」做成函数值参数
     （实测把函数当参数传会让 2000 元素排序从 0.4s 涨到 0.7s）。

**逐字节对照基准**：tp/test/fixtures/sort_util_baseline.json
    （由 tp/test/gen_sort_util_baseline.py 用**真 Python** 生成）

用法：python gen_sort_util.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'sort_util.wll')

# ── 两种「键」的取法 ────────────────────────────────────────────────────────
# 字符串排序：键 = 元素本身（0 次额外调用）
KEY_STR = {
    'va': 'va',
    'vb': 'vb',
}

# 日期排序：键 = 日期串的前 16 个字符（对齐 Python content.py:185 的 meta.date[:16]）
#  · 元素是 DICT ⇒ 取 "date" 字段
#  · 元素是 STRING ⇒ 元素本身就是日期串
#  · 其它（NULL / 数字 …）⇒ 键为 ""（降序时排最后，与 Python 的 datetime.min 同向）
KEY_DATE = {
    'va': ('IF(==(TYPE(va), "STRING"), SUB(va, 0, 16), '
           'IF(==(TYPE(va), "DICT"), '
           '(LET(dv, AT_K(va, "date", "")); '
           'IF(==(TYPE(dv), "STRING"), SUB(dv, 0, 16), "")), '
           '""))'),
    'vb': ('IF(==(TYPE(vb), "STRING"), SUB(vb, 0, 16), '
           'IF(==(TYPE(vb), "DICT"), '
           '(LET(dv, AT_K(vb, "date", "")); '
           'IF(==(TYPE(dv), "STRING"), SUB(dv, 0, 16), "")), '
           '""))'),
}

# 标题排序（缺口 A）：键 = `title or file`（对齐 Python content.py:698）
#  · 元素是 DICT ⇒ 取 "title" 字段；**空串**（或缺失/NULL）⇒ 回落 "file" 字段
#  · 其它（非 DICT）⇒ 键为 ""（字符串键 ⇒ 与其它元素同族，可比较）
# ⚠ Python 的 `or` 对**空串**也回落（不只是 None）：`""` 是 falsy。
# ⚠ 实测 WLWL 的 AT_K 对「键存在但值是 NULL」返回 **NULL**（不是默认值），
#   而 TYPE(NULL) == "NULL" ≠ "STRING" ⇒ 显式判 TYPE 才能把 NULL 也归到回落分支。
# ⚠ 回落值也必须是 STRING：实测 `>=(NULL, 0.5)` / `<("a", 0.5)` 都是 **E0030**
#   （硬诊断，不是 FALSE）⇒ 键的类型必须始终一致，否则整个排序崩掉。
# ⚠ `&&` 短路（实测 &&(FALSE, <会报错的表达式>) 不报错）⇒ TYPE 检查在前是安全的。
def _title_key(var):
    """键提取表达式：`title` 非空串 ⇒ title，否则回落 `file`（再否则 ""）。"""
    fallback = ('(LET(f, AT_K(%s, "file", "")); '
                'IF(==(TYPE(f), "STRING"), f, ""))' % var)
    inner = 'IF(&&(==(TYPE(t), "STRING"), !=(t, "")), t, %s)' % fallback
    group = '(LET(t, AT_K(%s, "title", "")); %s)' % (var, inner)
    return 'IF(==(TYPE(%s), "DICT"), %s, "")' % (var, group)


# 数值键排序（缺口 B）：键 = 二元组的**第 2 项**（对齐 Python content.py:237 的 x[1]）
#  · 元素是 ARRAY ⇒ 取元素[1]（0 基）
#  · 键必须是 INTEGER 或 FLOAT 之一：实测 `<`/`<=` 只在**同族数值**之间可比较
#    （实测 <(1, 1.5) 与 <(0.5, 1) 都是数值比较 ⇒ INTEGER/FLOAT 可混比）
#  · 其它（非 ARRAY / 非数值 / NULL）⇒ 键为 0（INTEGER）
# ⚠ AT 对**越界**下标返回**默认值**（实测 AT(["a"], 1, 7) == 7），
#   所以二元组缺第 2 项时键是 0，不会崩。
# ⚠ AT_K 对「键存在但值是 NULL」返回 NULL（不是默认值）⇒ 这里用 AT + TYPE 双检。
def _num_key(var):
    """键提取表达式：二元组的第 2 项（非数值 ⇒ 0）。"""
    tail = ('(LET(s, AT(%s, 1, 0)); '
            'IF(||(==(TYPE(s), "INTEGER"), ==(TYPE(s), "FLOAT")), s, 0))' % var)
    return 'IF(==(TYPE(%s), "ARRAY"), %s, 0)' % (var, tail)


def _check_paren(expr, label):
    """生成期自检：键提取表达式必须括号配平（wllgen 的逗号守卫只会报误导性的错）。"""
    if expr.count('(') != expr.count(')'):
        raise ValueError('unbalanced parens in %s: %s' % (label, expr))


KEY_TITLE = {'va': _title_key('va'), 'vb': _title_key('vb')}
KEY_NUM = {'va': _num_key('va'), 'vb': _num_key('vb')}
for _lbl, _k in (('KEY_TITLE', KEY_TITLE), ('KEY_NUM', KEY_NUM)):
    _check_paren(_k['va'], _lbl + '.va')
    _check_paren(_k['vb'], _lbl + '.vb')


def merge_body(keys):
    """归并两个**已按同一方向排好**的序列。

    `keys` 给出「当前 front 的键」的表达式（va / vb）。
    ⚠ 键相等时**取左半** ⇒ 稳定（Python `sorted(..., reverse=True)` 同样稳定）。
    """
    return [
        'LET MUT(out, [])',
        'LET MUT(i, 0)',
        'LET MUT(j, 0)',
        'LET MUT(la, LEN(a))',
        'LET MUT(lb, LEN(b))',
        '// ⚠ 缓存左右两半的当前 front：热循环里每输出一个元素只做**一次**',
        '//   下标访问（本解释器读数组会深拷贝整个数组 ⇒ 每次访问都是 O(n)）。',
        'LET MUT(va, AT(a, 0, NULL))',
        'LET MUT(vb, AT(b, 0, NULL))',
        'LET MUT(ka, %s)' % keys['va'],
        'LET MUT(kb, %s)' % keys['vb'],
        C('WHILE', '&&(<(i, la), <(j, lb))', [
            C('IF', 'IF(desc, >=(ka, kb), <=(ka, kb))', [
                'SET(out, PUSH(out, va))',
                'SET(i, +(i, 1))',
                'SET(va, AT(a, i, NULL))',
                'SET(ka, %s)' % keys['va'],
            ], [
                'SET(out, PUSH(out, vb))',
                'SET(j, +(j, 1))',
                'SET(vb, AT(b, j, NULL))',
                'SET(kb, %s)' % keys['vb'],
            ]),
        ]),
        C('WHILE', '<(i, la)', [
            'SET(out, PUSH(out, AT(a, i, NULL)))',
            'SET(i, +(i, 1))',
        ]),
        C('WHILE', '<(j, lb)', [
            'SET(out, PUSH(out, AT(b, j, NULL)))',
            'SET(j, +(j, 1))',
        ]),
        'out',
    ]


def sort_body(sort_name, merge_name):
    """归并排序本体（分治）。递归深度 = log2(n)。"""
    return [
        'LET(n, LEN(arr))',
        C('IF', '<=(n, 1)', [
            'arr',
        ], [
            'LET(mid, /(n, 2))',
            'LET(left, %s(SLICE(arr, 0, mid), desc))' % sort_name,
            'LET(right, %s(SLICE(arr, mid, n), desc))' % sort_name,
            '%s(left, right, desc)' % merge_name,
        ]),
    ]


def main():
    src = []
    A = src.append
    A('// tp/lib/sort_util.wll —— 手写排序（归并排序）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_sort_util.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 为什么不用内建 SORT：它是**二次复杂度**（实测 200 元素 850ms、')
    A('//   500 元素 6.1s、1000 元素 28.2s）⇒ 500 篇以上文章一次构建卡到分钟级。')
    A('//   ⇒ 本模块用**归并排序**：O(n log n) 次比较，稳定，可自定义键。')
    A('//')
    A('// 对齐的 Python 行为：')
    A('//   SORT_STRINGS(items) == Python sorted(list_of_str)（升序、码点序、稳定）')
    A('//   SORT_BY_DATE(items) == Python tinypage/content.py:196')
    A('//       arts.sort(key=lambda x: x.date_obj or datetime.min, reverse=True)')
    A('//     （**按日期倒序**、稳定；键口径同 content.py:185 的 meta.date[:16]）')
    A('//   SORT_BY_TITLE_OR_FILE(items) == Python tinypage/content.py:698')
    A('//       pages.sort(key=lambda x: x.title or x.file)')
    A('//     （**按「标题优先、空标题回落文件名」升序**、稳定；')
    A('//      ⚠ Python 的 or 对**空串**也回落，不只是 None）')
    A('//   SORT_BY_NUM_DESC(items) == Python tinypage/content.py:237')
    A('//       related.sort(key=lambda x: x[1], reverse=True)')
    A('//     （**按数值键倒序**、稳定；⚠ reverse=True **仍保持稳定**）')
    A('//')
    A('// 数据形态：')
    A('//   SORT_BY_DATE(items)  items = ARRAY[DICT{"date": STRING}] 或 ARRAY[STRING]')
    A('//   SORT_STRINGS(items)  items = ARRAY[STRING]')
    A('//   SORT_BY_TITLE_OR_FILE(items)  items = ARRAY[DICT{"title":…, "file":…}]')
    A('//   SORT_BY_NUM_DESC(items)       items = ARRAY[ARRAY[payload, number]]')
    A('//     （payload 是任意值；number 是 INTEGER 或 FLOAT —— 键取元素[1]）')
    A('//')
    A('// 稳定性：相等键时**取左半**（升序 <= / 降序 >= 都取左边）')
    A('//   ⇒ 与 Python sorted（含 reverse=True）一致。')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/sort_util_baseline.json')
    A('//   （由 tp/test/gen_sort_util_baseline.py 用真 Python 生成）')
    A('')

    # ── 内部：四个归并内核（字符串键 / 日期键 / 标题键 / 数值键）────────────
    src += fn('MERGE_RUNS_STR', 'a, b, desc', merge_body(KEY_STR),
              '// 内部：合并两个已排序的**字符串**序列（相等时取左 ⇒ 稳定）')
    src += fn('MERGE_RUNS_DATE', 'a, b, desc', merge_body(KEY_DATE),
              '// 内部：合并两个已排序的**日期**序列（键 = [:16]，相等时取左 ⇒ 稳定）')
    src += fn('MERGE_RUNS_TITLE', 'a, b, desc', merge_body(KEY_TITLE),
              '// 内部：合并两个已排序的**标题**序列（键 = title or file，相等时取左）')
    src += fn('MERGE_RUNS_NUM', 'a, b, desc', merge_body(KEY_NUM),
              '// 内部：合并两个已排序的**数值键**序列（键 = 元素[1]，相等时取左）')

    # ── 内部：归并排序本体（四套，键不同）───────────────────────────────
    src += fn('SORT_RUNS_STR', 'arr, desc', sort_body('SORT_RUNS_STR', 'MERGE_RUNS_STR'),
              '// 内部：字符串序列的归并排序（稳定；desc = TRUE ⇒ 降序）')
    src += fn('SORT_RUNS_DATE', 'arr, desc', sort_body('SORT_RUNS_DATE', 'MERGE_RUNS_DATE'),
              '// 内部：日期序列的归并排序（稳定；desc = TRUE ⇒ 降序）')
    src += fn('SORT_RUNS_TITLE', 'arr, desc', sort_body('SORT_RUNS_TITLE', 'MERGE_RUNS_TITLE'),
              '// 内部：标题序列的归并排序（稳定；desc = TRUE ⇒ 降序）')
    src += fn('SORT_RUNS_NUM', 'arr, desc', sort_body('SORT_RUNS_NUM', 'MERGE_RUNS_NUM'),
              '// 内部：数值键序列的归并排序（稳定；desc = TRUE ⇒ 降序）')

    # ── 公开面 ───────────────────────────────────────────────────────────
    src += fn('SORT_STRINGS', 'items', [
        '// 升序、稳定、码点序（== Python sorted(list_of_str)）。',
        'SORT_RUNS_STR(items, FALSE)',
    ], '// 升序稳定排序（== Python sorted(list_of_str)）')

    src += fn('SORT_BY_DATE', 'items', [
        '// 按日期**倒序**（新→旧）、稳定。',
        '// == Python tinypage/content.py:196 的 arts.sort(key=date_obj, reverse=True)',
        '// items 的元素可以是 DICT{"date": ...} 或 STRING（日期串本身）。',
        'SORT_RUNS_DATE(items, TRUE)',
    ], '// 按日期倒序稳定排序（== Python content.py:196）')

    src += fn('SORT_BY_TITLE_OR_FILE', 'items', [
        '// 按「标题优先、空标题回落文件名」**升序**、稳定。',
        '// == Python tinypage/content.py:698 的 pages.sort(key=lambda x: x.title or x.file)',
        '// ⚠ Python 的 or：""（空串）也是 falsy ⇒ 回落 file（不只是 None）。',
        '// items 的元素是 DICT{"title": …, "file": …}。',
        'SORT_RUNS_TITLE(items, FALSE)',
    ], '// 按标题（空则回落 file）升序稳定排序（== Python content.py:698）')

    src += fn('SORT_BY_NUM_DESC', 'items', [
        '// 按数值键**倒序**、稳定。',
        '// == Python tinypage/content.py:237 的 related.sort(key=lambda x: x[1], reverse=True)',
        '// items 的元素是**两元素数组** [payload, number]：键取元素[1]。',
        '// number 必须是 INTEGER 或 FLOAT（其它一律按 0 处理）。',
        '// ⚠ Python 的 reverse=True **保持稳定** ⇒ 相等键的元素保持输入次序。',
        'SORT_RUNS_NUM(items, TRUE)',
    ], '// 按数值键倒序稳定排序（== Python content.py:237）')

    A('EXPORT(["SORT_BY_DATE", "SORT_BY_NUM_DESC", "SORT_BY_TITLE_OR_FILE", '
      '"SORT_STRINGS"]);')

    chars, lines = write(OUT, src)
    print(f'wrote {OUT} ({chars} chars, {lines} lines)')


if __name__ == '__main__':
    main()
