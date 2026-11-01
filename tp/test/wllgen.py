"""WLWL 源码生成器的共享渲染器。

为什么单独抽出来：`gen_md_inline.py` 与 `gen_md.py` 都要用它，
而渲染器本身是最容易写错的部分（括号配平）⇒ 只留**一份**实现。

核心不变式：输出**括号必然平衡**。
每个分组的收尾括号只由 `render_group` 负责添加，调用方不得再补。

body 节点约定：
  - 字符串              → 一条普通语句（自身括号必须自平衡）
  - ('call', 名字, 参数…) → 一次调用
  - list（语句列表）     → 一个**分组**
  - ['#', '注释']        → 注释行

参数约定：
  - str            → 单个参数（可含逗号，按**顶层逗号**拆分）
  - 多行 str       → **每行一个参数项**（行内仍按顶层逗号拆分）
  - list           → 一个分组参数
"""
import os
import re


# ⚠ WLWL **没有逗号表达式** —— `(a, b)` 既是语法错误（E0011: expected ')' got Comma），
#   也与「函数调用参数列表」在字面上无法区分。
#   实测（2026-11-01）：
#     IF(TRUE, (SET(n, 1), NULL), NULL)  → E0011
#     PRINT(f((1, 2)))                  → E0011
#   ⇒ **参数位置永远不出现裸分组**；多语句一律用**语句序列** `(stmt1; stmt2)`。
#   本守卫在生成期就拦住它，避免产出坏代码再去调试。
#
# 检测方式：扫出所有括号组；**不是调用**（前面没有标识符）且内部有顶层逗号
# 的组 ⇒ 逗号表达式。调用参数列表里的逗号是合法的。
def _find_comma_exprs(text):
    """找出文本里所有"裸分组且内部有顶层逗号"的括号组。

    ⚠ 先**剥离注释与字符串内容**再扫描，否则注释里的 `(a, b)` 会误报。
    """
    # 用同长度但内容置空的掩码替换注释与字符串
    masked = list(text)
    in_str = False
    in_comment = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_comment:
            masked[i] = ' '
            if c == '\n':
                in_comment = False
            i += 1
            continue
        if in_str:
            masked[i] = ' '
            if c == '\\':
                if i + 1 < n:
                    masked[i + 1] = ' '
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            masked[i] = ' '
            i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            in_comment = True
            masked[i] = ' '
            i += 1
            continue
        i += 1
    mtext = ''.join(masked)

    out = []
    stack = []          # 每项: [起始位置, 顶层逗号数, 是否调用]
    in_str = False
    i = 0
    n = len(mtext)
    while i < n:
        c = mtext[i]
        if in_str:
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        if c == '(':
            j = i - 1
            while j >= 0 and mtext[j] in ' \t':
                j -= 1
            # 前面是**非空白、非分隔符** ⇒ 它是某个调用的参数列表
            # （包括 `IF(<(a, b), …)` 里 `<(` 这种情况）。
            # 特例：`FUN((a, b), …)` 的第二个 '(' 是**函数参数列表**，
            # 前面是 '(' —— 那是调用，不是裸分组。
            prev = mtext[j] if j >= 0 else ''
            is_call = j >= 0 and prev not in ',;()[]{}'
            if prev == '(' and j >= 1 and mtext[j - 1] in 'N':
                # FUN((a, b)) —— 前一个是 'N'（FUN 的最后一个字母）
                is_call = True
            stack.append([i, 0, is_call])
        elif c == '[':
            # 数组字面量 —— 其内部的逗号是**合法的元素分隔符**
            stack.append([i, 0, True])
        elif c == '{':
            stack.append([i, 0, True])
        elif c == ')':
            if stack:
                start, commas, is_call = stack.pop()
                if commas and not is_call:
                    snippet = text[start:i + 1].strip()
                    if snippet:
                        out.append(snippet)
        elif c in ']}':
            if stack:
                stack.pop()
        elif c == ',' and stack:
            stack[-1][1] += 1
        i += 1
    return out


def assert_no_comma_expr(text):
    """拒绝逗号表达式形态（WLWL 不支持）。"""
    hits = _find_comma_exprs(text)
    if hits:
        raise ValueError(
            'comma expressions are NOT valid WLWL (use a statement sequence '
            '"(stmt1; stmt2)" instead). Offending snippets:\n  '
            + '\n  '.join(hits[:12]))


def split_top_level(text):
    """按**顶层逗号**拆分参数文本；嵌套括号/字符串内的逗号保留。

    调用方（render_call）保证传入的是**单行** —— 多行会先被
    split_multiline_arg 拆成「每行一个参数项」。
    """
    parts = []
    depth = 0
    in_str = False
    cur = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            cur.append(c)
            if c == '\\' and i + 1 < n:
                cur.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            cur.append(c)
            i += 1
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        if c == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    parts.append(''.join(cur).strip())
    return [p for p in parts if p != '']


def split_multiline_arg(text):
    """把多行参数文本拆成「每个**参数项**」。

    规则：**括号未闭合的行是上一项的续行**，与上一项合并；
    括号闭合后另起一项。这样
        'IF(cond,\\n'
        '   (SET(n, 1), NULL),\\n'
        '   NULL)'
    被识别为**一个**参数项（一个 IF 调用），而不是三行独立语句。

    实测：不这样处理会产出 `IF(cond,;` 这种坏语法
    （WLWL 报 "expected ')' got Comma"）。
    """
    out = []
    cur = ''
    depth = 0
    for raw in text.split('\n'):
        s = raw.strip()
        if s == '':
            continue
        cur = (cur + ' ' + s) if cur else s
        depth += _bracket_delta(s)
        if depth <= 0:
            out.append(cur)
            cur = ''
            depth = 0
    if cur:
        out.append(cur)
    return out


def _bracket_delta(text):
    """一行文本带来的括号净变化（忽略字符串内的括号）。"""
    depth = 0
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        i += 1
    return depth


def _is_bare_group(pieces):
    """拆分结果是否构成**一个裸分组**（`(a, b)` 形式）。

    这种文本是**一个**参数（分组参数），不能按顶层逗号拆成多个。
    实测：IF 的第二参数 `(SET(n, 1), NULL)` 被拆开会产出坏语法
    （WLWL 报 "expected ')' got Comma"）。
    """
    if len(pieces) < 2:
        return False
    joined = ','.join(pieces).strip()
    if not joined.startswith('(') or not joined.endswith(')'):
        return False
    # 重新拼回去后必须仍然是一个完整分组（括号配平）
    return _bracket_delta(joined) == 0 and joined.count('(') == joined.count(')')


def _is_complete_call(text):
    """文本是否是一个**完整的调用**（括号配平）。

    这种文本要原样输出，不能按顶层逗号拆开 ——
    否则 `IF(a, b, c)` 会被拆成三个参数项（实测产出坏语法）。

    判定：括号整体配平，且**第一个括号不是字符串/顶层逗号之前**就出现
    （即它是 `NAME(...)` 形式，而不是 `(a, b)` 这样的裸分组）。
    """
    s = text.strip()
    if not s:
        return False
    # 找到第一个 '(' 的位置；它前面必须是非空标识符前缀
    depth = 0
    in_str = False
    first_paren = -1
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c in '([{':
            if first_paren < 0:
                first_paren = i
            depth += 1
        elif c in ')]}':
            depth -= 1
            if depth == 0 and i != n - 1:
                return False
        i += 1
    if depth != 0:
        return False
    if first_paren <= 0:
        return False
    prefix = s[:first_paren].strip()
    # 前缀必须是标识符（允许 NAME 或 NAME.SUB）
    if not prefix or not (prefix[0].isalpha() or prefix[0] == '_'):
        return False
    return all(ch.isalnum() or ch in '._' for ch in prefix)


def render_group(group, indent):
    """渲染一个语句分组 → 行列表。

    **返回的最后一行就是本分组的收尾**（一个 ')'）——调用方不得再补。
    开头括号**独占一行**，便于肉眼核对配平。
    """
    pad = '     ' * indent
    inner = []
    for i, item in enumerate(group):
        ls = render(item, indent + 1)
        if i < len(group) - 1:
            ls[-1] += ';'
        inner.extend(ls)
    if not inner:
        return ['(' + pad + ')']
    return ['(' + pad] + inner + [pad + ')']


def render_call(name, args, indent):
    """渲染一次调用。

    **收尾括号的责任划分**（避免多/少一个括号）：
      - 分组参数的收尾 ')' 由 render_group 的最后一行提供；
      - 本函数只负责在**所有参数之后**补上调用自身的 ')'。
    """
    pad = '     ' * indent
    lines = []
    cur = pad + name + '('
    first = True

    def flush(txt):
        nonlocal cur, first
        cur += ('' if first else ', ') + txt
        first = False

    for arg in args:
        if isinstance(arg, str):
            # 多行参数文本 ⇒ 按括号配平合并成参数项
            items = split_multiline_arg(arg) if ('\n' in arg or '\r' in arg) else [arg]
            for item in items:
                # 一个**完整的调用**（首尾括号配平且整体被括号包住）原样输出；
                # 其余按顶层逗号拆成多个参数。
                pieces = split_top_level(item)
                if len(pieces) == 1:
                    flush(pieces[0])
                elif _is_bare_group(pieces):
                    # `(a, b)` 是一个**分组参数**（如 IF 的第二个参数），
                    # 不能按顶层逗号拆开 —— 拆了就会多出参数。
                    flush(', '.join(pieces))
                else:
                    for piece in pieces:
                        flush(piece)
        elif isinstance(arg, list):
            # list 参数有两种含义：
            #  ① 调用节点 ['call', name, ...]  → 渲染成 NAME(...)
            #  ② 语句分组                    → 渲染成 ( ... )
            if arg and arg[0] == 'call':
                sub = render_call(arg[1], arg[2:], indent)
                flush(sub[0].strip())
                lines.append(cur)
                lines.extend(sub[1:])
                cur = pad + sub[-1].strip()
            else:
                grp = render_group(arg, indent)
                flush(grp[0].strip())
                lines.append(cur)
                lines.extend(grp[1:-1])
                cur = pad + grp[-1].strip()
        else:
            raise TypeError(f'bad arg: {arg!r}')
    cur += ')'
    lines.append(cur)
    return lines


def render(node, indent=0):
    """渲染一个 body 节点 → 行列表。"""
    pad = '     ' * indent
    if isinstance(node, str):
        return [pad + node]
    if not isinstance(node, list):
        raise TypeError(f'bad node: {node!r}')
    if node and node[0] == '#':
        return [pad + '// ' + node[1]]
    if node and node[0] == 'fun':
        return render_fun_def(node[1], node[2], node[3], indent)
    if node and node[0] == 'call':
        return render_call(node[1], node[2:], indent)
    return render_group(node, indent)


def C(name, *args):
    """构造一个调用节点。"""
    return ['call', name] + list(args)


def render_fun_def(name, params, body, indent):
    """渲染嵌套的 LET(name, FUN((params), (body))) → 行列表。

    与 fn() 的区别：fn() 产出**顶层**已收尾的源码行（自带 `);`），
    不能嵌进 body 列表 —— 外层 render_group 会把每行再当语句补 `;`，
    产出 `));;` 与游离括号（2026-11-01 实测）。
    本函数返回**未收尾**的行：末行以 `)))` 结束（依次关掉
    函数体分组、FUN、LET），**末尾分号由外层 render_group 补**。
    """
    pad = '     ' * indent
    grp = render_group(body, indent + 1)
    lines = [pad + 'LET(' + name + ', FUN((' + params + '), ' + grp[0].strip()]
    lines.extend(grp[1:-1])
    lines.append(grp[-1].strip() + '))')
    return lines


def FUN_DEF(name, params, body):
    """构造一个嵌套函数定义节点（闭包/局部函数）。

    params 为字符串（可为空串 ⇒ 零参）；body 是语句列表。
    ⚠ WLWL 的 FUN 是**两个**括号组：FUN((params), (body))。
      `FUN((body))` 会被解析器当成「参数名列表」而报
      E0010 "expected parameter name"（2026-11-01 实测）。
    """
    return ['fun', name, params, body]


def fn(name, params, body, comment=None):
    """生成 LET(name, FUN((params), (body)));。

    整个函数体交给渲染器处理；**LET 与 FUN 的收尾括号在此处补**
    （渲染器管不到这两个）。

    ⚠ 只用于**顶层**函数；函数体内的局部函数请用 FUN_DEF，
      fn() 的产物再嵌进 body 会被二次收尾。
    """
    out = []
    if comment:
        out.append(f'// {comment}')
    pad = '     '
    grp = render_group(body, 2)
    lines = []
    cur = pad + 'LET(' + name + ', FUN((' + params + '), ' + grp[0].strip()
    lines.append(cur)
    lines.extend(grp[1:-1])
    cur = pad + grp[-1].strip()
    # grp[-1] 已关掉函数体分组 ⇒ 再补 FUN 与 LET 的两个 ')'
    lines.append(cur + '));')
    out.extend(lines)
    out.append('')
    return out


def write(path, lines):
    """写出源码（LF，UTF-8 无 BOM）。"""
    text = '\n'.join(lines)
    assert_no_comma_expr(text)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    return len(text), text.count('\n') + 1
