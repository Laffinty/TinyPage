"""WLWL 源文件的括号平衡检查器。

三个能力：
1. **剥离 `//` 行注释** —— 注释里的括号会误判。
2. **按顶层语句报不平衡** —— 顶层 `LET(...)` 各自独立，
   逐个报出「这个语句结束时深度是多少」，一眼看出哪个函数少括号。
3. **检出中缀算术** —— WLWL **没有**中缀语法（`a + b` 是硬 E0011），
   这是手写 WLWL 最高频的错误。

用法：python paren_check.py <file.wll> [...]
"""
import re
import sys

INFIX = re.compile(r'(?<![\w"])\d\s*[+\-*/]\s*[\w(]|[a-zA-Z_]\s*[+\-*/]\s*[a-zA-Z_0-9]')


def strip_comments(src):
    out = []
    comment_lines = set()
    in_str = False
    i = 0
    line = 1
    n = len(src)
    while i < n:
        c = src[i]
        if c == '\n':
            out.append(c)
            line += 1
            i += 1
            continue
        if in_str:
            out.append(c)
            if c == '\\':
                if i + 1 < n:
                    out.append(src[i + 1])
                    i += 2
                    continue
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            comment_lines.add(line)
            while i < n and src[i] != '\n':
                i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out), comment_lines


def top_level_statements(code):
    """切出顶层语句（深度回到 0 的位置）。返回 [(起始行, 结束行, 结束深度)]。"""
    depth = 0
    in_str = False
    i = 0
    line = 1
    start_line = 1
    stmts = []
    n = len(code)
    while i < n:
        c = code[i]
        if c == '\n':
            if depth == 0:
                stmts.append((start_line, line, 0))
                start_line = line + 1
            line += 1
            i += 1
            continue
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
            i += 1
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        i += 1
    if start_line <= line:
        stmts.append((start_line, line, depth))
    return stmts


def check_infix(raw, comment_lines):
    hits = []
    for ln, text in enumerate(raw.split('\n'), 1):
        if ln in comment_lines:
            continue
        stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
        m = INFIX.search(stripped)
        if m:
            hits.append((ln, m.group(0), text.strip()[:90]))
    return hits


def report(path):
    raw = open(path, encoding='utf-8').read()
    code, comment_lines = strip_comments(raw)
    ok = True

    stmts = top_level_statements(code)
    bad = [(s, e, d) for s, e, d in stmts if d != 0]
    if bad:
        ok = False
        print(f'{path}: UNBALANCED top-level statements:')
        for s, e, d in bad:
            snippet = ''
            for ln, text in enumerate(raw.split('\n'), 1):
                if s <= ln <= e and text.strip() and not text.strip().startswith('//'):
                    snippet = text.strip()[:70]
                    break
            fix = f'needs {d} more ")"' if d > 0 else f'has {-d} extra ")"'
            print(f'    lines {s}-{e}: ends at depth {d} ({fix})  |  {snippet}')

    hits = check_infix(raw, comment_lines)
    if hits:
        ok = False
        print(f'{path}: suspected INFIX arithmetic (WLWL has no infix syntax):')
        for ln, frag, text in hits:
            print(f'    line {ln}: {frag!r}  |  {text}')

    if ok:
        print(f'{path}: OK (all top-level statements balanced, no infix)')
    return ok


def main():
    ok = True
    for p in sys.argv[1:]:
        ok = report(p) and ok
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
