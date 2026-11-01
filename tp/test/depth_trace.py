"""打印 WLWL 源文件逐行括号深度（用于定位不平衡点）。

用法：python depth_trace.py <file.wll> [起始行] [结束行]
"""
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0].rsplit('/', 1)[0])
from paren_check import strip_comments


def main():
    path = sys.argv[1]
    lo = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    hi = int(sys.argv[3]) if len(sys.argv) > 3 else 10 ** 9
    code, _ = strip_comments(open(path, encoding='utf-8').read())
    depth = 0
    in_str = False
    i = 0
    line = 1
    n = len(code)
    rows = []
    while i < n:
        c = code[i]
        if c == '\n':
            rows.append((line, depth))
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
    rows.append((line, depth))
    prev = None
    for l, d in rows:
        if lo <= l <= hi:
            mark = '  <<<' if d != prev and prev is not None else ''
            print(f'line {l:>4}: depth={d:>3}{mark}')
        prev = d


if __name__ == '__main__':
    main()
