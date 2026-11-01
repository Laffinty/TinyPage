"""检查 WLWL 顶层语句是否都以 `;` 结尾。

为什么需要：WLWL 的 `LET(...)` 是**语句**，必须以 `;` 终止。
缺分号的报错是 `expected ';' after expression`，而且位置指向**下一条**语句
（很难定位到真正缺分号的那一行）。

用法：python check_semis.py <file.wll> [...]
"""
import os
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paren_check import strip_comments


def main():
    bad_total = 0
    for path in sys.argv[1:]:
        raw = open(path, encoding='utf-8').read()
        code, _ = strip_comments(raw)
        lines = raw.split('\n')

        # 逐行深度
        depth = 0
        in_str = False
        i = 0
        line = 1
        depths = []
        n = len(code)
        while i < n:
            c = code[i]
            if c == '\n':
                depths.append(depth)
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
        depths.append(depth)

        problems = []
        for idx, d in enumerate(depths):
            if d != 0 or idx >= len(lines):
                continue
            # 找该顶层语句的最后一行非空、非注释
            last = None
            for ln in range(idx, -1, -1):
                t = lines[ln].strip()
                if t and not t.startswith('//'):
                    last = ln
                    break
            if last is None:
                continue
            t = lines[last].strip()
            if not t.endswith(';'):
                problems.append((last + 1, t[:70]))
        if problems:
            bad_total += len(problems)
            print(f'{path}: {len(problems)} top-level statement(s) missing semicolon:')
            for ln, t in problems:
                print(f'    line {ln}: {t}')
        else:
            print(f'{path}: all top-level statements end with ";"')
    sys.exit(1 if bad_total else 0)


if __name__ == '__main__':
    main()
