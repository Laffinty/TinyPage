"""检查 gen_md_inline.py 里 C(...) 调用的字符串参数是否有多余右括号。

背景：参数文本按顶层逗号拆分后直接拼进调用，所以文本里的括号必须
与调用自身的括号**配平**。多写一个 ')' 就会让生成结果多关一层。

用法：python check_c_args.py <gen_*.py>
"""
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


def main():
    pat = re.compile(r"C\('(\w+)', '([^']*)'")
    bad = 0
    for path in sys.argv[1:]:
        for i, line in enumerate(open(path, encoding='utf-8').read().split('\n'), 1):
            for m in pat.finditer(line):
                name, text = m.group(1), m.group(2)
                # 统计括号与引号内的括号
                depth = 0
                in_str = False
                j = 0
                while j < len(text):
                    c = text[j]
                    if in_str:
                        if c == '\\':
                            j += 2
                            continue
                        if c == '"':
                            in_str = False
                        j += 1
                        continue
                    if c == '"':
                        in_str = True
                    elif c == '(':
                        depth += 1
                    elif c == ')':
                        depth -= 1
                    j += 1
                if depth != 0:
                    bad += 1
                    print(f'{path}:{i}: C(\'{name}\', ...) unbalanced (depth={depth})')
                    print(f'    {text}')
    print('OK' if not bad else f'{bad} problem(s)')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
