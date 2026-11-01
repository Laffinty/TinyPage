"""检查 gen_*.py 里 fn(...) 调用的方括号是否平衡。

为什么需要：WLWL 源文件是 Python 生成的，**生成器本身有语法错误时**，
报错信息只说「closing parenthesis ']' does not match」，不指出哪个 fn 块。
本脚本按块报告，帮助快速定位。

用法：python check_gen_blocks.py <gen_*.py> [...]
"""
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

STR = re.compile(r'"(?:\\.|[^"\\])*"' r"|'(?:\\.|[^'\\])*'")


def mask(line):
    return STR.sub('""', line)


def main():
    bad = 0
    for path in sys.argv[1:]:
        lines = open(path, encoding='utf-8').read().split('\n')
        i = 0
        while i < len(lines):
            if 'fn(' in lines[i] and lines[i].lstrip().startswith(('src += fn(', 'src+=')):
                start = i
                depth = 0
                j = i
                closed = False
                while j < len(lines):
                    for ch in mask(lines[j]):
                        if ch == '[':
                            depth += 1
                        elif ch == ']':
                            depth -= 1
                    if depth == 0 and j > start:
                        closed = True
                        break
                    j += 1
                if not closed:
                    print(f'{path}: fn block starting line {start + 1} never closes '
                          f'(depth={depth} at EOF)')
                    bad += 1
                elif depth != 0:
                    print(f'{path}: fn block lines {start + 1}-{j + 1} ends at depth {depth}')
                    bad += 1
                i = j + 1
            else:
                i += 1
        print(f'{path}: scanned')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
