"""把 WLWL 源文件按顶层 LET 切成单函数文件，逐个用 wlwl check 验证。

为什么需要：括号平衡 ≠ 结构正确。WLWL 的括号诊断（E0011）只说
「expected ')' got X」，不指出是哪一层；手调括号会来回摇摆。
**让编译器逐函数说话**是唯一可靠的办法。

用法：python check_funcs.py <file.wll> [--exe <wlwl.exe>]
"""
import os
import re
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paren_check import strip_comments


def split_top_level(raw):
    """按顶层语句切分，返回 [(起始行, 结束行, 源码块)]。"""
    code, _ = strip_comments(raw)
    lines = raw.split('\n')
    # 计算每行结束时的深度
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

    blocks = []
    start = 0
    for idx, d in enumerate(depths):
        if d == 0 and idx + 1 < len(depths):
            chunk = '\n'.join(lines[start:idx + 1])
            if chunk.strip():
                blocks.append((start + 1, idx + 1, chunk))
            start = idx + 1
    if start < len(lines):
        chunk = '\n'.join(lines[start:])
        if chunk.strip():
            blocks.append((start + 1, len(lines), chunk))
    return blocks


def main():
    path = sys.argv[1]
    exe = 'D:\\wlwl_v0.12.1\\wlwl.exe'
    if '--exe' in sys.argv:
        exe = sys.argv[sys.argv.index('--exe') + 1]

    raw = open(path, encoding='utf-8').read()
    blocks = split_top_level(raw)

    # 收集文件头部的 IMPORT（每个单函数文件都需要）
    imports = [b[2] for b in blocks if b[2].lstrip().startswith('IMPORT(')]

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        for start, end, chunk in blocks:
            first = chunk.strip().split('\n')[0][:60]
            m = re.match(r'LET\((\w+)', chunk.strip())
            name = m.group(1) if m else first
            # 组合：所有 IMPORT + 该块
            src = '\n'.join(imports) + '\n' + chunk + '\n'
            f = os.path.join(td, 'fn.wll')
            open(f, 'w', encoding='utf-8', newline='\n').write(src)
            r = subprocess.run([exe, 'check', f], capture_output=True, text=True,
                               encoding='utf-8', errors='replace')
            if r.returncode == 0:
                print(f'  OK    lines {start}-{end}: {name}')
            else:
                failures += 1
                print(f'  FAIL  lines {start}-{end}: {name}')
                err = (r.stderr or '').strip()
                # 只留关键行
                for ln in err.split('\n')[:12]:
                    if ln.strip():
                        print(f'        {ln}')

    print(f'\n{len(blocks) - failures}/{len(blocks)} blocks OK')
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
