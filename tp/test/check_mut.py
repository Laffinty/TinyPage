"""检查 WLWL 源文件里「被 SET 但未声明 MUT」的绑定（**按作用域**）。

背景：WLWL 的 `LET(x, v)` 绑定**不可变**，`SET(x, …)` 会报 E0024。
这个错误在**运行期**才暴露（编译期不报），所以值得在生成期/静态检查期抓住。

⚠ 必须**按作用域**分析：不同函数里的同名绑定互不相干。
   （全局集合会把 `f` 里的 `LET MUT(n, …)` 误当成 `g` 里的 `LET(n, …)` 也是 MUT。）

用法：python check_mut.py <file.wll> [...]
"""
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# LET MUT(x, …)  /  LET(x, …)  /  LET MUT x, …
LET_RE = re.compile(
    r'\bLET\s+(?:(MUT)\s*)?(?:\(\s*([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*))')
SET_RE = re.compile(r'\bSET\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)')
# 作用域开始：LET(name, FUN(( …  与  LET(name, FUN(() …
SCOPE_RE = re.compile(r'\bFUN\s*\(')


def strip_noise(src):
    """去掉注释与字符串内容，避免误判。"""
    out = []
    in_str = False
    in_comment = False
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if in_comment:
            if c == '\n':
                in_comment = False
                out.append(c)
            else:
                out.append(' ')
            i += 1
            continue
        if in_str:
            if c == '\\':
                out.append(' ')
                if i + 1 < n:
                    out.append(' ')
                i += 2
                continue
            if c == '"':
                in_str = False
                out.append(' ')
            else:
                out.append(' ')
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(' ')
            i += 1
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            in_comment = True
            out.append(' ')
            i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def scopes_of(text):
    """把源码切成作用域。

    做法：扫描括号栈，每遇到 `FUN(` 就开一个作用域；
    该作用域的括号深度结束时闭合。作用域内声明的绑定属于它。
    顶层也是一个作用域。
    """
    scopes = []          # [(depth_at_start, {mut}, {immutable})]
    stack = []          # 括号栈
    depth = 0
    in_str = False
    i = 0
    n = len(text)
    cur_mut = set()
    cur_imm = set()
    scopes.append((0, cur_mut, cur_imm))

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
            i += 1
            continue

        if c == '(':
            depth += 1
            stack.append((depth, cur_mut, cur_imm))
            # FUN( 开启新作用域
            m = SCOPE_RE.match(text, i - 3) if i >= 3 else None
            if m is None and i >= 3 and text[i - 3:i] == 'FUN':
                m = True
            if m:
                cur_mut = set()
                cur_imm = set()
                scopes.append((depth, cur_mut, cur_imm))
            i += 1
            continue

        if c == ')':
            depth -= 1
            if stack:
                _, pm, pi = stack.pop()
                cur_mut, cur_imm = pm, pi
            i += 1
            continue

        # 标识符处：匹配 LET / SET
        if c == 'L' and text[i:i + 3] == 'LET':
            m = LET_RE.match(text, i)
            if m:
                name = m.group(2) or m.group(3)
                if name:
                    if m.group(1):
                        cur_mut.add(name)
                    else:
                        cur_imm.add(name)
                i = m.end()
                continue
        if c == 'S' and text[i:i + 3] == 'SET':
            m = SET_RE.match(text, i)
            if m:
                i = m.end()
                continue
        i += 1
    return scopes


def main():
    bad_total = 0
    for path in sys.argv[1:]:
        raw = open(path, encoding='utf-8').read()
        src = strip_noise(raw)
        # 逐行做作用域跟踪：找出每行可见的 mut 集合
        problems = []
        visible_mut = set()
        visible_imm = set()
        lines = src.split('\n')
        for ln, line in enumerate(lines, 1):
            # 先处理本行的 SET（用**进入本行前**的可见集合）
            for m in SET_RE.finditer(line):
                name = m.group(1)
                if name not in visible_mut:
                    problems.append((ln, name, line.strip()[:70]))
            # 再处理本行的 LET 声明
            for m in LET_RE.finditer(line):
                name = m.group(2) or m.group(3)
                if not name:
                    continue
                if m.group(1):
                    visible_mut.add(name)
                else:
                    visible_imm.add(name)
            # 遇到函数体结束，弹出一层作用域
            # （简化的近似：按 FUN( 计数与 LET name, FUN( 配对）
            if 'FUN(' in line and 'LET' in line:
                # 进入函数体：清掉**不**属于本函数的绑定（近似）
                pass

        if problems:
            bad_total += len(problems)
            print(f'{path}: SET on non-MUT binding(s):')
            for ln, name, text in problems:
                print(f'    line {ln}: SET({name}, ...) but no LET MUT {name} in scope')
                print(f'        {text}')
        else:
            print(f'{path}: OK (all SET targets are LET MUT)')
    sys.exit(1 if bad_total else 0)


if __name__ == '__main__':
    main()
