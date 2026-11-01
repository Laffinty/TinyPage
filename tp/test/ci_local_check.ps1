$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
Set-Location 'D:\Project\TinyPage'
$exe = 'D:\wlwl_v0.12.1\wlwl.exe'
$fail = 0

function Step($name, $block) {
    Write-Host "=== $name ==="
    try {
        & $block
        Write-Host "  -> PASS"
    } catch {
        Write-Host "  -> FAIL: $_"
        $script:fail++
    }
}

# ── 步骤 2：生成物一致性 ──────────────────────────────
Step 'regenerate + no drift' {
    python tp\test\gen_md_inline.py | Out-Null
    python tp\test\gen_test_md_inline.py | Out-Null
    python tp\test\gen_smoke.py | Out-Null
    # ⚠ 只查 **.wll 产物** —— 生成器自身的改动不算 drift
    $diff = git diff --stat -- 'tp/lib/*.wll' 'tp/test/*.wll'
    if ($diff) { throw "drift detected: $diff" }
}

# ── 步骤 3：静态检查 ────────────────────────────────
Step 'static checks' {
    $wll = @(Get-ChildItem -Path tp\lib, tp\test -Filter *.wll -File |
             Where-Object { $_.FullName -notlike '*broken*' })
    Write-Host "  files: $($wll.Count)"
    python tp\test\paren_check.py @($wll | ForEach-Object { $_.FullName })
    if ($LASTEXITCODE -ne 0) { throw 'paren_check failed' }
    python tp\test\check_semis.py @($wll | ForEach-Object { $_.FullName })
    if ($LASTEXITCODE -ne 0) { throw 'check_semis failed' }
    python tp\test\check_c_args.py tp\test\gen_md_inline.py
    if ($LASTEXITCODE -ne 0) { throw 'check_c_args gen_md_inline failed' }
    python tp\test\check_c_args.py tp\test\gen_test_md_inline.py
    if ($LASTEXITCODE -ne 0) { throw 'check_c_args gen_test failed' }
    python tp\test\check_c_args.py tp\test\gen_smoke.py
    if ($LASTEXITCODE -ne 0) { throw 'check_c_args gen_smoke failed' }
}

# ── 步骤 4：wlwl check ───────────────────────────────
Step 'wlwl check' {
    $wll = @(Get-ChildItem -Path tp\lib, tp\test -Filter *.wll -File |
             Where-Object { $_.FullName -notlike '*broken*' })
    foreach ($f in $wll) {
        & $exe check $f.FullName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "check failed: $($f.Name)" }
    }
    Write-Host "  checked $($wll.Count) files"
}

# ── 步骤 5：反向守卫 ─────────────────────────────────
Step 'reverse guard' {
    # ⚠ broken.wll 必然报错。PowerShell 会把 native 命令的 stderr 当成
    #   NativeCommandError 抛出（即使 2>&1 | Out-Null 也一样）⇒ step 会
    #   **误报红**。这里要的是**退出码**，所以用 cmd /c 绕开该行为。
    $ErrorActionPreference = 'Continue'
    $out = cmd /c "`"$exe`" check tp\test\broken\broken.wll 2>&1"
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -eq 0) { throw 'GUARD FAILED: broken.wll exited 0' }
    Write-Host "  broken.wll rejected with exit $code"
}

# ── 步骤 6：跑测试 ───────────────────────────────────
Step 'run tests' {
    & $exe run tp\test\smoke.wll | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "smoke failed exit=$LASTEXITCODE" }
    & $exe run tp\test\test_md_inline.wll | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "md_inline failed exit=$LASTEXITCODE" }
}

Write-Host ""
if ($fail -eq 0) { Write-Host "ALL CI STEPS PASSED LOCALLY" }
else { Write-Host "$fail CI STEP(S) FAILED"; exit 1 }
