$ErrorActionPreference = 'Continue'
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

# --- step 1: generated artifacts must match their generators ---
Step 'regenerate + no drift' {
    python tp\test\gen_md_inline.py | Out-Null
    python tp\test\gen_test_md_inline.py | Out-Null
    python tp\test\gen_smoke.py | Out-Null
    # only the .wll products count as drift - generator edits are expected
    $diff = git diff --stat -- 'tp/lib/*.wll' 'tp/test/*.wll'
    if ($diff) { throw "drift detected: $diff" }
}

# --- step 2: static checks ---
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

# --- step 3: compile ---
Step 'wlwl check' {
    $wll = @(Get-ChildItem -Path tp\lib, tp\test -Filter *.wll -File |
             Where-Object { $_.FullName -notlike '*broken*' })
    foreach ($f in $wll) {
        & $exe check $f.FullName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "check failed: $($f.Name)" }
    }
    Write-Host "  checked $($wll.Count) files"
}

# --- step 4: reverse guard ---
# NOTE: the exit code must be read via **cmd** - PowerShell (incl. pwsh 7)
#   turns native stderr into an error stream and throws under
#   $ErrorActionPreference='Stop' => the step would report red.
#   CI uses shell: cmd there too; this script runs the same cmd block so we
#   know it really works before pushing.
# NOTE: stderr must be dropped INSIDE cmd (2>nul) - if it reaches
#   PowerShell it becomes an exception and this step reports red.
Step 'reverse guard' {
    $ciBlock = @'
call :guard tp\test\broken\broken.wll
exit /b %ERRORLEVEL%

:guard
wlwl.exe check %1
if %ERRORLEVEL% EQU 0 (
  echo ::error::GUARD FAILED: %1 passed wlwl check
  exit /b 1
)
echo guard OK: %1 rejected with exit %ERRORLEVEL%
exit /b 0
'@
    $tmp = Join-Path $env:TEMP 'ci_guard_sim.cmd'
    [System.IO.File]::WriteAllText($tmp, $ciBlock, (New-Object System.Text.UTF8Encoding($false)))
    $env:PATH = (Split-Path -Parent $exe) + ';' + $env:PATH
    cmd /c "`"$tmp`" 2>nul" | Out-Null
    $code = $LASTEXITCODE
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if ($code -ne 0) { throw "guard block failed (exit $code)" }
    Write-Host "  broken.wll rejected; CI cmd block exits 0"
}

# --- step 5: run the tests ---
Step 'run tests' {
    & $exe run tp\test\smoke.wll | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "smoke failed exit=$LASTEXITCODE" }
    & $exe run tp\test\test_md_inline.wll | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "md_inline failed exit=$LASTEXITCODE" }
}

Write-Host ""
if ($fail -eq 0) { Write-Host "ALL CI STEPS PASSED LOCALLY" }
else { Write-Host "$fail CI STEP(S) FAILED"; exit 1 }
