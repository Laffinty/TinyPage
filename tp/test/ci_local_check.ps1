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
# auto-discover: every tp/test/gen_*.py (incl. gen_test_*.py and
# gen_*_baseline.py) - new modules are covered without editing this script
#
# NOTE: this step deliberately does NOT use `git diff` like the GitHub
# workflow does. In CI the checkout is clean, so "regenerate then git diff"
# correctly means "committed artifacts != generator output". LOCALLY you
# almost always have legitimate uncommitted work, so git diff against HEAD
# would report that work as "drift" and this gate could never pass before a
# commit - useless as a pre-commit check. The real question is:
#   do the generators reproduce the CURRENT content of these files?
# so snapshot SHA256 before, regenerate, compare after.
Step 'regenerate + no drift' {
    $gens = @(Get-ChildItem -Path tp\test -Filter 'gen_*.py' -File | Sort-Object Name)
    if ($gens.Count -eq 0) { throw 'no generators found' }
    function Artifacts {
        @(Get-ChildItem tp\lib -Filter *.wll -File) +
        @(Get-ChildItem tp\test -Filter *.wll -File) +
        @(Get-ChildItem tp\test\fixtures -Filter *.json -File)
    }
    $before = @{}
    foreach ($f in Artifacts) { $before[$f.FullName] = (Get-FileHash $f.FullName -Algorithm SHA256).Hash }
    foreach ($g in $gens) {
        python $g.FullName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "generator failed: $($g.Name)" }
    }
    $drift = @()
    foreach ($f in Artifacts) {
        $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
        if ($before[$f.FullName] -ne $h) { $drift += $f.Name }
    }
    if ($drift) { throw "drift detected (generators changed them): $($drift -join ', ')" }
    Write-Host "  $($gens.Count) generators, $($before.Count) artifacts, no drift"
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
    $gens = @(Get-ChildItem -Path tp\test -Filter 'gen_*.py' -File | Sort-Object Name)
    foreach ($g in $gens) {
        python tp\test\check_c_args.py $g.FullName
        if ($LASTEXITCODE -ne 0) { throw "check_c_args failed: $($g.Name)" }
    }
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
    $tests = @(Get-ChildItem -Path tp\test -Filter 'test_*.wll' -File | Sort-Object Name)
    foreach ($t in $tests) {
        & $exe run $t.FullName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "$($t.Name) failed exit=$LASTEXITCODE" }
    }
    Write-Host "  $($tests.Count + 1) test file(s) passed"
}

Write-Host ""
if ($fail -eq 0) { Write-Host "ALL CI STEPS PASSED LOCALLY" }
else { Write-Host "$fail CI STEP(S) FAILED"; exit 1 }
