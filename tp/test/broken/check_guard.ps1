$ErrorActionPreference = 'Continue'
$exe = 'D:\wlwl_v0.12.1\wlwl.exe'
$broken = 'D:\Project\TinyPage\tp\test\broken\broken.wll'

'=== check must FAIL (non-zero exit) ==='
& $exe check $broken 2>&1 | Out-String
"check_exit=$LASTEXITCODE"

'=== run must also FAIL (non-zero exit) ==='
& $exe run $broken 2>&1 | Out-String
"run_exit=$LASTEXITCODE"

if ($LASTEXITCODE -eq 0) {
  'GUARD FAIL: broken file exited 0'
} else {
  'GUARD OK: broken file exited non-zero'
}
