$ErrorActionPreference = 'Continue'
$root = 'D:\Project\TinyPage\tp\probe'
$out = Join-Path $env:TEMP 'wlwl_probe_out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$exe = 'D:\wlwl_v0.12.1\wlwl.exe'
Remove-Item -LiteralPath "$out\ts_o.txt","$out\ts_e.txt" -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $exe -ArgumentList @('run',"$root\probe_two_serve.wll") -PassThru -NoNewWindow -RedirectStandardOutput "$out\ts_o.txt" -RedirectStandardError "$out\ts_e.txt"
if (-not $p.WaitForExit(15000)) { $p.Kill(); 'TIMEOUT' } else { "exit=" + $p.ExitCode }
'--- stdout ---'
Get-Content -LiteralPath "$out\ts_o.txt" -Raw
'--- stderr ---'
Get-Content -LiteralPath "$out\ts_e.txt" -Raw
