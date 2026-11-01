$ErrorActionPreference = 'Continue'
$root = 'D:\Project\TinyPage\tp\probe'
$out = Join-Path $env:TEMP 'wlwl_probe_out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$exe  = 'D:\wlwl_v0.12.1\wlwl.exe'
$dll  = 'D:\wlwl_v0.12.1\lib\wlwl_tls.dll'
$sha  = '202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b'

Remove-Item -LiteralPath "$out\tls_out.txt","$out\tls_err.txt" -ErrorAction SilentlyContinue

$p = Start-Process -FilePath $exe `
  -ArgumentList @('run','--ext',$dll,'--ext-sha256',$sha,"$root\tls_probe.wll") `
  -PassThru -NoNewWindow -RedirectStandardOutput "$out\tls_out.txt" -RedirectStandardError "$out\tls_err.txt"

Start-Sleep -Milliseconds 1500

"=== curl -k (跳过证书校验) ==="
& curl.exe -k -s -S -m 8 --http1.1 'https://127.0.0.1:18461/hello' 2>&1 | Out-String
"curl_exit=$LASTEXITCODE"

"=== curl 严格校验（应失败，证明是真 TLS 且证书自签） ==="
& curl.exe -s -S -m 8 'https://127.0.0.1:18461/' 2>&1 | Out-String
"curl_strict_exit=$LASTEXITCODE"

$p.WaitForExit(15000) | Out-Null
if (-not $p.HasExited) { $p.Kill(); "PROC_KILLED" }

"=== wlwl stdout ==="
Get-Content -LiteralPath "$out\tls_out.txt" -Raw -ErrorAction SilentlyContinue
"=== wlwl stderr ==="
Get-Content -LiteralPath "$out\tls_err.txt" -Raw -ErrorAction SilentlyContinue
"exit=$($p.ExitCode)"
