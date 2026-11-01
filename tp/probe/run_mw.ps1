$ErrorActionPreference = 'Continue'
$root = 'D:\Project\TinyPage\tp\probe'
$out = Join-Path $env:TEMP 'wlwl_probe_out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$exe  = 'D:\wlwl_v0.12.1\wlwl.exe'
$dll  = 'D:\wlwl_v0.12.1\lib\wlwl_tls.dll'
$sha  = '202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b'

Remove-Item -LiteralPath "$out\up_out.txt","$out\up_err.txt","$out\mw_out.txt","$out\mw_err.txt" -ErrorAction SilentlyContinue

$up = Start-Process -FilePath $exe -ArgumentList @('run',"$root\upstream.wll") -PassThru -NoNewWindow `
      -RedirectStandardOutput "$out\up_out.txt" -RedirectStandardError "$out\up_err.txt"
Start-Sleep -Milliseconds 800

$mw = Start-Process -FilePath $exe `
      -ArgumentList @('run','--ext',$dll,'--ext-sha256',$sha,"$root\tls_middleware.wll") `
      -PassThru -NoNewWindow -RedirectStandardOutput "$out\mw_out.txt" -RedirectStandardError "$out\mw_err.txt"
Start-Sleep -Milliseconds 1200

"=== 1) 第一跳（-k）：TLS 终止 + 转发上游 ==="
& curl.exe -k -s -S -m 8 'https://127.0.0.1:18462/one' 2>&1 | Out-String
"exit=$LASTEXITCODE"

"=== 2) 第二跳（-k -v）：TLS 版本/套件/证书链 ==="
$v = & curl.exe -k -v -m 8 'https://127.0.0.1:18462/two' 2>&1 | Out-String
($v -split "`r?`n" | Select-String -Pattern 'SSL connection|TLSv1|ALPN|subject:|issuer:|HTTP/1.1 200|X-Middleware' | Select-Object -First 8) -join "`n"

"=== 3) 严格校验（应失败：自签证书不被信任 = 真 TLS） ==="
& curl.exe -s -S -m 8 'https://127.0.0.1:18462/three' 2>&1 | Select-Object -First 2 | Out-String
"exit=$LASTEXITCODE"

Start-Sleep -Milliseconds 600
$mw.WaitForExit(3000) | Out-Null
if (-not $mw.HasExited) { $mw.Kill(); "MW_KILLED(仍在监听，符合预期)" }
$up.Kill()

"=== 中间件 stdout ==="
Get-Content -LiteralPath "$out\mw_out.txt" -Raw -ErrorAction SilentlyContinue
"=== 中间件 stderr ==="
Get-Content -LiteralPath "$out\mw_err.txt" -Raw -ErrorAction SilentlyContinue
