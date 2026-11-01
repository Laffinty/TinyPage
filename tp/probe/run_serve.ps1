$ErrorActionPreference = 'Continue'
$root = 'D:\Project\TinyPage\tp\probe'
$out = Join-Path $env:TEMP 'wlwl_probe_out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$exe = 'D:\wlwl_v0.12.1\wlwl.exe'
Remove-Item -LiteralPath "$out\sv_o.txt","$out\sv_e.txt" -ErrorAction SilentlyContinue
$sv = Start-Process -FilePath $exe -ArgumentList @('run',"$root\probe_serve.wll") -PassThru -NoNewWindow -RedirectStandardOutput "$out\sv_o.txt" -RedirectStandardError "$out\sv_e.txt"
Start-Sleep -Milliseconds 900

'=== conn1 normal ==='
& curl.exe -s -S -m 5 'http://127.0.0.1:18470/alpha' 2>&1 | Out-String
"exit=$LASTEXITCODE"

'=== conn2 normal ==='
& curl.exe -s -S -m 5 'http://127.0.0.1:18470/beta' 2>&1 | Out-String
"exit=$LASTEXITCODE"

'=== conn3 garbage ==='
$bad = [System.Text.Encoding]::ASCII.GetBytes("GARBAGE-NOT-HTTP`r`n`r`n")
$tcp = New-Object System.Net.Sockets.TcpClient('127.0.0.1',18470)
$tcp.GetStream().Write($bad,0,$bad.Length)
$tcp.GetStream().Flush()
Start-Sleep -Milliseconds 300
$tcp.Close()
'garbage sent'

'=== conn4 after garbage ==='
& curl.exe -s -S -m 5 'http://127.0.0.1:18470/gamma' 2>&1 | Out-String
"exit=$LASTEXITCODE"

$sv.WaitForExit(12000) | Out-Null
if (-not $sv.HasExited) { $sv.Kill(); 'KILLED' }
'--- stdout ---'
Get-Content -LiteralPath "$out\sv_o.txt" -Raw
'--- stderr ---'
Get-Content -LiteralPath "$out\sv_e.txt" -Raw
