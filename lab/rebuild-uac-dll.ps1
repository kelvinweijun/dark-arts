param(
    [string]$Gcc = "",
    [switch]$SkipBeacon
)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$go = "C:\Program Files\Go\bin\go.exe"

if ([string]::IsNullOrWhiteSpace($Gcc)) {
    $candidates = @(
        "C:\Users\kelvi\w64devkit\w64devkit\bin\gcc.exe",
        (Join-Path $env:USERPROFILE "w64devkit\w64devkit\bin\gcc.exe")
    )
    $Gcc = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($Gcc) -or -not (Test-Path -LiteralPath $Gcc)) {
    throw "gcc not found - pass -Gcc <path\to\gcc.exe> or install w64devkit"
}
$env:Path = "$(Split-Path -Parent $Gcc);$env:Path"

$src = Join-Path $repo "pkg\beacon\uacdll\darts_ucd.c"
$dll = Join-Path $repo "pkg\beacon\uacdll\darts_ucd.dll"
& $Gcc -shared -O2 -o $dll $src
if ($LASTEXITCODE -ne 0) { throw "gcc failed" }
"compiled $dll"

& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "pkg\beacon\uacdll\gen.ps1")
if ($LASTEXITCODE -ne 0) { throw "gen.ps1 failed" }

if (-not $SkipBeacon) {
    & $go build ./pkg/beacon/
    if ($LASTEXITCODE -ne 0) { throw "go build ./pkg/beacon/ failed" }
    "go build ./pkg/beacon/ ok"
}

"--- next: bake it into a beacon.exe and re-register the same identity ---"
"  package -Seed <seed>"