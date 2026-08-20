param(
    [string]$Out = "beacon-inject.exe"
)
if (-not $env:GOROOT) { $env:GOROOT = "C:\Program Files\Go" }
if (-not $env:GOTMPDIR) { $env:GOTMPDIR = Join-Path $env:TEMP "opencode\gotmp" }
$buildID = -join ((1..16) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
if (Test-Path -LiteralPath $env:GOTMPDIR) {
    Get-ChildItem -LiteralPath $env:GOTMPDIR -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
& (Join-Path $env:GOROOT "bin\go.exe") build -tags inject -trimpath -buildvcs=false `
    -ldflags "-s -w -H windowsgui -buildid $buildID" -o $Out ./cmd/beacon
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "built $Out (inject, stripped, trimpath, gui, buildid=$buildID)"