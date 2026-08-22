param(
    [Parameter(Mandatory = $true)][string]$UserHost,
    [string]$TaskName = "dark-arts-reverse-tunnel"
)
$ErrorActionPreference = "Stop"
$tunnel = Join-Path $PSScriptRoot "tunnel.cmd"
if (-not (Test-Path -LiteralPath $tunnel)) { throw "tunnel.cmd not found next to this script" }
schtasks /Create /F /SC ONLOGON /RL LIMITED /TN $TaskName /TR "cmd /c `"$tunnel $UserHost`""
if ($LASTEXITCODE -ne 0) { throw "schtasks failed" }
"installed scheduled task $TaskName (runs $tunnel $UserHost at logon)"
"start it now with:  schtasks /Run /TN $TaskName"
