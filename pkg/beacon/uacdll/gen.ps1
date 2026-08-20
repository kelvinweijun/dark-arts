$dll = Join-Path $PSScriptRoot 'darts_ucd.dll'
$out = Join-Path (Split-Path $PSScriptRoot -Parent) 'uac_daily_dll.go'
$bytes = [System.IO.File]::ReadAllBytes($dll)
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('// Code generated from uacdll/darts_ucd.dll. DO NOT EDIT.')
[void]$sb.AppendLine('package beacon')
[void]$sb.AppendLine()
[void]$sb.AppendLine('var uacDailyDLL = []byte{')
for ($i = 0; $i -lt $bytes.Length; $i += 16) {
  $part = $bytes[$i..([Math]::Min($i + 15, $bytes.Length - 1))]
  $hex = ($part | ForEach-Object { '0x{0:x2}' -f $_ }) -join ', '
  [void]$sb.AppendLine('	' + $hex + ',')
}
[void]$sb.AppendLine('}')
[System.IO.File]::WriteAllText($out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Write-Output "generated $out ($($bytes.Length) bytes)"