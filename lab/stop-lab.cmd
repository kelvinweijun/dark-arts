@echo off
setlocal
cd /d "%~dp0"

set CLEAN=0
if /i "%~1"=="clean" set CLEAN=1

echo === dark-arts lab teardown ===
echo.

echo [1/4] killing local beacon processes...
powershell -NoProfile -Command "Get-Process beacon -ErrorAction SilentlyContinue | Stop-Process -Force"
echo   done.

echo [2/4] closing the reverse tunnel (ssh -R 7443 + tunnel windows)...
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'ssh.exe' -and $_.CommandLine -match '7443' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'cmd.exe' -and $_.CommandLine -match 'tunnel\.cmd' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
echo   done.

echo [3/4] stopping the docker stack...
docker compose down
if errorlevel 1 (
  echo   warning: docker compose down failed - is Docker Desktop running?
)

if %CLEAN%==1 (
  echo [4/4] clean mode: wiping volumes and local state...
  docker volume rm darkarts-lab_minio-data darkarts-lab_server-state >nul 2>&1
  if errorlevel 1 echo   warning: volume removal failed (containers may still hold them - retry after the stack is down)
  if exist "..\data\beacon" rmdir /s /q "..\data\beacon"
  if exist "..\data\server\state.json" del /q "..\data\server\state.json"
  echo   wiped: minio blobs, server engine state, beacon send markers.
) else (
  echo [4/4] kept: volumes and local state preserved (run "stop-lab clean" to wipe them)
)

echo.
echo done - stack stopped.
if %CLEAN%==0 echo restart with: docker compose up -d --build