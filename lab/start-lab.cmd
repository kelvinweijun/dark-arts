@echo off
setlocal
cd /d "%~dp0.."

echo === Dark Arts lab: starting stack ===

docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Desktop is not running. Start Docker Desktop first, then run this again.
    pause
    exit /b 1
)

docker compose -f lab/docker-compose.yml up -d --build
if errorlevel 1 (
    echo [ERROR] compose up failed.
    pause
    exit /b 1
)

echo Waiting for server and relay to become healthy...
set /a tries=0
:wait
set /a tries+=1
if %tries% gtr 90 (
    echo [ERROR] timed out waiting for the stack. Check: docker compose -f lab/docker-compose.yml ps
    pause
    exit /b 1
)
ping -n 3 127.0.0.1 >nul
curl -s -m 2 http://127.0.0.1:9002/healthz | findstr /i "ok" >nul
if errorlevel 1 goto wait
curl -s -m 2 http://127.0.0.1:7443/healthz | findstr /i "ok" >nul
if errorlevel 1 goto wait

echo.
echo === READY ===
echo   server API  : http://127.0.0.1:9002   (Bearer key: opkey)
echo   relay       : http://127.0.0.1:7443   (beacon path)
echo   edge        : http://127.0.0.1:8443
echo   minio       : http://127.0.0.1:9001   (darkarts / dark-arts-lab)
echo   beacon pkg  : lab\laptop-pkg\beacon.exe  (double-click on target laptop)
echo.
echo Sessions:
curl -s -m 5 -H "Authorization: Bearer opkey" http://127.0.0.1:9002/api/v1/sessions
echo.
echo Reverse tunnel:
powershell -NoProfile -Command "if (Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'ssh.exe' -and $_.CommandLine -match '7443' }) { '  tunnel already running' } else { & schtasks /Run /TN dark-arts-reverse-tunnel 2>$null; if ($LASTEXITCODE -eq 0) { '  started scheduled tunnel task' } else { '  no tunnel running and no tunnel task installed - start one in the console:' ; '  dark-arts> tunnel <user@vps>' } }"
echo.
echo Open the operator console with:  lab\console.cmd
echo.
pause