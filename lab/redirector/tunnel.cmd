@echo off
rem Dark Arts reverse-tunnel client (Windows, lab host).
rem Usage: tunnel.cmd <user@vps>
rem Keeps ssh -R 7443:127.0.0.1:7443 alive; reconnect every 5s on failure.
setlocal
:loop
ssh -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o ConnectTimeout=15 -R 7443:127.0.0.1:7443 %1
echo tunnel dropped, reconnecting in 5s...
timeout /t 5 /nobreak >nul
goto loop
