@echo off
cd /d "%~dp0.."
set DARK_ARTS_SERVER_URL=http://127.0.0.1:9002
set DARK_ARTS_API_KEY=opkey
go run ./cmd/console