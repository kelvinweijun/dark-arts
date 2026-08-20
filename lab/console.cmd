@echo off
cd /d "%~dp0.."
set DARKARTS_SERVER_URL=http://127.0.0.1:9002
set DARKARTS_API_KEY=opkey
go run ./cmd/console