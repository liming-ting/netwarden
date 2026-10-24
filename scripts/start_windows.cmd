@echo off
rem netwarden - double-click launcher for Windows + WSL.
rem If the dashboard already answers, just open it. Otherwise start scripts/start.sh
rem inside WSL in its own window (close that window or press Ctrl+C there to stop),
rem wait until the dashboard answers, then open the browser.
rem   NW_PORT     dashboard port (default 8787); extra arguments go to `netwarden run`.
rem   NW_NO_OPEN  set (e.g. by autostart_windows.cmd): start minimized, open no browser tab.
setlocal EnableExtensions
if not defined NW_PORT set "NW_PORT=8787"
set "URL=http://127.0.0.1:%NW_PORT%"
set "WINSTYLE="
if defined NW_NO_OPEN set "WINSTYLE=/min"

call :alive && goto open

rem This script lives in <repo>\scripts\ - resolve that folder as a WSL path.
set "HERE=%~dp0"
set "HERE=%HERE:~0,-1%"
set "WSLDIR="
for /f "usebackq delims=" %%P in (`wsl.exe wslpath -a "%HERE%"`) do set "WSLDIR=%%P"
if not defined WSLDIR (
    echo netwarden: WSL is not available - install it first: wsl --install
    pause
    exit /b 1
)

start "netwarden" %WINSTYLE% wsl.exe bash -lc "bash '%WSLDIR%/start.sh' --port %NW_PORT% %*"

rem Wait up to ~90 s (the first start may seed the demo database).
for /l %%i in (1,1,90) do (
    call :alive && goto open
    timeout /t 1 /nobreak >nul
)
echo netwarden did not answer on %URL% - see the "netwarden" window for details.
pause
exit /b 1

:open
if defined NW_NO_OPEN exit /b 0
start "" "%URL%/"
exit /b 0

:alive
curl.exe -s -f -m 2 -o nul "%URL%/api/meta" >nul 2>&1
exit /b %errorlevel%
