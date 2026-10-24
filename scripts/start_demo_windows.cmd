@echo off
rem netwarden - double-click launcher for the DEMO home (synthetic data, no loops).
rem Runs on its own port (8788) so it never gets mixed up with your real dashboard
rem on 8787. Seeds data/demo.db first if it is missing.
setlocal
set "NW_PORT=8788"
call "%~dp0start_windows.cmd" --demo
