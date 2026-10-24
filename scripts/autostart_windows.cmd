@echo off
rem netwarden - start the dashboard when you sign in to Windows (optional, off by default).
rem   scripts\autostart_windows.cmd install     add a "netwarden" shortcut to your Startup folder
rem   scripts\autostart_windows.cmd uninstall   remove that shortcut
rem   scripts\autostart_windows.cmd status      say whether it is installed (exit 0 = yes, 1 = no)
rem   add --dry-run to install / uninstall to only print what would happen ("[dry run] ...").
rem The shortcut runs "autostart_windows.cmd run" = start_windows.cmd with NW_NO_OPEN=1:
rem netwarden starts in a minimized window and no browser tab opens. Nothing else changes:
rem no service, no registry, no admin rights; uninstall (or deleting the shortcut) undoes it.
rem   NW_STARTUP_DIR  folder for the shortcut (default: your Startup folder) - for tests.
rem Messages come from netwarden\locales\<lang>.json (keys autostart.*): the language is
rem NETWARDEN_LANG, else the Windows display language, else English (NW_UI_CULTURE
rem stands in for the display language in tests). See :msg below.
setlocal EnableExtensions
set "ACTION="
set "DRY="
for %%A in (%*) do (
    if /i "%%~A"=="--dry-run" (set "DRY=1") else if not defined ACTION set "ACTION=%%~A"
)
if not defined ACTION set "ACTION=status"

set "NW_HERE=%~dp0"
set "NW_ME=%~f0"
set "NW_CMD=%~nx0"
if not defined NW_STARTUP_DIR set "NW_STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "NW_LINK=%NW_STARTUP_DIR%\netwarden.lnk"

rem The message helper (PowerShell, read-only): pick the locale file, print one string.
set "NW_PS=$d = Join-Path $env:NW_HERE '..\netwarden\locales'; $ui = $env:NW_UI_CULTURE; if (-not $ui) { $ui = (Get-UICulture).Name }; $pick = 'en'; foreach ($x in @($env:NETWARDEN_LANG, $ui)) { if (-not $x) { continue }; $x = $x.Trim().ToLower().Replace('_', '-'); $p = $x.Split('-')[0]; if ($x -match '^zh-(tw|hk|mo|hant)') { $m = 'zh-Hant' } elseif ($p -eq 'zh') { $m = 'zh-Hans' } elseif ($p -eq 'pt') { $m = 'pt-BR' } else { $m = $p }; if ($m -match '^[a-z]{2,3}(-[A-Za-z]{2,4})?$' -and (Test-Path -LiteralPath (Join-Path $d ($m + '.json')))) { $pick = $m; break } }; $k = $env:NW_KEY; $s = $null; foreach ($c in @($pick, 'en')) { try { $j = [IO.File]::ReadAllText((Join-Path $d ($c + '.json')), [Text.Encoding]::UTF8) | ConvertFrom-Json; $s = $j.$k } catch { }; if ($s) { break } }; if (-not $s) { $s = $k }; $s = $s.Replace('{path}', [string]$env:NW_ARG).Replace('{cmd}', [string]$env:NW_CMD); if ([Console]::IsOutputRedirected) { $b = [Text.Encoding]::UTF8.GetBytes($s + [Environment]::NewLine); $o = [Console]::OpenStandardOutput(); $o.Write($b, 0, $b.Length); $o.Flush() } else { Write-Host $s }"

if /i "%ACTION%"=="install" goto install
if /i "%ACTION%"=="uninstall" goto uninstall
if /i "%ACTION%"=="status" goto status
if /i "%ACTION%"=="run" goto run
call :msg autostart.usage
exit /b 2

:install
if defined DRY goto install_dry
if not exist "%NW_STARTUP_DIR%\" (
    call :msg autostart.no_folder "%NW_STARTUP_DIR%"
    exit /b 1
)
powershell.exe -NoProfile -NonInteractive -Command "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:NW_LINK); $s.TargetPath = $env:NW_ME; $s.Arguments = 'run'; $s.WorkingDirectory = $env:NW_HERE; $s.WindowStyle = 7; $s.Description = 'netwarden dashboard'; $s.Save()"
if errorlevel 1 (
    call :msg autostart.failed
    exit /b 1
)
call :msg autostart.installed
call :msg autostart.shortcut "%NW_LINK%"
call :msg autostart.undo
exit /b 0

:install_dry
call :msg autostart.dry_create "%NW_LINK%"
call :msg autostart.dry_target "%NW_ME%"
exit /b 0

:uninstall
if not exist "%NW_LINK%" (
    call :msg autostart.nothing
    exit /b 0
)
if defined DRY (
    call :msg autostart.dry_delete "%NW_LINK%"
    exit /b 0
)
del /q "%NW_LINK%"
call :msg autostart.removed
exit /b 0

:status
if exist "%NW_LINK%" (
    call :msg autostart.status_on "%NW_LINK%"
    exit /b 0
)
call :msg autostart.status_off
exit /b 1

:run
set "NW_NO_OPEN=1"
call "%NW_HERE%start_windows.cmd"
exit /b %errorlevel%

rem :msg <key> ["path"] - one localized line; falls back to the bare key if PowerShell fails.
:msg
set "NW_KEY=%~1"
set "NW_ARG=%~2"
powershell.exe -NoProfile -NonInteractive -Command "%NW_PS%" 2>nul || echo %~1 %~2
goto :eof
