@echo off
rem ==========================================================================
rem  YinShi Mesh Launcher -- TUI
rem
rem  Single purpose: start the TUI. No mode menu, no WebUI.
rem
rem  Encoding: pure ASCII, no BOM, CRLF. cmd.exe reads .bat in the OEM
rem  codepage (936 on zh-CN); a UTF-8 BOM is echoed as garbage and a CJK
rem  literal cannot match. The main program is found by wildcard because
rem  its filename is Chinese and therefore unmatchable from here.
rem
rem  Main program resolution: first .py in src\, skipping __pycache__.
rem  The old `for /r %%f in (*.py)` took the LAST match anywhere under the
rem  workspace, which only worked by luck -- .migration\ and .workbuddy\
rem  hold ~17 other .py files.
rem ==========================================================================
setlocal EnableExtensions EnableDelayedExpansion

set "WT=%LOCALAPPDATA%\Microsoft\WindowsApps\wt.exe"
set "PY=C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe"
set "DIR=%~dp0."

rem ---- locate main program ----
set "MAIN="
for %%f in ("%~dp0src\*.py") do (
    if not defined MAIN (
        set "CAND=%%~ff"
        set "SKIP="
        echo !CAND! | findstr /i /c:"\__pycache__\" >nul && set "SKIP=1"
        if not defined SKIP set "MAIN=!CAND!"
    )
)
if not defined MAIN (
    echo [ERROR] No main program found in "%~dp0src\".
    pause
    exit /b 1
)
if not exist "%PY%" (
    echo [ERROR] Python not found: %PY%
    pause
    exit /b 1
)

rem ---- admin check: already elevated? ----
if /i "%~1"=="--elevated-launch" goto :RUN
net session >nul 2>&1
if %errorlevel%==0 goto :RUN

rem ---- not admin: re-launch self via UAC ----
echo [UAC] Requesting administrator privileges...
set "SCRIPT=%~f0"
powershell -NoProfile -Command "Start-Process cmd -Verb RunAs -ArgumentList '/c \"\"%SCRIPT%\" --elevated-launch\"'"
exit /b

:RUN
if not exist "%WT%" (
    echo [WARN] Windows Terminal not found, fallback to cmd.
    cd /d "%~dp0"
    "%PY%" "%MAIN%"
    pause
    exit /b
)
start "" "%WT%" -d "%DIR%" cmd /k ""%PY%" "%MAIN%""
exit /b