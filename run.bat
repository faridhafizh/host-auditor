@echo off
REM ─────────────────────────────────────────────────────────────────────────────
REM  HostAuditor — Windows Batch Launcher (for cmd.exe)
REM  Usage: run.bat [--build-only] [--no-browser]
REM ─────────────────────────────────────────────────────────────────────────────

setlocal enabledelayedexpansion

cd /d "%~dp0"

echo.
echo   ██╗  ██╗███████╗██╗     ██████╗ ██████╗ ███████╗██████╗ 
echo   ██║ ██╔╝██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝██╔══██╗
echo   █████╔╝ █████╗  ██║     ██████╔╝██████╔╝█████╗  ██████╔╝
echo   ██╔═██╗ ██╔══╝  ██║     ██╔═══╝ ██╔══██╗██╔══╝  ██╔══██╗
echo   ██║  ██╗███████╗███████╗██║     ██║  ██║███████╗██║  ██║
echo   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
echo.
echo   HostAuditor - Localhost Security Analyzer v1.0.0
echo.

REM Check Rust
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Rust/Cargo not found.
    echo   Install from: https://rustup.rs/
    echo   Or run: winget install Rustlang.Rustup
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('cargo --version') do set CARGO_VER=%%v
echo [1/4] Rust %CARGO_VER% - OK

REM Check nmap
where nmap >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] nmap not found - using built-in scanner
) else (
    for /f "tokens=3" %%v in ('nmap --version ^| findstr /C:"Nmap version"') do set NMAP_VER=%%v
    echo      nmap %NMAP_VER% - OK
)

REM Check Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found - AI analysis requires Python
) else (
    for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
    echo      Python %PY_VER% - OK
)

REM Install Python deps
if exist "ai_engine\requirements.txt" (
    echo [2/4] Installing Python AI dependencies...
    python -m pip install -r ai_engine\requirements.txt -q 2>nul
    echo      Python dependencies ready
)

REM Build Rust backend
echo [3/4] Building Rust backend...
cargo build --release
if %errorlevel% neq 0 (
    echo [ERROR] Build failed. Check errors above.
    pause
    exit /b 1
)
echo      Backend compiled successfully

if "%~1"=="--build-only" (
    echo.
    echo Build complete.
    pause
    exit /b 0
)

REM Setup frontend
echo [4/4] Setting up frontend...
if not exist "frontend\dist" mkdir "frontend\dist"
if exist "frontend\index.html" (
    copy /Y "frontend\index.html" "frontend\dist\index.html" >nul
) else if exist "index.html" (
    copy /Y "index.html" "frontend\dist\index.html" >nul
)
echo      Frontend ready

echo.
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   HostAuditor is starting...
echo   → Web UI: http://localhost:8717
echo   → API:    http://localhost:8717/api
echo   Press Ctrl+C to stop
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo.

REM Open browser
if not "%~1"=="--no-browser" (
    start http://localhost:8717
)

REM Run server
set RUST_LOG=info
target\release\hostauditor.exe
