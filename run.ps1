#Requires -Version 5.1
# ─────────────────────────────────────────────────────────────────────────────
#  HostAuditor — Windows PowerShell Launcher Script
#  Usage: .\run.ps1 [-BuildOnly] [-NoBrowser]
# ─────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"

# ── Colors for output ─────────────────────────────────────────────────────────
function Write-Cyan { param($Message) Write-Host $Message -ForegroundColor Cyan }
function Write-Green { param($Message) Write-Host $Message -ForegroundColor Green }
function Write-Yellow { param($Message) Write-Host $Message -ForegroundColor Yellow }
function Write-Red { param($Message) Write-Host $Message -ForegroundColor Red }
function Write-Banner {
    Write-Host ""
    Write-Cyan "  ██╗  ██╗███████╗██╗     ██████╗ ██████╗ ███████╗██████╗ "
    Write-Cyan "  ██║ ██╔╝██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝██╔══██╗"
    Write-Cyan "  █████╔╝ █████╗  ██║     ██████╔╝██████╔╝█████╗  ██████╔╝"
    Write-Cyan "  ██╔═██╗ ██╔══╝  ██║     ██╔═══╝ ██╔══██╗██╔══╝  ██╔══██╗"
    Write-Cyan "  ██║  ██╗███████╗███████╗██║     ██║  ██║███████╗██║  ██║"
    Write-Cyan "  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"
    Write-Host ""
    Write-Host "  " -NoNewline
    Write-Host "HostAuditor - Localhost Security Analyzer" -NoNewline
    Write-Host " v1.0.0" -ForegroundColor Cyan
    Write-Host ""
}

# ── Parse parameters ──────────────────────────────────────────────────────────
param(
    [switch]$BuildOnly,
    [switch]$NoBrowser
)

Write-Banner

# ── Get script directory ──────────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

# ── Check dependencies ────────────────────────────────────────────────────────
Write-Yellow "[1/4] Checking dependencies..."

# Check Rust/Cargo
try {
    $cargoVersion = cargo --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $version = ($cargoVersion -split ' ')[1]
        Write-Green "  ✓ Rust $version"
    } else {
        throw "Cargo not found"
    }
} catch {
    Write-Red "✗ Rust/Cargo not found."
    Write-Host "  Install from: https://rustup.rs/"
    Write-Host "  Run in PowerShell: winget install Rustlang.Rustup"
    exit 1
}

# Check nmap
try {
    $nmapVersion = nmap --version 2>&1 | Select-Object -First 1
    if ($nmapVersion -match "Nmap version (\S+)") {
        Write-Green "  ✓ nmap $($matches[1]) (enhanced scanning)"
    } else {
        throw "nmap not found"
    }
} catch {
    Write-Yellow "  ⚠ nmap not found — using built-in scanner (install nmap for better results)"
    Write-Host "    Install: choco install nmap  OR  winget install Nmap"
}

# Check Python
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\S+)") {
        Write-Green "  ✓ Python $($matches[1]) (LangChain engine)"
    } else {
        throw "Python not found"
    }
} catch {
    try {
        $pythonVersion = python3 --version 2>&1
        if ($pythonVersion -match "Python (\S+)") {
            Write-Green "  ✓ Python $($matches[1]) (LangChain engine)"
        }
    } catch {
        Write-Yellow "  ⚠ Python not found — AI analysis requires Python"
    }
}

# ── Install Python deps ───────────────────────────────────────────────────────
if ((Test-Path "ai_engine\requirements.txt")) {
    Write-Yellow "[2/4] Installing Python AI dependencies..."
    try {
        $pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "python3" }
        & $pythonCmd -m pip install -r ai_engine\requirements.txt -q 2>&1 | Out-Null
        Write-Green "  ✓ Python dependencies ready"
    } catch {
        Write-Yellow "  ⚠ Some Python packages failed — AI analysis may be limited"
    }
}

# ── Build Rust backend ────────────────────────────────────────────────────────
Write-Yellow "[3/4] Building Rust backend..."
$cargoBuild = cargo build --release 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Green "  ✓ Backend compiled successfully"
} else {
    Write-Red "✗ Build failed. Check errors above."
    Write-Host $cargoBuild
    exit 1
}

if ($BuildOnly) {
    Write-Host ""
    Write-Green "Build complete."
    exit 0
}

# ── Setup frontend ────────────────────────────────────────────────────────────
Write-Yellow "[4/4] Setting up frontend..."
if (-not (Test-Path "frontend\dist")) {
    New-Item -ItemType Directory -Path "frontend\dist" -Force | Out-Null
}
if (Test-Path "frontend\index.html") {
    Copy-Item "frontend\index.html" "frontend\dist\index.html" -Force
} elseif (Test-Path "index.html") {
    Copy-Item "index.html" "frontend\dist\index.html" -Force
}
Write-Green "  ✓ Frontend ready"

# ── Launch ────────────────────────────────────────────────────────────────────
$PORT = 8717
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Green "  HostAuditor is starting..."
Write-Cyan "  → Web UI: http://localhost:$PORT"
Write-Cyan "  → API:    http://localhost:$PORT/api"
Write-Host "  Press Ctrl+C to stop"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""

# Open browser after 2s delay
if (-not $NoBrowser) {
    Start-Job -ScriptBlock {
        Start-Sleep -Seconds 2
        Start-Process "http://localhost:$($args[0])"
    } -ArgumentList $PORT | Out-Null
}

$env:RUST_LOG = "info"
& .\target\release\hostauditor.exe
