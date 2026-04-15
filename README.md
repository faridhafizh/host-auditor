# 🛡️ HostAuditor — Localhost Security Analyzer

A professional-grade vulnerability scanner for `localhost` / `127.0.0.1` with an AI-powered report engine built with **Rust** (Axum backend) and **Python LangChain** (AI analysis). HostAuditor provides comprehensive security auditing for your local host environment.

---

## ✨ Features

| Feature | Details |
|---------|---------|
| 🔍 **Port Discovery** | nmap integration + built-in TCP scanner |
| 🌐 **Web Vulnerability Checks** | Security headers, exposed paths (.env, .git, admin panels) |
| 🗄️ **Service Fingerprinting** | Redis, MongoDB, Elasticsearch, MySQL, PostgreSQL, etc. |
| 🤖 **AI Analysis** | LangChain-powered deep analysis with any AI provider |
| 📄 **Report Generation** | Full markdown report with CVEs, CVSS scores, remediation roadmap |
| ⚡ **Real-time UI** | Professional dark-mode WebUI with live scan progress |
| 🔄 **Multi-Provider AI** | OpenAI, Anthropic, Groq (free), Together AI, OpenRouter, Ollama |

---

## 🚀 Quick Start

### Prerequisites

```bash
# 1. Install Rust
# Windows (PowerShell):
winget install Rustlang.Rustup
# Linux/macOS:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install Python (for AI engine)
# Windows:
winget install Python.Python.3.12
# Python 3.9+ required

# 3. (Optional but recommended) Install nmap
winget install Nmap              # Windows
choco install nmap               # Windows (Chocolatey)
sudo apt install nmap            # Ubuntu/Debian
brew install nmap                # macOS
```

### Launch

```bash
# Windows (PowerShell)
.\run.ps1

# Windows (Command Prompt)
run.bat

# Linux/macOS
chmod +x run.sh
./run.sh

# Manual build
cargo build --release
mkdir -p frontend/dist && cp frontend/index.html frontend/dist/
RUST_LOG=info ./target/release/hostauditor
```

Open http://localhost:8717 in your browser.

📖 **Detailed Windows setup:** See [WINDOWS_SETUP.md](WINDOWS_SETUP.md)

---

## 🤖 AI Provider Setup

Go to **AI Config** tab in the UI and select your provider:

### Free Options

| Provider | Free Tier | How to Get Key |
|----------|-----------|----------------|
| **Groq** | ✅ Generous free tier | [console.groq.com](https://console.groq.com) |
| **OpenRouter** | ✅ Free models available | [openrouter.ai](https://openrouter.ai) |
| **Together AI** | ✅ $1 free credit | [api.together.xyz](https://api.together.xyz) |
| **Ollama** | ✅ Fully local, no key | [ollama.ai](https://ollama.ai) |

### Paid Options

| Provider | Model | Notes |
|----------|-------|-------|
| **OpenAI** | `gpt-4o-mini` | Best accuracy |
| **Anthropic** | `claude-3-haiku-20240307` | Great security analysis |

### Ollama (Fully Local)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3.2
ollama pull mistral

# In UI: select Ollama, set Base URL to http://localhost:11434/v1
```

---

## 🔍 Scan Types

| Mode | Description | Time |
|------|-------------|------|
| **Quick** ⚡ | Ports 1-1024 + web checks | ~30s |
| **Full** 🔍 | Ports 1-65535 comprehensive | ~2-5min |
| **Web** 🌐 | HTTP/HTTPS vulnerability focus | ~45s |
| **All** 🎯 | Everything: ports + services + web | ~3-7min |

---

## 🏗️ Architecture

```
hostauditor/
├── src/
│   └── main.rs              # Rust backend (Axum HTTP server)
│                            # - Port scanning (nmap + built-in)
│                            # - Web vulnerability checks
│                            # - Service fingerprinting
│                            # - AI integration (direct API)
├── ai_engine/
│   ├── engine.py            # LangChain AI analysis engine
│   └── requirements.txt     # Python dependencies
├── frontend/
│   └── index.html           # Single-file WebUI
├── Cargo.toml               # Rust project configuration
├── run.ps1                  # Windows PowerShell launcher
├── run.bat                  # Windows CMD launcher
└── README.md                # Main documentation
```

### API Endpoints

```
GET  /api/health              - Health check
GET  /api/config              - Get AI config
POST /api/config              - Set AI config
GET  /api/scans               - List all scans
POST /api/scans               - Start new scan
GET  /api/scans/:id           - Get scan details
DEL  /api/scans/:id           - Delete scan
GET  /api/scans/:id/report    - Get markdown report
```

---

## 🛡️ What Gets Scanned

### Port & Service Checks
- All TCP ports (quick: 1-1024, full: 1-65535)
- Service version detection via nmap
- Dangerous open ports: Telnet (23), FTP (21), RDP (3389), VNC (5900)
- Exposed databases: Redis (6379), MongoDB (27017), Elasticsearch (9200), MySQL (3306)

### Web Vulnerability Checks
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Exposed sensitive files: `.env`, `.git/HEAD`, `.htaccess`
- Admin panels: `/admin`, `/wp-admin`, `/actuator`
- Debug/info endpoints: `/phpinfo.php`, `/swagger-ui.html`, `/debug`
- Unauthenticated APIs

### AI-Enhanced Analysis
- CVE cross-referencing
- CVSS scoring
- Attack chain scenarios
- Prioritized remediation roadmap

---

## 📄 Sample Report

The AI engine generates reports like:

```markdown
# Security Vulnerability Assessment Report

**Target:** 127.0.0.1
**Overall Risk:** HIGH
**Risk Score:** 72/100

## Executive Summary
The scan identified 14 vulnerabilities across 3 severity levels...

## Attack Scenarios
### Redis → RCE via Cron Job Injection
An unauthenticated Redis instance (port 6379) allows an attacker...

## Detailed Findings
### 1. 🔴 Unauthenticated Redis Exposure
**Severity:** CRITICAL (CVSS: 9.8)
**CVE:** CVE-2022-0543, CVE-2023-28425
...
```

---

## ⚠️ Legal Notice

This tool is designed for scanning **your own localhost/127.0.0.1 only**. 
Only scan systems you own or have explicit written permission to test.
Unauthorized port scanning may be illegal in your jurisdiction.

---

## 🔧 Troubleshooting

**Backend won't start:**
```powershell
# Windows - Check if port 8717 is in use
netstat -ano | findstr :8717
taskkill /PID <PID> /F
```

**Scan finds nothing:**
```powershell
# Windows - Check if nmap is available
nmap --version
# Or run a test scan
nmap -sV -p 1-1024 127.0.0.1
```

**AI analysis fails:**
- Verify your API key is correct
- Check network connectivity to the AI provider
- For Ollama: ensure `ollama serve` is running
- Check the scan log in the terminal panel for error details

**PowerShell execution policy error:**
```powershell
# Run as Administrator
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Detailed Windows troubleshooting:** See [WINDOWS_SETUP.md](WINDOWS_SETUP.md)

---

*Built with Rust 🦀 + LangChain 🦜 + love for security*
