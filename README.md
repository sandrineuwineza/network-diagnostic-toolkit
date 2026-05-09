# 🛰️ Network Diagnostic Toolkit

> A professional Python-based network troubleshooting tool for Technical Support Engineers — available as both a CLI and a modern web dashboard.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![CCNA](https://img.shields.io/badge/CCNA-Cisco%20Certified-1ba0d7?logo=cisco)](https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna.html)

Built by **[Sandrine Uwineza](https://linkedin.com/in/sandrineuwineza)** — Technical Support Engineer · CCNA Certified · Computer Engineering BSc

---

## 🔍 What It Does

When a user reports "the network is down," a Technical Support Engineer follows a systematic path to find the root cause. This toolkit automates that entire first-response diagnostic checklist:

| Module | What it checks |
|---|---|
| **Ping** | Host reachability · latency · packet loss |
| **DNS** | A · AAAA · MX · NS · CNAME resolution |
| **Port Scanner** | TCP port state · service identification · banner grab |
| **HTTP Check** | Status code · response time · TLS certificate · redirects |
| **Traceroute** | Hop-by-hop path · latency per hop · route analysis |
| **Report Generator** | Professional Markdown incident reports |

---

## 🖥️ Web Dashboard

A modern, responsive web dashboard runs on top of the CLI tool — deployable for free on Railway or Render.

**Features:**
- Live diagnostics via REST API
- Full-scan mode: all modules in parallel
- Summary bar with key metrics at a glance
- Color-coded latency indicators
- SSL certificate expiry tracking
- Responsive for mobile and desktop

---

## ⚡ Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/sandrineuwineza/network-diagnostic-toolkit.git
cd network-diagnostic-toolkit
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the web dashboard (recommended)
```bash
python app.py
```
Open http://localhost:5000 in your browser.

### 5. Or use the CLI
```bash
# Full diagnostic sweep
python main.py --host google.com --all

# Ping only
python main.py --host 8.8.8.8 --ping

# Port scan with specific ports
python main.py --host example.com --ports 80 443 22

# HTTP health check
python main.py --url https://example.com --http

# Traceroute
python main.py --host google.com --traceroute

# Full scan + save report
python main.py --host google.com --all --report reports/incident_001.md
```

---

## 📋 CLI Reference

```
usage: netdiag [--host HOST] [--url URL] [options]

Target:
  --host HOST           Hostname or IP address
  --url URL             URL for HTTP check
  --hosts HOST [...]    Multiple hosts for ping sweep

Diagnostics:
  --all                 Run all modules
  --ping                ICMP/TCP ping
  --dns                 DNS resolution
  --ports PORT [...]    TCP port scan
  --port-group GROUP    Scan named group: web|remote|database|mail|common
  --http                HTTP/HTTPS health check
  --traceroute          Path trace

Options:
  --count N             Ping packet count (default: 4)
  --timeout N           Timeout per probe in seconds (default: 3)
  --max-hops N          Max traceroute hops (default: 30)
  --report FILE         Save Markdown report to file
  --json                Output raw JSON
  --analyst NAME        Analyst name for report header
  --ticket ID           Ticket ID for report header
```

---

## 🗂️ Project Structure

```
network-diagnostic-toolkit/
├── app.py                      # Flask web server + REST API
├── main.py                     # CLI entry point
├── requirements.txt
├── Procfile                    # Deployment (Railway/Render)
├── railway.toml                # Railway configuration
├── render.yaml                 # Render.com configuration
│
├── diagnostics/
│   ├── __init__.py
│   ├── ping.py                 # ICMP ping + TCP fallback
│   ├── dns_check.py            # DNS resolution (A/AAAA/MX/NS)
│   ├── port_scanner.py         # TCP port scanner (concurrent)
│   ├── http_check.py           # HTTP/HTTPS + TLS checker
│   └── traceroute.py           # Route tracing + hop analysis
│
├── reports/
│   ├── __init__.py
│   └── report_generator.py     # Markdown + JSON report output
│
├── templates/
│   └── index.html              # Web dashboard (single-file SPA)
│
└── tests/
    └── test_diagnostics.py     # pytest unit + integration tests
```

---

## 🔌 REST API

The Flask server exposes a clean REST API for integration:

| Endpoint | Method | Body | Description |
|---|---|---|---|
| `/health` | GET | — | Health check |
| `/api/ping` | POST | `{"host": "..."}` | Ping a host |
| `/api/dns` | POST | `{"domain": "..."}` | DNS resolution |
| `/api/ports` | POST | `{"host": "...", "group": "web"}` | Port scan |
| `/api/http` | POST | `{"url": "..."}` | HTTP health check |
| `/api/traceroute` | POST | `{"host": "..."}` | Traceroute |
| `/api/full-scan` | POST | `{"host": "..."}` | All modules |

**Example:**
```bash
curl -X POST http://localhost:5000/api/dns \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

---

## 🧪 Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ -v --cov=. --cov-report=html

# Run specific test class
python -m pytest tests/ -v -k TestDNS
```

---

## 🚀 Deployment

### Option A — Railway (Recommended · Free)

1. Push this repository to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Select `network-diagnostic-toolkit`
4. Railway auto-detects the `Procfile` and deploys
5. Your app is live at `https://your-app.up.railway.app`

> Railway free tier: 500 hours/month · No credit card required for hobby plan.

### Option B — Render.com (Free · Always-on with limits)

1. Push to GitHub
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Render reads `render.yaml` automatically
5. Deploy — live in ~2 minutes

> Render free tier: Sleeps after 15 min inactivity · Wakes on request · No cost.

### Option C — Local with Docker (optional)

```bash
# Build and run
docker build -t netdiag .
docker run -p 5000:5000 netdiag
```

---

## 🛠️ Skills Demonstrated

```
Networking:       TCP/IP · DNS · ICMP · HTTP/HTTPS · TLS/SSL
                  VLANs · Port scanning · Traceroute · CCNA
Python:           socket · subprocess · urllib · concurrent.futures
                  dataclasses · argparse · Flask · pytest
Engineering:      Modular architecture · error handling
                  fallback strategies · REST API design
Documentation:    Structured README · inline docstrings
                  incident report generation
Support Practice: Root cause analysis · systematic diagnostics
                  SLA awareness · technical documentation
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 👤 About the Author

**Sandrine Uwineza**
Technical Support Engineer · Computer Engineering BSc (Network Engineering) · University of Rwanda

🔗 [LinkedIn](https://linkedin.com/in/sandrineuwineza) · 
📧 mrs.uwineza@gmail.com · 
📍 Tlalnepantla de Baz, Estado de México, Mexico

> *"Built to automate the systematic first-response diagnostic checklist used in every IT support incident — based on CCNA-certified network engineering knowledge and real production support experience."*
