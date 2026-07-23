# 🔍 PhishGuard — URL Threat Scanner

A CLI-based URL threat detection system powered by machine learning anomaly detection, real-time threat intelligence APIs, WHOIS domain intelligence, and multi-format report generation — all controllable from a single interactive terminal menu.

```
                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                  ▄▄██████████████████████████▄▄
              ▄▄██████████████████████████████████▄▄
           ▄██████████████                ██████████████▄
         ▄████████████       ╔════════════╗       ████████████▄
        ██████████           ║  ●  ●  ●   ║           ██████████
       █████████             ║    ◉◉◉◉◉   ║             █████████
       █████████             ║   ◉ ▓▓▓ ◉  ║             █████████
       █████████             ║    ◉◉◉◉◉   ║             █████████
        ██████████           ║  ●  ●  ●   ║           ██████████
         ▀████████████       ╚════════════╝       ████████████▀
           ▀██████████████                ██████████████▀
              ▀▀██████████████████████████████████▀▀
                  ▀▀██████████████████████████▀▀
                       ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

     [ TARGET : incoming URL ]        [ STATUS : SCANNING... ]
     [ ENGINE : PHISHGUARD   ]        [ THREAT : ANALYZING…  ]

   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
   ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
   ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
```


---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [Direct CLI Commands](#direct-cli-commands)
  - [Training the Model](#training-the-model)
  - [Admin Panel (Web)](#admin-panel-web)
- [Machine Learning](#machine-learning)
- [Threat Intelligence Sources](#threat-intelligence-sources)
- [Report Formats](#report-formats)
- [Configuration](#configuration)
- [API Reference](#api-reference)

---

## Overview

PhishGuard detects malicious URLs using a multi-layered approach:

1. **ML Anomaly Detection** — K-means + Self-Organizing Map (SOM) trained on URL structural features. Flags URLs that look statistically unusual compared to known-normal patterns. No labelled dataset required.
2. **External Threat Intel** — Concurrent queries to VirusTotal (70+ AV engines), Google Safe Browsing (real-time phishing/malware), and URLhaus (active malware distribution URLs).
3. **WHOIS / RDAP** — Domain age, registrar, country, name servers, newly-registered domain detection — over HTTPS (no port 43 dependency).
4. **Report Generation** — Full scan reports saved as Markdown, PDF, DOCX, and TXT with dedicated sections for each intelligence source. Optional LLM narrative via local Ollama.

---

## Features

- **Interactive terminal menu** — arrow-key navigation, no commands to memorise
- **Single URL scan** with live polling and instant result display
- **Batch scanning** from `.txt` or `.csv` files — one batch ID, one consolidated report
- **Async scan pipeline** — VT + Safe Browsing + URLhaus + WHOIS all fire concurrently
- **ML anomaly scoring** — K-means + SOM run independently; disagreement is surfaced as a confidence signal
- **RDAP-based WHOIS** — uses HTTPS (port 443), no port 43 firewall issues
- **URLhaus integration** — catches active malware distribution URLs before AV engines do
- **Multi-format reports** — `.md` `.txt` `.pdf` `.docx` + rich terminal output
- **LLM report enhancement** — local Ollama generates a threat narrative (optional)
- **Web admin panel** — dashboard, scan history, model manager, label manager, quick scan
- **Offline model training** — train from accumulated scans or any CSV dataset
- **Hot model reload** — swap ML artifacts without restarting the server
- **Job cancellation** — cancel individual scans or entire batches mid-flight
- **WAL-mode SQLite** — concurrent reads and writes; admin panel never blocks CLI

---

## Architecture

```
Interactive Menu (cli/menu.py)
         │
         │  HTTP  (sync httpx)
         ▼
FastAPI Server  (server/main.py + api.py)
         │
         │  asyncio.Queue
         ▼
Scan Worker  (server/queue_worker.py)
         │
         │  asyncio.gather  ──────────────────────────────────────┐
         ▼                                                         │
Feature Extraction          ML Scoring          External APIs      │
(core/features.py)    (core/models.py)                            │
  17 URL features      K-means + SOM     VirusTotal  Safe Browsing │
  synchronous          synchronous       URLhaus     WHOIS/RDAP    │
                                         └───────────async─────────┘
         │
         ▼
Verdict Engine  (server/scanner.py)
  Priority: Safe Browsing → URLhaus online → VT ≥3 → ML → WHOIS → SAFE
         │
         ▼
Report Generator  (report/generator.py)
  Terminal  │  Markdown  │  TXT  │  PDF  │  DOCX
         │
         ▼
SQLite  (WAL mode, QueuePool)
  scan_jobs │ batch_jobs │ feature_vectors │ feedback
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Server** | FastAPI, Uvicorn |
| **Database** | SQLite via SQLModel (WAL mode, QueuePool) |
| **HTTP client** | httpx (async in scanner, sync in CLI) |
| **ML — Clustering** | scikit-learn (K-means + StandardScaler) |
| **ML — Topology** | MiniSom (Self-Organizing Map) |
| **Reports** | reportlab (PDF), python-docx (DOCX), rich (terminal) |
| **LLM** | Ollama (local, optional) |
| **CLI menu** | questionary + rich |
| **WHOIS** | RDAP over HTTPS (rdap.org, rdap.iana.org, Verisign) |
| **Env config** | python-dotenv |

---

## Project Structure

```
phishguard/
├── server/
│   ├── main.py              # App entry point, thread pool, lifespan
│   ├── api.py               # All API routes
│   ├── scanner.py           # Scan orchestrator (features → ML → APIs → verdict)
│   ├── queue_worker.py      # asyncio.Queue worker with cancellation
│   ├── db.py                # SQLModel schema, WAL mode, CRUD helpers
│   ├── migrations.py        # Idempotent schema migrations
│   └── static/
│       └── admin.html       # Web admin panel (single file)
│
├── core/
│   ├── features.py          # URL → 17-feature vector (shared)
│   ├── models.py            # Loads artifacts, K-means + SOM scoring
│   ├── whois_lookup.py      # RDAP-first WHOIS, in-process cache
│   └── urlhaus.py           # URLhaus API client (URL + host lookup)
│
├── training/
│   ├── train.py             # Offline training: DB / CSV streaming / feature CSV
│   └── artifacts/           # scaler_*.pkl  kmeans_*.pkl  som_*.pkl  latest.json
│
├── report/
│   └── generator.py         # 5 renderers: terminal, md, txt, pdf, docx
│
├── cli/
│   ├── client.py            # Direct CLI: scan, batch, cancel, admin, check-ollama
│   └── menu.py              # Interactive option-based terminal menu
│
├── reports/                 # Generated report files saved here
├── data.db                  # SQLite database
├── .env                     # API keys (not committed)
├── .env.example             # Key template
└── requirements.txt
```

---

## Installation

**Requirements:** Python 3.11+

```bash
# Clone the repository
git clone https://github.com/yourusername/phishguard.git
cd phishguard

# Install dependencies
pip install -r requirements.txt

# Copy env template and fill in your API keys
cp .env.example .env
```

**`.env` file:**
```env
VIRUSTOTAL_API_KEY=your_virustotal_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_key_here
```

> VirusTotal and Google Safe Browsing keys are optional — the scanner still works using ML + URLhaus + WHOIS when they are not set. Get free keys at [virustotal.com](https://virustotal.com) and [Google Cloud Console](https://console.cloud.google.com).

---

## Quick Start

```bash
# Terminal 1 — start the server
uvicorn server.main:app --port 8000

# Terminal 2 — open the interactive menu
python -m cli.menu
```

The menu connects to the server automatically and shows a live server status indicator.

---

## Usage

### Interactive Menu

```bash
python -m cli.menu
# With a custom server URL
python -m cli.menu --server http://192.168.1.100:8000
```

```
Main Menu:
❯ 🔍  Scan URL
  📋  Check Scan Status
  ✕   Cancel Scan / Batch
  📦  Batch Scan
  🕑  Scan History
  📄  Generate Report
  🧠  Train Model
  ⚙️   Admin
  🔧  Settings
  ❌  Exit
```

Navigate with arrow keys, press Enter to select. Each option prompts only for what it needs.

---

### Direct CLI Commands

For scripting and automation use `cli/client.py` directly:

```bash
# Scan a single URL
python -m cli.client scan https://suspicious-site.tk

# Scan with LLM report enhancement
python -m cli.client scan https://example.com --llm

# Scan and save specific formats only
python -m cli.client scan https://example.com --formats md,pdf

# Fire and forget (don't wait for result)
python -m cli.client scan https://example.com --async

# Check status of a previous scan
python -m cli.client status <scan_id>

# Regenerate report for any past scan
python -m cli.client report <scan_id> --formats pdf,docx

# Cancel a running scan
python -m cli.client cancel <scan_id>
```

**Batch scanning:**

```bash
# From a plain text file (one URL per line)
python -m cli.client batch urls.txt

# From a CSV file
python -m cli.client batch urls.csv --column url

# CSV with custom delimiter
python -m cli.client batch data.csv --column website --delimiter ";"

# Preview CSV columns before scanning
python -m cli.client batch data.csv --preview

# Batch with LLM summaries per URL
python -m cli.client batch urls.csv --column url --llm

# Cancel an entire batch
python -m cli.client cancel-batch <batch_id>
```

**Admin commands:**

```bash
# Server statistics
python -m cli.client admin stats

# Hot-reload ML model after retraining
python -m cli.client admin reload

# Label a scan result for training feedback
python -m cli.client admin label <scan_id> malicious
python -m cli.client admin label <scan_id> benign

# Diagnose Ollama connectivity
python -m cli.client check-ollama
python -m cli.client check-ollama --test
```

---

### Training the Model

PhishGuard uses **offline training** — the server only loads pre-trained artifacts. Train whenever you have enough new data, then hot-reload without restarting.

**Train on accumulated scan data (default):**
```bash
python -m training.train
```

**Train on a CSV of URLs (no scanning needed — extracts features automatically):**
```bash
# Using a PhishTank export, URLhaus download, or your own dataset
python -m training.train --csv phishtank.csv --url-column url

# Also save extracted feature vectors to DB for future reuse
python -m training.train --csv phishtank.csv --url-column url --save-to-db
```

**Train on pre-computed feature columns:**
```bash
python -m training.train --csv features.csv --all-features
python -m training.train --csv data.csv --feature-columns url_length,entropy,digit_ratio
```

**Hot-reload after training (no server restart):**
```bash
# Via CLI
python -m cli.client admin reload

# Via admin panel
# Admin → Model Manager → Reload Model Artifacts
```

Training shows a live progress bar for large datasets. Files with millions of rows are processed line-by-line without loading the full file into memory.

---

### Admin Panel (Web)

Open [http://localhost:8000/admin](http://localhost:8000/admin) while the server is running.

| Section | What it does |
|---|---|
| **Dashboard** | Verdict donut chart, scan counts, job statuses, recent scans |
| **Scan History** | Searchable/filterable table of all scans, drill-in to full results |
| **Model Manager** | Active model version, training instructions, one-click hot-reload |
| **Label Manager** | Mark scans as malicious/benign to build training feedback |
| **Quick Scan** | Submit a URL directly from the browser, results appear inline |

---

## Machine Learning

### Why Unsupervised?

Malicious URLs are a moving target. A supervised classifier trained on yesterday's phishing domains won't catch today's newly registered ones. PhishGuard uses **anomaly detection** instead — learning what normal URLs look like and flagging deviations — so it catches novel threats without needing a continuously updated labelled dataset.

### Feature Vector (17 features)

| Feature | What it measures |
|---|---|
| `url_length` | Total URL character count |
| `domain_length` | Length of the host/domain part |
| `path_length` | Length of the URL path |
| `query_length` | Length of query parameters |
| `num_subdomains` | Subdomain depth |
| `num_dots` | Total dot count |
| `num_hyphens` | Hyphen count |
| `num_digits` | Digit count |
| `digit_ratio` | Digits / total length |
| `special_char_ratio` | Non-alphanumeric / total length |
| `shannon_entropy` | Randomness of the URL string (0–5+) |
| `has_at_symbol` | `@` present (hides real destination) |
| `has_ip_host` | IP address used instead of domain name |
| `is_https` | HTTPS in use |
| `suspicious_tld` | TLD in known-bad list (.tk .xyz .gq etc.) |
| `num_query_params` | Number of `?key=value` pairs |
| `typosquat_distance` | Edit distance to nearest popular domain |

### K-means Clustering

Partitions URLs into 8 clusters (K=8) based on their feature vectors. At scan time, the URL is assigned to its nearest cluster and the distance to that centroid is measured. URLs far from any cluster centroid are anomalous. Score > 1.0 = noticeably unusual.

### Self-Organizing Map (SOM)

A 10×10 neural grid that learns the topology of the URL feature space. Similar URLs land in nearby neurons; unusual URLs land in sparse, unpopulated regions. The **Quantization Error** (distance from the URL's vector to its Best Matching Unit) is the anomaly signal. Catches URLs that fall *between* K-means clusters that K-means alone would miss.

### Combined Score

```
combined_score = 0.5 × kmeans_score + 0.5 × som_score
```

When both models independently flag a URL as anomalous the result carries `models_agree: true` and higher confidence. When they disagree the report explicitly marks it as a mixed signal.

---

## Threat Intelligence Sources

### Verdict Priority Order

```
1. Google Safe Browsing  →  MALICIOUS  (real-time, high authority)
2. URLhaus actively online  →  MALICIOUS
3. VirusTotal ≥ 3 engines  →  MALICIOUS
4. VT 1–2 engines + ML agree  →  SUSPICIOUS
5. ML combined score alone  →  SUSPICIOUS
6. WHOIS newly registered domain  →  SUSPICIOUS
7. No signals  →  SAFE
```

### VirusTotal
Checks the URL against 70+ antivirus engines. Free API key required. Best at catching known malware with established signatures.

### Google Safe Browsing
Real-time phishing, malware, and unwanted software detection maintained by Google. Free API key required.

### URLhaus (abuse.ch)
Tracks URLs actively distributing malware in real time — often before AV engines update their signatures. **Free, no API key required.** Checks both the specific URL and the host domain. An "actively online" URLhaus hit triggers MALICIOUS immediately.

### WHOIS / RDAP
Domain registration intelligence via RDAP over HTTPS (no port 43 needed). Returns domain age, registrar, country, name server count, and flags newly registered domains (< 30 days old) — a strong phishing indicator. Results are cached per domain for 1 hour.

---

## Report Formats

Every report has these independent sections:

1. **Overview** — URL, verdict, confidence, scan ID, timestamp
2. **Signal Summary** — all verdict reasons as a bullet list
3. **ML Anomaly Detection** — K-means score/cluster, SOM score/BMU, combined score, agreement flag
4. **External Threat Intelligence** — VirusTotal counts, Safe Browsing threat types
5. **URLhaus** — URL listing status, threat type, malware tags, host URL count, Spamhaus/SURBL blacklist status
6. **WHOIS Domain Intelligence** — registrar, country, domain age (colour-coded), expiry, name servers, risk flags
7. **URL Feature Breakdown** — all 17 features with inline risk markers
8. **AI Analysis** *(optional)* — LLM-generated threat narrative via local Ollama

### Format Options

| Format | Notes |
|---|---|
| **Terminal** | Rich colour-coded output with tables, panels, and inline flags |
| `.md` | Full Markdown with tables — renders on GitHub, Obsidian, etc. |
| `.txt` | Plain text, 60-char wide — readable anywhere, good for logging |
| `.pdf` | ReportLab — professional layout with styled tables and coloured verdict heading |
| `.docx` | python-docx — editable Word document with Table Grid styling |

**Batch reports** produce a single consolidated file covering all URLs in the batch, with a per-URL summary table and individual detail sections.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key (optional) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | — | Google Safe Browsing key (optional) |
| `OLLAMA_MODEL` | auto-detect | Ollama model to use for LLM reports |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `BATCH_MAX_URLS` | unlimited | Max URLs per batch submission |

### LLM Setup (optional)

PhishGuard can enhance reports with an AI-generated threat narrative using a locally running LLM via [Ollama](https://ollama.com).

```bash
# Install Ollama (see ollama.com for your platform)

# Pull a model
ollama pull llama3

# Start Ollama
ollama serve

# Diagnose the connection
python -m cli.client check-ollama --test

# Use LLM in a scan
python -m cli.client scan https://example.com --llm
```

### Running the Server

```bash
# Development (auto-reload on code changes)
uvicorn server.main:app --port 8000 --reload

# Production
uvicorn server.main:app --port 8000 --workers 1
```

---

## API Reference

| Method | Route | Description |
|---|---|---|
| `POST` | `/scan` | Submit URL → `scan_id` |
| `GET` | `/scan/{id}` | Poll status + result |
| `POST` | `/scan/{id}/cancel` | Cancel queued/running scan |
| `GET` | `/scan/{id}/report?fmt=pdf` | Download report file |
| `POST` | `/batch` | Submit URL list → `batch_id` |
| `GET` | `/batch/{id}?page=1&page_size=200` | Poll batch progress (paginated) |
| `POST` | `/batch/{id}/cancel` | Cancel all scans in batch |
| `GET` | `/batch/{id}/report?fmt=md` | Download batch report |
| `POST` | `/admin/reload-model` | Hot-swap ML artifacts |
| `POST` | `/admin/label/{id}` | Label scan malicious/benign |
| `GET` | `/admin/stats` | Verdict counts + model version |
| `GET` | `/admin/scans?limit=100` | Scan history |
| `GET` | `/admin` | Web admin panel |
| `GET` | `/health` | Lightweight health check |

Interactive API docs available at [http://localhost:8000/docs](http://localhost:8000/docs) when the server is running.

---

## Requirements

```
Python >= 3.11

fastapi==0.138.2        uvicorn==0.49.0         sqlmodel==0.0.39
httpx==0.28.1           python-dotenv==1.2.2    scikit-learn==1.8.0
MiniSom==2.3.6          rich==15.0.0            python-docx==1.2.0
reportlab==4.4.10       python-whois==0.9.6     questionary
ollama==0.6.2  (optional — only needed for --llm)
```

Install everything:
```bash
pip install -r requirements.txt
```

---
Built by Lakshmeesha Suvarna
