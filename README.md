# 🛡️ SENTINEL
### Local AI-Powered Phishing Intelligence Agent



Privacy-first email forensics platform that runs entirely on-device — zero email data leaves your machine.

---

## What It Does

- Analyzes email headers for phishing indicators including spoofing, suspicious TLDs, and urgency language
- Runs Mistral 7B locally via Ollama for AI-powered threat reasoning — no cloud API required
- Maps findings to MITRE ATT&CK techniques with tactic and technique IDs
- Supports air-gapped deployment via export/import of threat intelligence bundles
- Provides both a web dashboard and a full-featured CLI interface

---

## Key Features

| Feature | Description |
|---|---|
| Local AI (Mistral 7B via Ollama) | On-device LLM inference — no data sent to external AI services |
| MITRE ATT&CK Mapping | Findings automatically mapped to ATT&CK technique IDs and tactics |
| MaxMind GeoLite2 | Offline IP geolocation — works with no internet connection |
| AbuseIPDB Reputation | Real-time IP abuse scoring via AbuseIPDB API (optional) |
| ReAct Agent Investigation | Two-prompt ReAct architecture for multi-step reasoning over indicators |
| Air-Gap Export / Import | Export threat intel as STIX-compatible JSON for transfer to isolated networks |
| Web Dashboard | Flask-based dashboard with live progress, risk summary, and per-email reports |
| Offline Mode | Suppresses all external calls; uses local GeoLite2 DB and MySQL cache only |
| SIEM JSON Export | Structured JSON output compatible with downstream SIEM ingestion pipelines |
| MySQL Threat Intel DB | Persistent local database for caching IP reputation and analysis history |

---

## Architecture

```
Email Headers
      │
      ▼
┌─────────────────────┐
│   SENTINEL Core     │  email_forensics.py
│  Header Parsing     │
│  Spoofing Detection │
│  Urgency Analysis   │
└──────────┬──────────┘
           │
     ┌─────┴──────┐
     │            │
     ▼            ▼
IP Intelligence  Authentication
AbuseIPDB        SPF Check
GeoLite2         DKIM Check
ip-api.com       (dnspython)
     │            │
     └─────┬──────┘
           │
           ▼
    ┌──────────────┐
    │   AI Layer   │
    │  Mistral 7B  │
    │  (Ollama)    │
    │  ReAct Agent │
    └──────┬───────┘
           │
           ▼
  MITRE ATT&CK Mapping
  Confidence Scoring
  Analyst Notes
           │
           ▼
┌──────────────────────┐
│        Report        │
│  Web Dashboard       │
│  CLI Terminal Output │
│  JSON (SIEM Export)  │
└──────────────────────┘
```

---

## Quick Start

**Prerequisites**

- Python 3.12+
- [Ollama](https://ollama.com) installed and running
- MySQL (optional — for threat intelligence caching and offline IP reputation)
- MaxMind GeoLite2-City database (optional — for offline geolocation)
- AbuseIPDB API key (free) — register at abuseipdb.com


**Run the web dashboard**

```bash
python sentinel_web.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## Usage

### Web Dashboard

```bash
python sentinel_web.py
```

Point the dashboard at your emails folder, select Online or Offline mode, and click **Start Analysis**.

### CLI — Online Mode

```bash
python email_forensics.py
```

Analyzes all `.txt` and `.eml` files in the `emails/` directory. Queries AbuseIPDB and ip-api.com for live IP intelligence.

### CLI — Offline Mode

```bash
python email_forensics.py --offline
```

Suppresses all external HTTP calls. Uses the local GeoLite2 database and MySQL cache exclusively. Suitable for air-gapped environments.

### CLI — SIEM Export

```bash
python email_forensics.py --json
```

Writes structured results to `sentinel_results.json` after analysis. Output includes risk counts, per-email findings, and metadata for ingestion into SIEM platforms.

### Air-Gap Workflow

**On the internet-connected machine:**

```bash
python sentinel_update.py --export
```

Copy the generated `sentinel_export.json` to a USB drive.

**On the air-gapped machine:**

```bash
python sentinel_update.py --import sentinel_export.json
```

Imports threat intelligence (IP reputation, MITRE data) into the local MySQL database without requiring any internet access.

---

## Privacy Design

- **Zero email content sent externally** — header parsing, AI inference, and report generation all run on localhost
- **Only IP addresses are sent to external APIs** — AbuseIPDB and ip-api.com receive IP addresses only, never email content or metadata
- **AI inference runs on localhost** — Mistral 7B is served by Ollama locally; no tokens are sent to any cloud AI provider
- **Offline mode enforces zero external calls** — every network request is suppressed; all lookups fall back to local databases

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Web Framework | Flask |
| Local AI | Mistral 7B via Ollama |
| Agent Pattern | ReAct (Reason + Act) |
| Geolocation | MaxMind GeoLite2 |
| IP Reputation | AbuseIPDB API |
| DNS Validation | dnspython |
| Threat Intel | MITRE ATT&CK CTI / STIX 2.0 |
| Persistence | MySQL |

---

## Disclaimer

SENTINEL is intended for educational and authorized security research purposes only.