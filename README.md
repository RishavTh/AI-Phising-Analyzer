# PhishGuard

Automated phishing email analysis pipeline. Parses emails, extracts IOCs, enriches with threat intelligence, scans attachments, scores risk, and generates incident reports.

---

## Overview

PhishGuard is a 6-stage analysis pipeline for phishing triage automation.

```
Email Input → IOC Extraction → Threat Intel → Risk Scoring → Report → Alert
```

**Stack:** Python 3.11 · Groq LLaMA 3.1 · VirusTotal API · AbuseIPDB · Flask · Slack Webhooks

---

## Pipeline Stages

| Stage | Module | Description |
|-------|--------|-------------|
| 1 | `email_parser.py` | Parses raw `.eml` — headers, body, attachments |
| 2 | `ioc_extractor.py` | LLM-based IOC extraction with regex IP fallback |
| 3 | `enrichment.py` | VirusTotal URL scan + AbuseIPDB IP lookup |
| 3b | `attachment_scanner.py` | VirusTotal Files API — SHA256 lookup + upload |
| 4 | `risk_scorer.py` | Weighted signal model, 0–100 score |
| 5 | `reporter.py` | AI-generated SOC incident report |
| 6 | `slack_alert.py` | Slack webhook alert for MEDIUM/HIGH |

---

## Risk Scoring

Weighted model combining AI confidence, VirusTotal detections, AbuseIPDB score, and behavioral signals.

| Signal | Weight |
|--------|--------|
| AI confidence > 70% | +40 pts |
| VT malicious > 10 engines | +25 pts |
| VT malicious 3–10 engines | +15 pts |
| VT malicious 1–3 engines | +5 pts |
| AbuseIPDB score > 60% | +20 pts |
| AbuseIPDB score 30–60% | +10 pts |
| Tor exit node | +10 pts |
| Spoofing detected | +10 pts |
| Credential harvesting | +5 pts |
| All signals clean | Score capped at 30 |

**Thresholds:** LOW 0–29 · MEDIUM 30–70 · HIGH 71–100

---

## MITRE ATT&CK Mapping

Detected tactics are automatically mapped to ATT&CK techniques.

| Technique ID | Name | Tactic |
|-------------|------|--------|
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1566.002 | Spearphishing Link | Initial Access |
| T1598.003 | Spearphishing Link | Reconnaissance |
| T1566 | Phishing | Initial Access |
| T1583.001 | Acquire Domain | Resource Development |

---

## Attachment Scanning

Extracts attachments from `.eml` files and submits to VirusTotal Files API.

- SHA256 hash lookup checks VT cache before uploading
- Supports PDF, Word, Excel, ZIP, EXE, PS1, and other executable types
- Skips files over 5MB and non-suspicious MIME types
- Returns per-file verdict: malicious engine count + VT report link

---

## SIEM Logging

Every analysis is written to `output/siem_logs.ndjson` automatically.

- Format: Elastic Common Schema (ECS) NDJSON — one event per line
- Compatible with Splunk, Elastic, and Wazuh ingestion pipelines
- Persistent across server restarts
- Exposed via `/siem-logs` API endpoint

---

## Web Dashboard

Flask-based SOC dashboard at `localhost:5000`.

**Views:**
- **Email Analyzer** — paste raw EML or Gmail "Show Original" content
- **Alert Queue** — session history with CSV export
- **MITRE ATT&CK** — technique registry across session
- **IOC Registry** — accumulated indicators across all analyses
- **SIEM Logs** — live JSON viewer with `.ndjson` download

---

## Setup

**Requirements:** Python 3.11+, API keys for Groq, VirusTotal, AbuseIPDB

```bash
git clone https://github.com/RishavTh/AI-Phising-Analyzer.git
cd AI-Phising-Analyzer
pip3 install -r requirements.txt
cp .env.example .env
# Add API keys to .env
```

**CLI:**
```bash
python3 main.py sample_emails/test_phishing.eml
```

**Web:**
```bash
python3 web/app.py
# http://localhost:5000
```

---

## Security

- Rate limiting: 10 req/min, 100 req/hour per IP
- Input validation: 20–100,000 character limit
- Secure temp file handling with guaranteed cleanup
- API keys in `.env` — not committed to version control
- `safe_str()` applied to all JSON response values

---

## Project Structure

```
src/
├── email_parser.py
├── ioc_extractor.py
├── ip_extractor.py
├── enrichment.py
├── attachment_scanner.py
├── risk_scorer.py
├── reporter.py
├── slack_alert.py
└── siem_logger.py
web/
├── app.py
└── templates/index.html
sample_emails/
output/
main.py
```
