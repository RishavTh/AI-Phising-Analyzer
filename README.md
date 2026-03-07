# 🛡️ AI-Powered Phishing Email Analyzer

> Automated SOC Tier-1 email triage — from suspicious email to incident report in under 5 seconds.

![Python](https://img.shields.io/badge/Python-3.11-blue) ![Flask](https://img.shields.io/badge/Flask-3.x-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What It Does

PhishGuard is a full SOC automation tool that:

- Parses raw emails (`.eml` format or pasted text, including HTML emails)
- Uses **Groq AI (LLaMA 3.1)** to extract IOCs and detect phishing tactics
- Enriches indicators via **VirusTotal** (70+ AV engines) and **AbuseIPDB**
- Calculates a **weighted risk score (0–100)**
- Maps findings to **MITRE ATT&CK techniques**
- Generates a structured **SOC incident report**
- Sends **Slack alerts** for HIGH/MEDIUM severity findings
- Provides a **cinematic SIEM-style web dashboard**

Manual triage time: ~8 minutes. PhishGuard: ~4 seconds.

---

## Demo

| Email | Score | Level | Result |
|-------|-------|-------|--------|
| Microsoft spoofed (.ru domain, Tor IP) | 85/100 | 🔴 HIGH | Escalate to L2 |
| PayPal lookalike domain | 50/100 | 🟡 MEDIUM | Analyst review |
| Legitimate Google notification | 0/100 | 🟢 LOW | Log & monitor |
| Real Microsoft security alert | 20/100 | 🟢 LOW | Log & monitor |

---

## Architecture
```
Email Input (.eml or paste)
        ↓
[Stage 1] Email Parser      — headers, body, HTML extraction
        ↓
[Stage 2] AI IOC Extractor  — Groq/LLaMA 3.1, MITRE ATT&CK mapping
        ↓
[Stage 3] Threat Enrichment — VirusTotal + AbuseIPDB
        ↓
[Stage 4] Risk Scorer       — weighted model, false-positive reduction
        ↓
[Stage 5] Report Generator  — structured SOC incident report
        ↓
[Stage 6] Slack Alert       — HIGH/MEDIUM only, silent for LOW
```

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.11 | Core language |
| Groq API (LLaMA 3.1) | AI IOC extraction & report generation |
| VirusTotal API | URL/domain reputation (70+ engines) |
| AbuseIPDB API | IP abuse scoring & Tor detection |
| Flask + flask-limiter | Web dashboard + rate limiting |
| Slack Webhooks | Real-time SOC alerts |

---

## Setup

**1. Clone the repo**
```bash
git clone git@github.com:RishavTh/AI-Phising-Analyzer.git
cd AI-Phising-Analyzer
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Configure API keys**
```bash
cp .env.example .env
# Edit .env and add your keys
```

**4. Start the dashboard**
```bash
python3 web/app.py
# Open http://localhost:5000
```

---

## API Keys Required (all free tier)

- [Groq API](https://console.groq.com) — free, no credit card
- [VirusTotal](https://virustotal.com) — free, 4 req/min
- [AbuseIPDB](https://abuseipdb.com) — free, 1000 req/day
- [Slack Webhook](https://api.slack.com/messaging/webhooks) — free

---

## Security Features

- Rate limiting (10 req/min per IP via flask-limiter)
- Input validation & max content length enforcement
- Secure temp file handling with guaranteed cleanup
- API keys via `.env` — never committed to git
- False positive reduction via Python-level enforcement layer

---

## MITRE ATT&CK Coverage

| Technique | ID | Tactic |
|-----------|-----|--------|
| Spearphishing Link | T1566.002 | Initial Access |
| Spearphishing Attachment | T1566.001 | Initial Access |
| Acquire Domain | T1583.001 | Resource Development |
| Spearphishing Link (Recon) | T1598.003 | Reconnaissance |

---

## Project Structure
```
├── src/
│   ├── email_parser.py      # HTML + plain text email parsing
│   ├── ioc_extractor.py     # AI extraction + MITRE mapping
│   ├── ip_extractor.py      # Regex IPv4 backup extraction
│   ├── enrichment.py        # VirusTotal + AbuseIPDB with retry logic
│   ├── risk_scorer.py       # Weighted scoring engine
│   ├── reporter.py          # AI incident report generation
│   └── slack_alert.py       # Slack Block Kit alerts
├── web/
│   ├── app.py               # Flask dashboard (hardened)
│   └── templates/index.html # Cinematic SIEM UI
├── sample_emails/           # Test .eml files
├── main.py                  # CLI entry point
└── requirements.txt
```

---

## Built By

Rishav Kumar Thapa — learning cybersecurity for Junior SOC Analyst roles.

This project demonstrates: AI/LLM integration, REST API consumption, IOC enrichment, SOAR principles, risk-based decision logic, and automated incident response.
