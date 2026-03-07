# 🛡️ PhishGuard — AI-Powered Phishing Email Analyzer

> **SOC Automation Tool** | Built with Python, Groq LLaMA 3.1, VirusTotal, AbuseIPDB, Flask  
> Reduces manual phishing triage from ~8 minutes to under 5 seconds per email.

---

## 📸 Dashboard Preview

**Wazuh-style SOC Dashboard** — Dark blue SIEM interface with sidebar navigation, live stats, pipeline visualization, and full incident reports.

---

## 🚀 What It Does

PhishGuard is a full 6-stage SOC automation pipeline that analyzes phishing emails end-to-end:

1. **Email Parsing** — Extracts headers, body, and attachments from raw `.eml` or pasted email content
2. **AI IOC Extraction** — Uses Groq LLaMA 3.1 to extract URLs, domains, IPs, and phishing tactics
3. **Threat Intel Enrichment** — Checks every URL against VirusTotal (70+ engines) and every IP against AbuseIPDB
4. **Attachment Scanning** — Extracts PDF/Word/ZIP attachments and submits them to VirusTotal Files API
5. **Risk Scoring** — Weighted signal model produces a 0–100 risk score with full breakdown
6. **Incident Report + Slack Alert** — Generates a professional SOC report and sends alerts to `#soc-alerts`

---

## ✨ Features

### 🧠 AI Analysis Engine
- Groq API (LLaMA 3.1 8B) with `temperature=0.0` for deterministic output
- Python-level enforcement layer prevents AI hallucination of IOCs
- Sender domain whitelist: Google, Microsoft, Apple, PayPal, Amazon, etc.
- AI confidence score capped at 30 if email headers are missing

### 🔍 IOC Extraction
- URLs, domains, IP addresses extracted from headers + body
- Regex IP extraction as backup when AI misses IPs in received headers
- MITRE ATT&CK technique mapping for every detected tactic

### 🌐 Threat Intelligence
- **VirusTotal** — URL reputation across 70+ antivirus engines
- **AbuseIPDB** — IP abuse score, ISP, country, Tor node detection
- Retry logic (3 attempts, 2s delay) for API reliability
- Trust reduction logic: clean threat intel overrides high AI confidence

### 📎 Attachment Scanning *(New)*
- Extracts PDF, Word, Excel, ZIP, EXE attachments from `.eml` files
- SHA256 hash lookup — checks VirusTotal cache first (no re-upload needed)
- Falls back to direct file upload + polling for new/unknown files
- Skips files over 5MB and non-suspicious file types automatically

### 📊 SIEM Log Export *(New)*
- Every analysis auto-saved to `output/siem_logs.ndjson` on disk
- Elastic Common Schema (ECS) compatible format
- One JSON object per line — directly ingestible by Splunk, Elastic, Wazuh
- Persistent across server restarts and browser sessions
- `/siem-logs` API endpoint returns full history with stats

### 🖥️ Wazuh-Style SOC Dashboard *(New)*
- **Email Analyzer** — Paste raw `.eml` or Gmail "Show Original" content
- **Alert Queue** — Session history table with CSV export
- **MITRE ATT&CK View** — All detected techniques across session
- **IOC Registry** — Accumulated URLs, domains, IPs across all analyses
- **SIEM Logs View** — Live JSON viewer with download as `.ndjson`
- All copy buttons work reliably with clipboard fallback

### 🎯 MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Urgency | T1566.001 | Spearphishing Attachment |
| Credential Harvesting | T1598.003 | Spearphishing Link |
| Spoofing | T1566.002 | Spearphishing Link |
| Social Engineering | T1566 | Phishing |
| Lookalike Domain | T1583.001 | Acquire Domain |

---

## 📊 Risk Scoring Model

| Signal | Points |
|--------|--------|
| AI confidence > 70% | +40 pts |
| VirusTotal malicious > 10 engines | +25 pts |
| VirusTotal malicious 3–10 engines | +15 pts |
| VirusTotal malicious 1–3 engines | +5 pts |
| AbuseIPDB score > 60% | +20 pts |
| AbuseIPDB score 30–60% | +10 pts |
| Tor exit node detected | +10 pts |
| Sender spoofing detected | +10 pts |
| Credential harvesting detected | +5 pts |
| **Trust reduction** (all clean intel) | Score capped at 30 |

**Risk Levels:** 0–29 LOW · 30–70 MEDIUM · 71–100 HIGH

---

## 🧪 Test Results

| Email | Score | Level | Result |
|-------|-------|-------|--------|
| Microsoft phishing (.ru domain, Tor IP) | 85/100 | 🔴 HIGH | ✅ Correct |
| PayPal suspicious (lookalike domain) | 50/100 | 🟡 MEDIUM | ✅ Correct |
| Google legitimate (google.com) | 0/100 | 🟢 LOW | ✅ Correct |
| Body-only, no headers | 0/100 | 🟢 LOW | ✅ Correct |
| Real Microsoft security alert | 20/100 | 🟢 LOW | ✅ Correct |
| Real Chase bank alert | 20/100 | 🟢 LOW | ✅ Correct |
| CashApp scam | 50/100 | 🟡 MEDIUM | ✅ Correct |
| Salary phishing with PDF attachment | 30/100 | 🟡 MEDIUM | ✅ Correct |

**Zero false positives on legitimate emails.**

---

## 🏗️ Architecture

```
sample_emails/          # Test .eml files
src/
├── email_parser.py     # Stage 1: Parse .eml files
├── ioc_extractor.py    # Stage 2: AI IOC extraction (Groq)
├── ip_extractor.py     # Stage 2b: Regex IP backup
├── enrichment.py       # Stage 3: VirusTotal + AbuseIPDB
├── attachment_scanner.py # Stage 3b: VirusTotal Files API
├── risk_scorer.py      # Stage 4: Weighted risk scoring
├── reporter.py         # Stage 5: AI incident report generation
├── slack_alert.py      # Stage 6: Slack webhook alerts
└── siem_logger.py      # Auto-save NDJSON logs to disk
web/
├── app.py              # Flask API (rate-limited, input-validated)
└── templates/
    └── index.html      # Wazuh-style SOC dashboard
output/
├── report_*.txt        # Saved incident reports
└── siem_logs.ndjson    # Persistent SIEM log file
main.py                 # CLI pipeline controller
```

---

## ⚙️ Setup

### Requirements
- Python 3.11+
- Groq API key (free at [console.groq.com](https://console.groq.com))
- VirusTotal API key (free at [virustotal.com](https://virustotal.com))
- AbuseIPDB API key (free at [abuseipdb.com](https://abuseipdb.com))
- Slack webhook URL (optional)

### Installation

```bash
git clone https://github.com/RishavTh/AI-Phising-Analyzer.git
cd AI-Phising-Analyzer
pip3 install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys
```

### Environment Variables

```env
GROQ_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SLACK_WEBHOOK_URL=your_webhook_here   # optional
```

### Run CLI

```bash
python3 main.py sample_emails/test_phishing.eml
```

### Run Web Dashboard

```bash
python3 web/app.py
# Open http://localhost:5000
```

---

## 🔒 Security Hardening

- Rate limiting: 10 requests/minute, 100/hour per IP
- Input validation: 20–100,000 character limits
- Secure temp file handling with `finally` cleanup
- `.env` file at `chmod 600` — never committed to git
- Debug mode disabled in production
- All JSON response values sanitized via `safe_str()`

---

## 💡 Interview Talking Points

- **"Reduces triage from 8 minutes to under 5 seconds per email"**
- **"Discovered LLM was hallucinating IOCs — fixed with Python enforcement layer and temperature=0"**
- **"Weighted signal model similar to Splunk SOAR / Palo Alto XSOAR"**
- **"Automatically maps tactics to MITRE ATT&CK — same framework as CrowdStrike and Microsoft Defender"**
- **"Trust reduction logic prevents false positives on legitimate security emails like Chase and Microsoft"**
- **"Attachment scanning uses SHA256 hash lookup — same technique as enterprise EDR tools"**
- **"SIEM logs in ECS format — directly ingestible by Splunk, Elastic, or Wazuh without transformation"**
- **"Zero false positives across 8 real-world test scenarios"**

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| AI Engine | Groq API — LLaMA 3.1 8B Instant |
| URL Threat Intel | VirusTotal API v3 |
| IP Threat Intel | AbuseIPDB API v2 |
| Attachment Scanning | VirusTotal Files API |
| Web Framework | Flask + Flask-Limiter |
| Frontend | Vanilla JS + IBM Plex fonts |
| Alerting | Slack Webhooks |
| Log Format | Elastic Common Schema (ECS) NDJSON |
| Runtime | Python 3.11 on Debian Linux |

---

## 📁 Sample Emails Included

| File | Description |
|------|-------------|
| `test_phishing.eml` | Microsoft impersonation with Tor IP |
| `test_medium.eml` | PayPal lookalike domain |
| `test_clean.eml` | Legitimate Google email |
| `test_attachment.eml` | Salary phishing with PDF attachment |

---

*Built as a SOC portfolio project demonstrating real-world email triage automation.*
