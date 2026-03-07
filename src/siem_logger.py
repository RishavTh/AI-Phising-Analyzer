# siem_logger.py
# Auto-saves every analysis as NDJSON to output/siem_logs.ndjson
# Format: one JSON object per line — directly ingestible by Splunk/Elastic/Wazuh

import os
import json
from datetime import datetime, timezone

SIEM_LOG_FILE = "output/siem_logs.ndjson"


def write_siem_log(email_data, iocs, enrichment, risk_result):
    """
    Writes one SIEM log entry to disk after every analysis.
    Format: Elastic Common Schema (ECS) compatible NDJSON.
    One line per event — Splunk and Elastic can ingest this directly.
    """
    log = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "kind": "alert",
            "category": "email",
            "type": "info",
            "provider": "PhishGuard-SOC-v3",
            "severity": 3 if risk_result['risk_level'] == 'HIGH'
                        else 2 if risk_result['risk_level'] == 'MEDIUM'
                        else 1
        },
        "phishguard": {
            "risk_score":       risk_result['risk_score'],
            "risk_level":       risk_result['risk_level'],
            "action":           risk_result['action'],
            "score_breakdown":  risk_result['score_breakdown']
        },
        "email": {
            "from":     str(email_data.get('sender', '')),
            "reply_to": str(email_data.get('reply_to', '')),
            "subject":  str(email_data.get('subject', '')),
            "date":     str(email_data.get('date', ''))
        },
        "threat": {
            "ai_confidence":        iocs.get('ai_confidence_score', 0),
            "spoofing_detected":    iocs.get('spoofing_detected', False),
            "credential_harvesting":iocs.get('credential_harvesting', False),
            "urgency_detected":     iocs.get('urgency_detected', False),
            "phishing_tactics":     iocs.get('phishing_tactics', []),
            "summary":              iocs.get('summary', '')
        },
        "indicators": {
            "urls":    iocs.get('urls', []),
            "domains": iocs.get('domains', []),
            "ips":     iocs.get('ips', [])
        },
        "mitre_attack": [
            {
                "technique_id":   t['technique_id'],
                "technique_name": t['technique_name'],
                "tactic":         t['tactic']
            }
            for t in iocs.get('mitre_techniques', [])
        ],
        "enrichment": {
            "url_results": enrichment.get('url_results', []),
            "ip_results":  enrichment.get('ip_results', [])
        }
    }

    # Make sure output/ directory exists
    os.makedirs("output", exist_ok=True)

    # Append one line to the NDJSON file
    with open(SIEM_LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
        f.write(json.dumps(log, ensure_ascii=False) + "\n")

    return SIEM_LOG_FILE


def read_siem_logs(limit=50):
    """
    Reads last N log entries from disk.
    Used by the dashboard to show persistent history across sessions.
    """
    if not os.path.exists(SIEM_LOG_FILE):
        return []

    logs = []
    with open(SIEM_LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    # Return most recent first
    return list(reversed(logs[-limit:]))


def get_siem_stats():
    """
    Returns summary stats from the SIEM log file.
    Shows total alerts, HIGH/MEDIUM/LOW counts.
    """
    logs = read_siem_logs(limit=10000)
    if not logs:
        return {"total": 0, "high": 0, "medium": 0, "low": 0}

    return {
        "total":  len(logs),
        "high":   sum(1 for l in logs if l.get('phishguard',{}).get('risk_level') == 'HIGH'),
        "medium": sum(1 for l in logs if l.get('phishguard',{}).get('risk_level') == 'MEDIUM'),
        "low":    sum(1 for l in logs if l.get('phishguard',{}).get('risk_level') == 'LOW'),
    }


if __name__ == "__main__":
    stats = get_siem_stats()
    print(f"SIEM Log Stats: {stats}")
    logs = read_siem_logs(5)
    print(f"Last {len(logs)} entries:")
    for l in logs:
        ts = l.get('@timestamp','')[:19]
        level = l.get('phishguard',{}).get('risk_level','?')
        subject = l.get('email',{}).get('subject','?')
        print(f"  {ts} | {level:6} | {subject[:50]}")
