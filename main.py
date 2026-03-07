# main.py
# AI PHISHING ANALYZER - Master Controller
# Usage: python3 main.py sample_emails/test_phishing.eml

import sys
import json
from datetime import datetime

# Import all modules from src/
sys.path.insert(0, 'src')

from email_parser import parse_email
from ioc_extractor import extract_iocs
from enrichment import enrich_iocs
from risk_scorer import calculate_risk_score
from reporter import generate_report, save_report
from slack_alert import send_slack_alert

def run_pipeline(email_path):
    print("\n" + "=" * 60)
    print("   AI PHISHING ANALYZER - SOC AUTOMATION TOOL")
    print("=" * 60)
    print(f"Target:  {email_path}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    print("\n[STAGE 1/6] Parsing email...")
    email_data = parse_email(email_path)
    if not email_data:
        print("ERROR: Could not parse email. Exiting.")
        return
    print(f"From:    {email_data['sender']}")
    print(f"Subject: {email_data['subject']}")
    print("✅ Email parsed successfully")

    print("\n[STAGE 2/6] Extracting IOCs with AI...")
    iocs = extract_iocs(email_data)
    print(f"URLs found:    {len(iocs.get('urls', []))}")
    print(f"Domains found: {len(iocs.get('domains', []))}")
    print(f"Tactics found: {', '.join(iocs.get('phishing_tactics', []))}")
    print(f"AI Confidence: {iocs.get('ai_confidence_score')}%")
    print("✅ IOCs extracted successfully")

    print("\n[STAGE 3/6] Enriching IOCs with threat intelligence...")
    enrichment = enrich_iocs(iocs)
    print("✅ Enrichment complete")

    print("\n[STAGE 4/6] Calculating risk score...")
    risk_result = calculate_risk_score(iocs, enrichment)
    print(f"{risk_result['emoji']} Risk Level: {risk_result['risk_level']}")
    print(f"Risk Score:  {risk_result['risk_score']} / 100")
    print(f"Action:      {risk_result['action']}")
    print("✅ Risk score calculated")

    print("\n[STAGE 5/6] Generating analyst report...")
    report = generate_report(email_data, iocs, enrichment, risk_result)
    saved_path = save_report(report, risk_result)
    print("✅ Report generated and saved")

    print("\n[STAGE 6/6] Sending Slack alert...")
    alert_sent = send_slack_alert(email_data, iocs, risk_result)
    if alert_sent:
        print("✅ Slack alert sent")
    else:
        print("ℹ️  No Slack alert needed for this risk level")

    print("\n" + "=" * 60)
    print("   ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"{risk_result['emoji']}  VERDICT: {risk_result['risk_level']} RISK")
    print(f"📊 Score:   {risk_result['risk_score']} / 100")
    print(f"📄 Report:  {saved_path}")
    print(f"🕐 Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage: python3 main.py <path_to_email.eml>")
        print("Example: python3 main.py sample_emails/test_phishing.eml\n")
        sys.exit(1)

    email_path = sys.argv[1]
    run_pipeline(email_path)
