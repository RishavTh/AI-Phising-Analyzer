# slack_alert.py
# Stage 6: Slack Alerting
# Sends real-time alerts to your SOC team when HIGH risk email is detected
# This is exactly how real SOAR platforms notify analysts

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack_alert(email_data, iocs, risk_result):
    """
    Sends a formatted Slack alert to #soc-alerts channel.
    Only triggers for MEDIUM and HIGH risk emails.
    LOW risk = silent log only.
    """

    risk_level = risk_result['risk_level']
    risk_score = risk_result['risk_score']
    emoji = risk_result['emoji']

    # LOW risk = no Slack alert needed
    if risk_level == "LOW":
        print("Risk level LOW - no Slack alert sent. Logged silently.")
        return False

    # Build the Slack message
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} PHISHING ALERT - {risk_level} RISK DETECTED"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{risk_score} / 100"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Level:*\n{emoji} {risk_level}"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*From:*\n{email_data['sender']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Reply-To:*\n{email_data['reply_to']}"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Subject:*\n{email_data['subject']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*AI Confidence:*\n{iocs.get('ai_confidence_score')}%"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Phishing Tactics:*\n{', '.join(iocs.get('phishing_tactics', []))}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Action:*\n`{risk_result['action']}`"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Score Breakdown:*\n" + "\n".join([f"• {r}" for r in risk_result['score_breakdown']])
                }
            }
        ]
    }

    # Send to Slack
    response = requests.post(
        SLACK_WEBHOOK_URL,
        data=json.dumps(message),
        headers={"Content-Type": "application/json"}
    )

    if response.status_code == 200:
        print(f"Slack alert sent successfully!")
        return True
    else:
        print(f"Slack alert failed: {response.status_code} - {response.text}")
        return False


# --- TEST ---
if __name__ == "__main__":
    from email_parser import parse_email
    from ioc_extractor import extract_iocs
    from enrichment import enrich_iocs
    from risk_scorer import calculate_risk_score

    print("=" * 60)
    print("STAGE 6: SLACK ALERT SYSTEM")
    print("=" * 60)

    print("\n[1/4] Parsing email...")
    email_data = parse_email("sample_emails/test_phishing.eml")

    print("[2/4] Extracting IOCs with AI...")
    iocs = extract_iocs(email_data)

    print("[3/4] Enriching IOCs...")
    enrichment = enrich_iocs(iocs)

    print("[4/4] Calculating risk score...")
    risk_result = calculate_risk_score(iocs, enrichment)

    print(f"\nRisk Level: {risk_result['emoji']} {risk_result['risk_level']}")
    print(f"Risk Score: {risk_result['risk_score']} / 100")

    print("\nSending Slack alert...")
    send_slack_alert(email_data, iocs, risk_result)
