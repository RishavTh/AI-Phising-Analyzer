# reporter.py
# Stage 5: Analyst Report Generator
# This takes all our data and generates a human-readable SOC report
# In real SOC work this is what gets sent to L2 analysts and management

import os
import json
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def generate_report(email_data, iocs, enrichment, risk_result):
    """
    Sends all collected data to Groq AI and asks it to write
    a professional SOC analyst report.
    """

    # Build a summary of enrichment results for the prompt
    url_summary = ""
    for u in enrichment.get("url_results", []):
        url_summary += f"URL: {u.get('url')} | Malicious: {u.get('malicious', 0)} engines\n"

    ip_summary = ""
    for i in enrichment.get("ip_results", []):
        ip_summary += f"IP: {i.get('ip')} | Abuse Score: {i.get('abuse_confidence_score')}% | ISP: {i.get('isp')} | Tor: {i.get('is_tor')}\n"

    today = datetime.now().strftime("%Y-%m-%d")
    prompt = f"""
You are a senior SOC analyst. Write a professional incident report based on this data.
Today's date is {today}. Use this exact date in the report — never use 2023 or any other year.

EMAIL DETAILS:
- From: {email_data['sender']}
- Reply-To: {email_data['reply_to']}
- Subject: {email_data['subject']}
- Date: {email_data['date']}

AI ANALYSIS:
- Phishing Tactics: {iocs.get('phishing_tactics')}
- Spoofing Detected: {iocs.get('spoofing_detected')}
- Credential Harvesting: {iocs.get('credential_harvesting')}
- AI Confidence: {iocs.get('ai_confidence_score')}%
- Summary: {iocs.get('summary')}

THREAT INTEL:
{url_summary}
{ip_summary}

RISK ASSESSMENT:
- Risk Score: {risk_result['risk_score']} / 100
- Risk Level: {risk_result['risk_level']}
- Recommended Action: {risk_result['action']}

Write a structured SOC incident report with these sections:
1. EXECUTIVE SUMMARY
2. THREAT INDICATORS
3. ATTACK TECHNIQUE ANALYSIS  
4. RECOMMENDED ACTIONS
5. ANALYST NOTES

Keep it professional, concise and actionable.
"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "system",
                "content": "You are a senior SOC analyst writing professional incident reports."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2
    )

    report_text = response.choices[0].message.content
    return report_text


def save_report(report_text, risk_result):
    """
    Saves the report to the output folder with a timestamp.
    Every incident gets its own file — just like a real SOC ticketing system.
    """

    # Create timestamp for filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    risk_level = risk_result['risk_level']
    filename = f"output/report_{risk_level}_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("SOC INCIDENT REPORT - AI PHISHING ANALYZER\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Risk Level: {risk_result['emoji']} {risk_level}\n")
        f.write(f"Risk Score: {risk_result['risk_score']} / 100\n")
        f.write("=" * 60 + "\n\n")
        f.write(report_text)
        f.write("\n\n" + "=" * 60 + "\n")
        f.write("SCORE BREAKDOWN:\n")
        for reason in risk_result['score_breakdown']:
            f.write(f"  {reason}\n")
        f.write("=" * 60 + "\n")

    print(f"Report saved to: {filename}")
    return filename


# --- TEST ---
if __name__ == "__main__":
    from email_parser import parse_email
    from ioc_extractor import extract_iocs
    from enrichment import enrich_iocs
    from risk_scorer import calculate_risk_score

    print("=" * 60)
    print("STAGE 5: GENERATING ANALYST REPORT")
    print("=" * 60)

    # Run the full pipeline
    print("\n[1/4] Parsing email...")
    email_data = parse_email("sample_emails/test_phishing.eml")

    print("[2/4] Extracting IOCs with AI...")
    iocs = extract_iocs(email_data)

    print("[3/4] Enriching IOCs with threat intel...")
    enrichment = enrich_iocs(iocs)

    print("[4/4] Calculating risk score...")
    risk_result = calculate_risk_score(iocs, enrichment)

    print("\n Generating analyst report...")
    report = generate_report(email_data, iocs, enrichment, risk_result)

    # Print to screen
    print("\n" + "=" * 60)
    print(report)
    print("=" * 60)

    # Save to file
    saved_path = save_report(report, risk_result)
    print(f"\n Report saved!")
