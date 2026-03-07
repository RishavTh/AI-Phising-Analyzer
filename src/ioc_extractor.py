import os
import json
import re
from groq import Groq
from dotenv import load_dotenv
from ip_extractor import extract_ips_from_email

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

MITRE_MAPPING = {
    "urgency": {"technique": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "credential harvesting": {"technique": "T1598.003", "name": "Spearphishing Link", "tactic": "Reconnaissance"},
    "spoofing": {"technique": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
    "social engineering": {"technique": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    "lookalike domain": {"technique": "T1583.001", "name": "Acquire Domain", "tactic": "Resource Development"},
    "suspicious domain": {"technique": "T1583.001", "name": "Acquire Domain", "tactic": "Resource Development"}
}

VALID_DOMAIN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')

def map_to_mitre(tactics):
    mapped = []
    seen = set()
    for tactic in tactics:
        for keyword, technique in MITRE_MAPPING.items():
            if keyword in tactic.lower():
                key = technique['technique']
                if key not in seen:
                    seen.add(key)
                    mapped.append({
                        "technique_id": technique['technique'],
                        "technique_name": technique['name'],
                        "tactic": technique['tactic'],
                        "detected_as": tactic
                    })
    return mapped


def extract_iocs(email_data):

    sender   = email_data.get('sender', 'Unknown')
    reply_to = email_data.get('reply_to', 'Not set')
    subject  = email_data.get('subject', 'No subject')
    date     = email_data.get('date', 'Unknown')
    body     = email_data.get('body', '')

    headers_missing = (
        sender == 'Unknown' and
        reply_to == 'Not set' and
        subject == 'No subject'
    )

    prompt = f"""
You are a strict, precise SOC analyst extracting IOCs from an email.

EMAIL:
From: {sender}
Reply-To: {reply_to}
Subject: {subject}
Date: {date}
Body:
{body}

YOUR RULES:

RULE 1 — ONLY extract what literally exists in the email text above.
- urls: ONLY real URLs starting with http/https
- domains: ONLY domain names that actually appear (format: something.tld)
- ips: ONLY IP addresses that literally appear
- DO NOT invent or hallucinate domains like micros0ft/paypa1/g00gle
  unless they are literally in the email text above

RULE 2 — HEADERS MISSING = {headers_missing}
If True:
- ai_confidence_score MUST be 30 or below
- spoofing_detected MUST be false
- credential_harvesting: set true if email asks user to click a link to verify/confirm/review account details, reset password, or validate identity. This IS credential harvesting even without the word "password".

RULE 3 — ai_confidence_score above 60 requires TWO or more of:
- Lookalike domain in the actual email text
- Sender domain mismatches company name
- Reply-To differs from sender
- Explicit credential request in body
- Malicious IP in headers

RULE 4 — phishing_tactics:
- Only list tactics with direct evidence in the text
- Generic words like "verify" or "confirm" alone do NOT count

Return ONLY this JSON:
{{
    "urls": [],
    "domains": [],
    "ips": [],
    "sender_email": "",
    "sender_domain": "",
    "reply_to_email": "",
    "phishing_tactics": [],
    "urgency_detected": true or false,
    "credential_harvesting": true or false,
    "spoofing_detected": true or false,
    "ai_confidence_score": 0-100,
    "summary": "one sentence"
}}
"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "system",
                "content": "You are a strict SOC analyst. NEVER invent URLs or domains. ONLY extract what literally exists in the email. Return JSON only."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.0
    )

    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    iocs = json.loads(raw)

    # Hard enforce headers missing rule
    if headers_missing:
        iocs['ai_confidence_score'] = min(iocs.get('ai_confidence_score', 0), 30)
        iocs['spoofing_detected'] = False
        iocs['credential_harvesting'] = False

    # Clean domains — remove anything that is not a real domain format
    iocs['domains'] = [
        d for d in iocs.get('domains', [])
        if VALID_DOMAIN.match(d.strip())
    ]

    # Clean URLs — must start with http and contain a dot
    iocs['urls'] = [
        u for u in iocs.get('urls', [])
        if u.startswith('http') and '.' in u
    ]

    # Filter IPs — remove text strings that are not real IPs
    import re
    IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    iocs['ips'] = [ip for ip in iocs.get('ips', []) if IP_PATTERN.match(str(ip).strip())]

    # Regex IP backup
    full_text = f"{sender} {reply_to} {body}"
    regex_ips = extract_ips_from_email(full_text)
    iocs['ips'] = list(set(iocs.get('ips', []) + regex_ips))

    # Filter whitelisted legitimate domains to prevent false positives
    WHITELIST = {
        'gmail.com', 'google.com', 'microsoft.com', 'outlook.com',
        'yahoo.com', 'apple.com', 'amazon.com', 'facebook.com',
        'googleapis.com', 'gstatic.com', 'youtube.com', 'cloudflare.com'
    }
    iocs['domains'] = [d for d in iocs.get('domains', []) if d not in WHITELIST]

    # MITRE mapping
    iocs['mitre_techniques'] = map_to_mitre(iocs.get('phishing_tactics', []))

    return iocs
