# risk_scorer.py
from datetime import datetime
# Stage 4: Risk Scoring Engine

TRUSTED_DOMAINS = {
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'accounts.google.com', 'myaccount.google.com', 'mail.google.com',
    'account.microsoft.com', 'login.microsoftonline.com',
    'appleid.apple.com', 'secure.chase.com', 'account.chase.com',
    'paypal.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'github.com', 'dropbox.com', 'icloud.com', 'outlook.com',
    'live.com', 'hotmail.com', 'yahoo.com', 'gmail.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com',
}

# Major brands that phishers commonly impersonate
BRAND_KEYWORDS = {
    'microsoft': ['microsoft.com', 'office.com', 'sharepoint.com', 'live.com', 'outlook.com'],
    'apple':     ['apple.com', 'icloud.com'],
    'google':    ['google.com', 'gmail.com'],
    'paypal':    ['paypal.com'],
    'amazon':    ['amazon.com', 'aws.amazon.com'],
    'facebook':  ['facebook.com', 'fb.com'],
    'netflix':   ['netflix.com'],
    'dropbox':   ['dropbox.com'],
    'docusign':  ['docusign.com'],
    'chase':     ['chase.com'],
    'wellsfargo':['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com'],
}

def levenshtein(s1, s2):
    """Simple edit distance — detects typosquatting like m1crosoft vs microsoft."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1 != c2)))
        prev = curr
    return prev[-1]

BRAND_NAMES = list(BRAND_KEYWORDS.keys()) + [
    'sharepoint', 'onedrive', 'outlook', 'office365',
    'docusign', 'dropbox', 'wetransfer', 'zoom'
]

def detect_typosquatting(url_results):
    """
    Checks if any URL domain is a typosquat of a known brand.
    e.g. m1crosoft.com, paypa1.com, sharepont.com
    """
    for url_result in url_results:
        domain = url_result.get('domain', '') or url_result.get('url', '')
        if not domain:
            continue
        domain = domain.lower().strip()
        # Get base domain without TLD
        parts = domain.split('.')
        base = parts[-2] if len(parts) >= 2 else parts[0]
        # Check edit distance against known brands
        for brand in BRAND_NAMES:
            dist = levenshtein(base, brand)
            # Edit distance 1-2 = typosquat (e.g. m1crosoft, sharepont)
            if 0 < dist <= 2 and len(base) > 4:
                return brand, domain
    return None, None


def detect_brand_impersonation(email_body, url_results):
    """
    Returns (brand, True) if email mentions a brand name
    but the URL does not belong to that brand's real domain.
    """
    if not email_body:
        return None, False
    body_lower = email_body.lower()
    for brand, real_domains in BRAND_KEYWORDS.items():
        if brand in body_lower:
            # Brand is mentioned — check if any URL matches real domain
            for url_result in url_results:
                url = url_result.get('url', '').lower()
                domain = url_result.get('domain', '').lower()
                for real in real_domains:
                    if real in url or real in domain:
                        return None, False  # Legit — URL matches brand
            # Brand mentioned but no URL matches — impersonation
            return brand, True
    return None, False


def is_suspicious_domain(domain):
    """Returns True if domain looks suspicious but has 0 VT hits."""
    if not domain:
        return False
    domain = domain.lower().strip()
    # Trusted domain — not suspicious
    base = '.'.join(domain.split('.')[-2:])
    if base in TRUSTED_DOMAINS:
        return False
    # Suspicious patterns
    suspicious_keywords = [
        'verify', 'secure', 'login', 'account', 'update', 'confirm',
        'banking', 'security', 'alert', 'notification', 'support',
        'service', 'check', 'validation', 'protection'
    ]
    for kw in suspicious_keywords:
        if kw in domain:
            return True
    # Non-standard TLDs combined with long domain
    suspicious_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return True
    # Very long domain names are suspicious
    if len(domain) > 35:
        return True
    return False


def calculate_risk_score(iocs, enrichment):
    score = 0
    reasons = []

    # --- SIGNAL 1: AI Confidence Score (max 40 points) ---
    ai_score = iocs.get("ai_confidence_score", 0)
    if ai_score > 70:
        score += 40
        reasons.append(f"AI confidence high: {ai_score}% (+40pts)")
    elif ai_score > 40:
        score += 20
        reasons.append(f"AI confidence medium: {ai_score}% (+20pts)")

    # --- SIGNAL 2: VirusTotal Results (max 25 points) ---
    for url_result in enrichment.get("url_results", []):
        malicious = url_result.get("malicious", 0)
        if malicious > 10:
            score += 25
            reasons.append(f"VT highly malicious: {malicious} engines (+25pts)")
        elif malicious > 3:
            score += 15
            reasons.append(f"VT suspicious: {malicious} engines (+15pts)")
        elif malicious > 0:
            score += 5
            reasons.append(f"VT low detections: {malicious} engines (+5pts)")

    # --- SIGNAL 3: AbuseIPDB Results (max 20 points) ---
    for ip_result in enrichment.get("ip_results", []):
        abuse_score = ip_result.get("abuse_confidence_score", 0)
        if abuse_score > 60:
            score += 20
            reasons.append(f"IP abuse score critical: {abuse_score}% (+20pts)")
        elif abuse_score > 30:
            score += 10
            reasons.append(f"IP abuse score medium: {abuse_score}% (+10pts)")
        if ip_result.get("is_tor"):
            score += 10
            reasons.append("Tor exit node detected (+10pts)")

    # --- SIGNAL 4: Spoofing Detected (10 points) ---
    if iocs.get("spoofing_detected"):
        score += 10
        reasons.append("Sender spoofing detected (+10pts)")

    # --- SIGNAL 5: Credential Harvesting (5 points) ---
    if iocs.get("credential_harvesting"):
        score += 5
        reasons.append("Credential harvesting attempt (+5pts)")

    # --- SIGNAL 6: Brand Impersonation (25 points) ---
    # Email mentions a real brand (Microsoft, PayPal etc) but URL is fake
    email_body = enrichment.get('email_body', '') or iocs.get('summary', '')
    brand, impersonating = detect_brand_impersonation(email_body, enrichment.get('url_results', []))
    if impersonating:
        score += 25
        reasons.append(f"Brand impersonation detected: '{brand}' mentioned but URL not on real domain (+25pts)")

    # --- SIGNAL 6a: Financial/Banking credential request (20 points) ---
    # Asking for bank details, salary info, payment details = very high risk
    body_lower = enrichment.get('email_body', '').lower()

    # --- SIGNAL 6b: Typosquatting detection (20 points) ---
    typo_brand, typo_domain = detect_typosquatting(enrichment.get('url_results', []))
    if typo_brand:
        score += 20
        reasons.append(f"Typosquatting detected: '{typo_domain}' impersonates '{typo_brand}' (+20pts)")

    # --- SIGNAL 7: Time pressure tactics (10 points) ---
    import re
    body = enrichment.get('email_body', '').lower()
    time_pressure_patterns = [
        r'expire[s]? in \d+', r'\d+ hour[s]?', r'within \d+',
        r'24 hour', r'48 hour', r'act (now|immediately|urgently)',
        r'limited time', r'expires? (today|soon|shortly)'
    ]
    for pattern in time_pressure_patterns:
        if re.search(pattern, body):
            score += 10
            reasons.append("Time pressure tactic detected (+10pts)")
            break

    # --- SIGNAL 8: New domain age check (15 points) ---
    # Domains registered < 30 days ago are very suspicious
    try:
        import whois
        from datetime import timezone
        for url_result in enrichment.get('url_results', []):
            if url_result.get('malicious', 0) > 0:
                continue  # Already scored by VT
            domain = url_result.get('domain', '')
            if not domain or any(t in domain for t in TRUSTED_DOMAINS):
                continue
            try:
                w = whois.whois(domain)
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if creation:
                    if creation.tzinfo is None:
                        creation = creation.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - creation).days
                    if age_days < 30:
                        score += 15
                        reasons.append(f"Very new domain: {domain} registered {age_days} days ago (+15pts)")
                        break
                    elif age_days < 90:
                        score += 8
                        reasons.append(f"New domain: {domain} registered {age_days} days ago (+8pts)")
                        break
            except Exception:
                pass  # WHOIS lookup failed — skip silently
    except ImportError:
        pass

    # --- SIGNAL 9: Suspicious unknown domain pattern (10 points) ---
    # VT has no data on it — but domain pattern looks malicious
    for url_result in enrichment.get("url_results", []):
        if url_result.get("malicious", 0) == 0:
            domain = url_result.get("domain", "") or url_result.get("url", "")
            if is_suspicious_domain(domain):
                score += 10
                reasons.append(f"Suspicious unknown domain (0 VT hits but pattern suspicious) (+10pts)")
                break

    # --- Cap score at 100 ---
    score = min(score, 100)

    # --- Trust reduction: cap at 30 when all intel is clean ---
    url_results = enrichment.get('url_results', [])
    ip_results  = enrichment.get('ip_results', [])

    all_urls_clean = all(
        r.get('malicious', 0) == 0       # FIX: was 'malicious_engines', correct key is 'malicious'
        for r in url_results
    ) if url_results else True

    no_ip_abuse = all(
        r.get('abuse_confidence_score', 0) < 20   # FIX: was 'abuse_score', correct key is 'abuse_confidence_score'
        for r in ip_results
    ) if ip_results else True

    spoofing   = iocs.get('spoofing_detected', False)
    credential = iocs.get('credential_harvesting', False)

    # Only apply trust reduction if domain is also not suspicious
    no_suspicious_domain = not any(
        is_suspicious_domain(r.get("domain", "") or r.get("url", ""))
        for r in url_results
    )

    # Extra check: if ALL urls are on trusted domains, force LOW regardless
    all_urls_trusted = all(
        any(trusted in r.get('url', '').lower() for trusted in TRUSTED_DOMAINS)
        for r in url_results
    ) if url_results else False

    if all_urls_trusted and no_ip_abuse and not typo_brand:
        score = min(score, 20)
        if score == 20 and "trusted domain override" not in str(reasons):
            reasons.append("All URLs on trusted domains — score capped at 20")

    elif all_urls_clean and no_ip_abuse and not spoofing and not credential and no_suspicious_domain:
        if score > 25:
            score = 25
            reasons.append("Clean threat intel — score capped at 25")

    # --- Determine Risk Level AFTER trust reduction ---  # FIX: was calculated before capping
    if score >= 71:
        risk_level = "HIGH"
        action = "BLOCK IP | QUARANTINE EMAIL | ESCALATE TO L2"
        emoji = "🔴"
    elif score >= 30:
        risk_level = "MEDIUM"
        action = "FLAG FOR ANALYST REVIEW | MONITOR"
        emoji = "🟡"
    else:
        risk_level = "LOW"
        action = "LOG AND MONITOR"
        emoji = "🟢"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "action": action,
        "emoji": emoji,
        "score_breakdown": reasons
    }


if __name__ == "__main__":
    # Test 1: HIGH risk — Tor IP + spoofing
    result = calculate_risk_score(
        {"ai_confidence_score": 95, "spoofing_detected": True, "credential_harvesting": True},
        {"url_results": [{"url": "http://micros0ft-verify.ru", "malicious": 0, "domain": "micros0ft-verify.ru"}],
         "ip_results": [{"ip": "185.220.101.45", "abuse_confidence_score": 100, "is_tor": True}]}
    )
    print(f"Test 1 (HIGH expected): {result['risk_level']} {result['risk_score']}/100")

    # Test 2: LOW risk — legitimate bank email, trusted domain
    result = calculate_risk_score(
        {"ai_confidence_score": 80, "spoofing_detected": False, "credential_harvesting": False},
        {"url_results": [{"url": "https://www.yourbank.com/login", "malicious": 0, "domain": "yourbank.com"}],
         "ip_results": []}
    )
    print(f"Test 2 (LOW expected):  {result['risk_level']} {result['risk_score']}/100")

    # Test 3: MEDIUM — suspicious domain, 0 VT hits
    result = calculate_risk_score(
        {"ai_confidence_score": 75, "spoofing_detected": False, "credential_harvesting": False},
        {"url_results": [{"url": "http://account-verify-security-check.com/login", "malicious": 0, "domain": "account-verify-security-check.com"}],
         "ip_results": []}
    )
    print(f"Test 3 (MEDIUM expected): {result['risk_level']} {result['risk_score']}/100")
