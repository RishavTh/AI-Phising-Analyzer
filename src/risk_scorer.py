# risk_scorer.py
# Stage 4: Risk Scoring Engine
# This combines ALL signals into a single 0-100 risk score
# This is exactly how real SOAR platforms make triage decisions

def calculate_risk_score(iocs, enrichment):
    """
    Takes IOC data from Stage 2 and enrichment from Stage 3
    and calculates a final risk score from 0 to 100.
    
    Think of this like a judge adding up evidence before a verdict.
    """

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

        # Extra points for Tor exit nodes
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

    # --- Cap score at 100 ---
    score = min(score, 100)

    # --- Determine Risk Level ---
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

    # Trust reduction: cap score when all threat intel is clean
    url_results = enrichment.get('url_results', [])
    ip_results  = enrichment.get('ip_results', [])

    all_urls_clean = all(
        r.get('malicious_engines', 0) == 0
        for r in (url_results if isinstance(url_results, list) else url_results.values())
    ) if url_results else True

    no_ip_abuse = all(
        r.get('abuse_score', 0) < 20
        for r in (ip_results if isinstance(ip_results, list) else ip_results.values())
    ) if ip_results else True

    spoofing    = iocs.get('spoofing_detected', False)
    credential  = iocs.get('credential_harvesting', False)

    if all_urls_clean and no_ip_abuse and not spoofing and not credential:
        if score > 30:
            score = 30
            reasons.append("Clean threat intel — score capped at 30")

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "action": action,
        "emoji": emoji,
        "score_breakdown": reasons
    }


# --- TEST ---
if __name__ == "__main__":
    import json

    # Simulate data from Stage 2 and Stage 3
    test_iocs = {
        "ai_confidence_score": 95,
        "spoofing_detected": True,
        "credential_harvesting": True,
        "urgency_detected": True
    }

    test_enrichment = {
        "url_results": [
            {"url": "http://micros0ft-verify.ru", "malicious": 0}
        ],
        "ip_results": [
            {
                "ip": "185.220.101.45",
                "abuse_confidence_score": 100,
                "is_tor": True
            }
        ]
    }

    result = calculate_risk_score(test_iocs, test_enrichment)

    print("=" * 50)
    print("STAGE 4: RISK SCORING ENGINE")
    print("=" * 50)
    print(f"{result['emoji']} RISK LEVEL: {result['risk_level']}")
    print(f"RISK SCORE: {result['risk_score']} / 100")
    print(f"\nRECOMMENDED ACTION:\n{result['action']}")
    print(f"\nSCORE BREAKDOWN:")
    for reason in result['score_breakdown']:
        print(f"  + {reason}")
    print("=" * 50)
