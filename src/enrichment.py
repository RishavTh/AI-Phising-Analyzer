# enrichment.py
# Stage 3: IOC Enrichment
# Improvements: retry logic, timeouts, deduplication

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

API_TIMEOUT = 10
MAX_RETRIES = 3
RETRY_DELAY = 2


def with_retry(func, *args, **kwargs):
    """
    Retries a function up to MAX_RETRIES times.
    Waits RETRY_DELAY seconds between attempts.
    This prevents single network hiccups from failing the whole pipeline.
    """
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = func(*args, **kwargs)
            if result.get('error') and attempt < MAX_RETRIES:
                print(f"  ⚠️  Attempt {attempt} failed — retrying...")
                time.sleep(RETRY_DELAY)
                continue
            return result
        except Exception as e:
            last_error = e
            if attempt < MAX_RETRIES:
                print(f"  ⚠️  Attempt {attempt} error: {e} — retrying...")
                time.sleep(RETRY_DELAY)

    return {"error": str(last_error)}


def check_url_virustotal(url):
    """Checks URL against VirusTotal with retry logic"""
    try:
        headers = {"x-apikey": VT_API_KEY}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=API_TIMEOUT
        )

        if response.status_code != 200:
            return {"url": url, "malicious": 0,
                    "error": f"VT returned {response.status_code}"}

        analysis_id = response.json()["data"]["id"]

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=API_TIMEOUT
        )

        if result.status_code != 200:
            return {"url": url, "malicious": 0, "error": "VT fetch failed"}

        stats = result.json()["data"]["attributes"]["stats"]

        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"url": url, "malicious": 0, "error": "timeout"}
    except Exception as e:
        return {"url": url, "malicious": 0, "error": str(e)}


def check_ip_abuseipdb(ip):
    """Checks IP against AbuseIPDB with retry logic"""
    try:
        headers = {
            "Key": ABUSE_API_KEY,
            "Accept": "application/json"
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=API_TIMEOUT
        )

        if response.status_code != 200:
            return {
                "ip": ip,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "country": "Unknown",
                "isp": "Unknown",
                "is_tor": False,
                "error": f"AbuseIPDB returned {response.status_code}"
            }

        data = response.json()["data"]

        return {
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "is_tor": data.get("isTor", False),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {
            "ip": ip,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "is_tor": False,
            "error": "timeout"
        }
    except Exception as e:
        return {"ip": ip, "abuse_confidence_score": 0, "error": str(e)}


def enrich_iocs(iocs):
    """
    Enriches all IOCs with threat intelligence.
    Features: retry logic, deduplication, graceful failures.
    """
    enrichment_results = {
        "url_results": [],
        "ip_results": []
    }

    # Deduplicate URLs before checking
    unique_urls = list(set(iocs.get("urls", [])))
    unique_ips = list(set(iocs.get("ips", [])))

    # Check URLs against VirusTotal
    print("\n  Checking URLs against VirusTotal...")
    for url in unique_urls:
        print(f"  Checking: {url}")
        result = with_retry(check_url_virustotal, url)
        enrichment_results["url_results"].append(result)
        if result.get("error"):
            print(f"  ⚠️  VT skipped: {result['error']}")
        else:
            print(f"  Malicious engines: {result.get('malicious', 0)}")

    # Check IPs against AbuseIPDB
    print("\n  Checking IPs against AbuseIPDB...")
    for ip in unique_ips:
        print(f"  Checking: {ip}")
        result = with_retry(check_ip_abuseipdb, ip)
        enrichment_results["ip_results"].append(result)
        if result.get("error"):
            print(f"  ⚠️  AbuseIPDB skipped: {result['error']}")
        else:
            print(f"  Abuse Score: {result.get('abuse_confidence_score', 0)}%")

    return enrichment_results
