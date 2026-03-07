# ip_extractor.py
# Extracts IP addresses from email using regex
# Backup for when AI misses IPs in headers

import re

# Regex pattern for IPv4 addresses
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# IPs to always ignore — private/localhost ranges
IGNORED_IPS = {
    '127.0.0.1', '0.0.0.0', '255.255.255.255',
    '192.168.', '10.0.', '172.16.', '172.17.',
    '172.18.', '172.19.', '172.20.'
}

def extract_ips_from_email(email_content):
    """
    Uses regex to extract all public IPv4 addresses from email.
    This is a reliable backup when AI misses IPs in headers.
    """
    if not email_content:
        return []

    # Find all IP matches
    matches = IPV4_PATTERN.findall(email_content)

    # Filter out private/ignored IPs
    public_ips = []
    for ip in matches:
        is_private = any(ip.startswith(prefix)
                        for prefix in IGNORED_IPS
                        if '.' in prefix)
        is_exact = ip in IGNORED_IPS
        if not is_private and not is_exact:
            public_ips.append(ip)

    # Remove duplicates while preserving order
    seen = set()
    unique_ips = []
    for ip in public_ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    return unique_ips


# --- TEST ---
if __name__ == "__main__":
    test_email = """
    Received: from 185.220.101.45 (micros0ft-alert.ru)
    X-Originating-IP: 185.220.101.45
    From: security@evil.ru
    Body: Your IP 192.168.1.1 has been logged.
    Contact: 10.0.0.1 is our internal server.
    Malicious server: 91.108.56.130
    """
    ips = extract_ips_from_email(test_email)
    print(f"Extracted public IPs: {ips}")
    # Should show: ['185.220.101.45', '91.108.56.130']
    # Should NOT show: 192.168.1.1 or 10.0.0.1 (private IPs)
