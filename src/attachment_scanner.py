# attachment_scanner.py
# Stage: Attachment Scanning
# Extracts attachments from .eml files and submits to VirusTotal Files API
# Real SOC skill — most junior candidates have never done this

import os
import email
import hashlib
import requests
import time
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY     = os.getenv("VIRUSTOTAL_API_KEY")
API_TIMEOUT    = 30
MAX_FILE_SIZE  = 5 * 1024 * 1024  # 5MB max per file

# File types we care about — skip images/fonts/css
SUSPICIOUS_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.exe', '.dll', '.bat', '.ps1', '.sh',
    '.js', '.vbs', '.wsf', '.hta', '.iso', '.img'
}


def extract_attachments(eml_path):
    """
    Extracts all attachments from a .eml file.
    Returns list of dicts: {filename, content, size, extension}
    """
    attachments = []

    if not os.path.exists(eml_path):
        return attachments

    try:
        with open(eml_path, "rb") as f:
            msg = email.message_from_bytes(f.read())

        for part in msg.walk():
            # Skip non-attachment parts
            content_disposition = str(part.get("Content-Disposition", ""))
            if "attachment" not in content_disposition.lower():
                continue

            filename = part.get_filename()
            if not filename:
                continue

            # Decode filename if encoded
            try:
                from email.header import decode_header
                decoded = decode_header(filename)
                filename = decoded[0][0]
                if isinstance(filename, bytes):
                    filename = filename.decode(decoded[0][1] or 'utf-8', errors='replace')
            except Exception:
                pass

            content = part.get_payload(decode=True)
            if not content:
                continue

            # Get file extension
            _, ext = os.path.splitext(filename.lower())

            attachments.append({
                "filename":  filename,
                "content":   content,
                "size":      len(content),
                "extension": ext,
                "sha256":    hashlib.sha256(content).hexdigest(),
                "md5":       hashlib.md5(content).hexdigest()
            })

    except Exception as e:
        print(f"  ⚠ Attachment extraction error: {e}")

    return attachments


def scan_file_virustotal(attachment):
    """
    Submits a file to VirusTotal Files API.
    Returns scan results with malicious engine count.
    """
    filename  = attachment['filename']
    content   = attachment['content']
    sha256    = attachment['sha256']
    size      = attachment['size']

    result = {
        "filename":  filename,
        "sha256":    sha256,
        "md5":       attachment['md5'],
        "size_kb":   round(size / 1024, 1),
        "extension": attachment['extension'],
        "malicious": 0,
        "suspicious": 0,
        "harmless":  0,
        "total_engines": 0,
        "scan_status": "not_scanned",
        "vt_link":   f"https://www.virustotal.com/gui/file/{sha256}",
        "error":     None
    }

    # Skip if too large
    if size > MAX_FILE_SIZE:
        result['scan_status'] = 'skipped_too_large'
        result['error'] = f'File too large ({round(size/1024/1024,1)}MB > 5MB limit)'
        return result

    # Skip non-suspicious file types
    if attachment['extension'] not in SUSPICIOUS_EXTENSIONS:
        result['scan_status'] = 'skipped_not_suspicious'
        return result

    try:
        headers = {"x-apikey": VT_API_KEY}

        # Step 1: Check if VT already has this file by hash
        check_resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=API_TIMEOUT
        )

        if check_resp.status_code == 200:
            # VT already knows this file — use cached result
            stats = check_resp.json()['data']['attributes']['last_analysis_stats']
            result['malicious']     = stats.get('malicious', 0)
            result['suspicious']    = stats.get('suspicious', 0)
            result['harmless']      = stats.get('harmless', 0)
            result['total_engines'] = sum(stats.values())
            result['scan_status']   = 'found_in_cache'
            print(f"  VT cache hit: {filename} — {result['malicious']} malicious engines")
            return result

        # Step 2: Upload file to VT for scanning
        print(f"  Uploading to VirusTotal: {filename} ({result['size_kb']}KB)...")
        upload_resp = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": (filename, content)},
            timeout=API_TIMEOUT
        )

        if upload_resp.status_code != 200:
            result['scan_status'] = 'upload_failed'
            result['error'] = f"VT upload returned {upload_resp.status_code}"
            return result

        analysis_id = upload_resp.json()['data']['id']

        # Step 3: Poll for results (max 3 attempts, 5s apart)
        for attempt in range(3):
            time.sleep(5)
            analysis_resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=API_TIMEOUT
            )

            if analysis_resp.status_code != 200:
                continue

            data   = analysis_resp.json()['data']
            status = data['attributes']['status']

            if status == 'completed':
                stats = data['attributes']['stats']
                result['malicious']     = stats.get('malicious', 0)
                result['suspicious']    = stats.get('suspicious', 0)
                result['harmless']      = stats.get('harmless', 0)
                result['total_engines'] = sum(stats.values())
                result['scan_status']   = 'scanned'
                print(f"  ✅ Scan complete: {filename} — {result['malicious']}/{result['total_engines']} malicious")
                return result

            print(f"  Waiting for scan... (attempt {attempt+1}/3)")

        # Scan still queued after polling
        result['scan_status'] = 'queued'
        result['error']       = 'Scan queued — check VT link for results'

    except requests.exceptions.Timeout:
        result['scan_status'] = 'timeout'
        result['error']       = 'VT request timed out'
    except Exception as e:
        result['scan_status'] = 'error'
        result['error']       = str(e)

    return result


def scan_attachments(eml_path):
    """
    Main function — extracts and scans all attachments from an email.
    Called from the pipeline after email parsing.
    Returns list of scan results.
    """
    print("\n  Scanning attachments...")

    attachments = extract_attachments(eml_path)

    if not attachments:
        print("  No attachments found.")
        return []

    print(f"  Found {len(attachments)} attachment(s)")

    results = []
    for att in attachments:
        print(f"  → {att['filename']} ({round(att['size']/1024,1)}KB, {att['extension']})")
        scan_result = scan_file_virustotal(att)
        results.append(scan_result)

    return results


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_emails/test_phishing.eml"
    results = scan_attachments(path)
    if results:
        for r in results:
            print(f"\nFile: {r['filename']}")
            print(f"SHA256: {r['sha256']}")
            print(f"Status: {r['scan_status']}")
            print(f"Malicious: {r['malicious']}/{r['total_engines']} engines")
            print(f"VT Link: {r['vt_link']}")
    else:
        print("No attachments to scan.")
