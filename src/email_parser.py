import email
import os
import re
import base64
from html.parser import HTMLParser
from email.header import decode_header as _decode_header


class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = []
        self.links = []
        self.skip_tags = {'script', 'style'}
        self.current_skip = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.skip_tags:
            self.current_skip = True
        if tag.lower() == 'a':
            for attr, val in attrs:
                if attr == 'href' and val and val.startswith('http'):
                    self.links.append(val.strip())

    def handle_endtag(self, tag):
        if tag.lower() in self.skip_tags:
            self.current_skip = False

    def handle_data(self, data):
        if not self.current_skip:
            stripped = data.strip()
            if stripped:
                self.result.append(stripped)

    def get_text(self):
        return ' '.join(self.result)

    def get_links(self):
        return self.links


def decode_subject(raw):
    """Decode email subject including encoded-word syntax and unicode"""
    if not raw:
        return "No subject"
    try:
        parts = _decode_header(str(raw))
        result = ""
        for part, charset in parts:
            if isinstance(part, bytes):
                try:
                    result += part.decode(charset or 'utf-8', errors='replace')
                except (LookupError, UnicodeDecodeError):
                    result += part.decode('utf-8', errors='replace')
            else:
                result += str(part)
        return result.strip()
    except Exception:
        return str(raw)


def try_decode_payload(part):
    """
    Try multiple methods to decode a MIME part payload.
    Handles: quoted-printable, base64, 8bit, raw strings.
    """
    # Method 1: standard decode=True (handles QP and base64 automatically)
    try:
        payload = part.get_payload(decode=True)
        if payload:
            charset = part.get_content_charset() or 'utf-8'
            try:
                return payload.decode(charset, errors='replace')
            except (LookupError, UnicodeDecodeError):
                return payload.decode('utf-8', errors='replace')
    except Exception:
        pass

    # Method 2: raw string payload - might be base64 text
    try:
        raw = part.get_payload()
        if isinstance(raw, str):
            # Try to base64 decode it
            cleaned = raw.replace('\n', '').replace('\r', '').strip()
            decoded = base64.b64decode(cleaned + '==').decode('utf-8', errors='replace')
            if len(decoded) > 50:  # Sanity check
                return decoded
    except Exception:
        pass

    # Method 3: just return raw string as-is
    try:
        raw = part.get_payload()
        if isinstance(raw, str):
            return raw
    except Exception:
        pass

    return ""


def html_to_text_and_links(html):
    """Parse HTML into plain text + extract all href links"""
    try:
        parser = HTMLTextExtractor()
        parser.feed(html)
        return parser.get_text(), parser.get_links()
    except Exception:
        links = re.findall(r'https?://[^\s\'"<>]+', html)
        clean = re.sub(r'<[^>]+>', ' ', html)
        return re.sub(r'\s+', ' ', clean).strip(), links


def truncate_body(body, max_chars=3000):
    if len(body) > max_chars:
        return body[:max_chars] + '\n... [truncated]'
    return body


def parse_email(file_path):
    if not os.path.exists(file_path):
        print(f"ERROR: File not found -> {file_path}")
        return None

    with open(file_path, "rb") as f:
        msg = email.message_from_bytes(f.read())

    body = ""
    extracted_links = []

    if msg.is_multipart():
        # Walk all parts - collect plain text first, HTML as fallback
        plain_body = ""
        html_body = ""
        html_links = []

        for part in msg.walk():
            ct = part.get_content_type()

            if ct == "text/plain" and not plain_body:
                plain_body = try_decode_payload(part)

            elif ct == "text/html":
                raw_html = try_decode_payload(part)
                if raw_html and len(raw_html) > len(html_body):
                    text, links = html_to_text_and_links(raw_html)
                    html_body = text
                    html_links = links

        # Prefer plain text body, but always grab links from HTML
        body = plain_body if plain_body.strip() else html_body
        extracted_links = html_links

    else:
        ct = msg.get_content_type()
        raw = try_decode_payload(msg)
        if ct == "text/html":
            body, extracted_links = html_to_text_and_links(raw)
        else:
            body = raw

    # Clean up body
    body = body.strip()
    body = re.sub(r'\n{3,}', '\n\n', body)
    body = re.sub(r' {3,}', ' ', body)

    # Append extracted links so AI can see them
    if extracted_links:
        unique_links = list(dict.fromkeys(extracted_links))[:10]
        body += "\n\nEXTRACTED LINKS:\n" + "\n".join(unique_links)

    body = truncate_body(body, max_chars=3000)

    # Decode headers
    subject = decode_subject(msg.get("Subject", "No subject"))
    sender  = decode_subject(msg.get("From", "Unknown"))

    return {
        "sender":   sender,
        "reply_to": str(msg.get("Reply-To", "Not set")),
        "subject":  subject,
        "date":     str(msg.get("Date", "Unknown")),
        "body":     body
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_emails/test_phishing.eml"
    result = parse_email(path)
    if result:
        print(f"From:    {result['sender']}")
        print(f"Subject: {result['subject']}")
        print(f"Body ({len(result['body'])} chars):\n{result['body'][:1000]}")
