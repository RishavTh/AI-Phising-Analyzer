import sys
import os
import tempfile
import logging
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from email_parser import parse_email
from ioc_extractor import extract_iocs
from enrichment import enrich_iocs
from risk_scorer import calculate_risk_score
from reporter import generate_report, save_report
from slack_alert import send_slack_alert
from siem_logger import write_siem_log, read_siem_logs, get_siem_stats

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('output/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Fix: use memory storage to suppress the warning
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "10 per minute"],
    storage_uri="memory://"
)

MAX_EMAIL_LENGTH = 100000
MIN_EMAIL_LENGTH = 20

def validate_email_input(content):
    if not content or not content.strip():
        return False, "Email content cannot be empty"
    if len(content) < MIN_EMAIL_LENGTH:
        return False, "Email content too short"
    if len(content) > MAX_EMAIL_LENGTH:
        return False, "Email too large"
    return True, None

def safe_str(value):
    """Force any value to plain string — fixes Header not JSON serializable"""
    if value is None:
        return ""
    return str(value)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    tmp_path = None
    start_time = datetime.now()

    try:
        email_content = request.form.get('email_content', '').strip()

        is_valid, error_msg = validate_email_input(email_content)
        if not is_valid:
            return jsonify({"error": error_msg}), 400

        logger.info(f"Analysis started — content length: {len(email_content)}")

        tmp_fd, tmp_path = tempfile.mkstemp(suffix='.eml', prefix='phish_')
        try:
            with os.fdopen(tmp_fd, 'w') as tmp:
                tmp.write(email_content)
        except Exception:
            os.close(tmp_fd)
            raise

        email_data = parse_email(tmp_path)
        if not email_data:
            return jsonify({"error": "Could not parse email"}), 400

        iocs = extract_iocs(email_data)
        enrichment = enrich_iocs(iocs)
        risk_result = calculate_risk_score(iocs, enrichment)
        report = generate_report(email_data, iocs, enrichment, risk_result)
        saved_path = save_report(report, risk_result)
        send_slack_alert(email_data, iocs, risk_result)
        write_siem_log(email_data, iocs, enrichment, risk_result)

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"Analysis complete — "
            f"Risk: {risk_result['risk_level']} "
            f"Score: {risk_result['risk_score']} — "
            f"{duration:.1f}s"
        )

        return jsonify({
            "success": True,
            "duration": round(duration, 1),
            "email": {
                "sender":   safe_str(email_data.get('sender')),
                "reply_to": safe_str(email_data.get('reply_to')),
                "subject":  safe_str(email_data.get('subject')),
                "date":     safe_str(email_data.get('date'))
            },
            "iocs": {
                "urls":                  [safe_str(u) for u in iocs.get('urls', [])],
                "domains":               [safe_str(d) for d in iocs.get('domains', [])],
                "ips":                   [safe_str(i) for i in iocs.get('ips', [])],
                "phishing_tactics":      [safe_str(t) for t in iocs.get('phishing_tactics', [])],
                "ai_confidence_score":   iocs.get('ai_confidence_score', 0),
                "spoofing_detected":     iocs.get('spoofing_detected', False),
                "credential_harvesting": iocs.get('credential_harvesting', False),
                "urgency_detected":      iocs.get('urgency_detected', False),
                "summary":               safe_str(iocs.get('summary', '')),
                "mitre_techniques":      iocs.get('mitre_techniques', [])
            },
            "enrichment": enrichment,
            "risk": {
                "score":     risk_result['risk_score'],
                "level":     risk_result['risk_level'],
                "emoji":     risk_result['emoji'],
                "action":    risk_result['action'],
                "breakdown": risk_result['score_breakdown']
            },
            "report":     safe_str(report),
            "saved_path": safe_str(saved_path)
        })

    except Exception as e:
        logger.error(f"Pipeline error: {str(e)}", exc_info=True)
        return jsonify({"error": "Analysis failed. Check logs."}), 500

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


@app.route('/history')
def history():
    try:
        reports = []
        output_dir = 'output'
        if os.path.exists(output_dir):
            for filename in sorted(os.listdir(output_dir), reverse=True):
                if filename.startswith('report_') and filename.endswith('.txt'):
                    parts = filename.replace('.txt', '').split('_')
                    if len(parts) >= 3:
                        reports.append({
                            "filename":   filename,
                            "risk_level": parts[1],
                            "timestamp":  parts[2] + '_' + parts[3] if len(parts) > 3 else parts[2]
                        })
        return jsonify({"reports": reports[:20]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/siem-logs')
def siem_logs():
    """Returns SIEM logs from disk — persistent across sessions"""
    try:
        logs = read_siem_logs(limit=100)
        stats = get_siem_stats()
        return jsonify({"logs": logs, "stats": stats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Too many requests. Wait 1 minute."}), 429

@app.errorhandler(413)
def input_too_large(e):
    return jsonify({"error": "Email too large."}), 413


if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.getenv('FLASK_PORT', 5000))
    logger.info(f"Starting PhishGuard — Port: {port}")
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
