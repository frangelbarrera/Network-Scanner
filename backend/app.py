from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import hmac
import os
import re
from datetime import datetime


PRODUCTION_SECRET_PLACEHOLDERS = {
    "",
    "dev-key-change-in-production",
    "your-secret-key-change-this",
    "change-this",
    "secret",
}
VALID_VULNERABILITY_SCAN_TYPES = {"basic", "web", "network", "comprehensive"}
VALID_AUTOMATED_SCAN_TYPES = {"subdomain", "port", "vuln", "dns"}
PORT_RANGE_PATTERN = re.compile(r"^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$")


# Initialize Flask app
app = Flask(__name__)
is_production = os.environ.get("FLASK_ENV") == "production"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key-change-in-production")
if is_production and app.config["SECRET_KEY"] in PRODUCTION_SECRET_PLACEHOLDERS:
    raise RuntimeError("SECRET_KEY must be a strong, unique value in production")

api_access_token = os.environ.get("API_ACCESS_TOKEN", "")
if is_production and not api_access_token:
    raise RuntimeError("API_ACCESS_TOKEN must be set in production")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///network_scanner.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# CORS is unnecessary for the default same-origin deployment. Operators can
# explicitly configure trusted origins when hosting the UI separately.
cors_origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]
if cors_origins:
    CORS(app, origins=cors_origins)

socketio_options = {"cors_allowed_origins": cors_origins} if cors_origins else {}
socketio = SocketIO(
    app,
    async_mode=os.environ.get("SOCKETIO_ASYNC_MODE", "threading"),
    **socketio_options,
)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[os.environ.get("RATE_LIMIT_DEFAULT", "60 per minute")],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)
db = SQLAlchemy(app)


# Import modules
from modules.reconnaissance import ReconModule
from modules.ai_assistant import AIAssistant
from modules.scanner import VulnScanner
from modules.report_generator import ReportGenerator
from models.scan_results import ScanResult, User, Project

# Initialize modules
recon_module = ReconModule()
ai_assistant = AIAssistant()
vuln_scanner = VulnScanner()
report_generator = ReportGenerator()


def get_json_payload():
    """Return a JSON object body or None when the request body is invalid."""
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else None


def require_api_token(view):
    """Require the operator-provided bearer token when one is configured."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not api_access_token:
            return view(*args, **kwargs)

        authorization = request.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token, api_access_token):
            return jsonify({"error": "Valid bearer token required"}), 401
        return view(*args, **kwargs)

    return wrapped_view


def validate_target(value):
    """Return a normalized target or a human-readable validation error."""
    if not isinstance(value, str):
        return None, "Target must be a string"
    target = value.strip()
    if not target:
        return None, "Target is required"
    if len(target) > 253 or any(character.isspace() for character in target):
        return None, "Target contains invalid characters"
    return target, None


def validate_port_range(value):
    """Accept only Nmap-compatible numeric single ports, ranges, and lists."""
    if not isinstance(value, str):
        return None, "Port range must be a string"
    port_range = value.strip()
    if not PORT_RANGE_PATTERN.fullmatch(port_range):
        return None, "Port range must contain only ports, ranges, and commas"

    for part in port_range.split(","):
        start_text, separator, end_text = part.partition("-")
        start = int(start_text)
        end = int(end_text) if separator else start
        if not 1 <= start <= end <= 65535:
            return None, "Ports must be between 1 and 65535"
    return port_range, None


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

@app.route('/api/scan/subdomain', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN", "10 per minute"))
@require_api_token
def scan_subdomains():
    """Subdomain enumeration endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain, error = validate_target(payload.get("domain"))
        if error:
            return jsonify({"error": error}), 400

        # Perform subdomain scan
        results = recon_module.find_subdomains(domain)
        
        # Get AI analysis
        ai_analysis = ai_assistant.analyze_subdomains(results)
        
        subdomain_data = results if isinstance(results, dict) else {}
        return jsonify({
            "domain": domain,
            "subdomains": subdomain_data.get("subdomains", results if isinstance(results, list) else []),
            "total_found": subdomain_data.get("total_found", 0),
            "subdomain_data": subdomain_data,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/ports', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN", "10 per minute"))
@require_api_token
def scan_ports():
    """Port scanning endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        target, target_error = validate_target(payload.get("target"))
        if target_error:
            return jsonify({"error": target_error}), 400
        port_range, port_range_error = validate_port_range(payload.get("port_range", "1-1000"))
        if port_range_error:
            return jsonify({"error": port_range_error}), 400

        # Perform port scan
        results = recon_module.port_scan(target, port_range)
        
        # Get AI analysis
        ai_analysis = ai_assistant.analyze_ports(results)
        
        port_data = results if isinstance(results, dict) else {}
        return jsonify({
            "target": target,
            "port_range": port_range,
            "open_ports": results,
            "scan_results": port_data.get("scan_results", []),
            "total_open_ports": port_data.get("total_open_ports", 0),
            "port_data": port_data,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/whois', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN", "10 per minute"))
@require_api_token
def whois_lookup():
    """WHOIS lookup endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain, error = validate_target(payload.get("domain"))
        if error:
            return jsonify({"error": error}), 400

        # Perform WHOIS lookup
        results = recon_module.whois_lookup(domain)
        
        return jsonify({
            "domain": domain,
            "whois_data": results,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/dns', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN", "10 per minute"))
@require_api_token
def dns_enumeration():
    """DNS enumeration endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain, error = validate_target(payload.get("domain"))
        if error:
            return jsonify({"error": error}), 400

        # Perform DNS enumeration
        results = recon_module.dns_enumeration(domain)
        
        # Get AI analysis
        ai_analysis = ai_assistant.analyze_dns(results)
        
        return jsonify({
            "domain": domain,
            "dns_records": results,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vulnerability/scan', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN", "10 per minute"))
@require_api_token
def vulnerability_scan():
    """Vulnerability scanning endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        target, target_error = validate_target(payload.get("target"))
        if target_error:
            return jsonify({"error": target_error}), 400
        scan_type = payload.get("scan_type", "basic")
        if scan_type not in VALID_VULNERABILITY_SCAN_TYPES:
            return jsonify({"error": "scan_type must be one of: basic, web, network, comprehensive"}), 400

        # Perform vulnerability scan
        results = vuln_scanner.scan_target(target, scan_type)
        
        # Get AI analysis and recommendations
        ai_analysis = ai_assistant.analyze_vulnerabilities(results)
        
        vulnerability_data = results if isinstance(results, dict) else {}
        return jsonify({
            "target": target,
            "scan_type": scan_type,
            "vulnerabilities": vulnerability_data.get("vulnerabilities", results if isinstance(results, list) else []),
            "total_vulnerabilities": vulnerability_data.get("total_vulnerabilities", 0),
            "severity_breakdown": vulnerability_data.get("severity_breakdown", {}),
            "vulnerability_data": vulnerability_data,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/generate', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_REPORT", "20 per minute"))
@require_api_token
def generate_report():
    """Generate scan report endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        scan_data = payload.get('scan_data')
        report_format = payload.get('format', 'html')
        
        if not isinstance(scan_data, dict) or not scan_data:
            return jsonify({"error": "Scan data must be a non-empty JSON object"}), 400
        if not isinstance(report_format, str) or report_format.lower() not in {"html", "pdf"}:
            return jsonify({"error": "Format must be either html or pdf"}), 400
        
        # Generate report
        report_path = report_generator.generate_report(scan_data, report_format.lower())
        
        return jsonify({
            "report_path": report_path,
            "format": report_format.lower(),
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/download/<path:filename>', methods=['GET'])
@require_api_token
def download_report(filename):
    """Download a generated report from the configured reports directory."""
    reports_dir = os.environ.get('REPORTS_DIR', os.path.join(os.getcwd(), 'reports'))
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        return jsonify({"error": "Invalid report filename"}), 400
    return send_from_directory(reports_dir, safe_filename, as_attachment=True)

@app.route('/api/ai/chat', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_AI", "20 per minute"))
@require_api_token
def ai_chat():
    """AI assistant chat endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        message = payload.get('message')
        context = payload.get('context', {})
        
        if not message:
            return jsonify({"error": "Message is required"}), 400
        
        # Get AI response
        response = ai_assistant.chat_response(message, context)
        
        return jsonify({
            "message": message,
            "response": response,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@socketio.on("connect")
def authenticate_socket(auth):
    """Reject WebSocket clients that do not present the configured API token."""
    if not api_access_token:
        return True
    token = auth.get("token") if isinstance(auth, dict) else None
    return bool(token and hmac.compare_digest(token, api_access_token))


@socketio.on("start_automated_scan")
def handle_automated_scan(data):
    """Run the selected, validated scan types for an authenticated socket client."""
    try:
        if not isinstance(data, dict):
            emit("scan_error", {"error": "Scan request must be an object"})
            return

        target, target_error = validate_target(data.get("target"))
        if target_error:
            emit("scan_error", {"error": target_error})
            return

        scan_types = data.get("scan_types", ["subdomain", "port", "vuln"])
        if not isinstance(scan_types, list) or not scan_types:
            emit("scan_error", {"error": "scan_types must be a non-empty list"})
            return
        if any(scan_type not in VALID_AUTOMATED_SCAN_TYPES for scan_type in scan_types):
            emit("scan_error", {"error": "scan_types contains an unsupported scan type"})
            return

        # Preserve selection order while avoiding duplicate work.
        selected_scan_types = list(dict.fromkeys(scan_types))
        emit("scan_status", {"status": "starting", "message": f"Starting automated scan for {target}"})
        results = {}

        for scan_type in selected_scan_types:
            emit("scan_status", {"status": "running", "message": f"Running {scan_type} scan..."})
            if scan_type == "subdomain":
                results["subdomains"] = recon_module.find_subdomains(target)
            elif scan_type == "port":
                results["ports"] = recon_module.port_scan(target)
            elif scan_type == "vuln":
                results["vulnerabilities"] = vuln_scanner.scan_target(target)
            elif scan_type == "dns":
                results["dns"] = recon_module.dns_enumeration(target)

        results["ai_analysis"] = ai_assistant.analyze_comprehensive_scan(results)
        emit("scan_complete", {"results": results, "target": target})

    except Exception:
        app.logger.exception("Automated scan failed")
        emit("scan_error", {"error": "Automated scan failed"})

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()

    # SECURITY: debug=False prevents RCE via the Werkzeug debugger PIN.
    # debug_mode is enabled only when FLASK_ENV=development (explicit opt-in).
    # SECURITY: bind to 127.0.0.1 by default to prevent public exposure.
    # Operators who need remote access (including Docker deployments) MUST set
    # the HOST env var (e.g. HOST=0.0.0.0) and place a reverse proxy with TLS
    # and authentication in front. docker-compose.yml sets HOST=0.0.0.0 for the
    # backend service so the container remains reachable on the Docker network.
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    host = os.environ.get('HOST', '127.0.0.1')
    socketio.run(app, host=host, port=5000, debug=debug_mode)
