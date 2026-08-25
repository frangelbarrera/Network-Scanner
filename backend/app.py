from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
if app.config['SECRET_KEY'] == 'dev-key-change-in-production' and os.environ.get('FLASK_ENV') == 'production':
    raise RuntimeError("SECRET_KEY must be set in production")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///network_scanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
CORS(app, origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","))
socketio = SocketIO(app, cors_allowed_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","))
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


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

@app.route('/api/scan/subdomain', methods=['POST'])
def scan_subdomains():
    """Subdomain enumeration endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain = payload.get('domain')
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
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
def scan_ports():
    """Port scanning endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        target = payload.get('target')
        port_range = payload.get('port_range', '1-1000')
        
        if not target:
            return jsonify({"error": "Target is required"}), 400
        
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
def whois_lookup():
    """WHOIS lookup endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain = payload.get('domain')
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
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
def dns_enumeration():
    """DNS enumeration endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain = payload.get('domain')
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
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
def vulnerability_scan():
    """Vulnerability scanning endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        target = payload.get('target')
        scan_type = payload.get('scan_type', 'basic')
        
        if not target:
            return jsonify({"error": "Target is required"}), 400
        
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
def download_report(filename):
    """Download a generated report from the configured reports directory."""
    reports_dir = os.environ.get('REPORTS_DIR', os.path.join(os.getcwd(), 'reports'))
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        return jsonify({"error": "Invalid report filename"}), 400
    return send_from_directory(reports_dir, safe_filename, as_attachment=True)

@app.route('/api/ai/chat', methods=['POST'])
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

@socketio.on('start_automated_scan')
def handle_automated_scan(data):
    """Handle automated scan via WebSocket"""
    try:
        target = data.get('target')
        scan_types = data.get('scan_types', ['subdomain', 'port', 'vuln'])
        
        emit('scan_status', {'status': 'starting', 'message': f'Starting automated scan for {target}'})
        
        results = {}
        
        # Perform each type of scan
        for scan_type in scan_types:
            emit('scan_status', {'status': 'running', 'message': f'Running {scan_type} scan...'})
            
            if scan_type == 'subdomain':
                results['subdomains'] = recon_module.find_subdomains(target)
            elif scan_type == 'port':
                results['ports'] = recon_module.port_scan(target)
            elif scan_type == 'vuln':
                results['vulnerabilities'] = vuln_scanner.scan_target(target)
        
        # Get AI analysis of all results
        ai_analysis = ai_assistant.analyze_comprehensive_scan(results)
        results['ai_analysis'] = ai_analysis
        
        emit('scan_complete', {'results': results, 'target': target})
        
    except Exception as e:
        emit('scan_error', {'error': str(e)})

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
