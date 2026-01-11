from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///secscanx.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*")
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

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

@app.route('/api/scan/subdomain', methods=['POST'])
def scan_subdomains():
    """Subdomain enumeration endpoint"""
    try:
        payload = request.get_json()
        domain = payload.get('domain')
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Perform subdomain scan
        results = recon_module.find_subdomains(domain)
        
        # Get AI analysis
        ai_analysis = ai_assistant.analyze_subdomains(results)
        
        return jsonify({
            "domain": domain,
            "subdomains": results,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/ports', methods=['POST'])
def scan_ports():
    """Port scanning endpoint"""
    try:
        payload = request.get_json()
        target = payload.get('target')
        port_range = payload.get('port_range', '1-1000')
        
        if not target:
            return jsonify({"error": "Target is required"}), 400
        
        # Perform port scan
        results = recon_module.port_scan(target, port_range)
        
        # Get AI analysis
        ai_analysis = ai_assistant.analyze_ports(results)
        
        return jsonify({
            "target": target,
            "port_range": port_range,
            "open_ports": results,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/whois', methods=['POST'])
def whois_lookup():
    """WHOIS lookup endpoint"""
    try:
        payload = request.get_json()
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
        payload = request.get_json()
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
        payload = request.get_json()
        target = payload.get('target')
        scan_type = payload.get('scan_type', 'basic')
        
        if not target:
            return jsonify({"error": "Target is required"}), 400
        
        # Perform vulnerability scan
        results = vuln_scanner.scan_target(target, scan_type)
        
        # Get AI analysis and recommendations
        ai_analysis = ai_assistant.analyze_vulnerabilities(results)
        
        return jsonify({
            "target": target,
            "scan_type": scan_type,
            "vulnerabilities": results,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Generate scan report endpoint"""
    try:
        payload = request.get_json()
        scan_data = payload.get('scan_data')
        report_format = payload.get('format', 'html')
        
        if not scan_data:
            return jsonify({"error": "Scan data is required"}), 400
        
        # Generate report
        report_path = report_generator.generate_report(scan_data, report_format)
        
        return jsonify({
            "report_path": report_path,
            "format": report_format,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ai/chat', methods=['POST'])
def ai_chat():
    """AI assistant chat endpoint"""
    try:
        payload = request.get_json()
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
    
    # Run the application
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
