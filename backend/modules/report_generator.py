from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from jinja2 import Template
import json
import os
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64

class ReportGenerator:
    """Generate comprehensive security assessment reports in PDF and HTML formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for reports"""
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
        
        self.subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=colors.darkred
        )
        
        self.vulnerability_style = ParagraphStyle(
            'VulnerabilityStyle',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            spaceAfter=6
        )
    
    def generate_report(self, scan_data, report_format='html'):
        """Generate a comprehensive security assessment report"""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            
            if report_format.lower() == 'pdf':
                filename = f"security_report_{timestamp}.pdf"
                filepath = os.path.join('/workspaces/SecScanX/reports', filename)
                self._generate_pdf_report(scan_data, filepath)
            elif report_format.lower() == 'html':
                filename = f"security_report_{timestamp}.html"
                filepath = os.path.join('/workspaces/SecScanX/reports', filename)
                self._generate_html_report(scan_data, filepath)
            else:
                raise ValueError(f"Unsupported report format: {report_format}")
            
            print(f"[SUCCESS] Report generated: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"[ERROR] Report generation failed: {str(e)}")
            raise e
    
    def _generate_pdf_report(self, scan_data, filepath):
        """Generate PDF report"""
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=1*inch)
        story = []
        
        # Title page
        story.append(Paragraph("SecScanX Security Assessment Report", self.title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        # Extract key metrics
        total_vulnerabilities = 0
        critical_vulns = 0
        high_vulns = 0
        
        if isinstance(scan_data, dict):
            if 'vulnerabilities' in scan_data:
                vulns = scan_data['vulnerabilities'].get('vulnerabilities', [])
                total_vulnerabilities = len(vulns)
                for vuln in vulns:
                    if vuln.get('severity') == 'Critical':
                        critical_vulns += 1
                    elif vuln.get('severity') == 'High':
                        high_vulns += 1
        
        summary_text = f"""
        This security assessment was conducted on {datetime.utcnow().strftime('%B %d, %Y')}. 
        The assessment identified {total_vulnerabilities} total security issues, including 
        {critical_vulns} critical vulnerabilities and {high_vulns} high-severity vulnerabilities.
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Target Information
        story.append(Paragraph("Target Information", self.heading_style))
        target_info = [
            ['Target', scan_data.get('target', 'Unknown')],
            ['Scan Date', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Scan Type', scan_data.get('scan_type', 'Comprehensive')],
            ['Total Issues Found', str(total_vulnerabilities)]
        ]
        
        target_table = Table(target_info, colWidths=[2*inch, 3*inch])
        target_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(target_table)
        story.append(Spacer(1, 20))
        
        # Vulnerability Summary
        if 'vulnerabilities' in scan_data:
            story.append(Paragraph("Vulnerability Assessment Results", self.heading_style))
            self._add_vulnerability_section_pdf(story, scan_data['vulnerabilities'])
        
        # Reconnaissance Results
        if 'subdomains' in scan_data:
            story.append(PageBreak())
            story.append(Paragraph("Reconnaissance Results", self.heading_style))
            self._add_reconnaissance_section_pdf(story, scan_data)
        
        # AI Analysis
        if 'ai_analysis' in scan_data:
            story.append(PageBreak())
            story.append(Paragraph("AI Analysis and Recommendations", self.heading_style))
            self._add_ai_analysis_section_pdf(story, scan_data['ai_analysis'])
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.heading_style))
        self._add_recommendations_section_pdf(story, scan_data)
        
        # Build PDF
        doc.build(story)
    
    def _add_vulnerability_section_pdf(self, story, vuln_data):
        """Add vulnerability section to PDF"""
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            story.append(Paragraph("No vulnerabilities detected.", self.styles['Normal']))
            return
        
        # Severity breakdown
        severity_breakdown = vuln_data.get('severity_breakdown', {})
        if severity_breakdown:
            story.append(Paragraph("Severity Breakdown", self.subheading_style))
            
            severity_data = [['Severity', 'Count']]
            for severity, count in severity_breakdown.items():
                severity_data.append([severity, str(count)])
            
            severity_table = Table(severity_data, colWidths=[2*inch, 1*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(severity_table)
            story.append(Spacer(1, 20))
        
        # Detailed vulnerabilities
        story.append(Paragraph("Detailed Vulnerability List", self.subheading_style))
        
        for i, vuln in enumerate(vulnerabilities[:20], 1):  # Limit to first 20 for PDF
            vuln_title = f"{i}. {vuln.get('title', 'Unknown Vulnerability')}"
            story.append(Paragraph(vuln_title, self.vulnerability_style))
            
            vuln_details = f"""
            <b>Severity:</b> {vuln.get('severity', 'Unknown')}<br/>
            <b>Type:</b> {vuln.get('type', 'Unknown')}<br/>
            <b>Description:</b> {vuln.get('description', 'No description available')}<br/>
            <b>Recommendation:</b> {vuln.get('recommendation', 'No recommendation available')}<br/>
            <b>Port/Service:</b> {vuln.get('port', 'N/A')} / {vuln.get('service', 'N/A')}
            """
            
            story.append(Paragraph(vuln_details, self.styles['Normal']))
            story.append(Spacer(1, 10))
    
    def _add_reconnaissance_section_pdf(self, story, scan_data):
        """Add reconnaissance section to PDF"""
        if 'subdomains' in scan_data:
            subdomain_data = scan_data['subdomains']
            story.append(Paragraph("Subdomain Enumeration", self.subheading_style))
            
            subdomains = subdomain_data.get('subdomains', [])
            total_found = len(subdomains)
            
            story.append(Paragraph(f"Total subdomains found: {total_found}", self.styles['Normal']))
            
            if subdomains:
                # Show first 20 subdomains
                subdomain_list = subdomains[:20]
                subdomain_text = "<br/>".join([f"• {sub}" for sub in subdomain_list])
                if len(subdomains) > 20:
                    subdomain_text += f"<br/>... and {len(subdomains) - 20} more"
                
                story.append(Paragraph(subdomain_text, self.styles['Normal']))
            
            story.append(Spacer(1, 15))
        
        if 'ports' in scan_data:
            port_data = scan_data['ports']
            story.append(Paragraph("Port Scan Results", self.subheading_style))
            
            total_ports = port_data.get('total_open_ports', 0)
            story.append(Paragraph(f"Total open ports found: {total_ports}", self.styles['Normal']))
            
            # Show open ports summary
            scan_results = port_data.get('scan_results', [])
            for host in scan_results:
                open_ports = host.get('open_ports', [])
                if open_ports:
                    ports_text = "<br/>".join([
                        f"• Port {port['port']}/{port['protocol']} - {port['service']} {port.get('version', '')}"
                        for port in open_ports[:10]  # Limit to first 10
                    ])
                    story.append(Paragraph(ports_text, self.styles['Normal']))
            
            story.append(Spacer(1, 15))
    
    def _add_ai_analysis_section_pdf(self, story, ai_analysis):
        """Add AI analysis section to PDF"""
        if isinstance(ai_analysis, dict):
            if 'assessment' in ai_analysis:
                story.append(Paragraph("Assessment Summary", self.subheading_style))
                story.append(Paragraph(ai_analysis['assessment'], self.styles['Normal']))
                story.append(Spacer(1, 10))
            
            if 'recommendations' in ai_analysis:
                story.append(Paragraph("AI Recommendations", self.subheading_style))
                recommendations = ai_analysis['recommendations']
                if isinstance(recommendations, list):
                    rec_text = "<br/>".join([f"• {rec}" for rec in recommendations])
                    story.append(Paragraph(rec_text, self.styles['Normal']))
                else:
                    story.append(Paragraph(str(recommendations), self.styles['Normal']))
                
                story.append(Spacer(1, 10))
            
            if 'risk_level' in ai_analysis:
                story.append(Paragraph("Risk Assessment", self.subheading_style))
                risk_text = f"Overall Risk Level: <b>{ai_analysis['risk_level']}</b>"
                if 'explanation' in ai_analysis:
                    risk_text += f"<br/>Explanation: {ai_analysis['explanation']}"
                story.append(Paragraph(risk_text, self.styles['Normal']))
    
    def _add_recommendations_section_pdf(self, story, scan_data):
        """Add recommendations section to PDF"""
        recommendations = [
            "1. Prioritize fixing critical and high-severity vulnerabilities immediately",
            "2. Implement proper input validation and output encoding to prevent injection attacks",
            "3. Keep all software and systems updated with the latest security patches",
            "4. Use strong, unique passwords and implement multi-factor authentication",
            "5. Regularly review and update security configurations",
            "6. Implement network segmentation and principle of least privilege",
            "7. Conduct regular security assessments and penetration testing",
            "8. Establish an incident response plan and security monitoring",
            "9. Provide security awareness training to all personnel",
            "10. Maintain proper backup and disaster recovery procedures"
        ]
        
        rec_text = "<br/>".join(recommendations)
        story.append(Paragraph(rec_text, self.styles['Normal']))
    
    def _generate_html_report(self, scan_data, filepath):
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecScanX Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #2c3e50;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-bottom: 20px;
        }
        .section h3 {
            color: #e74c3c;
            margin-bottom: 15px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .info-card {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .info-card h4 {
            margin: 0 0 10px 0;
            color: #2c3e50;
        }
        .severity-high { border-left-color: #e74c3c; }
        .severity-medium { border-left-color: #f39c12; }
        .severity-low { border-left-color: #27ae60; }
        .severity-critical { border-left-color: #8e44ad; }
        .vulnerability {
            background: #ffffff;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #3498db;
        }
        .vulnerability.critical { border-left-color: #8e44ad; }
        .vulnerability.high { border-left-color: #e74c3c; }
        .vulnerability.medium { border-left-color: #f39c12; }
        .vulnerability.low { border-left-color: #27ae60; }
        .vulnerability h4 {
            margin: 0 0 10px 0;
            color: #2c3e50;
        }
        .vulnerability .severity {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
            margin-bottom: 10px;
        }
        .severity.critical { background-color: #8e44ad; }
        .severity.high { background-color: #e74c3c; }
        .severity.medium { background-color: #f39c12; }
        .severity.low { background-color: #27ae60; }
        .subdomain-list {
            columns: 3;
            column-gap: 30px;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }
        .subdomain-list div {
            break-inside: avoid;
            margin-bottom: 5px;
            padding: 5px;
            background: white;
            border-radius: 4px;
            font-family: monospace;
        }
        .port-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .port-table th,
        .port-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        .port-table th {
            background-color: #2c3e50;
            color: white;
        }
        .port-table tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .ai-analysis {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .ai-analysis h3 {
            color: white;
            margin-top: 0;
        }
        .recommendations {
            background: #e8f5e8;
            border: 1px solid #27ae60;
            border-radius: 8px;
            padding: 20px;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin-bottom: 10px;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
        }
        .summary-stats {
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
        }
        .stat-box {
            text-align: center;
            padding: 20px;
            background: #3498db;
            color: white;
            border-radius: 10px;
            min-width: 120px;
        }
        .stat-box.critical { background: #8e44ad; }
        .stat-box.high { background: #e74c3c; }
        .stat-box.medium { background: #f39c12; }
        .stat-box.low { background: #27ae60; }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SecScanX Security Assessment Report</h1>
            <div class="subtitle">Generated on {{ report_date }}</div>
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h4>Target Information</h4>
                    <strong>Target:</strong> {{ target }}<br>
                    <strong>Scan Type:</strong> {{ scan_type }}<br>
                    <strong>Scan Date:</strong> {{ report_date }}
                </div>
                <div class="info-card">
                    <h4>Overall Assessment</h4>
                    <strong>Total Issues:</strong> {{ total_vulnerabilities }}<br>
                    <strong>Risk Level:</strong> {{ overall_risk }}<br>
                    <strong>Status:</strong> {{ scan_status }}
                </div>
            </div>

            {% if severity_breakdown %}
            <div class="summary-stats">
                {% for severity, count in severity_breakdown.items() %}
                <div class="stat-box {{ severity.lower() }}">
                    <span class="stat-number">{{ count }}</span>
                    {{ severity }}
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </div>

        {% if vulnerabilities %}
        <div class="section">
            <h2>🔍 Vulnerability Assessment Results</h2>
            <h3>Detailed Vulnerability List</h3>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability {{ vuln.severity.lower() }}">
                <h4>{{ vuln.title }}</h4>
                <span class="severity {{ vuln.severity.lower() }}">{{ vuln.severity }}</span>
                <p><strong>Type:</strong> {{ vuln.type }}</p>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                <p><strong>Recommendation:</strong> {{ vuln.recommendation }}</p>
                <p><strong>Port/Service:</strong> {{ vuln.port }} / {{ vuln.service }}</p>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if subdomains %}
        <div class="section">
            <h2>🌐 Reconnaissance Results</h2>
            <h3>Subdomain Enumeration</h3>
            <p><strong>Total subdomains found:</strong> {{ subdomains|length }}</p>
            {% if subdomains %}
            <div class="subdomain-list">
                {% for subdomain in subdomains %}
                <div>{{ subdomain }}</div>
                {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endif %}

        {% if open_ports %}
        <div class="section">
            <h3>Port Scan Results</h3>
            <table class="port-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>State</th>
                    </tr>
                </thead>
                <tbody>
                    {% for port in open_ports %}
                    <tr>
                        <td>{{ port.port }}</td>
                        <td>{{ port.protocol }}</td>
                        <td>{{ port.service }}</td>
                        <td>{{ port.version }}</td>
                        <td>{{ port.state }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if ai_analysis %}
        <div class="section">
            <h2>🤖 AI Analysis and Recommendations</h2>
            <div class="ai-analysis">
                <h3>AI Security Assessment</h3>
                {% if ai_analysis.assessment %}
                <p><strong>Assessment:</strong> {{ ai_analysis.assessment }}</p>
                {% endif %}
                {% if ai_analysis.risk_level %}
                <p><strong>Risk Level:</strong> {{ ai_analysis.risk_level }}</p>
                {% endif %}
                {% if ai_analysis.explanation %}
                <p><strong>Explanation:</strong> {{ ai_analysis.explanation }}</p>
                {% endif %}
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2>💡 Security Recommendations</h2>
            <div class="recommendations">
                <ul>
                    <li>Prioritize fixing critical and high-severity vulnerabilities immediately</li>
                    <li>Implement proper input validation and output encoding to prevent injection attacks</li>
                    <li>Keep all software and systems updated with the latest security patches</li>
                    <li>Use strong, unique passwords and implement multi-factor authentication</li>
                    <li>Regularly review and update security configurations</li>
                    <li>Implement network segmentation and principle of least privilege</li>
                    <li>Conduct regular security assessments and penetration testing</li>
                    <li>Establish an incident response plan and security monitoring</li>
                    <li>Provide security awareness training to all personnel</li>
                    <li>Maintain proper backup and disaster recovery procedures</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>This report was generated by SecScanX - AI-Assisted Vulnerability Assessment Tool</p>
            <p>Report generated on {{ report_date }}</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare template data
        template_data = self._prepare_template_data(scan_data)
        
        # Render HTML
        template = Template(html_template)
        html_content = template.render(**template_data)
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _prepare_template_data(self, scan_data):
        """Prepare data for template rendering"""
        data = {
            'report_date': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'target': scan_data.get('target', 'Unknown'),
            'scan_type': scan_data.get('scan_type', 'Comprehensive'),
            'scan_status': 'Completed',
            'total_vulnerabilities': 0,
            'overall_risk': 'Medium',
            'vulnerabilities': [],
            'subdomains': [],
            'open_ports': [],
            'ai_analysis': {},
            'severity_breakdown': {}
        }
        
        # Extract vulnerabilities
        if 'vulnerabilities' in scan_data and isinstance(scan_data['vulnerabilities'], dict):
            vuln_data = scan_data['vulnerabilities']
            data['vulnerabilities'] = vuln_data.get('vulnerabilities', [])
            data['total_vulnerabilities'] = len(data['vulnerabilities'])
            data['severity_breakdown'] = vuln_data.get('severity_breakdown', {})
            
            # Determine overall risk
            critical_count = data['severity_breakdown'].get('Critical', 0)
            high_count = data['severity_breakdown'].get('High', 0)
            
            if critical_count > 0:
                data['overall_risk'] = 'Critical'
            elif high_count > 0:
                data['overall_risk'] = 'High'
            elif data['total_vulnerabilities'] > 5:
                data['overall_risk'] = 'Medium'
            else:
                data['overall_risk'] = 'Low'
        
        # Extract subdomain data
        if 'subdomains' in scan_data and isinstance(scan_data['subdomains'], dict):
            data['subdomains'] = scan_data['subdomains'].get('subdomains', [])
        
        # Extract port data
        if 'ports' in scan_data and isinstance(scan_data['ports'], dict):
            port_results = scan_data['ports'].get('scan_results', [])
            for host in port_results:
                data['open_ports'].extend(host.get('open_ports', []))
        
        # Extract AI analysis
        if 'ai_analysis' in scan_data:
            data['ai_analysis'] = scan_data['ai_analysis']
        
        return data
