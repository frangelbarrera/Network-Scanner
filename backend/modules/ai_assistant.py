import openai
import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class AIAssistant:
    """AI Assistant for interpreting scan results and providing security recommendations"""
    
    def __init__(self):
        self.api_key = os.getenv('OPENAI_API_KEY')
        if self.api_key:
            openai.api_key = self.api_key
        self.learning_mode = True
    
    def analyze_subdomains(self, subdomain_results):
        """Analyze subdomain enumeration results"""
        try:
            if not self.api_key:
                return self._fallback_subdomain_analysis(subdomain_results)
            
            subdomains = subdomain_results.get('subdomains', [])
            domain = subdomain_results.get('domain', 'unknown')
            
            prompt = f"""
            As a cybersecurity expert, analyze the following subdomain enumeration results for {domain}:
            
            Found subdomains: {subdomains}
            Total count: {len(subdomains)}
            
            Please provide:
            1. Security assessment of discovered subdomains
            2. Potentially interesting targets for further investigation
            3. Common attack vectors for these subdomains
            4. Recommended next steps
            5. Risk level (Low/Medium/High) with justification
            
            Format the response as JSON with keys: assessment, interesting_targets, attack_vectors, next_steps, risk_level, explanation
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.3
            )
            
            try:
                analysis = json.loads(response.choices[0].message.content)
            except json.JSONDecodeError:
                analysis = {
                    "assessment": response.choices[0].message.content,
                    "risk_level": "Medium",
                    "explanation": "AI analysis completed but formatting needs adjustment"
                }
            
            return analysis
            
        except Exception as e:
            return self._fallback_subdomain_analysis(subdomain_results)
    
    def _fallback_subdomain_analysis(self, subdomain_results):
        """Fallback analysis when AI is not available"""
        subdomains = subdomain_results.get('subdomains', [])
        count = len(subdomains)
        
        interesting_subdomains = []
        high_value_keywords = ['admin', 'test', 'dev', 'staging', 'api', 'internal', 'vpn', 'mail', 'ftp']
        
        for subdomain in subdomains:
            for keyword in high_value_keywords:
                if keyword in subdomain.lower():
                    interesting_subdomains.append(subdomain)
                    break
        
        if count > 50:
            risk_level = "High"
            explanation = "Large attack surface with many subdomains discovered"
        elif count > 20:
            risk_level = "Medium" 
            explanation = "Moderate attack surface discovered"
        else:
            risk_level = "Low"
            explanation = "Limited attack surface discovered"
        
        return {
            "assessment": f"Discovered {count} subdomains. {len(interesting_subdomains)} potentially interesting targets identified.",
            "interesting_targets": interesting_subdomains,
            "attack_vectors": ["Subdomain takeover", "Information disclosure", "Weak authentication"],
            "next_steps": ["Port scan interesting subdomains", "Check for subdomain takeover", "Enumerate web applications"],
            "risk_level": risk_level,
            "explanation": explanation
        }
    
    def analyze_ports(self, port_results):
        """Analyze port scan results"""
        try:
            if not self.api_key:
                return self._fallback_port_analysis(port_results)
            
            scan_results = port_results.get('scan_results', [])
            target = port_results.get('target', 'unknown')
            
            open_ports_info = []
            for host in scan_results:
                for port in host.get('open_ports', []):
                    open_ports_info.append(f"Port {port['port']}/{port['protocol']} - {port['service']} {port.get('version', '')}")
            
            prompt = f"""
            As a cybersecurity expert, analyze the following port scan results for {target}:
            
            Open ports found:
            {chr(10).join(open_ports_info)}
            
            Please provide:
            1. Security assessment of open ports
            2. Potential vulnerabilities based on services
            3. Recommended security tests for each service
            4. Risk level (Low/Medium/High) with justification
            5. Immediate security concerns
            
            Format the response as JSON with keys: assessment, vulnerabilities, recommended_tests, risk_level, security_concerns
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.3
            )
            
            try:
                analysis = json.loads(response.choices[0].message.content)
            except json.JSONDecodeError:
                analysis = {
                    "assessment": response.choices[0].message.content,
                    "risk_level": "Medium"
                }
            
            return analysis
            
        except Exception as e:
            return self._fallback_port_analysis(port_results)
    
    def _fallback_port_analysis(self, port_results):
        """Fallback port analysis when AI is not available"""
        scan_results = port_results.get('scan_results', [])
        total_ports = port_results.get('total_open_ports', 0)
        
        high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432]
        critical_services = ['ssh', 'ftp', 'telnet', 'smtp', 'http', 'https', 'mysql', 'rdp']
        
        risks = []
        recommendations = []
        
        for host in scan_results:
            for port in host.get('open_ports', []):
                port_num = port['port']
                service = port['service'].lower()
                
                if port_num in high_risk_ports:
                    risks.append(f"Port {port_num} ({service}) - commonly targeted")
                
                if service in critical_services:
                    recommendations.append(f"Test {service} on port {port_num} for default credentials")
        
        risk_level = "High" if total_ports > 10 else "Medium" if total_ports > 5 else "Low"
        
        return {
            "assessment": f"Found {total_ports} open ports. {len(risks)} potentially risky services identified.",
            "vulnerabilities": risks,
            "recommended_tests": recommendations,
            "risk_level": risk_level,
            "security_concerns": ["Excessive open ports", "Unencrypted services", "Default configurations"]
        }
    
    def analyze_dns(self, dns_results):
        """Analyze DNS enumeration results"""
        try:
            dns_records = dns_results.get('dns_records', {})
            domain = dns_results.get('domain', 'unknown')
            
            findings = []
            recommendations = []
            
            # Check for security-relevant DNS records
            if 'TXT' in dns_records:
                txt_records = dns_records['TXT']
                for record in txt_records:
                    if 'spf' in record.lower():
                        findings.append("SPF record found - good for email security")
                    if 'dmarc' in record.lower():
                        findings.append("DMARC record found - enhanced email security")
                    if 'google-site-verification' in record.lower():
                        findings.append("Google site verification found")
            
            if 'MX' in dns_records:
                mx_records = dns_records['MX']
                findings.append(f"Mail servers configured: {len(mx_records)} MX records")
                recommendations.append("Test mail servers for vulnerabilities")
            
            if 'NS' in dns_records:
                ns_records = dns_records['NS']
                findings.append(f"Name servers: {len(ns_records)} NS records")
                recommendations.append("Check for DNS zone transfer vulnerabilities")
            
            return {
                "assessment": f"DNS analysis completed for {domain}",
                "findings": findings,
                "recommendations": recommendations,
                "risk_level": "Low",
                "explanation": "Standard DNS configuration analysis"
            }
            
        except Exception as e:
            return {"error": str(e), "domain": dns_results.get('domain', 'unknown')}
    
    def analyze_vulnerabilities(self, vuln_results):
        """Analyze vulnerability scan results"""
        try:
            if not self.api_key:
                return self._fallback_vuln_analysis(vuln_results)
            
            vulnerabilities = vuln_results.get('vulnerabilities', [])
            target = vuln_results.get('target', 'unknown')
            
            prompt = f"""
            As a cybersecurity expert, analyze the following vulnerability scan results for {target}:
            
            Vulnerabilities found: {json.dumps(vulnerabilities, indent=2)}
            
            Please provide:
            1. Critical vulnerabilities that need immediate attention
            2. Exploitation likelihood and impact assessment
            3. Prioritized remediation steps
            4. Overall risk score (1-10)
            5. Business impact assessment
            
            Format the response as JSON with keys: critical_vulns, exploitation_assessment, remediation_steps, risk_score, business_impact
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1200,
                temperature=0.3
            )
            
            try:
                analysis = json.loads(response.choices[0].message.content)
            except json.JSONDecodeError:
                analysis = {
                    "assessment": response.choices[0].message.content,
                    "risk_score": 5
                }
            
            return analysis
            
        except Exception as e:
            return self._fallback_vuln_analysis(vuln_results)
    
    def _fallback_vuln_analysis(self, vuln_results):
        """Fallback vulnerability analysis"""
        vulnerabilities = vuln_results.get('vulnerabilities', [])
        
        critical_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'high')
        
        risk_score = min(10, critical_count * 3 + high_count * 2)
        
        return {
            "critical_vulns": [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical'],
            "exploitation_assessment": f"{critical_count} critical and {high_count} high severity vulnerabilities found",
            "remediation_steps": ["Patch critical vulnerabilities immediately", "Review security configurations", "Implement monitoring"],
            "risk_score": risk_score,
            "business_impact": "High" if risk_score > 7 else "Medium" if risk_score > 4 else "Low"
        }
    
    def analyze_comprehensive_scan(self, all_results):
        """Analyze results from comprehensive automated scan"""
        try:
            analysis = {
                "summary": "Comprehensive security assessment completed",
                "findings": [],
                "recommendations": [],
                "overall_risk": "Medium",
                "next_steps": []
            }
            
            # Analyze each component
            if 'subdomains' in all_results:
                subdomain_analysis = self.analyze_subdomains(all_results['subdomains'])
                analysis['findings'].append(f"Subdomain enumeration: {subdomain_analysis.get('assessment', 'Completed')}")
                if 'next_steps' in subdomain_analysis:
                    analysis['next_steps'].extend(subdomain_analysis['next_steps'])
            
            if 'ports' in all_results:
                port_analysis = self.analyze_ports(all_results['ports'])
                analysis['findings'].append(f"Port scanning: {port_analysis.get('assessment', 'Completed')}")
                if 'recommended_tests' in port_analysis:
                    analysis['recommendations'].extend(port_analysis['recommended_tests'])
            
            if 'vulnerabilities' in all_results:
                vuln_analysis = self.analyze_vulnerabilities(all_results['vulnerabilities'])
                analysis['findings'].append(f"Vulnerability assessment: {vuln_analysis.get('assessment', 'Completed')}")
                if 'remediation_steps' in vuln_analysis:
                    analysis['recommendations'].extend(vuln_analysis['remediation_steps'])
            
            return analysis
            
        except Exception as e:
            return {"error": str(e), "message": "Comprehensive analysis failed"}
    
    def chat_response(self, message, context=None):
        """Handle general chat interactions with learning mode explanations"""
        try:
            if not self.api_key:
                return self._fallback_chat_response(message, context)
            
            system_message = """You are SecScanX AI Assistant, a cybersecurity expert that helps with vulnerability assessment and penetration testing. 
            You should be helpful, educational, and always emphasize ethical hacking practices. 
            If learning mode is enabled, explain concepts clearly for beginners."""
            
            messages = [{"role": "system", "content": system_message}]
            
            if context:
                messages.append({"role": "user", "content": f"Context: {json.dumps(context)}"})
            
            messages.append({"role": "user", "content": message})
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=800,
                temperature=0.7
            )
            
            return {
                "response": response.choices[0].message.content,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return self._fallback_chat_response(message, context)
    
    def _fallback_chat_response(self, message, context=None):
        """Fallback chat response when AI is not available"""
        responses = {
            "help": "SecScanX offers subdomain enumeration, port scanning, vulnerability assessment, and automated reporting. Use the web interface or CLI to get started.",
            "scan": "You can perform different types of scans: subdomain enumeration, port scanning, DNS enumeration, and vulnerability assessment.",
            "vulnerability": "Vulnerability scanning helps identify security weaknesses in your target systems. Always ensure you have permission before scanning.",
            "subdomain": "Subdomain enumeration helps discover additional attack surface by finding subdomains of your target domain.",
            "port": "Port scanning identifies open network ports and services running on your target system."
        }
        
        # Simple keyword matching for fallback
        for keyword, response in responses.items():
            if keyword in message.lower():
                return {
                    "response": response,
                    "timestamp": datetime.utcnow().isoformat(),
                    "note": "AI assistant is not configured. Using fallback responses."
                }
        
        return {
            "response": "I'm here to help with cybersecurity assessments. You can ask about scanning techniques, vulnerability assessment, or use my analysis features.",
            "timestamp": datetime.utcnow().isoformat(),
            "note": "AI assistant is not configured. Using fallback responses."
        }
