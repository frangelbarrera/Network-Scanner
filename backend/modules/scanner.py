import nmap
import requests
import json
from datetime import datetime
import subprocess
import socket
import ssl
import re
from urllib.parse import urlparse
import concurrent.futures

class VulnScanner:
    """Vulnerability scanner for web applications and network services"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.common_vulns = {
            'http': ['HTTP methods', 'Directory traversal', 'XSS', 'SQL injection', 'CSRF'],
            'https': ['SSL/TLS vulnerabilities', 'Certificate issues', 'Weak ciphers'],
            'ssh': ['Weak algorithms', 'Default credentials', 'Key-based attacks'],
            'ftp': ['Anonymous access', 'Weak credentials', 'Directory traversal'],
            'smtp': ['Open relay', 'User enumeration', 'Authentication bypass'],
            'mysql': ['Default credentials', 'SQL injection', 'Privilege escalation'],
            'rdp': ['Weak credentials', 'BlueKeep vulnerability', 'Network level authentication']
        }
    
    def scan_target(self, target, scan_type='basic'):
        """Perform vulnerability scan on target"""
        try:
            print(f"[INFO] Starting vulnerability scan on {target} (type: {scan_type})")
            
            vulnerabilities = []
            
            # First, get open ports for context
            port_scan_results = self._quick_port_scan(target)
            
            if scan_type == 'basic':
                vulnerabilities.extend(self._basic_vulnerability_scan(target, port_scan_results))
            elif scan_type == 'web':
                vulnerabilities.extend(self._web_vulnerability_scan(target))
            elif scan_type == 'network':
                vulnerabilities.extend(self._network_vulnerability_scan(target, port_scan_results))
            elif scan_type == 'comprehensive':
                vulnerabilities.extend(self._basic_vulnerability_scan(target, port_scan_results))
                vulnerabilities.extend(self._web_vulnerability_scan(target))
                vulnerabilities.extend(self._network_vulnerability_scan(target, port_scan_results))
            
            # Add SSL/TLS checks if HTTPS is available
            if self._is_https_available(target):
                vulnerabilities.extend(self._ssl_vulnerability_scan(target))
            
            result = {
                'target': target,
                'scan_type': scan_type,
                'vulnerabilities': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities),
                'severity_breakdown': self._categorize_by_severity(vulnerabilities),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            print(f"[SUCCESS] Vulnerability scan completed for {target}. Found {len(vulnerabilities)} issues.")
            return result
            
        except Exception as e:
            print(f"[ERROR] Vulnerability scan failed: {str(e)}")
            return {'error': str(e), 'target': target}
    
    def _quick_port_scan(self, target):
        """Quick port scan to identify services"""
        try:
            # Scan common ports quickly
            common_ports = "21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,5900,8080,8443"
            self.nm.scan(target, common_ports, arguments='-sS --top-ports 1000')
            
            open_ports = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        if self.nm[host][proto][port]['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': self.nm[host][proto][port].get('name', 'unknown'),
                                'version': self.nm[host][proto][port].get('version', ''),
                                'product': self.nm[host][proto][port].get('product', '')
                            })
            
            return open_ports
            
        except Exception as e:
            print(f"[WARNING] Quick port scan failed: {str(e)}")
            return []
    
    def _basic_vulnerability_scan(self, target, port_scan_results):
        """Basic vulnerability checks"""
        vulnerabilities = []
        
        try:
            # Check for common service vulnerabilities
            for port_info in port_scan_results:
                service = port_info['service'].lower()
                port = port_info['port']
                
                # Check for default credentials
                if service in ['ssh', 'ftp', 'telnet', 'http', 'https']:
                    vuln = self._check_default_credentials(target, port, service)
                    if vuln:
                        vulnerabilities.append(vuln)
                
                # Check for anonymous access
                if service == 'ftp':
                    vuln = self._check_anonymous_ftp(target, port)
                    if vuln:
                        vulnerabilities.append(vuln)
                
                # Check for open SMTP relay
                if service == 'smtp':
                    vuln = self._check_smtp_relay(target, port)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                # Check for weak SSH configuration
                if service == 'ssh':
                    vuln = self._check_ssh_config(target, port)
                    if vuln:
                        vulnerabilities.append(vuln)
            
        except Exception as e:
            print(f"[WARNING] Basic vulnerability scan error: {str(e)}")
        
        return vulnerabilities
    
    def _web_vulnerability_scan(self, target):
        """Web application vulnerability scan"""
        vulnerabilities = []
        
        try:
            # Determine if target is HTTP/HTTPS
            urls_to_test = []
            
            if target.startswith('http'):
                urls_to_test.append(target)
            else:
                # Try both HTTP and HTTPS
                urls_to_test.extend([f'http://{target}', f'https://{target}'])
            
            for url in urls_to_test:
                try:
                    # Basic connectivity test
                    response = requests.get(url, timeout=10, verify=False)
                    
                    # Check for information disclosure
                    vulns = self._check_info_disclosure(url, response)
                    vulnerabilities.extend(vulns)
                    
                    # Check for security headers
                    vulns = self._check_security_headers(url, response)
                    vulnerabilities.extend(vulns)
                    
                    # Check for common files
                    vulns = self._check_common_files(url)
                    vulnerabilities.extend(vulns)
                    
                    # Basic XSS check
                    vulns = self._basic_xss_check(url)
                    vulnerabilities.extend(vulns)
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"[WARNING] Web vulnerability scan error: {str(e)}")
        
        return vulnerabilities
    
    def _network_vulnerability_scan(self, target, port_scan_results):
        """Network-level vulnerability scan"""
        vulnerabilities = []
        
        try:
            # Check for excessive open ports
            if len(port_scan_results) > 10:
                vulnerabilities.append({
                    'type': 'Network Configuration',
                    'severity': 'Medium',
                    'title': 'Excessive Open Ports',
                    'description': f'Target has {len(port_scan_results)} open ports, which increases attack surface',
                    'recommendation': 'Close unnecessary ports and services',
                    'port': 'Multiple',
                    'service': 'Network'
                })
            
            # Check for unencrypted services
            unencrypted_services = []
            for port_info in port_scan_results:
                service = port_info['service'].lower()
                if service in ['ftp', 'telnet', 'http', 'smtp'] and port_info['port'] not in [443, 993, 995]:
                    unencrypted_services.append(f"{service}:{port_info['port']}")
            
            if unencrypted_services:
                vulnerabilities.append({
                    'type': 'Encryption',
                    'severity': 'High',
                    'title': 'Unencrypted Services',
                    'description': f'Unencrypted services detected: {", ".join(unencrypted_services)}',
                    'recommendation': 'Use encrypted alternatives (HTTPS, SFTP, SSH, etc.)',
                    'port': 'Multiple',
                    'service': 'Network'
                })
            
            # Check for potentially dangerous services
            dangerous_services = []
            for port_info in port_scan_results:
                service = port_info['service'].lower()
                port = port_info['port']
                
                if service == 'telnet':
                    dangerous_services.append('Telnet (unencrypted)')
                elif service == 'ftp' and port == 21:
                    dangerous_services.append('FTP (unencrypted)')
                elif port == 3389:  # RDP
                    dangerous_services.append('RDP (potential for brute force)')
                elif port in [1433, 3306, 5432]:  # Database ports
                    dangerous_services.append(f'Database service on port {port}')
            
            if dangerous_services:
                vulnerabilities.append({
                    'type': 'Service Security',
                    'severity': 'Medium',
                    'title': 'Potentially Dangerous Services',
                    'description': f'Services that commonly have security issues: {", ".join(dangerous_services)}',
                    'recommendation': 'Review necessity of these services and harden configurations',
                    'port': 'Multiple',
                    'service': 'Network'
                })
                
        except Exception as e:
            print(f"[WARNING] Network vulnerability scan error: {str(e)}")
        
        return vulnerabilities
    
    def _ssl_vulnerability_scan(self, target):
        """SSL/TLS vulnerability scan"""
        vulnerabilities = []
        
        try:
            # Parse target to get hostname and port
            if target.startswith('https://'):
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or 443
            else:
                hostname = target
                port = 443
            
            # Check SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    if cert:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            vulnerabilities.append({
                                'type': 'SSL/TLS',
                                'severity': 'High' if days_until_expiry < 7 else 'Medium',
                                'title': 'SSL Certificate Expiring Soon',
                                'description': f'SSL certificate expires in {days_until_expiry} days',
                                'recommendation': 'Renew SSL certificate before expiration',
                                'port': port,
                                'service': 'HTTPS'
                            })
                    
                    # Check for weak ciphers
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'SHA1']):
                            vulnerabilities.append({
                                'type': 'SSL/TLS',
                                'severity': 'High',
                                'title': 'Weak SSL Cipher',
                                'description': f'Weak cipher suite in use: {cipher_name}',
                                'recommendation': 'Configure stronger cipher suites',
                                'port': port,
                                'service': 'HTTPS'
                            })
                            
        except Exception as e:
            print(f"[WARNING] SSL vulnerability scan error: {str(e)}")
        
        return vulnerabilities
    
    def _check_default_credentials(self, target, port, service):
        """Check for default credentials"""
        # This is a simplified check - in practice, you'd test actual credentials
        common_defaults = {
            'ssh': [('root', 'root'), ('admin', 'admin'), ('root', '')],
            'ftp': [('anonymous', ''), ('ftp', 'ftp')],
            'http': [('admin', 'admin'), ('admin', 'password')]
        }
        
        if service in common_defaults:
            return {
                'type': 'Authentication',
                'severity': 'High',
                'title': 'Potential Default Credentials',
                'description': f'{service.upper()} service may be using default credentials',
                'recommendation': 'Test for default credentials and change if found',
                'port': port,
                'service': service.upper()
            }
        
        return None
    
    def _check_anonymous_ftp(self, target, port):
        """Check for anonymous FTP access"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=10)
            ftp.login()  # Anonymous login
            ftp.quit()
            
            return {
                'type': 'Authentication',
                'severity': 'Medium',
                'title': 'Anonymous FTP Access',
                'description': 'FTP server allows anonymous access',
                'recommendation': 'Disable anonymous access if not required',
                'port': port,
                'service': 'FTP'
            }
            
        except Exception:
            return None
    
    def _check_smtp_relay(self, target, port):
        """Check for open SMTP relay"""
        # Simplified check - would need more comprehensive testing
        return {
            'type': 'Mail Security',
            'severity': 'Medium',
            'title': 'Potential SMTP Relay',
            'description': 'SMTP server should be tested for open relay configuration',
            'recommendation': 'Verify SMTP relay restrictions are properly configured',
            'port': port,
            'service': 'SMTP'
        }
    
    def _check_ssh_config(self, target, port):
        """Check SSH configuration"""
        return {
            'type': 'SSH Security',
            'severity': 'Low',
            'title': 'SSH Configuration Review',
            'description': 'SSH service detected - configuration should be reviewed',
            'recommendation': 'Disable root login, use key-based auth, change default port',
            'port': port,
            'service': 'SSH'
        }
    
    def _check_info_disclosure(self, url, response):
        """Check for information disclosure"""
        vulnerabilities = []
        
        # Check server header
        server_header = response.headers.get('Server', '')
        if server_header:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'title': 'Server Information Disclosure',
                'description': f'Server header reveals: {server_header}',
                'recommendation': 'Remove or obfuscate server version information',
                'port': 'HTTP',
                'service': 'Web'
            })
        
        # Check for powered-by headers
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'title': 'Technology Stack Disclosure',
                'description': f'X-Powered-By header reveals: {powered_by}',
                'recommendation': 'Remove X-Powered-By header',
                'port': 'HTTP',
                'service': 'Web'
            })
        
        return vulnerabilities
    
    def _check_security_headers(self, url, response):
        """Check for missing security headers"""
        vulnerabilities = []
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'XSS and injection protection'
        }
        
        missing_headers = []
        for header, description in security_headers.items():
            if header not in response.headers:
                missing_headers.append(f'{header} ({description})')
        
        if missing_headers:
            vulnerabilities.append({
                'type': 'Web Security',
                'severity': 'Medium',
                'title': 'Missing Security Headers',
                'description': f'Missing headers: {", ".join(missing_headers)}',
                'recommendation': 'Implement missing security headers',
                'port': 'HTTP',
                'service': 'Web'
            })
        
        return vulnerabilities
    
    def _check_common_files(self, url):
        """Check for common sensitive files"""
        vulnerabilities = []
        
        common_files = [
            'robots.txt', 'sitemap.xml', '.git/config', '.env',
            'config.php', 'phpinfo.php', 'admin/', 'backup/'
        ]
        
        found_files = []
        for file in common_files:
            try:
                test_url = f"{url.rstrip('/')}/{file}"
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    found_files.append(file)
            except:
                continue
        
        if found_files:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Medium',
                'title': 'Sensitive Files Accessible',
                'description': f'Accessible files: {", ".join(found_files)}',
                'recommendation': 'Restrict access to sensitive files',
                'port': 'HTTP',
                'service': 'Web'
            })
        
        return vulnerabilities
    
    def _basic_xss_check(self, url):
        """Basic XSS vulnerability check"""
        vulnerabilities = []
        
        # This is a very basic check - production tools would be much more comprehensive
        test_payload = '<script>alert("XSS")</script>'
        
        try:
            # Test for reflected XSS in URL parameters
            test_url = f"{url}?test={test_payload}"
            response = requests.get(test_url, timeout=5, verify=False)
            
            if test_payload in response.text:
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting',
                    'severity': 'High',
                    'title': 'Potential Reflected XSS',
                    'description': 'Application may be vulnerable to reflected XSS',
                    'recommendation': 'Implement proper input validation and output encoding',
                    'port': 'HTTP',
                    'service': 'Web'
                })
                
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_https_available(self, target):
        """Check if HTTPS is available on target"""
        try:
            if target.startswith('https://'):
                return True
            elif target.startswith('http://'):
                return False
            else:
                # Test HTTPS connectivity
                test_url = f'https://{target}'
                requests.get(test_url, timeout=5, verify=False)
                return True
        except:
            return False
    
    def _categorize_by_severity(self, vulnerabilities):
        """Categorize vulnerabilities by severity"""
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in severity_count:
                severity_count[severity] += 1
        
        return severity_count
