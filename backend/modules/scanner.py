import logging
import nmap
import requests
from datetime import datetime
import socket
import ssl
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _raw_socket_available():
    """Return True when the process may create raw sockets (CAP_NET_RAW/root)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP):
            return True
    except (PermissionError, OSError):
        return False


def _nmap_scan_args():
    """Pick Nmap arguments that work with the privileges we actually have.

    SYN scans and OS detection require raw sockets. Without them Nmap aborts
    ("You requested a scan type which requires root privileges"), so fall
    back to a full connect scan and drop -O instead of failing the scan.
    """
    if _raw_socket_available():
        return '-sS -sV'
    logger.info("No raw-socket privileges: using Nmap connect scan (-sT)")
    return '-sT -sV'


class VulnScanner:
    """Vulnerability scanner for web applications and network services"""
    
    def __init__(self):
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
            logger.info(f"Starting vulnerability scan on {target} (type: {scan_type})")
            
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
            
            logger.info(f"Vulnerability scan completed for {target}. Found {len(vulnerabilities)} issues.")
            return result
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {str(e)}")
            return {'error': str(e), 'target': target}
    
    def _quick_port_scan(self, target):
        """Quick port scan to identify services or raise when Nmap cannot run."""
        # A shared PortScanner instance is not thread-safe: python-nmap keeps
        # per-scan state on the object, so concurrent requests would read each
        # other's results. A fresh instance per scan keeps scans isolated.
        nm = nmap.PortScanner()
        # Scan common ports quickly. Service banners are part of the results
        # contract, so -sV must be present for version/product to be filled.
        common_ports = "21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,5900,8080,8443"
        scan_output = nm.scan(target, common_ports, arguments=_nmap_scan_args())
        scan_error = scan_output.get('nmap', {}).get('scaninfo', {}).get('error') if isinstance(scan_output, dict) else None
        if scan_error:
            message = ''.join(scan_error) if isinstance(scan_error, list) else str(scan_error)
            raise RuntimeError(f"Nmap execution failed: {message.strip()}")

        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'service': nm[host][proto][port].get('name', 'unknown'),
                            'version': nm[host][proto][port].get('version', ''),
                            'product': nm[host][proto][port].get('product', '')
                        })

        return open_ports
    
    def _basic_vulnerability_scan(self, target, port_scan_results):
        """Basic vulnerability checks"""
        vulnerabilities = []
        
        try:
            # Check for common service vulnerabilities
            for port_info in port_scan_results:
                service = port_info['service'].lower()
                port = port_info['port']
                
                # Anonymous FTP is the only authentication condition verified by
                # this scanner. Do not report default credentials, SMTP relays, or
                # SSH configuration without a protocol-specific confirmation.
                if service == 'ftp':
                    vuln = self._check_anonymous_ftp(target, port)
                    if vuln:
                        vulnerabilities.append(vuln)
            
        except Exception as e:
            logger.warning(f"Basic vulnerability scan error: {str(e)}")
        
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
            logger.warning(f"Web vulnerability scan error: {str(e)}")
        
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
            logger.warning(f"Network vulnerability scan error: {str(e)}")
        
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
            
            # Check SSL certificate. With verify_mode=CERT_NONE the peer
            # certificate dict is always empty, so the expiry check below
            # never ran. Verify against the system trust store instead;
            # untrusted certificates surface as findings rather than being
            # silently dropped.
            context = ssl.create_default_context()
            context.check_hostname = False
            
            try:
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
            except ssl.SSLCertVerificationError as cert_error:
                vulnerabilities.append({
                    'type': 'SSL/TLS',
                    'severity': 'Medium',
                    'title': 'SSL Certificate Verification Failed',
                    'description': f'Certificate could not be verified: {cert_error.reason}',
                    'recommendation': 'Review the TLS certificate chain and renewal status',
                    'port': port,
                    'service': 'HTTPS'
                })
                # Untrusted certificates are a documented use case (internal
                # self-signed hosts); keep reporting the negotiated cipher by
                # peeking at it through a verification-disabled connection.
                cert = None
                cipher = None
                try:
                    cipher_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    cipher_context.check_hostname = False
                    cipher_context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((hostname, port), timeout=10) as sock:
                        with cipher_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cipher = ssock.cipher()
                except OSError:
                    pass

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
            logger.warning("SSL vulnerability scan error: %s", e)
        
        return vulnerabilities
    
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
            except requests.exceptions.RequestException:
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
        except requests.exceptions.RequestException:
            return False
    
    def _categorize_by_severity(self, vulnerabilities):
        """Categorize vulnerabilities by severity"""
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in severity_count:
                severity_count[severity] += 1
        
        return severity_count
