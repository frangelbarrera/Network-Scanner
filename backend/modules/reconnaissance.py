import subprocess
import nmap
import dns.resolver
import whois
import requests
import json
from datetime import datetime
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

class ReconModule:
    """Reconnaissance module for subdomain enumeration, port scanning, DNS enumeration, and WHOIS lookups"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns4', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile',
            'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo',
            'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img',
            'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
            'stats', 'dns1', 'ns5', 'upload', 'client', 'forum', 'bb', 'subdomain',
            'stage', 'app', 'cdn1', 'cdn2', 'ns6', 'ns7', 'ns8', 'ns9', 'ns10'
        ]
    
    def find_subdomains(self, domain):
        """Find subdomains using multiple techniques"""
        try:
            subdomains = set()
            
            # Method 1: Common subdomain brute force
            print(f"[INFO] Starting subdomain enumeration for {domain}")
            subdomains.update(self._brute_force_subdomains(domain))
            
            # Method 2: Certificate transparency logs
            subdomains.update(self._cert_transparency_search(domain))
            
            # Method 3: DNS zone transfer attempt
            subdomains.update(self._dns_zone_transfer(domain))
            
            # Remove the main domain from results if present
            subdomains.discard(domain)
            
            # Verify subdomains are actually resolvable
            verified_subdomains = self._verify_subdomains(list(subdomains))
            
            result = {
                'domain': domain,
                'total_found': len(verified_subdomains),
                'subdomains': verified_subdomains,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            print(f"[SUCCESS] Found {len(verified_subdomains)} subdomains for {domain}")
            return result
            
        except Exception as e:
            print(f"[ERROR] Subdomain enumeration failed: {str(e)}")
            return {'error': str(e), 'domain': domain}
    
    def _brute_force_subdomains(self, domain):
        """Brute force common subdomains"""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                print(f"[FOUND] {full_domain}")
            except socket.gaierror:
                pass
        
        # Use ThreadPoolExecutor for concurrent subdomain checking
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_subdomain, self.common_subdomains)
        
        return found_subdomains
    
    def _cert_transparency_search(self, domain):
        """Search certificate transparency logs for subdomains"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                cert_data = response.json()
                subdomains = set()

                for cert in cert_data:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        # Handle multi-line certificate names
                        names = name_value.split('\n')
                        for domain_name in names:
                            domain_name = domain_name.strip()
                            if name.endswith(f'.{domain}') or name == domain:
                                subdomains.add(name)
                
                print(f"[INFO] Certificate transparency found {len(subdomains)} entries")
                return list(subdomains)
            
        except Exception as e:
            print(f"[WARNING] Certificate transparency search failed: {str(e)}")
        
        return []
    
    def _dns_zone_transfer(self, domain):
        """Attempt DNS zone transfer"""
        subdomains = []
        try:
            # Get nameservers for the domain
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}"
                        if subdomain != domain:
                            subdomains.append(subdomain)
                    
                    print(f"[SUCCESS] Zone transfer successful from {ns}")
                    break
                    
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"[INFO] Zone transfer not available: {str(e)}")
        
        return subdomains
    
    def _verify_subdomains(self, subdomains):
        """Verify that subdomains are actually resolvable"""
        verified = []
        
        def verify_subdomain(subdomain):
            try:
                socket.gethostbyname(subdomain)
                verified.append(subdomain)
            except socket.gaierror:
                pass
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(verify_subdomain, subdomains)
        
        return sorted(verified)
    
    def port_scan(self, target, port_range='1-1000'):
        """Perform port scan on target"""
        try:
            print(f"[INFO] Starting port scan on {target} (ports {port_range})")
            
            # Parse port range
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                ports = f"{start_port}-{end_port}"
            else:
                ports = port_range
            
            # Perform the scan
            self.nm.scan(target, ports, arguments='-sS -sV -O')
            
            results = []
            for host in self.nm.all_hosts():
                host_info = {
                    'host': host,
                    'state': self.nm[host].state(),
                    'open_ports': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        if port_info['state'] == 'open':
                            host_info['open_ports'].append({
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'state': port_info['state']
                            })
                
                results.append(host_info)
            
            result = {
                'target': target,
                'port_range': port_range,
                'scan_results': results,
                'total_open_ports': sum(len(host['open_ports']) for host in results),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            print(f"[SUCCESS] Port scan completed for {target}")
            return result
            
        except Exception as e:
            print(f"[ERROR] Port scan failed: {str(e)}")
            return {'error': str(e), 'target': target}
    
    def whois_lookup(self, domain):
        """Perform WHOIS lookup"""
        try:
            print(f"[INFO] Performing WHOIS lookup for {domain}")
            
            w = whois.whois(domain)
            
            result = {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else [],
                'emails': w.emails if w.emails else [],
                'org': w.org,
                'country': w.country,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            print(f"[SUCCESS] WHOIS lookup completed for {domain}")
            return result
            
        except Exception as e:
            print(f"[ERROR] WHOIS lookup failed: {str(e)}")
            return {'error': str(e), 'domain': domain}
    
    def dns_enumeration(self, domain):
        """Perform comprehensive DNS enumeration"""
        try:
            print(f"[INFO] Starting DNS enumeration for {domain}")
            
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = []
                    
                    for answer in answers:
                        dns_records[record_type].append(str(answer))
                        
                except dns.resolver.NXDOMAIN:
                    dns_records[record_type] = ['NXDOMAIN']
                except dns.resolver.NoAnswer:
                    dns_records[record_type] = ['No Answer']
                except Exception as e:
                    dns_records[record_type] = [f'Error: {str(e)}']
            
            result = {
                'domain': domain,
                'dns_records': dns_records,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            print(f"[SUCCESS] DNS enumeration completed for {domain}")
            return result
            
        except Exception as e:
            print(f"[ERROR] DNS enumeration failed: {str(e)}")
            return {'error': str(e), 'domain': domain}
