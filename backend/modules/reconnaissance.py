import logging
import nmap
import dns.resolver
import whois
import requests
from datetime import datetime
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from modules.scanner import _nmap_scan_args

logger = logging.getLogger(__name__)

class ReconModule:
    """Reconnaissance module for subdomain enumeration, port scanning, DNS enumeration, and WHOIS lookups"""
    
    def __init__(self):
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
            logger.info(f"Starting subdomain enumeration for {domain}")
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
            
            logger.info(f"Found {len(verified_subdomains)} subdomains for {domain}")
            return result
            
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {str(e)}")
            return {'error': str(e), 'domain': domain}
    
    def _brute_force_subdomains(self, domain):
        """Brute force common subdomains"""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                logger.info(f"Subdomain found: {full_domain}")
            except socket.gaierror:
                pass
        
        # Use ThreadPoolExecutor for concurrent subdomain checking; consuming
        # the map iterator surfaces worker exceptions instead of burying them
        # in futures that are never inspected.
        with ThreadPoolExecutor(max_workers=50) as executor:
            list(executor.map(check_subdomain, self.common_subdomains))
        
        return found_subdomains
    
    def _cert_transparency_search(self, domain):
        """Search certificate transparency logs for subdomains"""
        try:
            # crt.sh matches lowercase names; an uppercase domain from the
            # client would silently return zero matches.
            domain = domain.strip().lower()
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': 'Network-Scanner/1.0 (security auditing tool)'},
            )

            if response.status_code == 200:
                cert_data = response.json()
                subdomains = set()

                for cert in cert_data:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        # Handle multi-line certificate names
                        names = name_value.split('\n')
                        for domain_name in names:
                            domain_name = domain_name.strip().lower()
                            # Skip wildcard cert entries (e.g. *.example.com) —
                            # the wildcard itself is not a real subdomain.
                            if domain_name.startswith('*.'):
                                continue
                            if domain_name.endswith(f'.{domain}') or domain_name == domain:
                                subdomains.add(domain_name)
                
                logger.info(f"Certificate transparency found {len(subdomains)} entries")
                return list(subdomains)
            
        except Exception as e:
            logger.warning(f"Certificate transparency search failed: {str(e)}")
        
        return []
    
    def _dns_zone_transfer(self, domain):
        """Attempt DNS zone transfer"""
        subdomains = []
        try:
            # Get nameservers for the domain
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                try:
                    # Attempt zone transfer. Without an explicit lifetime a
                    # silent nameserver would leave the request thread hanging
                    # forever (dnspython does not apply a default cap here).
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=5, lifetime=15))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}"
                        if subdomain != domain:
                            subdomains.append(subdomain)
                    
                    logger.info(f"Zone transfer successful from {ns}")
                    break
                    
                except Exception:
                    continue
                    
        except Exception as e:
            logger.info(f"Zone transfer not available: {str(e)}")
        
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
            # Consume the map so worker exceptions propagate to the caller
            # instead of dying with the uniterated futures.
            list(executor.map(verify_subdomain, subdomains))
        
        return sorted(verified)
    
    def port_scan(self, target, port_range='1-1000'):
        """Perform port scan on target"""
        try:
            logger.info(f"Starting port scan on {target} (ports {port_range})")
            
            # A shared PortScanner instance is not thread-safe under the
            # threaded WSGI server: python-nmap stores per-scan state on the
            # object, so concurrent scans would read each other's results.
            nm = nmap.PortScanner()
            # The API validator already accepts Nmap's numeric single-port,
            # range, and comma-separated range syntax. Preserve that validated
            # expression so values such as "1-2,80" reach Nmap unchanged.
            # OS detection (-O) only runs when raw sockets are available.
            scan_args = _nmap_scan_args()
            if '-sS' in scan_args:
                scan_args += ' -O'
            scan_output = nm.scan(target, port_range, arguments=scan_args)
            scan_error = scan_output.get('nmap', {}).get('scaninfo', {}).get('error')
            if scan_error:
                message = ''.join(scan_error) if isinstance(scan_error, list) else str(scan_error)
                raise RuntimeError(f"Nmap execution failed: {message.strip()}")

            results = []
            for host in nm.all_hosts():
                host_info = {
                    'host': host,
                    'state': nm[host].state(),
                    'open_ports': [],
                    'os_match': [o.get('name') for o in nm[host].get('osmatch', [])]
                }
                
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        port_info = nm[host][proto][port]
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
            
            logger.info(f"Port scan completed for {target}")
            return result
            
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return {'error': str(e), 'target': target}
    
    def whois_lookup(self, domain):
        """Perform WHOIS lookup"""
        try:
            logger.info(f"Performing WHOIS lookup for {domain}")

            # The pinned whois==0.9.27 release exposes query(), while older
            # builds of the same package expose whois(). Support both entry
            # points so the lookup does not depend on which variant was
            # resolved at install time.
            lookup = getattr(whois, 'whois', None) or getattr(whois, 'query', None)
            if lookup is None:
                raise RuntimeError("whois library exposes neither whois() nor query()")
            # The whois package exposes no per-call timeout; bound the wait so
            # a slow WHOIS server cannot pin request threads indefinitely.
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                w = executor.submit(lookup, domain).result(timeout=20)
            except FutureTimeoutError:
                return {'error': f'WHOIS lookup timed out for {domain}', 'domain': domain}
            finally:
                executor.shutdown(wait=False)
            if w is None:
                return {'error': f'No WHOIS data available for {domain}', 'domain': domain}

            result = {
                'domain': domain,
                'registrar': getattr(w, 'registrar', None),
                'creation_date': str(w.creation_date) if getattr(w, 'creation_date', None) else None,
                'expiration_date': str(w.expiration_date) if getattr(w, 'expiration_date', None) else None,
                'name_servers': list(w.name_servers) if getattr(w, 'name_servers', None) else [],
                'status': w.status if getattr(w, 'status', None) else [],
                'emails': w.emails if getattr(w, 'emails', None) else [],
                'org': getattr(w, 'org', None),
                'country': getattr(w, 'country', None),
                'timestamp': datetime.utcnow().isoformat()
            }

            logger.info(f"WHOIS lookup completed for {domain}")
            return result

        except Exception as e:
            logger.error("WHOIS lookup failed for %s: %s", domain, e)
            return {'error': str(e), 'domain': domain}
    
    def dns_enumeration(self, domain):
        """Perform comprehensive DNS enumeration"""
        try:
            logger.info(f"Starting DNS enumeration for {domain}")
            
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
            
            logger.info(f"DNS enumeration completed for {domain}")
            return result
            
        except Exception as e:
            logger.error(f"DNS enumeration failed: {str(e)}")
            return {'error': str(e), 'domain': domain}
