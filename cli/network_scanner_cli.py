#!/usr/bin/env python3
"""
Network Scanner CLI - Command Line Interface for AI-Assisted Vulnerability Assessment
"""

import argparse
import json
import sys
import time
import requests
from datetime import datetime
import colorama
from colorama import Fore, Back, Style

# Initialize colorama for cross-platform colored output
colorama.init()

class NetworkScannerCLI:
    def __init__(self, api_url="http://localhost:5000/api"):
        self.api_url = api_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'Network-Scanner-CLI/1.0'
        })

    def print_banner(self):
        """Print Network Scanner banner"""
        banner = f"""
{Fore.CYAN}
███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗
██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}AI-Assisted Vulnerability Assessment & Penetration Testing Tool{Style.RESET_ALL}
{Fore.GREEN}Version 1.0 | Open Source Security Scanner{Style.RESET_ALL}
        """
        print(banner)

    def print_status(self, message, status="INFO"):
        """Print colored status messages"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "FOUND": Fore.MAGENTA
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = colors.get(status, Fore.WHITE)
        print(f"{color}[{timestamp}] [{status}] {message}{Style.RESET_ALL}")

    def make_request(self, endpoint, data=None, method="GET"):
        """Make API request with error handling"""
        try:
            url = f"{self.api_url}{endpoint}"
            
            if method == "POST":
                response = self.session.post(url, json=data, timeout=300)
            else:
                response = self.session.get(url, timeout=30)
            
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.ConnectionError:
            self.print_status("Cannot connect to Network Scanner server. Is it running?", "ERROR")
            return None
        except requests.exceptions.Timeout:
            self.print_status("Request timed out", "ERROR")
            return None
        except requests.exceptions.HTTPError as e:
            self.print_status(f"HTTP Error: {e}", "ERROR")
            return None
        except Exception as e:
            self.print_status(f"Unexpected error: {e}", "ERROR")
            return None

    def subdomain_scan(self, domain, output_file=None):
        """Perform subdomain enumeration"""
        self.print_status(f"Starting subdomain enumeration for {domain}")
        
        result = self.make_request("/scan/subdomain", {"domain": domain}, "POST")
        if not result:
            return
        
        if "error" in result:
            self.print_status(f"Scan failed: {result['error']}", "ERROR")
            return
        
        subdomains = result.get("subdomains", [])
        total = len(subdomains)
        
        self.print_status(f"Found {total} subdomains", "SUCCESS")
        
        if total > 0:
            print(f"\n{Fore.CYAN}Discovered Subdomains:{Style.RESET_ALL}")
            for subdomain in sorted(subdomains):
                print(f"  {Fore.GREEN}• {subdomain}{Style.RESET_ALL}")
        
        # AI Analysis
        if "ai_analysis" in result:
            self.print_ai_analysis(result["ai_analysis"])
        
        # Save to file if requested
        if output_file:
            self.save_results(result, output_file)
            self.print_status(f"Results saved to {output_file}", "SUCCESS")

    def port_scan(self, target, port_range="1-1000", output_file=None):
        """Perform port scanning"""
        self.print_status(f"Starting port scan on {target} (ports {port_range})")
        
        result = self.make_request("/scan/ports", {
            "target": target,
            "port_range": port_range
        }, "POST")
        
        if not result:
            return
        
        if "error" in result:
            self.print_status(f"Scan failed: {result['error']}", "ERROR")
            return
        
        scan_results = result.get("scan_results", [])
        total_ports = result.get("total_open_ports", 0)
        
        self.print_status(f"Found {total_ports} open ports", "SUCCESS")
        
        if total_ports > 0:
            print(f"\n{Fore.CYAN}Open Ports:{Style.RESET_ALL}")
            for host in scan_results:
                if host.get("open_ports"):
                    print(f"\n{Fore.YELLOW}Host: {host['host']}{Style.RESET_ALL}")
                    for port in host["open_ports"]:
                        service = port.get("service", "unknown")
                        version = port.get("version", "")
                        print(f"  {Fore.GREEN}• {port['port']}/{port['protocol']} - {service} {version}{Style.RESET_ALL}")
        
        # AI Analysis
        if "ai_analysis" in result:
            self.print_ai_analysis(result["ai_analysis"])
        
        if output_file:
            self.save_results(result, output_file)
            self.print_status(f"Results saved to {output_file}", "SUCCESS")

    def vulnerability_scan(self, target, scan_type="basic", output_file=None):
        """Perform vulnerability scanning"""
        self.print_status(f"Starting {scan_type} vulnerability scan on {target}")
        
        result = self.make_request("/vulnerability/scan", {
            "target": target,
            "scan_type": scan_type
        }, "POST")
        
        if not result:
            return
        
        if "error" in result:
            self.print_status(f"Scan failed: {result['error']}", "ERROR")
            return
        
        vulnerabilities = result.get("vulnerabilities", [])
        total_vulns = len(vulnerabilities)
        
        self.print_status(f"Found {total_vulns} potential security issues", "SUCCESS")
        
        if total_vulns > 0:
            # Severity breakdown
            severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "Low")
                if severity in severity_count:
                    severity_count[severity] += 1
            
            print(f"\n{Fore.CYAN}Vulnerability Summary:{Style.RESET_ALL}")
            for severity, count in severity_count.items():
                if count > 0:
                    color = {
                        "Critical": Fore.MAGENTA,
                        "High": Fore.RED,
                        "Medium": Fore.YELLOW,
                        "Low": Fore.GREEN
                    }.get(severity, Fore.WHITE)
                    print(f"  {color}• {severity}: {count}{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Detailed Findings:{Style.RESET_ALL}")
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get("severity", "Low")
                color = {
                    "Critical": Fore.MAGENTA,
                    "High": Fore.RED,
                    "Medium": Fore.YELLOW,
                    "Low": Fore.GREEN
                }.get(severity, Fore.WHITE)
                
                print(f"\n{color}[{severity}] {vuln.get('title', 'Unknown Vulnerability')}{Style.RESET_ALL}")
                print(f"  Type: {vuln.get('type', 'Unknown')}")
                print(f"  Port/Service: {vuln.get('port', 'N/A')} / {vuln.get('service', 'N/A')}")
                print(f"  Description: {vuln.get('description', 'No description available')}")
                print(f"  Recommendation: {vuln.get('recommendation', 'No recommendation available')}")
        
        # AI Analysis
        if "ai_analysis" in result:
            self.print_ai_analysis(result["ai_analysis"])
        
        if output_file:
            self.save_results(result, output_file)
            self.print_status(f"Results saved to {output_file}", "SUCCESS")

    def dns_enumeration(self, domain, output_file=None):
        """Perform DNS enumeration"""
        self.print_status(f"Starting DNS enumeration for {domain}")
        
        result = self.make_request("/scan/dns", {"domain": domain}, "POST")
        if not result:
            return
        
        if "error" in result:
            self.print_status(f"Scan failed: {result['error']}", "ERROR")
            return
        
        dns_records = result.get("dns_records", {})
        
        print(f"\n{Fore.CYAN}DNS Records for {domain}:{Style.RESET_ALL}")
        for record_type, records in dns_records.items():
            if records and records != ["No Answer"] and records != ["NXDOMAIN"]:
                print(f"\n{Fore.YELLOW}{record_type} Records:{Style.RESET_ALL}")
                for record in records:
                    print(f"  {Fore.GREEN}• {record}{Style.RESET_ALL}")
        
        if output_file:
            self.save_results(result, output_file)
            self.print_status(f"Results saved to {output_file}", "SUCCESS")

    def whois_lookup(self, domain, output_file=None):
        """Perform WHOIS lookup"""
        self.print_status(f"Starting WHOIS lookup for {domain}")
        
        result = self.make_request("/scan/whois", {"domain": domain}, "POST")
        if not result:
            return
        
        if "error" in result:
            self.print_status(f"Lookup failed: {result['error']}", "ERROR")
            return
        
        print(f"\n{Fore.CYAN}WHOIS Information for {domain}:{Style.RESET_ALL}")
        
        fields = [
            ("Registrar", "registrar"),
            ("Creation Date", "creation_date"),
            ("Expiration Date", "expiration_date"),
            ("Organization", "org"),
            ("Country", "country")
        ]
        
        for label, key in fields:
            value = result.get(key)
            if value and value != "None":
                print(f"  {Fore.YELLOW}{label}:{Style.RESET_ALL} {value}")
        
        name_servers = result.get("name_servers", [])
        if name_servers:
            print(f"  {Fore.YELLOW}Name Servers:{Style.RESET_ALL}")
            for ns in name_servers:
                print(f"    {Fore.GREEN}• {ns}{Style.RESET_ALL}")
        
        if output_file:
            self.save_results(result, output_file)
            self.print_status(f"Results saved to {output_file}", "SUCCESS")

    def print_ai_analysis(self, analysis):
        """Print AI analysis in a formatted way"""
        if not analysis:
            return
        
        print(f"\n{Back.BLUE}{Fore.WHITE} 🤖 AI SECURITY ANALYSIS {Style.RESET_ALL}")
        
        if "assessment" in analysis:
            print(f"\n{Fore.CYAN}Assessment:{Style.RESET_ALL}")
            print(f"  {analysis['assessment']}")
        
        if "risk_level" in analysis:
            risk_color = {
                "Critical": Fore.MAGENTA,
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN
            }.get(analysis["risk_level"], Fore.WHITE)
            print(f"\n{Fore.CYAN}Risk Level:{Style.RESET_ALL} {risk_color}{analysis['risk_level']}{Style.RESET_ALL}")
        
        if "recommendations" in analysis:
            recommendations = analysis["recommendations"]
            if isinstance(recommendations, list):
                print(f"\n{Fore.CYAN}AI Recommendations:{Style.RESET_ALL}")
                for rec in recommendations:
                    print(f"  {Fore.GREEN}• {rec}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.CYAN}AI Recommendations:{Style.RESET_ALL}")
                print(f"  {recommendations}")
        
        if "next_steps" in analysis:
            next_steps = analysis["next_steps"]
            if isinstance(next_steps, list):
                print(f"\n{Fore.CYAN}Suggested Next Steps:{Style.RESET_ALL}")
                for step in next_steps:
                    print(f"  {Fore.YELLOW}→ {step}{Style.RESET_ALL}")

    def save_results(self, data, filename):
        """Save scan results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            self.print_status(f"Failed to save results: {e}", "ERROR")

    def generate_report(self, scan_data_file, format_type="html"):
        """Generate a security report"""
        try:
            with open(scan_data_file, 'r') as f:
                scan_data = json.load(f)
            
            self.print_status(f"Generating {format_type.upper()} report...")
            
            result = self.make_request("/report/generate", {
                "scan_data": scan_data,
                "format": format_type
            }, "POST")
            
            if result and "report_path" in result:
                self.print_status(f"Report generated: {result['report_path']}", "SUCCESS")
            else:
                self.print_status("Report generation failed", "ERROR")
                
        except FileNotFoundError:
            self.print_status(f"Scan data file not found: {scan_data_file}", "ERROR")
        except Exception as e:
            self.print_status(f"Report generation error: {e}", "ERROR")

def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner CLI - AI-Assisted Vulnerability Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  network-scanner-cli subdomain example.com
  network-scanner-cli port 192.168.1.1 --port-range 1-65535
  network-scanner-cli vuln https://example.com --scan-type web
  network-scanner-cli dns example.com --output results.json
  network-scanner-cli whois example.com
  network-scanner-cli report results.json --format pdf
        """
    )
    
    # Global options
    parser.add_argument("--api-url", default="http://localhost:5000/api",
                       help="Network Scanner API server URL")
    parser.add_argument("--output", "-o", help="Save results to file")
    parser.add_argument("--quiet", "-q", action="store_true",
                       help="Quiet mode - minimal output")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Subdomain enumeration
    subdomain_parser = subparsers.add_parser("subdomain", help="Subdomain enumeration")
    subdomain_parser.add_argument("domain", help="Target domain")
    
    # Port scanning
    port_parser = subparsers.add_parser("port", help="Port scanning")
    port_parser.add_argument("target", help="Target IP or domain")
    port_parser.add_argument("--port-range", default="1-1000",
                           help="Port range to scan (default: 1-1000)")
    
    # Vulnerability scanning
    vuln_parser = subparsers.add_parser("vuln", help="Vulnerability scanning")
    vuln_parser.add_argument("target", help="Target URL or IP")
    vuln_parser.add_argument("--scan-type", choices=["basic", "web", "network", "comprehensive"],
                           default="basic", help="Type of vulnerability scan")
    
    # DNS enumeration
    dns_parser = subparsers.add_parser("dns", help="DNS enumeration")
    dns_parser.add_argument("domain", help="Target domain")
    
    # WHOIS lookup
    whois_parser = subparsers.add_parser("whois", help="WHOIS lookup")
    whois_parser.add_argument("domain", help="Target domain")
    
    # Report generation
    report_parser = subparsers.add_parser("report", help="Generate security report")
    report_parser.add_argument("data_file", help="JSON file with scan results")
    report_parser.add_argument("--format", choices=["html", "pdf"], default="html",
                             help="Report format")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize CLI
    cli = NetworkScannerCLI(args.api_url)
    
    if not args.quiet:
        cli.print_banner()
    
    # Execute commands
    try:
        if args.command == "subdomain":
            cli.subdomain_scan(args.domain, args.output)
        
        elif args.command == "port":
            cli.port_scan(args.target, args.port_range, args.output)
        
        elif args.command == "vuln":
            cli.vulnerability_scan(args.target, args.scan_type, args.output)
        
        elif args.command == "dns":
            cli.dns_enumeration(args.domain, args.output)
        
        elif args.command == "whois":
            cli.whois_lookup(args.domain, args.output)
        
        elif args.command == "report":
            cli.generate_report(args.data_file, args.format)
    
    except KeyboardInterrupt:
        cli.print_status("Scan interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        cli.print_status(f"Unexpected error: {e}", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main()