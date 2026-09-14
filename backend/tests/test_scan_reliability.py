"""Regression tests for scan reliability fixes.

Covers: per-scan PortScanner instances, privilege-aware Nmap arguments,
WHOIS library compatibility, report template robustness against missing
severity fields, AXFR timeouts and SSL verification failure reporting.
"""
import os
import ssl
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

nmap_mock = types.ModuleType("nmap")
nmap_mock.PortScanner = type("MockPortScanner", (), {})
sys.modules["nmap"] = nmap_mock

import app as application  # noqa: E402
from modules.reconnaissance import ReconModule  # noqa: E402
from modules.scanner import VulnScanner, _nmap_scan_args  # noqa: E402
from modules.report_generator import ReportGenerator  # noqa: E402


class TestNmapScanArguments(unittest.TestCase):
    def test_syn_scan_selected_when_raw_sockets_available(self):
        with patch('modules.scanner._raw_socket_available', return_value=True):
            self.assertEqual(_nmap_scan_args(), '-sS -sV')

    def test_connect_scan_fallback_without_raw_sockets(self):
        with patch('modules.scanner._raw_socket_available', return_value=False):
            self.assertEqual(_nmap_scan_args(), '-sT -sV')

    def test_quick_port_scan_no_longer_mixes_top_ports_flag(self):
        """-p <port list> combined with --top-ports produced version-dependent
        scans and dropped service banners; the explicit list must win."""
        scanner = VulnScanner()
        with patch('modules.scanner._raw_socket_available', return_value=False), \
                patch('modules.scanner.nmap.PortScanner') as scanner_cls:
            scanner_cls.return_value.scan.return_value = {
                'nmap': {'scaninfo': {}},
            }
            scanner_cls.return_value.all_hosts.return_value = []
            scanner._quick_port_scan('127.0.0.1')

        arguments = scanner_cls.return_value.scan.call_args.kwargs['arguments']
        self.assertIn('-sT', arguments)
        self.assertIn('-sV', arguments)
        self.assertNotIn('--top-ports', arguments)


class TestPerScanPortScannerInstances(unittest.TestCase):
    def test_port_scan_builds_a_fresh_scanner_per_call(self):
        """A shared PortScanner is not thread-safe; concurrent scans would
        read each other's results. Every scan must create its own instance."""
        module = ReconModule()
        with patch('modules.scanner._raw_socket_available', return_value=True), \
                patch('modules.reconnaissance.nmap.PortScanner') as scanner_cls:
            scanner_cls.return_value.scan.return_value = {'nmap': {'scaninfo': {}}}
            scanner_cls.return_value.all_hosts.return_value = []

            module.port_scan('127.0.0.1', '1-100')

        self.assertEqual(scanner_cls.call_count, 1)
        self.assertFalse(hasattr(module, 'nm'))

    def test_quick_port_scan_builds_a_fresh_scanner_per_call(self):
        scanner = VulnScanner()
        with patch('modules.scanner._raw_socket_available', return_value=True), \
                patch('modules.scanner.nmap.PortScanner') as scanner_cls:
            scanner_cls.return_value.scan.return_value = {'nmap': {'scaninfo': {}}}
            scanner_cls.return_value.all_hosts.return_value = []

            scanner._quick_port_scan('127.0.0.1')

        self.assertEqual(scanner_cls.call_count, 1)
        self.assertFalse(hasattr(scanner, 'nm'))

    def test_port_scan_reports_os_matches_when_available(self):
        """-O output was parsed by python-nmap but never surfaced in the
        API response; the host entry must carry the OS guesses."""
        module = ReconModule()
        host = MagicMock()
        host.state.return_value = 'up'
        host.get.return_value = [{'name': 'Linux 5.15'}]
        host.all_protocols.return_value = []

        with patch('modules.scanner._raw_socket_available', return_value=True), \
                patch('modules.reconnaissance.nmap.PortScanner') as scanner_cls:
            scanner_cls.return_value.scan.return_value = {'nmap': {'scaninfo': {}}}
            scanner_cls.return_value.all_hosts.return_value = ['127.0.0.1']
            scanner_cls.return_value.__getitem__.return_value = host

            result = module.port_scan('127.0.0.1', '1-100')

        self.assertEqual(result['scan_results'][0]['os_match'], ['Linux 5.15'])


class TestWhoisLibraryCompatibility(unittest.TestCase):
    def test_whois_lookup_supports_query_api(self):
        """whois==0.9.27 on PyPI exposes query() instead of whois(); the
        lookup must work with both entry points."""
        module = ReconModule()
        record = MagicMock()
        record.registrar = 'Example Registrar'
        record.creation_date = '1995-08-14'
        record.expiration_date = '2027-08-13'
        record.name_servers = ['ns1.example.test']
        record.status = 'ok'
        record.emails = 'abuse@example.test'
        record.org = 'Example Org'
        record.country = 'US'

        with patch.object(sys.modules['whois'], 'whois', None, create=True), \
                patch.object(sys.modules['whois'], 'query', lambda d: record, create=True):
            result = module.whois_lookup('example.test')

        self.assertNotIn('error', result)
        self.assertEqual(result['registrar'], 'Example Registrar')
        self.assertEqual(result['name_servers'], ['ns1.example.test'])

    def test_whois_lookup_reports_missing_data(self):
        module = ReconModule()
        with patch.object(sys.modules['whois'], 'whois', None, create=True), \
                patch.object(sys.modules['whois'], 'query', lambda d: None, create=True):
            result = module.whois_lookup('example.test')

        self.assertIn('error', result)


class TestZoneTransferTimeout(unittest.TestCase):
    def test_zone_transfer_uses_bounded_lifetime(self):
        """Without timeout/lifetime a silent nameserver leaves the request
        thread hanging forever."""
        import dns.query

        module = ReconModule()
        ns = MagicMock()
        ns_records = [ns]

        with patch('dns.resolver.resolve', return_value=ns_records), \
                patch('dns.query.xfr', side_effect=dns.exception.Timeout()) as xfr_mock:
            result = module._dns_zone_transfer('example.test')

        self.assertEqual(result, [])
        self.assertEqual(xfr_mock.call_args.kwargs.get('timeout'), 5)
        self.assertEqual(xfr_mock.call_args.kwargs.get('lifetime'), 15)


class TestSslVerificationFailureReporting(unittest.TestCase):
    def test_untrusted_certificate_surfaces_as_finding(self):
        """With verify_mode=CERT_NONE the peer certificate dict was always
        empty, so the expiry check never ran and untrusted certificates
        disappeared silently."""
        scanner = VulnScanner()
        verification_error = ssl.SSLCertVerificationError(
            1, "self signed certificate in certificate chain")
        verification_error.reason = "self signed certificate in certificate chain"

        with patch('socket.create_connection', side_effect=verification_error):
            vulnerabilities = scanner._ssl_vulnerability_scan('self-signed.test')

        self.assertEqual(len(vulnerabilities), 1)
        self.assertIn('Verification Failed', vulnerabilities[0]['title'])
        self.assertIn('self signed', vulnerabilities[0]['description'])


class TestReportTemplateRobustness(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_html_report_renders_vulnerabilities_without_severity(self):
        """scan_data payloads without a severity field (CLI imports, custom
        JSON) crashed the HTML template with a 500."""
        scan_data = {
            'scan_type': 'vulnerability_scan',
            'target': '127.0.0.1',
            'timestamp': '2026-09-14T20:00:00',
            'vulnerabilities': [
                {
                    'title': 'Reflected XSS',
                    'type': 'Web',
                    'description': 'Unescaped parameter',
                    'recommendation': 'Encode output',
                    'port': 80,
                    'service': 'http',
                }
            ],
        }

        generator = ReportGenerator()
        filepath = os.path.join(self.temp_dir, 'test_report_no_severity.html')
        generator._generate_html_report(scan_data, filepath)

        self.assertTrue(filepath.endswith('.html'))
        with open(filepath, 'r', encoding='utf-8') as report_file:
            html = report_file.read()
        self.assertIn('Reflected XSS', html)
        self.assertIn('vulnerability info', html)


if __name__ == '__main__':
    unittest.main(verbosity=2)
