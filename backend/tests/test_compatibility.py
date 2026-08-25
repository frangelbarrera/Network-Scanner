import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

nmap_mock = types.ModuleType("nmap")
nmap_mock.PortScanner = type("MockPortScanner", (), {})
sys.modules.setdefault("nmap", nmap_mock)

import app as application
from modules.report_generator import ReportGenerator


class TestRestCompatibility(unittest.TestCase):
    def setUp(self):
        self.client = application.app.test_client()
        self.original_subdomains = application.recon_module.find_subdomains
        self.original_ports = application.recon_module.port_scan
        self.original_vulnerabilities = application.vuln_scanner.scan_target
        self.original_subdomain_analysis = application.ai_assistant.analyze_subdomains
        self.original_port_analysis = application.ai_assistant.analyze_ports
        self.original_vulnerability_analysis = application.ai_assistant.analyze_vulnerabilities
        application.ai_assistant.analyze_subdomains = MagicMock(return_value={})
        application.ai_assistant.analyze_ports = MagicMock(return_value={})
        application.ai_assistant.analyze_vulnerabilities = MagicMock(return_value={})

    def tearDown(self):
        application.recon_module.find_subdomains = self.original_subdomains
        application.recon_module.port_scan = self.original_ports
        application.vuln_scanner.scan_target = self.original_vulnerabilities
        application.ai_assistant.analyze_subdomains = self.original_subdomain_analysis
        application.ai_assistant.analyze_ports = self.original_port_analysis
        application.ai_assistant.analyze_vulnerabilities = self.original_vulnerability_analysis

    def test_subdomain_response_keeps_raw_data_and_exposes_list(self):
        application.recon_module.find_subdomains = MagicMock(return_value={
            "domain": "example.test",
            "total_found": 1,
            "subdomains": ["api.example.test"],
        })
        response = self.client.post("/api/scan/subdomain", json={"domain": "example.test"})
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["subdomains"], ["api.example.test"])
        self.assertEqual(body["subdomain_data"]["total_found"], 1)

    def test_port_response_keeps_raw_data_and_exposes_flat_results(self):
        application.recon_module.port_scan = MagicMock(return_value={
            "target": "127.0.0.1",
            "scan_results": [{"host": "127.0.0.1", "open_ports": []}],
            "total_open_ports": 1,
        })
        response = self.client.post("/api/scan/ports", json={"target": "127.0.0.1"})
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["total_open_ports"], 1)
        self.assertEqual(body["scan_results"][0]["host"], "127.0.0.1")
        self.assertEqual(body["port_data"]["total_open_ports"], 1)

    def test_vulnerability_response_keeps_raw_data_and_exposes_list(self):
        application.vuln_scanner.scan_target = MagicMock(return_value={
            "target": "127.0.0.1",
            "vulnerabilities": [{"title": "simulated", "severity": "Low"}],
            "total_vulnerabilities": 1,
            "severity_breakdown": {"Low": 1},
        })
        response = self.client.post(
            "/api/vulnerability/scan", json={"target": "127.0.0.1", "scan_type": "basic"}
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["vulnerabilities"][0]["title"], "simulated")
        self.assertEqual(body["vulnerability_data"]["total_vulnerabilities"], 1)

    def test_report_endpoint_rejects_unsupported_format_and_invalid_shape(self):
        unsupported_format = self.client.post(
            "/api/report/generate", json={"scan_data": {"target": "example.test"}, "format": "txt"}
        )
        invalid_shape = self.client.post(
            "/api/report/generate", json={"scan_data": [], "format": "html"}
        )
        self.assertEqual(unsupported_format.status_code, 400)
        self.assertEqual(invalid_shape.status_code, 400)


class TestReportCompatibility(unittest.TestCase):
    def test_html_escapes_report_values_and_pdf_accepts_vulnerability_list(self):
        with tempfile.TemporaryDirectory() as reports_dir:
            original_reports_dir = os.environ.get("REPORTS_DIR")
            os.environ["REPORTS_DIR"] = reports_dir
            try:
                generator = ReportGenerator()
                scan_data = {
                    "target": "<img src=x onerror=alert(1)>",
                    "vulnerabilities": [{"title": "simulated", "severity": "Low"}],
                }
                html_path = generator.generate_report(scan_data, "html")
                pdf_path = generator.generate_report(scan_data, "pdf")
                html = Path(html_path).read_text(encoding="utf-8")
                self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
                self.assertNotIn("<img src=x onerror=alert(1)>", html)
                self.assertTrue(Path(pdf_path).is_file())
            finally:
                if original_reports_dir is None:
                    os.environ.pop("REPORTS_DIR", None)
                else:
                    os.environ["REPORTS_DIR"] = original_reports_dir


if __name__ == "__main__":
    unittest.main()
