import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

nmap_mock = types.ModuleType("nmap")
nmap_mock.PortScanner = type("MockPortScanner", (), {})
sys.modules["nmap"] = nmap_mock

import app as application
from modules.report_generator import ReportGenerator
from modules.scanner import VulnScanner


class TestTargetValidationRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = application.app.test_client()

    def test_target_with_option_prefix_is_rejected_before_port_scan(self):
        with patch.object(application.recon_module, "port_scan") as port_scan:
            response = self.client.post(
                "/api/scan/ports",
                json={"target": "--local-test", "port_range": "80"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("option prefix", response.get_json()["error"])
        port_scan.assert_not_called()

    def test_target_with_option_prefix_is_rejected_before_vulnerability_scan(self):
        with patch.object(application.vuln_scanner, "scan_target") as scan_target:
            response = self.client.post(
                "/api/vulnerability/scan",
                json={"target": "--local-test", "scan_type": "basic"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("option prefix", response.get_json()["error"])
        scan_target.assert_not_called()

    def test_target_reinterpreted_by_argument_parser_is_rejected_before_port_scan(self):
        with patch.object(application.recon_module, "port_scan") as port_scan:
            response = self.client.post(
                "/api/scan/ports",
                json={"target": r"\\--local-test", "port_range": "80"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("option prefix", response.get_json()["error"])
        port_scan.assert_not_called()


class TestNmapFailureRegression(unittest.TestCase):
    def test_vulnerability_scan_reports_nmap_execution_failure(self):
        scanner = VulnScanner()
        scanner.nm = MagicMock()
        scanner.nm.scan.return_value = {
            "nmap": {"scaninfo": {"error": ["local nmap failure\n"]}},
        }

        result = scanner.scan_target("127.0.0.1", "basic")

        self.assertIn("error", result)
        self.assertIn("Nmap execution failed", result["error"])
        self.assertNotIn("vulnerabilities", result)


class TestPdfTextEscapingRegression(unittest.TestCase):
    def test_vulnerability_values_are_literal_text_in_pdf_paragraphs(self):
        generator = ReportGenerator()
        story = []
        marker = "<local-marker>"
        vulnerability = {
            "title": marker,
            "severity": marker,
            "type": marker,
            "description": marker,
            "recommendation": marker,
            "port": marker,
            "service": marker,
        }

        with patch("modules.report_generator.Paragraph", side_effect=lambda text, style: text):
            generator._add_vulnerability_section_pdf(story, [vulnerability])

        paragraph_text = "\n".join(str(item) for item in story)
        self.assertIn("&lt;local-marker&gt;", paragraph_text)
        self.assertNotIn(marker, paragraph_text)


class TestSystemdInstallRegression(unittest.TestCase):
    def test_generated_service_path_keeps_system_nmap_available(self):
        installer = (BACKEND_DIR.parent / "scripts" / "install.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/bin", installer)
        self.assertIn("Environment=\"PATH=$PROJECT_ROOT/backend/venv/bin:", installer)
        self.assertIn("ExecStart=$PROJECT_ROOT/backend/venv/bin/gunicorn --worker-class gthread", installer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
