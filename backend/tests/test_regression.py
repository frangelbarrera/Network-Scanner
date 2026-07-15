"""
Regression tests for Network-Scanner critical security fixes.

Tests:
1. app.py does NOT hardcode debug=True in __main__ (closes RCE via Werkzeug debugger)
2. app.py does NOT hardcode host='0.0.0.0' (defaults to 127.0.0.1, env-var override)
3. SocketIO CORS is not wildcard '*' (cross-origin WebSocket closed)
4. reconnaissance._cert_transparency_search uses domain_name (not undefined name)
5. ai_assistant uses OPENAI_MODEL env var (no hardcoded gpt-3.5-turbo)
6. report_generator uses REPORTS_DIR env var (no hardcoded /workspaces/ path)
7. requirements.txt does not contain jwt==1.3.1 (conflict with pyjwt)
8. Unused imports removed (subprocess/json/threading in reconnaissance, subprocess in scanner)
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add backend/ to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestAppSecurityConfig(unittest.TestCase):
    """Tests that app.py security-critical config is correct."""

    def _read_app_py(self):
        app_py_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_py_path, 'r') as f:
            return f.read()

    def test_app_py_does_not_use_debug_true_in_main(self):
        """Verify that debug=True is not hardcoded."""
        source = self._read_app_py()
        # The buggy pattern: socketio.run(app, host='0.0.0.0', port=5000, debug=True)
        # The fix uses debug=debug_mode where debug_mode is False unless FLASK_ENV=development
        self.assertNotIn(
            "debug=True",
            source,
            "app.py still has debug=True hardcoded. Werkzeug debugger RCE risk."
        )

    def test_app_py_does_not_hardcode_wildcard_host(self):
        """Verify that host='0.0.0.0' is not hardcoded as a literal in socketio.run.

        The fix uses host = os.environ.get('HOST', '127.0.0.1'). The literal
        '0.0.0.0' should NOT appear inside socketio.run() — it can only appear
        as a default value of the HOST env var, which is fine.
        """
        source = self._read_app_py()
        # The buggy pattern: socketio.run(app, host='0.0.0.0', ...)
        # If the literal string appears inside socketio.run, that's the bug.
        # The fix should pass a variable `host` to socketio.run, not a literal.
        self.assertNotIn(
            "host='0.0.0.0'",
            source,
            "app.py still hardcodes host='0.0.0.0' as a literal. Use env var with safe default."
        )
        self.assertNotIn(
            'host="0.0.0.0"',
            source,
            "app.py still hardcodes host=\"0.0.0.0\" as a literal. Use env var with safe default."
        )

    def test_app_py_defaults_host_to_loopback(self):
        """Verify that the default host (when env var unset) is 127.0.0.1."""
        source = self._read_app_py()
        self.assertIn(
            "127.0.0.1",
            source,
            "app.py should default to 127.0.0.1 when HOST env var is not set."
        )

    def test_socketio_cors_not_wildcard(self):
        """Verify that SocketIO CORS is not '*'."""
        source = self._read_app_py()
        # The buggy pattern: cors_allowed_origins="*"
        self.assertNotIn(
            'cors_allowed_origins="*"',
            source,
            "SocketIO still allows cross-origin WebSocket from any domain. Use env var."
        )
        self.assertNotIn(
            "cors_allowed_origins='*'",
            source,
            "SocketIO still allows cross-origin WebSocket from any domain. Use env var."
        )


class TestReconnaissanceBugFix(unittest.TestCase):
    """Tests that reconnaissance.py name-undefined bug is fixed."""

    def test_cert_transparency_search_uses_domain_name_not_name(self):
        """Verify that _cert_transparency_search uses domain_name variable."""
        recon_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'reconnaissance.py')
        with open(recon_path, 'r') as f:
            source = f.read()

        # Find the _cert_transparency_search method body
        cert_section_start = source.find('_cert_transparency_search')
        # End at the next def _ inside the class
        cert_section_end = source.find('def _dns_zone_transfer')
        if cert_section_start == -1 or cert_section_end == -1:
            self.fail("Could not locate _cert_transparency_search method in source")

        cert_section = source[cert_section_start:cert_section_end]

        # The buggy pattern was `name.endswith(...)` where `name` is undefined.
        # The fix uses `domain_name.endswith(...)` which is correct.
        # We check for the buggy tokens that would only appear if `name` (the
        # undefined variable) is used — `name.endswith` (with space prefix or
        # line-start to avoid matching `domain_name.endswith`) and
        # `subdomains.add(name)` (exact).
        import re
        # Match `name.endswith` only when preceded by a word boundary that is
        # NOT part of `domain_name`. We use a negative lookbehind for `domain_`.
        buggy_pattern = re.compile(r'(?<!domain_)name\.endswith')
        self.assertIsNone(
            buggy_pattern.search(cert_section),
            "_cert_transparency_search still uses undefined 'name.endswith' instead of 'domain_name.endswith'"
        )
        self.assertNotIn(
            'subdomains.add(name)',
            cert_section,
            "_cert_transparency_search still adds 'name' to subdomains instead of 'domain_name'"
        )

    def test_cert_transparency_search_works_with_mock(self):
        """Functional test: _cert_transparency_search returns subdomains with mock."""
        import types
        # Mock nmap to avoid PortScannerError
        nmap_mock = types.ModuleType('nmap')
        class MockPortScanner:
            def __init__(self): pass
            def scan(self, *a, **kw): pass
            def all_hosts(self): return []
        nmap_mock.PortScanner = MockPortScanner
        sys.modules['nmap'] = nmap_mock

        from modules.reconnaissance import ReconModule

        r = ReconModule()

        # Mock requests.get to simulate crt.sh response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {'name_value': 'www.example.com\nmail.example.com'},
            {'name_value': 'dev.example.com'},
            {'name_value': 'other.org'},  # should be filtered out
            {'name_value': '*.example.com'},  # wildcard — should be skipped
        ]

        with patch('requests.get', return_value=mock_response):
            result = r._cert_transparency_search('example.com')

        # Bug fix: should return ['www.example.com', 'mail.example.com', 'dev.example.com']
        # Bug: would return [] (NameError swallowed by except)
        self.assertIsInstance(result, list)
        self.assertIn('www.example.com', result, "www.example.com should be in results")
        self.assertIn('mail.example.com', result, "mail.example.com should be in results")
        self.assertIn('dev.example.com', result, "dev.example.com should be in results")
        self.assertNotIn('other.org', result, "other.org should be filtered out (not .example.com)")
        self.assertNotIn('*.example.com', result, "wildcard entries should be skipped")


class TestAIAssistantModelEnvVar(unittest.TestCase):
    """Tests that ai_assistant.py uses OPENAI_MODEL env var."""

    def test_ai_assistant_does_not_hardcode_gpt_3_5(self):
        """Verify that gpt-3.5-turbo is not hardcoded."""
        ai_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'ai_assistant.py')
        with open(ai_path, 'r') as f:
            source = f.read()

        self.assertNotIn(
            'model="gpt-3.5-turbo"',
            source,
            "ai_assistant.py still hardcodes gpt-3.5-turbo. Use os.getenv('OPENAI_MODEL', 'gpt-4o-mini')."
        )
        self.assertNotIn(
            "model='gpt-3.5-turbo'",
            source,
            "ai_assistant.py still hardcodes gpt-3.5-turbo. Use os.getenv('OPENAI_MODEL', 'gpt-4o-mini')."
        )

    def test_ai_assistant_uses_env_var(self):
        """Verify that OPENAI_MODEL env var is referenced."""
        ai_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'ai_assistant.py')
        with open(ai_path, 'r') as f:
            source = f.read()

        self.assertIn(
            'OPENAI_MODEL',
            source,
            "ai_assistant.py should reference OPENAI_MODEL env var."
        )


class TestReportGeneratorPath(unittest.TestCase):
    """Tests that report_generator.py does not use hardcoded /workspaces/ path."""

    def test_report_generator_does_not_use_workspaces_path(self):
        """Verify that /workspaces/Network-Scanner path is not hardcoded."""
        rg_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'report_generator.py')
        with open(rg_path, 'r') as f:
            source = f.read()

        self.assertNotIn(
            "/workspaces/Network-Scanner",
            source,
            "report_generator.py still hardcodes /workspaces/Network-Scanner path. Use REPORTS_DIR env var."
        )

    def test_report_generator_uses_env_var(self):
        """Verify that REPORTS_DIR env var is referenced."""
        rg_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'report_generator.py')
        with open(rg_path, 'r') as f:
            source = f.read()

        self.assertIn(
            'REPORTS_DIR',
            source,
            "report_generator.py should reference REPORTS_DIR env var."
        )

    def test_report_generator_creates_reports_dir(self):
        """Verify that the reports directory is created with exist_ok=True."""
        rg_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'report_generator.py')
        with open(rg_path, 'r') as f:
            source = f.read()

        self.assertIn(
            "os.makedirs(reports_dir, exist_ok=True)",
            source,
            "report_generator.py should create the reports dir with exist_ok=True to handle concurrent scans."
        )


class TestRequirementsTxt(unittest.TestCase):
    """Tests that requirements.txt does not have jwt/pyjwt conflict."""

    def test_requirements_does_not_have_jwt_131(self):
        """Verify that jwt==1.3.1 is not in requirements.txt."""
        req_path = os.path.join(os.path.dirname(__file__), '..', 'requirements.txt')
        with open(req_path, 'r') as f:
            source = f.read()

        self.assertNotIn(
            'jwt==1.3.1',
            source,
            "requirements.txt still has jwt==1.3.1 which conflicts with pyjwt==2.8.0."
        )

    def test_requirements_keeps_pyjwt(self):
        """Verify that pyjwt is still present (it's the maintained successor)."""
        req_path = os.path.join(os.path.dirname(__file__), '..', 'requirements.txt')
        with open(req_path, 'r') as f:
            source = f.read()

        self.assertIn(
            'pyjwt==2.8.0',
            source,
            "requirements.txt must keep pyjwt==2.8.0 (maintained successor)."
        )


class TestNoUnusedImports(unittest.TestCase):
    """Tests that the specific dead imports flagged in the bug report are removed."""

    def test_reconnaissance_no_subprocess_import(self):
        recon_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'reconnaissance.py')
        with open(recon_path, 'r') as f:
            lines = f.readlines()
        for i, line in enumerate(lines, 1):
            self.assertFalse(
                line.strip() == 'import subprocess',
                f"reconnaissance.py line {i} still has 'import subprocess' (unused)"
            )

    def test_reconnaissance_no_json_import(self):
        recon_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'reconnaissance.py')
        with open(recon_path, 'r') as f:
            lines = f.readlines()
        for i, line in enumerate(lines, 1):
            self.assertFalse(
                line.strip() == 'import json',
                f"reconnaissance.py line {i} still has 'import json' (unused)"
            )

    def test_reconnaissance_no_threading_import(self):
        recon_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'reconnaissance.py')
        with open(recon_path, 'r') as f:
            lines = f.readlines()
        for i, line in enumerate(lines, 1):
            self.assertFalse(
                line.strip() == 'import threading',
                f"reconnaissance.py line {i} still has 'import threading' (unused)"
            )

    def test_scanner_no_subprocess_import(self):
        scanner_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'scanner.py')
        with open(scanner_path, 'r') as f:
            lines = f.readlines()
        for i, line in enumerate(lines, 1):
            self.assertFalse(
                line.strip() == 'import subprocess',
                f"scanner.py line {i} still has 'import subprocess' (unused)"
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)
