"""Regression tests for the API hardening batch.

Covers: hashed rate-limit keys, proxy-conditional setup, request size and
input limits, generic 500 responses, report filename responses and retention,
bounded automated-scan concurrency, and the OpenAI client guardrails.
"""
import os
import sys
import time
import types
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

nmap_mock = types.ModuleType("nmap")
nmap_mock.PortScanner = type("MockPortScanner", (), {})
sys.modules["nmap"] = nmap_mock

import app as application  # noqa: E402
from modules.ai_assistant import AIAssistant  # noqa: E402
from modules.report_generator import ReportGenerator  # noqa: E402


class TestRateLimitKeyHygiene(unittest.TestCase):
    def test_authenticated_key_is_hashed_not_plaintext(self):
        """Limiter keys are persisted in the configured storage; the raw
        API token must never become part of them."""
        with patch.object(application, "api_access_token", "unit-test-token"):
            with application.app.test_request_context(
                "/", headers={"Authorization": "Bearer unit-test-token"}
            ):
                key = application.rate_limit_key()

        self.assertTrue(key.startswith("token:"))
        self.assertNotIn("unit-test-token", key)
        self.assertEqual(len(key), len("token:") + 32)

    def test_unauthenticated_key_falls_back_to_address(self):
        with application.app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.1.2.3"}):
            self.assertEqual(application.rate_limit_key(), "10.1.2.3")


class TestAppHardeningConfig(unittest.TestCase):
    def test_request_body_size_is_bounded(self):
        self.assertEqual(application.app.config["MAX_CONTENT_LENGTH"], 5 * 1024 * 1024)

    def test_oversized_body_returns_413_not_500(self):
        """RequestEntityTooLarge must surface as 413, not as a generic 500."""
        client = application.app.test_client()
        response = client.post(
            "/api/ai/chat",
            data="x" * (6 * 1024 * 1024),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 413)

    def test_proxy_fix_is_opt_in(self):
        """ProxyFix must only engage when the operator explicitly trusts the
        proxy; otherwise X-Forwarded-* spoofing would drive rate limits."""
        source_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(source_path, 'r') as source_file:
            source = source_file.read()

        self.assertIn('os.environ.get("TRUST_PROXY") == "1"', source)
        self.assertIn('ProxyFix(app.wsgi_app', source)

    def test_port_range_rejects_oversized_input(self):
        oversized = ",".join(["80"] * 120)
        value, error = application.validate_port_range(oversized)
        self.assertIsNone(value)
        self.assertIn("too long", error)


class TestAiChatInputValidation(unittest.TestCase):
    def setUp(self):
        self.client = application.app.test_client()
        token = application.api_access_token
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}

    def _chat(self, payload):
        return self.client.post("/api/ai/chat", json=payload, headers=self.headers)

    def test_non_string_message_is_rejected(self):
        response = self._chat({"message": ["nested", "array"]})
        self.assertEqual(response.status_code, 400)

    def test_oversized_message_is_rejected(self):
        response = self._chat({"message": "x" * 4001})
        self.assertEqual(response.status_code, 400)

    def test_non_object_context_is_rejected(self):
        response = self._chat({"message": "hello", "context": "not-an-object"})
        self.assertEqual(response.status_code, 400)

    def test_oversized_context_is_truncated(self):
        """Large scan payloads must not travel wholesale into the prompt."""
        with patch.object(application.ai_assistant, "chat_response") as chat_mock:
            chat_mock.return_value = {"response": "ok", "timestamp": "now"}
            response = self._chat(
                {"message": "analyze", "context": {"scan_results": "A" * 30000}}
            )

        self.assertEqual(response.status_code, 200)
        sent_context = chat_mock.call_args[0][1]
        self.assertNotIn("A" * 30000, str(sent_context))


class TestAutomatedScanConcurrency(unittest.TestCase):
    def test_second_scan_is_rejected_while_slots_are_taken(self):
        """Automated scans spawn nmap processes; a second concurrent scan
        must be rejected instead of piling onto the host."""
        socketio_client = application.socketio.test_client(application.app)
        self.assertTrue(socketio_client.is_connected())

        # Occupy every scan slot.
        while application.SCAN_SLOTS.acquire(blocking=False):
            pass
        try:
            socketio_client.get_received()  # drain connect ack
            socketio_client.emit(
                "start_automated_scan",
                {"target": "127.0.0.1", "scan_types": ["port"]},
            )
            received = socketio_client.get_received()
        finally:
            for _ in range(2):
                try:
                    application.SCAN_SLOTS.release()
                except ValueError:
                    break

        events = [event for event in received if event["name"] == "scan_error"]
        self.assertTrue(events)
        self.assertIn("already in progress", events[0]["args"][0]["error"])
        socketio_client.disconnect()


class TestReportResponseContract(unittest.TestCase):
    def test_generate_report_returns_filename_not_server_path(self):
        """The API response must not disclose the server-side reports
        directory; clients only need the basename to download."""
        with patch.object(
            application.report_generator,
            "generate_report",
            return_value="/srv/scanner/reports/security_report_20260914.html",
        ):
            response = self.client_post_report()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["report_path"], "security_report_20260914.html"
        )

    def test_stale_reports_are_purged_on_generation(self):
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            stale = os.path.join(temp_dir, "security_report_20200101_000000.html")
            fresh = os.path.join(temp_dir, "security_report_29991231_235959.html")
            for filepath in (stale, fresh):
                with open(filepath, "w") as report_file:
                    report_file.write("<html></html>")
            # Age the stale file beyond the retention window.
            old_timestamp = time.time() - 30 * 86400
            os.utime(stale, (old_timestamp, old_timestamp))

            generator = ReportGenerator()
            generator._purge_stale_reports(temp_dir)

            self.assertFalse(os.path.exists(stale))
            self.assertTrue(os.path.exists(fresh))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def client_post_report(self):
        client = application.app.test_client()
        token = application.api_access_token
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        scan_data = {"scan_type": "port_scan", "target": "127.0.0.1"}
        return client.post(
            "/api/report/generate",
            json={"scan_data": scan_data, "format": "html"},
            headers=headers,
        )


class TestOpenAIClientGuardrails(unittest.TestCase):
    def test_client_uses_bounded_timeout_and_retries(self):
        """The SDK default is a 10-minute timeout with retries; every hung
        call would pin a request thread, so the client must be bounded."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            assistant = AIAssistant()

        self.assertIsNotNone(assistant.client)
        self.assertEqual(assistant.client.timeout, 30.0)
        self.assertEqual(assistant.client.max_retries, 2)

    def test_fallback_analyses_are_labeled(self):
        """Heuristic fallbacks must not masquerade as LLM assessments."""
        assistant = AIAssistant()
        with patch.object(assistant, "api_key", ""):
            port_analysis = assistant.analyze_ports({"scan_results": [], "target": "t"})
            subdomain_analysis = assistant.analyze_subdomains({"subdomains": [], "domain": "d"})
            vuln_analysis = assistant.analyze_vulnerabilities({"vulnerabilities": [], "target": "t"})

        for analysis in (port_analysis, subdomain_analysis, vuln_analysis):
            self.assertEqual(analysis.get("source"), "fallback")

    def test_analysis_prompt_carries_untrusted_data_delimiters(self):
        """Scan output (hostnames, banners) is attacker-controlled; it must
        reach the model between delimiters with a system instruction."""
        assistant = AIAssistant()
        with patch.object(assistant, "api_key", "test-key"), \
                patch.object(assistant, "client") as client_mock:
            client_mock.chat.completions.create.return_value.choices = [
                MagicMock(message=MagicMock(content='{"risk_level": "Low"}'))
            ]
            assistant.analyze_ports(
                {"scan_results": [{"open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}]}], "target": "example.test"}
            )

        messages = client_mock.chat.completions.create.call_args.kwargs["messages"]
        system_content = messages[0]["content"]
        user_content = messages[1]["content"]

        self.assertIn("untrusted", system_content.lower())
        self.assertIn("<<<SCAN_DATA", user_content)
        self.assertIn("SCAN_DATA>>>", user_content)
        self.assertIn("80", user_content)


if __name__ == '__main__':
    unittest.main(verbosity=2)
