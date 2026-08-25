"""Regression tests for CLI transport and exit-code behavior."""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))
from network_scanner_cli import NetworkScannerCLI, main  # noqa: E402


class TestNetworkScannerCLI(unittest.TestCase):
    def test_accepts_server_url_with_or_without_api_suffix(self):
        self.assertEqual(
            NetworkScannerCLI('http://scanner.example.test:5000').api_url,
            'http://scanner.example.test:5000/api',
        )
        self.assertEqual(
            NetworkScannerCLI('http://scanner.example.test:5000/api/').api_url,
            'http://scanner.example.test:5000/api',
        )

    def test_adds_bearer_token_when_provided(self):
        cli = NetworkScannerCLI('http://scanner.example.test', api_token='test-token')
        self.assertEqual(cli.session.headers['Authorization'], 'Bearer test-token')

    def test_report_failure_returns_false(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as data_file:
            data_file.write('{}')
            data_path = data_file.name
        try:
            cli = NetworkScannerCLI('http://scanner.example.test')
            cli.make_request = lambda *args, **kwargs: None
            self.assertFalse(cli.generate_report(data_path))
        finally:
            os.unlink(data_path)

    def test_main_returns_nonzero_when_command_fails(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as data_file:
            data_file.write('{}')
            data_path = data_file.name
        try:
            with patch.object(NetworkScannerCLI, 'generate_report', return_value=False):
                with patch.object(sys, 'argv', ['network-scanner-cli', '--quiet', 'report', data_path]):
                    self.assertEqual(main(), 1)
        finally:
            os.unlink(data_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
