"""Regression tests for protected API contracts and automated scan behavior."""
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class _MockPortScanner:
    def __init__(self):
        pass


nmap_mock = types.ModuleType("nmap")
nmap_mock.PortScanner = _MockPortScanner
sys.modules["nmap"] = nmap_mock

import app as application  # noqa: E402
from models.scan_results import db as models_db  # noqa: E402
from modules.reconnaissance import ReconModule  # noqa: E402


class TestProductionConfiguration(unittest.TestCase):
    def test_compose_placeholder_is_listed_as_invalid_production_secret(self):
        self.assertIn("your-secret-key-change-this", application.PRODUCTION_SECRET_PLACEHOLDERS)
        self.assertIn(
            "replace-with-a-random-secret-key-at-least-32-characters",
            application.PRODUCTION_SECRET_PLACEHOLDERS,
        )
        self.assertIn(
            "replace-with-a-separate-random-api-access-token",
            application.PRODUCTION_API_TOKEN_PLACEHOLDERS,
        )

    def test_production_secret_has_a_minimum_length_check(self):
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_path, encoding='utf-8') as app_file:
            source = app_file.read()
        self.assertIn('len(app.config["SECRET_KEY"]) < 32', source)
        dockerfile_path = os.path.join(os.path.dirname(__file__), '..', '..', 'Dockerfile.backend')
        with open(dockerfile_path, encoding='utf-8') as dockerfile:
            dockerfile_source = dockerfile.read()
        self.assertIn('setcap cap_net_raw+ep /usr/bin/nmap', dockerfile_source)

    def test_compose_requires_independent_api_token(self):
        compose_path = os.path.join(os.path.dirname(__file__), '..', '..', 'docker-compose.yml')
        with open(compose_path, encoding='utf-8') as compose_file:
            compose = compose_file.read()
        self.assertIn('API_ACCESS_TOKEN: ${API_ACCESS_TOKEN:?', compose)
        self.assertNotIn('"5000:5000"', compose)
        self.assertNotIn('"443:443"', compose)
        self.assertIn('"127.0.0.1:80:80"', compose)
        self.assertIn('cap_add:\n      - NET_RAW', compose)

    def test_dotenv_is_loaded_before_application_configuration(self):
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_path, encoding='utf-8') as app_file:
            source = app_file.read()
        self.assertLess(
            source.index('load_dotenv(os.path.join(PROJECT_ROOT, ".env"))'),
            source.index('app = Flask(__name__)'),
        )

    def test_environment_template_defaults_to_production(self):
        env_path = os.path.join(os.path.dirname(__file__), '..', '..', '.env.example')
        with open(env_path, encoding='utf-8') as env_file:
            environment = env_file.read()
        self.assertIn('FLASK_ENV=production', environment)


class TestDatabaseBinding(unittest.TestCase):
    def test_models_share_the_application_database_instance(self):
        self.assertIs(models_db, application.db)
        self.assertIn('user', application.db.metadata.tables)
        self.assertIn('scan_result', application.db.metadata.tables)


class TestReconnaissanceContract(unittest.TestCase):
    def test_port_scan_exposes_python_nmap_execution_errors(self):
        module = ReconModule()
        module.nm = MagicMock()
        module.nm.scan.return_value = {
            'nmap': {'scaninfo': {'error': ['raw socket permission denied\\n']}},
        }

        result = module.port_scan('127.0.0.1', '1-2,80')

        self.assertIn('Nmap execution failed', result['error'])
        self.assertIn('raw socket permission denied', result['error'])
        module.nm.scan.assert_called_once_with(
            '127.0.0.1',
            '1-2,80',
            arguments='--privileged -sS -sV -O',
        )


class TestApiValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = application.app.test_client()

    def test_port_range_rejects_non_numeric_values_before_scanning(self):
        application.recon_module.port_scan = MagicMock()
        response = self.client.post(
            '/api/scan/ports',
            json={'target': '127.0.0.1', 'port_range': 'not-a-port-range'},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('Port range', response.get_json()['error'])
        application.recon_module.port_scan.assert_not_called()

    def test_port_range_rejects_out_of_bounds_port_before_scanning(self):
        application.recon_module.port_scan = MagicMock()
        response = self.client.post(
            '/api/scan/ports',
            json={'target': '127.0.0.1', 'port_range': '1-70000'},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('between 1 and 65535', response.get_json()['error'])
        application.recon_module.port_scan.assert_not_called()

    def test_vulnerability_scan_rejects_unsupported_type(self):
        application.vuln_scanner.scan_target = MagicMock()
        response = self.client.post(
            '/api/vulnerability/scan',
            json={'target': '127.0.0.1', 'scan_type': 'unsupported'},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('scan_type must be one of', response.get_json()['error'])
        application.vuln_scanner.scan_target.assert_not_called()

    def test_port_scan_failure_is_returned_as_an_explicit_http_error(self):
        with patch.object(
            application.recon_module,
            'port_scan',
            return_value={'error': 'local nmap failure', 'target': '127.0.0.1'},
        ), patch.object(application.ai_assistant, 'analyze_ports') as analyze_ports:
            response = self.client.post(
                '/api/scan/ports',
                json={'target': '127.0.0.1', 'port_range': '1'},
            )

        self.assertEqual(response.status_code, 502)
        body = response.get_json()
        self.assertEqual(body['error'], 'Port scan failed')
        self.assertEqual(body['details'], 'local nmap failure')
        analyze_ports.assert_not_called()

    def test_port_scan_preserves_valid_multiple_ranges(self):
        with patch.object(
            application.recon_module,
            'port_scan',
            return_value={'scan_results': [], 'total_open_ports': 0},
        ) as port_scan, patch.object(application.ai_assistant, 'analyze_ports', return_value={}):
            response = self.client.post(
                '/api/scan/ports',
                json={'target': '127.0.0.1', 'port_range': '1-2,80'},
            )

        self.assertEqual(response.status_code, 200)
        port_scan.assert_called_once_with('127.0.0.1', '1-2,80')

    def test_vulnerability_scan_failure_is_returned_as_an_explicit_http_error(self):
        with patch.object(
            application.vuln_scanner,
            'scan_target',
            return_value={'error': 'local scanner failure', 'target': '127.0.0.1'},
        ), patch.object(application.ai_assistant, 'analyze_vulnerabilities') as analyze_vulnerabilities:
            response = self.client.post(
                '/api/vulnerability/scan',
                json={'target': '127.0.0.1', 'scan_type': 'basic'},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()['error'], 'Vulnerability scan failed')
        analyze_vulnerabilities.assert_not_called()


class TestAutomatedScanContract(unittest.TestCase):
    def setUp(self):
        application.recon_module.dns_enumeration = MagicMock(return_value={'A': ['127.0.0.1']})
        application.ai_assistant.analyze_comprehensive_scan = MagicMock(return_value={'source': 'test'})
        self.client = application.socketio.test_client(application.app)

    def tearDown(self):
        self.client.disconnect()

    def test_dns_selection_executes_dns_and_returns_its_result(self):
        self.client.emit('start_automated_scan', {'target': '127.0.0.1', 'scan_types': ['dns']})
        events = self.client.get_received()
        completed = [event for event in events if event['name'] == 'scan_complete']
        self.assertEqual(len(completed), 1)
        result = completed[0]['args'][0]['results']
        self.assertEqual(result['dns'], {'A': ['127.0.0.1']})
        application.recon_module.dns_enumeration.assert_called_once_with('127.0.0.1')

    def test_automated_scan_rejects_unsupported_type(self):
        self.client.emit('start_automated_scan', {'target': '127.0.0.1', 'scan_types': ['invalid']})
        events = self.client.get_received()
        errors = [event for event in events if event['name'] == 'scan_error']
        self.assertEqual(len(errors), 1)
        self.assertIn('unsupported', errors[0]['args'][0]['error'])

    def test_automated_scan_stops_on_module_failure(self):
        with patch.object(
            application.recon_module,
            'port_scan',
            return_value={'error': 'local nmap failure', 'target': '127.0.0.1'},
        ), patch.object(application.ai_assistant, 'analyze_comprehensive_scan') as analyze:
            self.client.emit('start_automated_scan', {'target': '127.0.0.1', 'scan_types': ['port']})
            events = self.client.get_received()

        errors = [event for event in events if event['name'] == 'scan_error']
        completed = [event for event in events if event['name'] == 'scan_complete']
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['args'][0]['error'], 'port scan failed')
        self.assertEqual(completed, [])
        analyze.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
