**Maintainer:** Frangel Raúl Crespo Barrera
**Last verified:** 2026-10-02
**Scope:** Flask API, CLI, React UI, target validation, subprocess execution, reports, and retention.

| Field | Current record |
|---|---|
| Status | Backend, CLI, and frontend tests exist; policy enforcement should remain covered by tests. |
| Evidence | `backend/tests/`, `cli/test_network_scanner_cli.py`, `frontend/src/*.test.js`, `backend/`, `cli/`, `.github/workflows/ci.yml`. |
| Verification | Run backend/CLI/frontend tests; keep nmap mocked in CI and inspect target validation before runtime use. |
| Owner | Repository owner; scan operator owns authorization. |
| Limitations | No third-party scanning is authorized by this repository; reports may contain sensitive topology. |

Scan only owned or explicitly authorized systems. Safe mode should use laboratory allowlists, reject public targets by default, limit concurrency/rate, redact credentials and tokens, and define retention/cleanup.
