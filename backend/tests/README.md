# Network-Scanner Backend Tests

## Running the tests

The tests use only the Python standard library (`unittest`, `unittest.mock`), so
no extra dependencies are required. Run them from the `backend/` directory:

```bash
cd backend

# Option A — stdlib unittest (no install needed)
python -m unittest tests.test_regression -v

# Option B — pytest (if installed; uses the same test cases)
python -m pytest tests/ -v
```

## Test dependencies

The regression tests rely on `unittest` + `unittest.mock` (stdlib) plus the
packages already declared in `backend/requirements.txt` (so that the production
modules can be imported by the test process). `nmap` is mocked via
`sys.modules` injection before import, so the test machine does not need
`python-nmap` to be functional at runtime.

## What the tests cover

These are regression tests for the critical security fixes. Each test verifies
that a specific bug pattern does not return:

1. `TestAppSecurityConfig` — `debug=True`, `host='0.0.0.0'`, SocketIO CORS `*`,
   and presence of the safe `127.0.0.1` default.
2. `TestReconnaissanceBugFix` — `name.endswith` and `subdomains.add(name)`
   patterns (the `name` undefined bug) + functional test of
   `_cert_transparency_search` with a mocked crt.sh response (also asserts
   wildcard entries are skipped).
3. `TestAIAssistantModelEnvVar` — `model="gpt-3.5-turbo"` hardcoded pattern is
   gone, and `OPENAI_MODEL` env var is referenced.
4. `TestReportGeneratorPath` — `/workspaces/Network-Scanner` hardcoded path is
   gone, `REPORTS_DIR` env var is referenced, and the directory is created with
   `exist_ok=True`.
5. `TestRequirementsTxt` — `jwt==1.3.1` is removed, `pyjwt==2.8.0` is kept.
6. `TestNoUnusedImports` — dead `import subprocess`, `import json`,
   `import threading` (reconnaissance) and `import subprocess` (scanner) are
   gone.

The tests use a mix of static source-code pattern matching (for bugs that are
hard to trigger in unit tests) and functional tests with mocks (for the cert
transparency bug, which can be triggered with mocked HTTP responses).

## Out of scope

Other pyflakes warnings (unused imports in `app.py`, `report_generator.py`,
`scanner.py`, `ai_assistant.py`) exist but are NOT covered by these regression
tests because they were not part of the security-critical fix scope. They are
documented in `SECURITY.md` as known issues.
