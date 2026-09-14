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
5. `TestRequirementsTxt` — `jwt==1.3.1` is removed, and unused packages
   (pyjwt, bcrypt) stay out until the auth work that needs them lands.
6. `TestNoUnusedImports` — dead `import subprocess`, `import json`,
   `import threading` (reconnaissance) and `import subprocess` (scanner) are
   gone.

Additional suites cover later hardening batches:

7. `test_api_regressions.py` — Nmap failure surfacing, PDF text escaping, and
   API validation contracts (target and port-range rejection before scanning).
8. `test_compatibility.py` — HTML report escaping and cross-version contracts.
9. `test_scan_reliability.py` — per-scan `PortScanner` instances,
   privilege-aware Nmap arguments, WHOIS library compatibility (both `whois()`
   and `query()` entry points), zone-transfer timeouts, SSL verification
   failure reporting, and report rendering with missing severity fields.
10. `test_security_contracts.py` — production configuration, protected API
    contracts and automated scan behavior.
11. `test_api_hardening.py` — hashed rate-limit keys, opt-in ProxyFix, request
    size limits, AI chat input validation, report filename responses and
    retention, bounded automated-scan concurrency, OpenAI client guardrails
    (timeouts, untrusted-data delimiters, labeled fallbacks), and empty-string
    environment fallbacks.

The tests use a mix of static source-code pattern matching (for bugs that are
hard to trigger in unit tests) and functional tests with mocks (for the cert
transparency bug, which can be triggered with mocked HTTP responses).

## Out of scope

Residual lint-level warnings (unused imports outside the modules above) are
not tracked here; the CI build gate keeps the tree compiling and the behavior
contracts green.
