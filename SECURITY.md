# Security Policy

## Network-Scanner — AI-Assisted Network Scanning Platform

This document explains how to responsibly report security issues found
in the Network-Scanner project itself (Flask backend, React frontend,
Python CLI). It does **not** describe how to use the tool offensively —
for that, see `README.md` and `docs/`.

> **Project status (2026):** This repository received a critical security
> patch addressing the issues below. The project remains functional and
> open for security reports; new features are not the priority, but the
> existing functionality (Flask backend, React frontend, Docker stack,
> CLI) is preserved.
>
> Fixes applied in the latest security commit:
>
> - `app.py`: `debug=True` → `debug=False` by default (closes RCE via the
>   Werkzeug debugger PIN). Debug mode is opt-in via `FLASK_ENV=development`.
> - `app.py`: `host='0.0.0.0'` → `host=os.environ.get('HOST', '127.0.0.1')`
>   (loopback by default; Docker sets `HOST=0.0.0.0` explicitly in
>   `docker-compose.yml` so the container remains reachable).
> - `app.py`: SocketIO `cors_allowed_origins="*"` → env-var-driven via
>   `CORS_ORIGINS` (default `http://localhost:3000`). `docker-compose.yml`
>   sets it to allow the frontend container.
> - `reconnaissance.py`: undefined `name` → `domain_name` in
>   `_cert_transparency_search`. The method was silently broken (the
>   `except Exception` swallowed the `NameError` and returned `[]`). Wildcard
>   certificate entries (`*.example.com`) are now explicitly skipped.
> - `ai_assistant.py`: hardcoded `gpt-3.5-turbo` (4 occurrences) →
>   `OPENAI_MODEL` env var (default `gpt-4o-mini`, the recommended
>   successor; the `gpt-3.5-turbo-0125` snapshot is scheduled for
>   shutdown on 2026-10-23).
> - `requirements.txt`: removed `jwt==1.3.1` (it conflicts with
>   `pyjwt==2.8.0` and neither is imported by the codebase). `pyjwt`
>   is kept as the maintained successor.
> - `report_generator.py`: hardcoded `/workspaces/Network-Scanner/reports`
>   → `REPORTS_DIR` env var (default `<cwd>/reports`, which resolves
>   correctly in local dev and inside the Docker container where
>   `WORKDIR=/app` and `./reports` is bind-mounted to `/app/reports`).
> - `docker-compose.yml`: added `HOST=0.0.0.0`, `REPORTS_DIR=/app/reports`,
>   and `CORS_ORIGINS` to the backend service so the Docker stack keeps
>   working with the new secure defaults.
> - Removed unused imports: `subprocess`, `json`, `threading` in
>   `reconnaissance.py`; `subprocess` in `scanner.py`.
>
> **Known remaining issues (documented; not all are planned to be fixed):**
>
> - `/api/scan/*` and `/api/vulnerability/*` endpoints have no
>   authentication. Operators exposing the backend publicly MUST put a
>   reverse proxy with authentication in front. The default
>   `host='127.0.0.1'` (when `HOST` is unset) limits exposure to localhost.
> - `scanner.py` uses `verify=False` in 4 `requests.get()` calls (MITM
>   risk for the scanner itself, but necessary because scanned targets
>   may have self-signed certs).
> - 31 broad `except Exception` catches across the codebase hide errors
>   silently (refactor is out of scope for this patch).
> - `socket.gethostbyname()` calls in `reconnaissance.py` have no timeout
>   (potential DoS via slow DNS, low priority).
> - Additional unused imports remain in `app.py` (`json`, `ScanResult`,
>   `User`, `Project`), `scanner.py` (`json`, `re`, `concurrent.futures`),
>   `report_generator.py` (8 imports), and 4 unused `e` vars in
>   `ai_assistant.py`. They are not security-relevant and are deferred.
>
> Security reports are still welcome and will be triaged.

## Supported Versions

| Version | Supported          | Notes                                          |
|---------|--------------------|------------------------------------------------|
| `main`  | Security fixes only| Pre-archive; receives the final critical patch |
| `<1.0`  | Unsupported        | No tagged releases exist                       |

There are no tagged releases. All reports should reference a git commit
hash.

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security reports.**

Email the maintainer privately at **frangelrcbarrera@gmail.com** with
the subject `Network-Scanner security report`. Please include:

1. Description of the issue and its impact.
2. Reproduction steps (request payload, environment, expected vs actual
   behavior).
3. Affected version (git commit hash).
4. Suggested fix (optional but appreciated).

You should receive an acknowledgement within **7 days**. If confirmed,
a fix will be prepared and a coordinated disclosure date agreed. You
will be credited in the commit message unless you request otherwise.

## Response Timeline

- **Day 0**: Private report received.
- **Day 1–7**: Maintainer acknowledges and triages.
- **Day 7–30**: Fix developed. Critical issues (RCE, command injection)
  are expedited; lower-severity issues may run to the full window.
- **Day 30 (or earlier for critical)**: Fix committed. Public disclosure
  coordinated with the reporter.
- **Post-fix**: Repository is archived once the final critical patch
  (`debug=True`) lands.

The maintainer is an individual working part-time on this project. If
the SLA slips, a status update will be sent rather than silence.

## Scope

**In scope:**

- Bugs in the Flask backend (`backend/app.py`, `backend/modules/`,
  `backend/models/`) that compromise the host running Network-Scanner or
  its users.
- Command injection, SSRF, or path traversal in scan orchestration
  (`scanner.py`, `reconnaissance.py`, `report_generator.py`).
- WebSocket/HTTP CORS misconfigurations enabling CSRF or cross-origin
  abuse (`flask-socketio`, `flask-cors`).
- Dependency conflicts that break authentication or transport security
  (`jwt` vs `pyjwt` in `requirements.txt`).
- Docker misconfigurations that escalate privileges or leak secrets
  (`Dockerfile.backend`, `Dockerfile.frontend`, `docker-compose.yml`).

**Out of scope:**

- "The scanner can scan a host I don't own." Yes — that is its purpose.
  Operators are responsible for authorization (see `README.md`
  disclaimer).
- "nmap returns findings the operator didn't expect." That is nmap's
  behavior, not a bug in this project.
- Reports that the AI assistant (`/api/ai/chat`) follows instructions
  embedded in `context`. The assistant passes user-supplied `context`
  to OpenAI without sanitization; this is a known limitation (see
  below), not a novel finding.

## Safe Harbor

Good-faith security research on this repository is welcomed. The
maintainer will not pursue legal action against researchers who:

- Test only against locally-owned lab instances of Network-Scanner
  (not public deployments, which the maintainer does not operate).
- Avoid degrading service for other users (the project has no shared
  infrastructure).
- Report findings privately per the timeline above before any public
  disclosure.
- Do not exfiltrate, destroy, or tamper with data that is not their own.

Researchers uncertain about scope should email first — a quick
clarification is always preferable to a misstep.

## Legal Framework

This policy operates within:

- **International references**: ISO/IEC 29147 (vulnerability disclosure)
  and ISO/IEC 30111 (vulnerability handling), which the maintainer
  follows as best practice regardless of jurisdiction.
- **USA** — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030.
- **European Union** — Directive 2013/40/EU on attacks against
  information systems.
- **United Kingdom** — Computer Misuse Act 1990 (CMA).
- **Council of Europe** — Convention on Cybercrime (Budapest, 2001).
- The repository's **MIT License**, which disclaims liability and
  defines permitted use of the code.

Researchers operating from any jurisdiction should respect their local
computer-misuse statutes.

## Known Security Considerations

This project is a vulnerability scanner that itself carries known
security debt. Reporting the items below as novel findings is not
useful — they are documented here as part of the pre-archive cleanup.

**Critical (fix in progress before archive):**

- `backend/app.py:253` — `socketio.run(app, ..., debug=True)` exposes
  the Werkzeug debugger on `0.0.0.0:5000`. The debugger allows
  unauthenticated remote code execution via crafted tracebacks. This is
  the trigger for archiving the repository and is being patched to
  `debug=False`.

**High (will not be fixed before archive — documented as accepted
risk):**

- `backend/app.py:19` — `cors_allowed_origins="*"` on the SocketIO
  server allows any origin to open the scan WebSocket, enabling
  cross-site WebSocket hijacking of scan commands.
- `backend/modules/scanner.py` — user-supplied `target` reaches
  `nmap.PortScanner().scan()` without argument sanitization. A payload
  such as `8.8.8.8 -iL /etc/passwd` causes nmap to read arbitrary
  files as input lists (argument injection).
- `backend/modules/scanner.py:150,445,474,502` — `requests(...,
  verify=False)` disables TLS verification on outbound scans, exposing
  the scanner host to MITM.
- `backend/app.py:20` vs `backend/models/scan_results.py:5` — two
  `SQLAlchemy()` instances. `db.create_all()` against the app's
  instance creates no tables because the models are registered on the
  bare instance in `models/`. The persistence layer is inert.
- `backend/modules/reconnaissance.py:100` — `name.endswith(...)` where
  `name` is undefined (should be `domain_name`). Certificate
  transparency parsing raises `NameError`.

**Medium / Lower (accepted risk):**

- `backend/modules/scanner.py` — `_check_default_credentials`,
  `_check_smtp_relay`, and `_check_ssh_config` return canned findings
  without testing the target. Operators should treat these as
  placeholders, not verified results.
- `backend/requirements.txt` — both `jwt==1.3.1` and `pyjwt==2.8.0`
  are declared; both export the `jwt` package and conflict at install
  time. `jwt==1.3.1` is a dead dependency (0 imports in the codebase).
  Authentication code, if ever wired in, would be unreliable.
- `backend/app.py:12` — `SECRET_KEY` guard only fires when
  `FLASK_ENV=production` explicitly; unset or any other value bypasses
  the check and keeps the default `dev-key-change-in-production`.
- `backend/modules/ai_assistant.py` — user-supplied `context` is
  interpolated into the OpenAI prompt without sanitization. Operators
  should assume the assistant is prompt-injectable.
- `Dockerfile.frontend` copies `nginx.conf` that does not exist in the
  repo; `docker-compose.yml` mounts `./nginx/` which is also absent.
  The frontend service cannot build as published.
- `Dockerfile.backend` runs as non-root but `scanner.py` issues
  `nmap -sS` (SYN scan), which requires `CAP_NET_RAW`. The
  `docker-compose.yml` does not grant `--cap-add NET_RAW`, so
  SYN scans fail at runtime even if the container ran as root.
- Hardcoded paths `/workspaces/Network-Scanner/` appear in
  `scripts/install.sh` and `backend/modules/report_generator.py` and
  will break deployments outside the original devcontainer.

**Documentation accuracy:** the `README.md` feature table advertises
multi-user authentication, projects, audit logs, API keys, rate
limiting, learning mode, and a fully functional AI assistant. Of these,
only the AI assistant (OpenAI integration with fallback) is partially
implemented; the rest exist only as SQLAlchemy models without routes.
The README also references `CONTRIBUTING.md`, `backend/requirements-dev.txt`,
`backend/tests/`, and frontend test files — none of which exist in the
repository (35 files tracked via `git ls-files`). The README overstates
the project's capabilities. This is acknowledged here so that
researchers do not file reports of the form "feature X is missing" —
they are missing by current state, not by accident.

## Contact

- Maintainer: Frangel Raúl Crespo Barrera
- Email: **frangelrcbarrera@gmail.com**
- GitHub: [frangelbarrera](https://github.com/frangelbarrera)
