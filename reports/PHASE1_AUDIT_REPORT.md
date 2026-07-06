# PHASE 1: AUDITOR — Full Audit Report

**Repository:** `OneByJorah/Network-Scanner`
**Date:** 2026-07-05
**Analyst:** J1-PIPELINE AUDITOR

---

## Scoring Breakdown

| Category | Score | Weight | Weighted |
|----------|-------|--------|----------|
| Security | 25/100 | 20% | 5.0 |
| Architecture | 50/100 | 15% | 7.5 |
| Documentation | 30/100 | 15% | 4.5 |
| Testing | 0/100 | 15% | 0.0 |
| Deployment | 40/100 | 10% | 4.0 |
| Automation | 0/100 | 10% | 0.0 |
| GitHub Quality | 15/100 | 10% | 1.5 |
| Branding | 60/100 | 5% | 3.0 |

**Overall Production Score: 25.5/100 — CRITICAL**

---

## 1. Lint & Formatting

### Python (Backend)
- **No linter configuration** — no `.pylintrc`, `.flake8`, `pyproject.toml`, or `setup.cfg` with lint settings
- **No type hints** — all Python files lack type annotations
- **Inconsistent line endings** — `cli/network_scanner_cli.py` uses CRLF (`\r\n`) while all other files use LF
- **Long lines** — several lines exceed 100 chars (e.g., `reconnaissance.py` line 86: `url = f"https://crt.sh/?q=%.{domain}&output=json"`)
- **Unused imports** — `subprocess` imported in `reconnaissance.py` but never used; `concurrent.futures` imported in `scanner.py` but never used
- **Bare except clauses** — `scanner.py` lines 448-449: `except: continue` (catches all exceptions silently)

### JavaScript (Frontend)
- **No ESLint config** — only extends `react-app` defaults
- **No Prettier config**

### Shell
- **No shellcheck** — `scripts/install.sh` has no shellcheck annotations
- **Unquoted variables** — `install.sh` line 79: `sudo ln -sf $(pwd)/network_scanner_cli.py /usr/local/bin/network-scanner-cli` (unquoted)

**Score: 40/100 — DEGRADED**

---

## 2. Dead Code

### CRITICAL: Dual SQLAlchemy instances
- `backend/app.py` line 20: `db = SQLAlchemy(app)` — creates one instance
- `backend/models/scan_results.py` line 5: `db = SQLAlchemy()` — creates a second, unbound instance
- The models in `scan_results.py` are bound to the second instance, but `app.py` calls `db.create_all()` on the first instance
- **Result: `db.create_all()` creates NO tables** — the entire persistence layer is inert

### CRITICAL: Missing nginx.conf
- `Dockerfile.frontend` line 26: `COPY nginx.conf /etc/nginx/conf.d/default.conf` — file does not exist
- `docker-compose.yml` line 70: `- ./nginx/nginx.conf:/etc/nginx/nginx.conf` — directory/file does not exist
- **Result: Docker build fails at the frontend stage**

### CRITICAL: Missing nginx/ directory
- `docker-compose.yml` mounts `./nginx/nginx.conf` and `./nginx/ssl` — neither exists
- **Result: `docker-compose up` fails with mount errors**

### DEGRADED: Hardcoded paths
- `backend/modules/report_generator.py` lines 65, 69: `/workspaces/Network-Scanner/reports` — devcontainer-specific
- `scripts/install.sh` lines 63, 71, 76, 83, 84, 87, 89, 106, 107, 129: `/workspaces/Network-Scanner/` — devcontainer-specific
- **Result: Scripts fail outside devcontainer environment**

### DEGRADED: Unused dependencies in requirements.txt
- `bcrypt==4.0.1` — no bcrypt usage in code (uses `hashlib`? No password hashing at all)
- `jwt==1.3.1` — no JWT encoding/decoding in code
- `pyjwt==2.8.0` — no JWT usage in code
- `celery==5.3.4` — no Celery tasks defined
- `redis==5.0.1` — no Redis usage in code (Redis client is configured but never used)
- `pandas==2.1.3` — no pandas usage in code
- `matplotlib==3.8.2` — imported in `report_generator.py` but never actually called to create charts
- `seaborn==0.13.0` — imported in `report_generator.py` but never actually called

### DEGRADED: Unused imports
- `reconnaissance.py` line 1: `import subprocess` — never used
- `scanner.py` line 10: `import concurrent.futures` — never used
- `scanner.py` line 5: `import subprocess` — never used

**Score: 30/100 — CRITICAL**

---

## 3. Dependency Review

### requirements.txt (backend)
| Package | Version | Status |
|---------|---------|--------|
| flask | 2.3.3 | Pinned ✓ |
| flask-cors | 4.0.0 | Pinned ✓ |
| flask-socketio | 5.3.6 | Pinned ✓ |
| python-socketio | 5.9.0 | Pinned ✓ |
| requests | 2.31.0 | Pinned ✓ |
| python-nmap | 0.7.1 | Pinned ✓ |
| dnspython | 2.4.2 | Pinned ✓ |
| whois | 0.9.27 | Pinned ✓ |
| reportlab | 4.0.4 | Pinned ✓ |
| jinja2 | 3.1.2 | Pinned ✓ |
| openai | >=1.0.0 | **Unpinned** — DEGRADED |
| python-dotenv | 1.0.0 | Pinned ✓ |
| sqlalchemy | 2.0.23 | Pinned ✓ |
| flask-sqlalchemy | 3.1.1 | Pinned ✓ |
| bcrypt | 4.0.1 | **Dead dependency** |
| jwt | 1.3.1 | **Dead dependency** |
| pyjwt | 2.8.0 | **Dead dependency** |
| celery | 5.3.4 | **Dead dependency** |
| redis | 5.0.1 | **Dead dependency** |
| pandas | 2.1.3 | **Dead dependency** |
| matplotlib | 3.8.2 | **Dead dependency** |
| seaborn | 0.13.0 | **Dead dependency** |

### cli/requirements.txt
| Package | Version | Status |
|---------|---------|--------|
| requests | 2.31.0 | Pinned ✓ |
| colorama | 0.4.6 | Pinned ✓ |

### package.json (frontend)
- 28 dependencies, all version-pinned with `^` or exact
- No known critical CVEs in the pinned versions (as of audit date)
- `react-scripts` 5.0.1 is known to have moderate-severity issues in its transitive dependencies

### CVE Scan
- No automated CVE scan performed (no tooling available on audit host)
- Manual review: No known critical CVEs in pinned versions of Flask 2.3.3, requests 2.31.0, or other core deps
- `openai>=1.0.0` unpinned — could pull a breaking change

**Score: 50/100 — DEGRADED**

---

## 4. Secrets Detection

### CRITICAL: `debug=True` in production
- `backend/app.py` line 253: `socketio.run(app, host='0.0.0.0', port=5000, debug=True)`
- Flask debug mode enables the Werkzeug debugger, which allows **remote code execution**
- This is the critical fix documented in SECURITY.md that will trigger archiving

### CRITICAL: Weak default SECRET_KEY
- `backend/app.py` line 11: `app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')`
- The default value is a weak, well-known string
- The production check on line 12-13 only raises an error if `FLASK_ENV=production` AND the default key is used — but `FLASK_ENV` is not set to `production` by default in `.env.example`

### CRITICAL: CORS allows all origins
- `backend/app.py` line 19: `socketio = SocketIO(app, cors_allowed_origins="*")`
- SocketIO allows all origins regardless of the CORS_ORIGINS env var

### DEGRADED: TLS verification disabled
- `backend/modules/scanner.py` lines 150, 445, 474: `verify=False` in requests.get() calls
- Disables SSL certificate validation for all outbound HTTP requests

### DEGRADED: Hardcoded database password
- `docker-compose.yml` line 21: `POSTGRES_PASSWORD: network_scanner_password`
- Password is hardcoded in the compose file, not using an env var

### Secrets present in codebase
- No actual secrets (API keys, tokens) found in source code
- `.env.example` has empty `OPENAI_API_KEY=` — good practice

**Score: 20/100 — CRITICAL**

---

## 5. README Compliance

### What's present
- Project title and description ✓
- Feature table ✓
- Quick Start with prerequisites and installation ✓
- Configuration section ✓
- Running instructions ✓
- Usage examples (web, CLI, API) ✓
- Architecture section with tree ✓
- Scan types documentation ✓
- AI features section ✓
- Reporting section ✓
- Security considerations ✓
- Contributing section (links to CONTRIBUTING.md) ✓
- Support section ✓
- Acknowledgments ✓
- Disclaimer ✓

### What's missing or wrong
- **CRITICAL: References non-existent files** — `CONTRIBUTING.md` was deleted (commit `fb384e0`), `backend/requirements-dev.txt` doesn't exist, `backend/tests/` doesn't exist
- **CRITICAL: Overstates capabilities** — "Multi-user" features (auth, projects, audit logs, API keys, rate limiting) are modeled but not wired; the SECURITY.md acknowledges this
- **DEGRADED: References upstream repo** — All links point to `frangelbarrera/Network-Scanner` instead of `OneByJorah/Network-Scanner`
- **DEGRADED: No badges for CI/CD** — Badges show Python 3.8+ and React 18+ but no build status, test coverage, or security audit badges
- **DEGRADED: No license badge** — MIT License exists but no badge in README
- **DEGRADED: No table of contents** — README is long (267 lines) with no navigation

**Score: 40/100 — DEGRADED**

---

## 6. Tests

### CRITICAL: No tests exist
- `backend/tests/` — directory does not exist (referenced in README)
- No `test_*.py` files anywhere in the repo
- No `__tests__/` directory in frontend
- No `pytest.ini`, `setup.cfg`, or `pyproject.toml` with test configuration
- README references `pytest backend/tests/` and `npm test --prefix frontend` — neither works

**Score: 0/100 — CRITICAL**

---

## 7. Docker

### Dockerfile.backend
- Uses `python:3.9-slim` — reasonable base image ✓
- Creates non-root user `scanner` ✓
- Has HEALTHCHECK ✓
- Installs nmap, dnsutils, whois ✓
- **DEGRADED: No `.dockerignore`** — may copy unnecessary files into build context

### Dockerfile.frontend
- **CRITICAL: References non-existent `nginx.conf`** — line 26: `COPY nginx.conf /etc/nginx/conf.d/default.conf`
- Multi-stage build (Node 18 → nginx:alpine) ✓
- Has HEALTHCHECK ✓
- Uses `npm ci --only=production` — good for reproducible builds ✓

### docker-compose.yml
- **CRITICAL: Mounts non-existent `./nginx/` directory** — lines 70-71
- **CRITICAL: Hardcoded PostgreSQL password** — line 21
- **DEGRADED: Exposes Redis port 6379** — should not be exposed externally
- **DEGRADED: Exposes PostgreSQL port 5432** — should not be exposed externally
- **DEGRADED: No health checks on services** — only Dockerfiles have HEALTHCHECK, compose services don't
- **DEGRADED: No restart policy on nginx** — missing `restart: unless-stopped`
- **DEGRADED: No network restrictions** — all services on same bridge network with no isolation
- **DEGRADED: Backend uses `SECRET_KEY=your-secret-key-change-this`** — weak default in compose

**Score: 30/100 — CRITICAL**

---

## 8. Folder Structure

```
Network-Scanner/
├── backend/                    # ✓ Well-organized
│   ├── app.py                  # Main entry point
│   ├── requirements.txt        # Dependencies
│   ├── models/
│   │   └── scan_results.py     # SQLAlchemy models
│   └── modules/
│       ├── reconnaissance.py   # Network recon
│       ├── scanner.py          # Vuln scanning
│       ├── ai_assistant.py     # AI integration
│       └── report_generator.py # Report generation
├── frontend/                   # ✓ Well-organized
│   ├── package.json
│   ├── public/
│   │   └── index.html
│   └── src/
│       ├── App.js
│       ├── index.js
│       ├── index.css
│       ├── context/
│       ├── services/
│       └── components/         # 9 components
├── cli/                        # ✓ Clean
│   ├── network_scanner_cli.py
│   └── requirements.txt
├── scripts/
│   └── install.sh
├── docs/
│   └── readme.md               # Placeholder (3 lines)
├── reports/
│   └── readme.md               # Placeholder (3 lines)
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.frontend
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── INTENT.md
└── SECURITY.md
```

### Issues
- **DEGRADED: Empty docs/** — `docs/readme.md` is a 3-line placeholder
- **DEGRADED: Empty reports/** — `reports/readme.md` is a 3-line placeholder
- **DEGRADED: No `.github/` directory** — no CI/CD, issue templates, PR templates, Dependabot
- **DEGRADED: No `.dockerignore`** — Docker builds may include unnecessary files
- **DEGRADED: No `logs/` directory** — referenced in docker-compose.yml but doesn't exist

**Score: 50/100 — DEGRADED**

---

## 9. Git History

```
6256741 Create SECURITY.md
800d96b update
80755cd Create LICENSE
f2a7c03 update
455e795 Actualizar README.md
c6d4243 Actualizar README.md
fb384e0 Delete CONTRIBUTING.md
2fcda27 Add files via upload
```

- 8 commits total
- No tagged releases (v0.0.0 state)
- No CI/CD workflows
- No Dependabot configuration
- No branch protection
- Initial commit is a bulk upload — no incremental development history
- OneByJorah fork has 1 commit beyond upstream (SECURITY.md creation)

**Score: 15/100 — CRITICAL**

---

## Summary of Findings

### CRITICAL Items (must fix)
1. **`debug=True` in production** — RCE via Werkzeug debugger (`app.py:253`)
2. **Dual SQLAlchemy instances** — persistence layer is completely inert (`app.py:20` vs `scan_results.py:5`)
3. **Missing `nginx.conf`** — Docker build fails (`Dockerfile.frontend:26`)
4. **Missing `nginx/` directory** — `docker-compose up` fails (compose lines 70-71)
5. **No tests** — zero test coverage across entire codebase
6. **Weak default SECRET_KEY** — `'dev-key-change-in-production'` (`app.py:11`)
7. **CORS allows all origins on SocketIO** — `cors_allowed_origins="*"` (`app.py:19`)
8. **README references non-existent files** — CONTRIBUTING.md, requirements-dev.txt, tests/

### DEGRADED Items (should fix)
1. **Hardcoded paths** — `/workspaces/Network-Scanner/` in 2 files
2. **8 dead dependencies** — bcrypt, jwt, pyjwt, celery, redis, pandas, matplotlib, seaborn
3. **Unpinned `openai`** — `>=1.0.0` could pull breaking changes
4. **TLS verification disabled** — `verify=False` in 3 places
5. **Hardcoded PostgreSQL password** — in docker-compose.yml
6. **Redis and PostgreSQL ports exposed** — should be internal only
7. **No `.dockerignore`** — bloated build context
8. **No `.github/` directory** — no CI/CD, templates, or Dependabot
9. **Empty docs/ and reports/** — placeholder files only
10. **README links point to upstream** — should point to OneByJorah fork
11. **Unused imports** — subprocess, concurrent.futures
12. **Bare except clauses** — silent error swallowing
13. **CRLF line endings** — in CLI file
14. **No health checks on compose services** — only in Dockerfiles
