# PHASE 3: GUARDIAN — Security Review

**Repository:** `OneByJorah/Network-Scanner`
**Date:** 2026-07-05
**Analyst:** J1-PIPELINE GUARDIAN

---

## Security Score: 25/100 — CRITICAL

### Sub-Score Breakdown

| Category | Score | Weight | Weighted |
|----------|-------|--------|----------|
| Auth/AuthZ | 0/100 | 15% | 0.0 |
| HTTPS/TLS | 20/100 | 10% | 2.0 |
| CSP/Headers | 0/100 | 10% | 0.0 |
| Docker Hardening | 30/100 | 10% | 3.0 |
| Least Privilege | 40/100 | 10% | 4.0 |
| Supply Chain | 20/100 | 10% | 2.0 |
| Secrets Management | 20/100 | 10% | 2.0 |
| AppArmor/SELinux | 0/100 | 5% | 0.0 |
| Rate Limiting | 0/100 | 10% | 0.0 |
| Firewall/Network | 30/100 | 5% | 1.5 |
| Input Validation | 50/100 | 5% | 2.5 |

---

## 1. Authentication & Authorization — CRITICAL (0/100)

### CRITICAL: No Authentication on Any Endpoint
All API endpoints (`/api/scan/*`, `/api/vulnerability/*`, `/api/report/*`, `/api/ai/*`) are completely unauthenticated. Anyone who can reach the API can:
- Run arbitrary port scans against any target
- Execute nmap with arbitrary arguments
- Access the AI chat assistant
- Generate reports

### CRITICAL: No Login/Session Endpoints
The `User` model exists but there are no login, register, or session management routes. The `ApiKey` model exists but no key validation middleware.

### CRITICAL: No JWT or Token Validation
`pyjwt` and `jwt` are in requirements.txt but never used. No token-based auth is implemented.

### CRITICAL: No Role-Based Access Control
The `User.role` field (`admin`, `user`, `viewer`) exists in the model but no RBAC middleware enforces it.

---

## 2. HTTPS/TLS — DEGRADED (20/100)

### CRITICAL: TLS Verification Disabled
`backend/modules/scanner.py` uses `verify=False` in 3 places:
- Line 150: `response = requests.get(url, timeout=10, verify=False)` — web vuln scan
- Line 445: `response = requests.get(test_url, timeout=5, verify=False)` — common files check
- Line 474: `response = requests.get(test_url, timeout=5, verify=False)` — XSS check

This disables SSL certificate validation, making the app vulnerable to MITM attacks.

### DEGRADED: No HTTPS in Docker Deployment
The nginx service is configured but has no SSL configuration. No `nginx/ssl/` directory exists. The compose file references `./nginx/ssl` but the directory doesn't exist.

### DEGRADED: No HSTS
No `Strict-Transport-Security` header is configured anywhere.

---

## 3. CSP & Security Headers — CRITICAL (0/100)

### CRITICAL: No Content-Security-Policy
Neither the Flask backend nor the React frontend sets a Content-Security-Policy header. This leaves the application vulnerable to XSS attacks.

### CRITICAL: No Security Headers on Backend
The Flask app does not set any security headers:
- No `X-Content-Type-Options`
- No `X-Frame-Options`
- No `X-XSS-Protection`
- No `Strict-Transport-Security`
- No `Content-Security-Policy`
- No `Referrer-Policy`
- No `Permissions-Policy`

### DEGRADED: No CORS Restrictions on SocketIO
`app.py:19`: `socketio = SocketIO(app, cors_allowed_origins="*")` — allows any origin to establish WebSocket connections.

---

## 4. Docker Hardening — DEGRADED (30/100)

### CRITICAL: Missing nginx.conf — Docker Build Fails
`Dockerfile.frontend:26` references a non-existent `nginx.conf`. The Docker build cannot complete.

### CRITICAL: Missing nginx/ Directory — Compose Fails
`docker-compose.yml` mounts `./nginx/nginx.conf` and `./nginx/ssl` — neither exists.

### DEGRADED: No `.dockerignore`
Docker builds may include unnecessary files (`.git/`, `node_modules/`, etc.), increasing image size and attack surface.

### DEGRADED: Redis Port Exposed
`docker-compose.yml` exposes Redis port 6379 to the host. Redis should only be accessible from the backend container.

### DEGRADED: PostgreSQL Port Exposed
`docker-compose.yml` exposes PostgreSQL port 5432 to the host. Database should only be accessible from the backend container.

### DEGRADED: No Health Checks on Compose Services
Only the Dockerfiles have HEALTHCHECK directives. The compose services don't define health checks.

### DEGRADED: No Resource Limits
No CPU or memory limits are set on any container.

### PASS: Non-root User in Backend
`Dockerfile.backend:35-36` creates and uses a non-root `scanner` user. ✓

---

## 5. Least Privilege — DEGRADED (40/100)

### DEGRADED: nmap Runs with Full Network Access
The backend container runs nmap with `-sS` (SYN scan) which requires raw socket access. This typically requires `CAP_NET_RAW` or root privileges. The Dockerfile creates a non-root user but nmap may not work correctly without additional capabilities.

### DEGRADED: No Capability Dropping
The Dockerfile doesn't drop unnecessary Linux capabilities. The container likely runs with default capabilities.

### PASS: Non-root User
The backend Dockerfile creates a non-root user. ✓

---

## 6. Supply Chain — DEGRADED (20/100)

### DEGRADED: Unpinned openai Dependency
`requirements.txt:11`: `openai>=1.0.0` — unpinned, could pull breaking or vulnerable versions.

### DEGRADED: No Dependabot
No `.github/dependabot.yml` — no automated dependency updates.

### DEGRADED: No SBOM
No Software Bill of Materials is generated or maintained.

### DEGRADED: No Lock File for Python
No `requirements.txt.lock` or `pip freeze` output — Python dependencies are not fully pinned with transitive dependencies.

### PASS: npm package-lock.json
Frontend has `package-lock.json` for reproducible npm installs. ✓

---

## 7. Secrets Management — CRITICAL (20/100)

### CRITICAL: Weak Default SECRET_KEY
`app.py:11`: `app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')`
The default is a well-known string. The production check only triggers if `FLASK_ENV=production` is set AND the default key is used.

### CRITICAL: Hardcoded PostgreSQL Password
`docker-compose.yml:21`: `POSTGRES_PASSWORD: network_scanner_password`
Password is hardcoded in the compose file, visible to anyone with repo access.

### CRITICAL: Hardcoded SECRET_KEY in Compose
`docker-compose.yml:39`: `SECRET_KEY=your-secret-key-change-this`
Another hardcoded secret in the compose file.

### PASS: `.env.example` has empty API key
`OPENAI_API_KEY=` is empty in the example file. ✓

### PASS: `.env` in `.gitignore`
The `.env` file is properly gitignored. ✓

---

## 8. AppArmor/SELinux — CRITICAL (0/100)

### CRITICAL: No AppArmor or SELinux Profiles
No AppArmor profiles or SELinux policies are defined for any container or service.

### CRITICAL: No Seccomp Profiles
No seccomp profiles are configured for any container.

---

## 9. Rate Limiting — CRITICAL (0/100)

### CRITICAL: No Rate Limiting on Any Endpoint
All API endpoints can be called without throttling. A misbehaving client can:
- Launch hundreds of concurrent nmap scans
- Exhaust system resources
- Trigger rate limiting on target systems (causing the scanner to be blocked)

### CRITICAL: No Rate Limiting on WebSocket
The `start_automated_scan` WebSocket event has no rate limiting. A client can open multiple WebSocket connections and launch unlimited scans.

---

## 10. Firewall/Network — DEGRADED (30/100)

### DEGRADED: No Network Segmentation
All services are on the same `network-scanner` bridge network with no isolation between them.

### DEGRADED: No Internal Network for Backend/Database
The database and Redis should be on an internal network not accessible from the frontend or nginx.

### DEGRADED: No iptables Rules
No firewall rules are configured as part of the deployment.

---

## 11. Input Validation — DEGRADED (50/100)

### CRITICAL: Potential nmap Argument Injection
`reconnaissance.py:167`: `self.nm.scan(target, ports, arguments='-sS -sV -O')`
The `target` parameter comes directly from user input via the API. While `python-nmap` may sanitize input, the `arguments` parameter is hardcoded. However, the `port_range` parameter is user-controlled and passed to nmap.

### DEGRADED: No Input Sanitization on Target
The `target` parameter is not validated or sanitized before being passed to nmap, DNS resolver, or WHOIS lookup. An attacker could inject special characters.

### DEGRADED: No Request Size Limits
No limits on request body size. An attacker could send a very large payload to exhaust memory.

### PASS: Basic Type Checking
The code checks for required fields (`if not domain: return error`). ✓

---

## Summary of Security Findings

### CRITICAL (must fix)
1. **`debug=True` enables RCE** — Werkzeug debugger allows arbitrary code execution
2. **No authentication on any endpoint** — Anyone can run scans
3. **TLS verification disabled** — MITM vulnerable (`verify=False`)
4. **No security headers** — No CSP, HSTS, XFO, etc.
5. **Weak default SECRET_KEY** — Well-known default
6. **Hardcoded secrets in docker-compose.yml** — PostgreSQL password, SECRET_KEY
7. **No rate limiting** — Unlimited scan requests
8. **CORS allows all origins on SocketIO** — Any website can connect
9. **Potential nmap argument injection** — User-controlled target passed to nmap

### DEGRADED (should fix)
1. **No HTTPS in deployment** — No SSL certs configured
2. **Redis/PostgreSQL ports exposed** — Should be internal only
3. **No `.dockerignore`** — Bloated build context
4. **No Dependabot** — No automated dependency updates
5. **Unpinned openai** — Could pull breaking changes
6. **No AppArmor/SELinux** — No mandatory access control
7. **No network segmentation** — All services on same network
8. **No input sanitization** — Target parameter not validated
