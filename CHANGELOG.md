# Changelog

Notable changes to Network Scanner are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
before the hardening batches are summarized under their original scope.

## [Unreleased]

### Fixed

- hostile `Authorization` header values (non-ASCII bearer tokens) and
  non-string WebSocket auth payloads no longer crash the token comparison
  with a server error that never consumed rate-limit quota
- report downloads only serve generated `security_report_*` files; operator
  notes kept in the reports directory are no longer downloadable
- URL-shaped targets (`https://example.com`) are handed to Nmap as the bare
  hostname, so vulnerability and port scans no longer abort before the web
  checks can run (schemes are matched case-insensitively per RFC 3986); URL
  targets whose hostname would start with an option prefix are refused,
  keeping option injection out of Nmap's argv once the scheme is stripped,
  and malformed IPv6 URL targets are rejected as invalid input
- every Nmap run is bounded (`--host-timeout` plus a process timeout), so a
  wedged scan can no longer pin a request thread or a scan slot forever
- timed-out WHOIS lookups no longer leak a joinable worker thread per call;
  the bounded wait now runs on a daemon thread
- AI analysis prompts cap the scan data they carry: oversized payloads were
  rejected by the model on context length and silently degraded to the
  fallback analysis
- fallback analyses are labeled per component in the comprehensive
  aggregate, in the CLI output and in the web UI instead of masquerading as
  model analysis
- the CLI prints the DNS record map instead of the API wrapper's keys (the
  previous output listed letters of the domain and the wrapper's field
  names as if they were records)
- `python app.py` serves directly outside debug mode again; flask-socketio
  5.5.1 refused the Werkzeug dev server without an explicit operator
  acknowledgment

### Changed

- upgraded pinned dependencies past published advisories: flask 3.1.3,
  flask-cors 6.0.0, requests 2.33.0, dnspython 2.6.1, python-dotenv 1.2.2
  and gunicorn 23.0.0 (request smuggling, CVE-2024-6827)
- flask-socketio moves to 5.6.1 alongside the flask 3.1 stack: 5.5.1 cannot
  serve the request session its event dispatcher needs
- the CLI's requests pin moves with the backend's so the combined CI install
  still resolves

## [2026-09-14]

### Security

- hardened API request handling: hashed rate-limit keys, opt-in proxy
  header trust, request size caps mapped to 413, generic 500 responses,
  bounded automated-scan concurrency and a bounded OpenAI client
- wrapped scan data in untrusted-data delimiters with a system instruction
  so scanned banners cannot steer the analysis prompts
- closed known dependency advisories of that date (gunicorn, jinja2,
  flask-cors, python-socketio, requests) and dropped unused runtime
  packages
- overrode vulnerable transitive frontend dependencies without leaving the
  Create React App toolchain

### Added

- automated CI (backend, CLI and frontend suites on Python 3.10/3.12 and
  Node 20) and a weekly Dependabot schedule
- regression suites covering validation, limiter, OpenAI and reliability
  contracts

### Migration notes (from deployments older than 2026-09-14)

- `FLASK_ENV=production` refuses placeholder `SECRET_KEY` values and any
  `SECRET_KEY` shorter than 32 characters, and placeholder
  `API_ACCESS_TOKEN` values: generation fails fast at startup instead of
  silently running with insecure defaults. Set both to unique random
  values before upgrading.
- rate-limit storage moves from `REDIS_URL` to `RATELIMIT_STORAGE_URI`
  (`memory://` by default; point it at Redis to share limits across
  workers). `REDIS_URL` was never read by the application.
- empty-string environment values are treated as unset for optional
  settings (`SCAN_CONCURRENCY`, `OPENAI_MODEL`, rate-limit overrides),
  matching how Docker Compose passes them.
- the sqlite database moved to the persistent Docker volume, so container
  recreation no longer loses it.
- the frontend build requires Node 20 or newer and the backend requires
  Python 3.10 or newer, matching the pinned dependencies, the Docker
  images and CI.
