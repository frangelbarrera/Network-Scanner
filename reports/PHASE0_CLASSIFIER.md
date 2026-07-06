# PHASE 0: CLASSIFIER — Project Classification

**Repository:** `OneByJorah/Network-Scanner`
**Date:** 2026-07-05
**Analyst:** J1-PIPELINE CLASSIFIER

---

## Classification

**Primary Class:** `Security`
**Secondary Classes:** `Python`, `Web`, `Docker`, `AI`, `LLM`, `CLI`, `Networking`

---

## Classification Evidence

| Class | Evidence |
|-------|----------|
| **Security** | Vulnerability assessment & penetration testing platform; nmap integration; web app security checks (XSS, info disclosure, security headers); network service checks (default creds, anonymous FTP, SMTP relay, SSL/TLS) |
| **Python** | Flask backend (app.py), 4 Python modules, CLI tool, SQLAlchemy models |
| **Web** | React 18 SPA frontend with MUI, Recharts; RESTful API endpoints; WebSocket-based real-time updates |
| **Docker** | docker-compose.yml (5 services), Dockerfile.backend, Dockerfile.frontend |
| **AI** | OpenAI GPT-3.5-turbo integration for scan analysis, risk assessment, remediation guidance |
| **LLM** | OpenAI API integration with rule-based fallback when no API key configured |
| **CLI** | Full-featured CLI (network_scanner_cli.py) with argparse, colored output, all scan types |
| **Networking** | nmap port scanning, DNS enumeration (dnspython), WHOIS lookups, subdomain enumeration, Certificate Transparency log search |

---

## j1.yaml

```yaml
repo: Network-Scanner
class: Security
org: OneByJorah
owner: Jhonattan L. Jimenez
license: MIT
production_score: 0
last_audit: 2026-07-05
last_publish: null
standards_version: "2.1"
dependencies: []
deploy_target: scratch
tailscale_only: false
public_facing: false
community_sla_hours: null
adoption_tracked: false
```

---

## Notes

- This is a **fork** of `frangelbarrera/Network-Scanner` into the `OneByJorah` org
- SECURITY.md explicitly states the project is in **maintenance mode** and will be archived after a critical fix
- The repo has 8 commits total, no tagged releases, no CI/CD
- Multi-class repo: Security is primary, but Python, Web, Docker, AI, LLM, CLI, and Networking all apply
- The Docker class gates Docker hardening checklists in later phases
- The AI/LLM class gates Phase 11 AI REVIEW if the pipeline continues that far
