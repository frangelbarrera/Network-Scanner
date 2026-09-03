# Security Policy

## Network-Scanner

Network-Scanner is an open-source toolkit for authorized network reconnaissance and security assessment. This policy covers the Flask backend, React frontend, Python CLI, Docker configuration and report-generation components.

## Supported versions

| Version | Support |
|---|---|
| `main` | Active development and security fixes |
| Untagged historical commits | Best effort only |

There are currently no tagged releases. Please include the commit hash in any report.

## Reporting a vulnerability

Please do not publish sensitive vulnerability details in a public issue. Send reports privately to **frangelrcbarrera@gmail.com** with:

1. A concise description and impact.
2. A minimal reproduction against a locally owned instance.
3. The affected component and commit hash.
4. Suggested remediation, if available.

Good-faith reports will be acknowledged and triaged. Researchers will be credited unless they request anonymity.

## Deployment and operational security

This project is under active development and should be evaluated in a controlled environment before operational use. Port and vulnerability workflows use Nmap SYN/OS detection and may require root or `CAP_NET_RAW`; the Compose backend grants `NET_RAW`. Operators should:

- scan only owned or explicitly authorized targets;
- use unique, non-default values for `SECRET_KEY`, `API_ACCESS_TOKEN` and other secrets;
- run production mode with the API token configured;
- keep the backend, data stores and administrative services on trusted networks;
- place externally hosted instances behind authentication, TLS and appropriate network controls;
- treat automated findings as assessment leads that require manual validation; and
- note that selected web checks currently use disabled TLS certificate verification to support self-signed targets; this can permit man-in-the-middle interference with scanner traffic and is inappropriate where certificate validation is required; and
- understand that when `OPENAI_API_KEY` is configured, submitted messages, context and scan results are sent to OpenAI. Do not send personal, confidential or third-party data without appropriate authority and review of applicable terms, retention and compliance obligations.

The repository does not claim that every assessment check is a verified vulnerability proof, nor that the default development workflow is suitable for direct Internet exposure. AI-assisted analysis can be influenced by untrusted context and is advisory rather than a verified security decision. The current Compose PostgreSQL profile only starts PostgreSQL and is not automatically wired to the backend, which uses SQLite by default; the published image does not include a PostgreSQL driver, so operators must provide and test the dependency, URL and persistence configuration if they choose to use PostgreSQL.

## Scope

In scope are vulnerabilities in the project code or deployment configuration that could cause unauthorized access, command injection, SSRF, path traversal, cross-origin abuse, secret exposure, unsafe report generation or compromise of an operator-controlled instance.

Testing should be limited to a local or otherwise authorized instance. Do not scan third-party systems, access data that is not yours, or degrade availability while validating a report.

## Safe harbor

Good-faith research performed against a locally owned instance, with minimal-impact validation and private disclosure, is welcomed. This policy does not authorize testing of third-party infrastructure or override applicable law.
