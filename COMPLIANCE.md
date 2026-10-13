# IEC 62443-3-3 — Informative Scope Notes

**Status:** Informative code-level notes only. This is not a compliance claim, conformity assessment, certification, or security-level assessment.

## Scope

Network Scanner is a general-purpose network reconnaissance and security-assessment application. Its scans are active; it is not a passive OT monitoring platform. This note describes a few application safeguards that may be relevant to an engineering discussion. It does not claim that the application or any target IACS meets IEC 62443-3-3.

No target security level (SL-T) is assigned. A security level cannot be inferred from isolated scanner features or from the presence of a documentation file.

## Related application controls

| Area | Repository evidence | Limit of this note |
|---|---|---|
| API access gate (related to FR 1 / FR 2 concepts) | Optional bearer-token enforcement: `backend/app.py:61-63`, `:160-174`. | A shared API token is not individual human identity, device identity, or full role-based authorization. It is not evidence that an IEC SR is satisfied. |
| Input handling (related to FR 3 concepts) | Target parsing and rejection of malformed/option-like inputs: `backend/app.py:179-205`; port-range validation begins at `:208`. | These are application input checks, not a complete system-integrity assessment or proof of parser correctness for an IACS. |
| Local request/resource guardrails (related to FR 7 concepts) | Request-size cap and scan concurrency cap: `backend/app.py:46-48`, `:67-68`; endpoint limits: `:232-235`; Nmap process timeout: `backend/modules/scanner.py:127-145`. | These controls are partial, deployment-dependent safeguards. They do not establish DoS resistance, availability targets, or protection of an industrial control system. |
| Restricted data flow, continuous monitoring, and audit events (FR 5–6) | No IEC 62443-3-3 implementation claim is made here. | Active scans and generated reports are not network segmentation, zone-boundary enforcement, or a continuous OT monitoring/audit pipeline. |

## Explicit limitations

- This project is not a passive Modbus/S7/DNP3 asset monitor and does not implement zone or conduit enforcement.
- API authentication is optional outside production configuration and uses a shared bearer token rather than per-user identities (`backend/app.py:61-63`, `:160-174`).
- Active scanning can affect targets and must be limited to systems the operator is authorized to assess (see the README security considerations and safe-target policy).
- The note does not assess the deployment, network architecture, target assets, operational procedures, or a complete system under consideration.

## Interpretation

The listed safeguards describe parts of this application only. They must not be presented as IEC 62443-3-3 compliance, certification, or achievement of any SL-T. No such status is claimed.
