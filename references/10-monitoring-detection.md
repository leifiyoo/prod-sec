# Monitoring, Detection, and Incident Response

## What to Check
Test logging quality, SIEM coverage, IDS/IPS/WAF visibility, threat detection, incident response readiness, alert routing, forensic retention, tamper resistance, and secure logging without sensitive data exposure.

## How to Test (Active)
1. Send benign canary probes with unique IDs:
   `curl -isk -H 'X-ProdSec-Canary: ps-001' 'https://target/%3Cscript%3Eprodsec%3C/script%3E'`
2. Run representative scripts with `--safe-mode` and record timestamps.
3. Ask defenders or inspect authorized logs for request ID, account, IP, route, payload class, status, WAF decision, and alert.
4. Test auth events: failed login burst, password reset request, MFA failure, role change, export, and API token creation.
5. Verify incident playbooks, owner contacts, escalation paths, and evidence preservation.

## What Good Looks Like (Pass Criteria)
Security events are captured with useful context, alerts are routed, sensitive fields are redacted, logs are immutable and time-synchronized, detections cover common attack classes, and incident responders can trace test activity quickly.

## What Bad Looks Like (Fail Criteria)
No logs for exploit attempts, only 200/500 summaries, tokens or passwords in logs, no alert for obvious attack strings, missing request IDs, no centralized logging, logs writable by app role, insufficient retention, and no tested incident workflow.

## Exploitation Proof of Concept
Run a canary XSS request and a failed login burst in safe mode. A control fails if the application owner cannot locate the events by timestamp, source, route, and marker within the agreed response window.

## Edge Cases & Hidden Traps
Async jobs, webhook receivers, GraphQL resolvers, websocket messages, CDN/WAF edge logs, mobile APIs, admin actions, support impersonation, and data exports often bypass primary logging. Logging raw payloads can create stored XSS in SIEM dashboards or leak secrets.

## Remediation
Define security event taxonomy, add structured logging with request IDs, redact secrets, centralize immutable logs, enable WAF/IDS telemetry, alert on high-signal events, test runbooks quarterly, and add detections for every confirmed exploit class.

## References
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- NIST Incident Handling SP 800-61: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- MITRE D3FEND: https://d3fend.mitre.org/
- CWE-532 Sensitive Information in Log Files: https://cwe.mitre.org/data/definitions/532.html
