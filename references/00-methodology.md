# Methodology

## What to Check
Confirm scope, authorization, target ownership, excluded actions, credentials, rate limits, business-critical paths, data classification, and logging contacts. Map the full attack surface from DNS through application workflows, APIs, cloud assets, CI/CD, identity, database paths, monitoring, and resilience controls.

## How to Test (Active)
1. Record scope and start with non-invasive probes:
   `bash scripts/recon/dns_recon.sh example.com --safe-mode`
   `bash scripts/recon/subdomain_enum.sh example.com --safe-mode`
   `bash scripts/recon/port_scan.sh example.com --safe-mode`
   `python3 scripts/recon/tech_fingerprint.py https://example.com --safe-mode`
2. Build a target map from observed links, forms, headers, API docs, robots.txt, sitemap.xml, GraphQL endpoints, and JavaScript bundles.
3. Execute domain-specific scripts for each discovered surface, beginning in safe mode.
4. For every suspected vulnerability, attempt a minimal exploit that proves impact without damaging data.
5. Chain findings: weak CORS plus token storage, open redirect plus OAuth, SSRF plus metadata access, IDOR plus predictable IDs, stored XSS plus admin session.
6. Run canary requests and confirm whether application, WAF, SIEM, and incident processes detect them.

## What Good Looks Like (Pass Criteria)
All tests are scoped, rate-limited, logged, reproducible, and tied to a control. Sensitive actions require authorization and proof uses harmless markers. Defensive telemetry captures suspicious probes with useful user, IP, route, request ID, and outcome fields.

## What Bad Looks Like (Fail Criteria)
Unknown exposed services, unowned subdomains, permissive cloud resources, unauthenticated admin panels, silent exploit attempts, missing audit logs, test accounts with excessive privileges, undocumented trust boundaries, and findings that only exist as theory without observed evidence.

## Exploitation Proof of Concept
Use a controlled proof pattern:
```bash
curl -sk -H 'X-ProdSec-Canary: audit-001' 'https://target/path?input=prodsec-canary'
```
Then prove impact with a bounded read, role transition, state change in a test object, alert event, or reflected/stored marker. If the exploit cannot be safely attempted, document `Unconfirmed` and the exact blocker.

## Edge Cases & Hidden Traps
Second-order payloads may trigger in admin exports, notifications, PDFs, or background jobs. Race conditions require concurrent requests and state verification. Caching layers may leak personalized responses. Business logic bypass often appears in skipped workflow steps, negative quantities, coupon stacking, refund loops, or stale authorization decisions. Chained low-severity issues can become critical when combined.

## Remediation
Define asset ownership, scope inventory, test credentials, safe testing windows, rate limits, emergency stop contacts, and logging expectations. Require every finding to include exploit evidence, impact, fix owner, exact remediation, retest command, and residual risk.

## References
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- MITRE ATT&CK: https://attack.mitre.org/
- CWE Top 25: https://cwe.mitre.org/top25/
