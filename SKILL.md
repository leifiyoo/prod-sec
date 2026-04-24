---
name: prod-sec
description: >
  Active offensive + defensive security auditing skill. Performs full-spectrum
  penetration testing of web applications, APIs, infrastructure, and cloud environments.
  Covers OWASP Top 10, authentication, injection, cryptography, supply chain, and advanced
  attack surfaces. Uses real tools and scripts - not just code review. Trigger for any
  security audit, pentest, vulnerability assessment, or hardening task.
---

# Prod Sec

Use this skill only for systems the user is authorized to test. Establish scope, target URLs,
credentials, rate limits, and excluded actions before testing live systems. Prefer `--safe-mode`
first, then expand only when the user authorizes higher-risk checks.

## Responsible Use Guardrails

- Require explicit authorization and a bounded target scope before active testing.
- Do not test third-party systems, production accounts, or external networks without written permission.
- Keep `--safe-mode` enabled by default; escalate only for approved test windows and test data.
- Do not persist access, evade detection, exfiltrate real data, deploy malware, or bypass legal controls.
- Stop testing if scope is unclear, service health degrades, or a destructive effect is possible.
- Report impact with minimal proof, redacted secrets, and remediation steps.

## Execution Model

1. **Recon**: identify hosts, DNS, ports, technologies, TLS, and exposed services.
2. **Enum**: map routes, forms, APIs, auth flows, headers, CORS, sessions, roles, and data paths.
3. **Attack**: run controlled exploits and manual payloads. Confirm with observable impact.
4. **Post-Exploit**: validate scope-limited impact, chaining, privilege boundaries, and detection.
5. **Report**: score, evidence, remediation, retest status, and coverage matrix.

The agent must actually execute scripts and tools against the target when authorized, not merely
describe what could be done. When in doubt, attempt the exploit in a controlled manner and document
the outcome. Mark any unproven issue as `Unconfirmed`.

## Quick Start

```bash
# Recon
bash scripts/recon/dns_recon.sh TARGET_HOST --safe-mode
bash scripts/recon/subdomain_enum.sh TARGET_HOST --safe-mode
bash scripts/recon/port_scan.sh TARGET_HOST --safe-mode
python3 scripts/recon/tech_fingerprint.py TARGET_URL --safe-mode

# Web attack surface
python3 scripts/web/header_audit.py TARGET_URL --safe-mode
python3 scripts/web/cors_tester.py TARGET_URL --safe-mode
python3 scripts/web/sqli_test.py TARGET_URL --param id --safe-mode
python3 scripts/web/xss_fuzzer.py TARGET_URL --param q --safe-mode
python3 scripts/web/ssrf_probe.py TARGET_URL --param url --safe-mode
python3 scripts/web/lfi_tester.py TARGET_URL --param file --safe-mode
python3 scripts/web/open_redirect_scan.py TARGET_URL --param next --safe-mode
python3 scripts/web/jwt_attack.py TARGET_JWT --safe-mode

# Auth and API
python3 scripts/auth/bruteforce_sim.py TARGET_URL --username test --wordlist passwords.txt --safe-mode
python3 scripts/auth/session_fixation_test.py TARGET_URL --safe-mode
python3 scripts/auth/mfa_bypass_test.py TARGET_URL --safe-mode
python3 scripts/auth/oauth_test.py TARGET_URL --safe-mode
python3 scripts/api/rate_limit_test.py TARGET_URL --safe-mode
python3 scripts/api/graphql_introspection.py TARGET_URL --safe-mode
python3 scripts/api/api_fuzz.py TARGET_URL --safe-mode
python3 scripts/api/webhook_spoof_test.py TARGET_URL --safe-mode

# Infra, crypto, report
bash scripts/infra/tls_audit.sh TARGET_HOST --safe-mode
bash scripts/infra/http_methods_test.sh TARGET_URL --safe-mode
python3 scripts/infra/cloud_enum.py TARGET_HOST --safe-mode
bash scripts/infra/docker_escape_check.sh TARGET_HOST --safe-mode
python3 scripts/crypto/secrets_scanner.py PATH_OR_URL --safe-mode
python3 scripts/report/generate_report.py findings.json --out report
python3 scripts/report/cvss_scorer.py
```

## Decision Tree

- **Recon, scope, chaining, reporting workflow** -> load `references/00-methodology.md` and run `scripts/recon/*`.
- **Authentication, sessions, MFA, OAuth, access control** -> load `references/01-auth-session.md` and run `scripts/auth/*`.
- **SQL/NoSQL/command/LDAP/XML injection, deserialization, RCE** -> load `references/02-injection-attacks.md` and run `scripts/web/sqli_test.py`, `scripts/api/api_fuzz.py`, plus sqlmap when authorized.
- **XSS, CSRF, clickjacking, open redirect, prototype pollution** -> load `references/03-xss-csrf-clickjacking.md` and run `scripts/web/xss_fuzzer.py`, `csrf_poc_gen.py`, `open_redirect_scan.py`.
- **SSRF, XXE, LFI/RFI, traversal** -> load `references/04-ssrf-xxe-lfi-rfi.md` and run `scripts/web/ssrf_probe.py`, `lfi_tester.py`.
- **TLS, certificates, JWT, keys, hashing, secrets** -> load `references/05-crypto-secrets.md` and run `scripts/crypto/*`, `scripts/web/jwt_attack.py`, `scripts/infra/tls_audit.sh`.
- **REST, GraphQL, webhooks, rate limits, API auth** -> load `references/06-api-graphql-rest.md` and run `scripts/api/*`.
- **Infra, DNS, cloud, containers, reverse proxy, email auth** -> load `references/07-infra-cloud-container.md` and run `scripts/infra/*`, `scripts/recon/*`.
- **Database access, encryption, backups, DLP, auditing** -> load `references/08-database-security.md` and run injection/API tests plus DB-specific commands with provided credentials.
- **SAST/DAST/SCA, CI/CD, SBOM, IaC, artifact signing** -> load `references/09-supply-chain-cicd.md` and run `scripts/crypto/secrets_scanner.py` plus local dependency scanners.
- **Logging, SIEM, IDS/IPS, incident response** -> load `references/10-monitoring-detection.md` and perform canary requests while checking logs.
- **IAM, RBAC, SSO, PAM, federation, Zero Trust** -> load `references/11-identity-access.md` and run auth/API role tests.
- **Backups, DDoS posture, ransomware, compliance** -> load `references/12-resilience-compliance.md` and run safe readiness checks only.
- **AI/LLM, mobile, IoT, browser, blockchain, side-channel, PQC** -> load `references/13-advanced-ai-mobile-iot.md` and run focused safe probes.
- **Final report** -> load `references/14-reporting-template.md` and run `scripts/report/generate_report.py`.

## Severity

- **Critical**: unauthenticated RCE, auth bypass to admin, mass data access, secrets enabling takeover, exploitable supply-chain compromise. Usually CVSS >= 9.0.
- **High**: account takeover, stored XSS with privileged impact, SQLi reading sensitive data, SSRF to metadata, broken object-level authorization. Usually CVSS 7.0-8.9.
- **Medium**: reflected XSS requiring interaction, weak TLS fallback, limited info disclosure, missing rate limits with bounded impact. Usually CVSS 4.0-6.9.
- **Low**: hardening gaps, missing non-critical headers, verbose errors without sensitive data. Usually CVSS 0.1-3.9.
- **Info**: observations, tested controls, non-exploitable behavior, and defense-in-depth improvements.

Use CVSS v3.1 as the baseline, then adjust narrative risk for exploit chainability, business impact,
data sensitivity, exposure, and detection gaps. Always include evidence, exact payload, response
indicator, impact, remediation, and retest command.
