---
name: prod-sec
description: >
  Defensive production security review skill for AI agents. Reviews local code,
  configuration, dependencies, secrets, authentication design, data flows, and
  deployment posture. Produces evidence-backed findings and remediation guidance
  without offensive exploitation, target scanning, brute forcing, or unauthorized
  network activity. Trigger for secure code review, security audit, hardening,
  threat modeling, dependency review, secrets review, or GitHub-safe AppSec tasks.
---

# Prod Sec

Use this skill to review code and configuration the user owns or has permission
to assess. Do not run exploit payloads, brute-force attempts, recon against third
parties, or active attacks. Prefer local repository analysis, framework-aware
review, safe dependency checks, and clear remediation.

## Operating Model

1. **Scope**: identify repo path, application type, sensitive areas, deployment model, and excluded files.
2. **Map**: inspect auth, authorization, input handling, data access, secrets, dependencies, CI/CD, and config.
3. **Analyze**: run local audit scripts, read relevant code, trace user-controlled data, and verify framework defaults.
4. **Validate**: confirm findings from source evidence, tests, configs, logs, or safe local checks only.
5. **Report**: rank severity, cite files/lines, explain impact, provide exact fixes, and include retest steps.

Mark findings as `Confirmed` only when source evidence demonstrates the issue.
Mark uncertain issues as `Needs Review`. Do not claim exploitability without proof.

## Quick Start

```bash
# Local code review helpers
python3 scripts/code/static_code_audit.py PATH_TO_REPO --json-out static-findings.json
python3 scripts/code/secrets_audit.py PATH_TO_REPO --json-out secret-findings.json
python3 scripts/code/dependency_audit.py PATH_TO_REPO --json-out dependency-findings.json

# Report helpers
python3 scripts/report/cvss_scorer.py
python3 scripts/report/generate_report.py findings.json --out report
```

## Decision Tree

- **Overall workflow or report structure** -> load `references/00-methodology.md`.
- **Authentication, sessions, MFA, OAuth, access control** -> load `references/01-auth-session.md`.
- **Injection risk in source code** -> load `references/02-injection-attacks.md` and run `scripts/code/static_code_audit.py`.
- **XSS, CSRF, clickjacking controls** -> load `references/03-xss-csrf-clickjacking.md`.
- **SSRF, XXE, file access, path traversal controls** -> load `references/04-ssrf-xxe-lfi-rfi.md`.
- **Crypto, secrets, JWT, certificates** -> load `references/05-crypto-secrets.md` and run `scripts/code/secrets_audit.py`.
- **REST, GraphQL, webhooks, rate limits** -> load `references/06-api-graphql-rest.md`.
- **Infra, cloud, containers, reverse proxy, DNS/email auth** -> load `references/07-infra-cloud-container.md`.
- **Database security** -> load `references/08-database-security.md`.
- **Dependencies, CI/CD, SBOM, IaC, artifact signing** -> load `references/09-supply-chain-cicd.md` and run `scripts/code/dependency_audit.py`.
- **Logging, detection, incident response** -> load `references/10-monitoring-detection.md`.
- **IAM, RBAC, SSO, PAM, federation, Zero Trust** -> load `references/11-identity-access.md`.
- **Backups, resilience, compliance** -> load `references/12-resilience-compliance.md`.
- **AI/LLM, mobile, IoT, browser, blockchain, side-channel, PQC readiness** -> load `references/13-advanced-ai-mobile-iot.md`.
- **Final report** -> load `references/14-reporting-template.md` and run `scripts/report/generate_report.py`.

## Review Rules

- Read the code path that handles each risky behavior before writing a finding.
- Cite exact files and line numbers whenever possible.
- Prefer framework-native fixes over custom security logic.
- Check both server-side enforcement and client-side assumptions.
- Review authorization at object, action, tenant, and workflow boundaries.
- Review secrets in source, history notes, example env files, CI variables, and logs.
- Review dependency manifests and lockfiles; recommend native audit commands.
- Review security-relevant defaults: cookies, CORS, CSP, TLS, headers, rate limits, logging, and error handling.
- Include tests or retest steps that verify the fix without attacking live systems.

## Severity

- **Critical**: source evidence of auth bypass, secret enabling takeover, unsafe deserialization/RCE path, cross-tenant data access, or supply-chain compromise. Usually CVSS >= 9.0.
- **High**: broken object-level authorization, unsafe command/query construction reachable from user input, stored XSS sink, weak session/JWT validation, or exposed privileged config. Usually CVSS 7.0-8.9.
- **Medium**: reflected XSS risk, CSRF-sensitive state change, missing rate limits, weak crypto choice, verbose error leakage, or insecure headers with plausible impact. Usually CVSS 4.0-6.9.
- **Low**: hardening gaps, defense-in-depth improvements, incomplete logging, or low-impact configuration issues. Usually CVSS 0.1-3.9.
- **Info**: tested controls, non-exploitable observations, and documentation improvements.

Use CVSS v3.1 as a baseline, then adjust narrative risk for business impact,
data sensitivity, exposure, tenant boundaries, and detection coverage.
