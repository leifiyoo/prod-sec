# prod-sec

`prod-sec` is a Codex skill for authorized, production-grade security auditing of web applications, APIs, infrastructure, cloud-adjacent surfaces, and development pipelines. It gives an AI agent a structured penetration-testing workflow with runnable probes, reference playbooks, and report generation.

This is not a passive checklist. The skill guides the agent through controlled recon, enumeration, exploit validation, impact assessment, and remediation reporting.

## GitHub Repository Metadata

- **Repository name:** `prod-sec`
- **Display name:** ProdSec - Authorized Security Auditing Skill
- **Short description:** Authorized active security auditing skill for Codex agents.
- **GitHub description:** Active offensive and defensive security auditing skill for authorized web, API, infrastructure, cloud, and supply-chain assessments.
- **Suggested topics:** `codex-skill`, `security-audit`, `penetration-testing`, `web-security`, `api-security`, `owasp`, `red-team`, `blue-team`, `devsecops`, `vulnerability-assessment`

## Responsible Use

Use this skill only on systems you own or are explicitly authorized to assess. The included tools are designed for bounded validation, not unauthorized access.

The skill intentionally defaults to `--safe-mode` where active probes could be noisy or risky. Higher-risk testing should be done only inside an approved scope, with test accounts, rate limits, an agreed test window, and a rollback/contact plan.

Do not use this repository to attack third-party systems, bypass access controls, persist access, exfiltrate real data, evade monitoring, deploy malware, or perform destructive testing.

## What It Finds

- Web application issues: SQL injection indicators, reflected XSS, CSRF exposure, CORS mistakes, missing security headers, open redirects, SSRF, LFI/path traversal, JWT weaknesses.
- Authentication and identity issues: weak session handling, MFA enforcement gaps, OAuth/OIDC misconfiguration, rate-limit gaps, role/tenant authorization probes.
- API issues: GraphQL introspection, webhook spoofing/replay, schema validation gaps, abuse-prevention weaknesses.
- Infrastructure and crypto issues: TLS/certificate weaknesses, exposed HTTP methods, cloud storage exposure signals, container management exposure, weak password hashes, leaked secrets.
- Program-level issues: supply chain, CI/CD, database security, monitoring, resilience, compliance, and advanced AI/mobile/IoT/browser risks through progressive reference guides.

## Repository Layout

```text
prod-sec/
|-- SKILL.md
|-- references/
|   |-- 00-methodology.md
|   |-- 01-auth-session.md
|   |-- 02-injection-attacks.md
|   |-- 03-xss-csrf-clickjacking.md
|   |-- 04-ssrf-xxe-lfi-rfi.md
|   |-- 05-crypto-secrets.md
|   |-- 06-api-graphql-rest.md
|   |-- 07-infra-cloud-container.md
|   |-- 08-database-security.md
|   |-- 09-supply-chain-cicd.md
|   |-- 10-monitoring-detection.md
|   |-- 11-identity-access.md
|   |-- 12-resilience-compliance.md
|   |-- 13-advanced-ai-mobile-iot.md
|   `-- 14-reporting-template.md
`-- scripts/
    |-- api/
    |-- auth/
    |-- crypto/
    |-- infra/
    |-- recon/
    |-- report/
    `-- web/
```

## Quick Start

Run probes only against authorized targets.

```bash
# Recon
bash scripts/recon/dns_recon.sh example.com --safe-mode
bash scripts/recon/port_scan.sh example.com --safe-mode
python3 scripts/recon/tech_fingerprint.py https://example.com --safe-mode

# Web/API checks
python3 scripts/web/header_audit.py https://example.com --safe-mode
python3 scripts/web/cors_tester.py https://example.com/api/session --safe-mode
python3 scripts/api/rate_limit_test.py https://example.com/api/session --safe-mode
python3 scripts/web/open_redirect_scan.py 'https://example.com/login?next=/dashboard' --param next --safe-mode

# Reporting
python3 scripts/report/cvss_scorer.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
python3 scripts/report/generate_report.py findings.json --out report
```

## Using As A Codex Skill

Place this folder where Codex can discover skills, then trigger it with requests like:

```text
Use prod-sec to audit my local app at http://localhost:5173 and API at http://localhost:3001.
Use prod-sec to perform an authorized security assessment of staging.example.com in safe mode.
Use prod-sec to generate a security report from these JSON findings.
```

The entry point is `SKILL.md`. Detailed attack guidance is loaded progressively from `references/` only when relevant.

## Safety Model

The skill is designed to reduce accidental misuse:

- `--safe-mode` exists on active scripts where applicable.
- Findings distinguish confirmed exploitability from unconfirmed signals.
- Scripts output JSON snippets for traceable reporting.
- The methodology requires authorization, scope, excluded actions, rate limits, and minimal proof.
- Report guidance requires redaction of secrets and exact remediation steps.

No security tool can guarantee that a platform, hosting provider, or target owner will permit a test. To reduce account or platform risk, keep testing limited to systems you control, retain written permission, prefer local/staging targets, avoid destructive payloads, and stop if rate limits, warnings, or instability appear.

## Requirements

- Python 3 standard library.
- Bash for shell scripts.
- Optional external tools for deeper authorized testing: `curl`, `nmap`, `sqlmap`, `ffuf`, `nuclei`, `nikto`, `wfuzz`, `jwt_tool`.
- Optional Python packages for future extensions: `requests`, `beautifulsoup4`, `cryptography`, `pyjwt`.

The current Python scripts are intentionally standard-library-first for portability.

## GitHub Publishing Checklist

- Keep `SKILL.md` concise and under 200 lines.
- Do not commit local reports, generated caches, virtual environments, or secrets.
- Redact target names, tokens, cookies, and screenshots before publishing examples.
- Add a license only after deciding the intended reuse terms.
- Run validation before release:

```bash
python -m compileall -q scripts
bash -lc 'find scripts -name "*.sh" -print0 | xargs -0 -n1 bash -n'
python scripts/report/cvss_scorer.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

## Status

This repository is useful for real authorized assessments today, especially as an AI-agent operating framework. It will find common and subtle security issues when the target exposes testable surfaces and the operator provides valid scope, test accounts, and enough context.

It is not a replacement for human authorization, legal review, production change control, or manual validation of high-impact findings.
