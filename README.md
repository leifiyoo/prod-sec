<div align="center">

# prod-sec

### Authorized active security auditing for AI agents

`prod-sec` turns a general-purpose AI agent into a structured security assessment operator for authorized web, API, infrastructure, cloud-adjacent, and supply-chain audits.

![Skill](https://img.shields.io/badge/AI_Agent-Skill-111827?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Auditing-0F766E?style=for-the-badge)
![OWASP](https://img.shields.io/badge/OWASP-Coverage-7C3AED?style=for-the-badge)
![Mode](https://img.shields.io/badge/Safe_Mode-Default-2563EB?style=for-the-badge)

</div>

> [!IMPORTANT]
> Use this skill only on systems you own or are explicitly authorized to assess. The scripts and workflows are intended for bounded validation, remediation, and reporting. They are not intended for unauthorized access, persistence, evasion, data theft, destructive testing, or abuse.

## Overview

`prod-sec` is a production-grade security auditing skill with progressive references and runnable test scripts. It goes beyond passive code review by guiding the agent through controlled reconnaissance, enumeration, exploit validation, impact analysis, and reporting.

The skill is designed for:

- Local and staging web application audits
- Authorized API and authentication testing
- Security hardening reviews with active validation
- OWASP-style vulnerability assessment
- Internal red-team/blue-team collaboration
- Evidence-backed remediation reports
- Multi-agent skill distribution through `SKILL.md`, `skill.sh`, `skills/llms.txt`, and platform instruction files

It is not a "hack anything" toolkit. It is an authorized assessment framework with safe-mode defaults and explicit scope controls.

## Agent And Platform Support

The canonical skill lives at `SKILL.md`. Compatibility files are included so other agent platforms can discover or follow the same operating rules:

| Platform or convention | File |
| --- | --- |
| Codex / OpenAI-style skills | `SKILL.md`, `agents/openai.yaml` |
| skills.sh-style local registry | `skill.sh` |
| LLM/agent registry hints | `llms.txt`, `skills/llms.txt` |
| OpenAI Codex / general agents | `AGENTS.md`, `CODEX.md` |
| Claude Code | `CLAUDE.md` |
| Gemini CLI | `GEMINI.md` |
| GitHub Copilot | `.github/copilot-instructions.md` |
| Cursor | `.cursorrules` |
| Cline | `.clinerules` |
| Windsurf | `.windsurfrules` |
| Aider | `AIDER.md` |
| Augment | `.augment/rules.md` |
| Kilo Code | `.kilocode/rules.md` |
| OpenCode | `.opencode/AGENTS.md` |
| Continue | `.continue/rules/prod-sec.md` |

All platform files point back to the same responsible-use model: authorized targets only, safe mode first, minimal proof, no persistence, no evasion, no real data exfiltration, and evidence-backed remediation.

## What It Can Find

| Area | Examples |
| --- | --- |
| Web security | SQL injection indicators, reflected XSS, CSRF exposure, CORS mistakes, missing headers, open redirects, SSRF, LFI/path traversal |
| Authentication | weak session handling, MFA enforcement gaps, OAuth/OIDC misconfiguration, JWT weaknesses, rate-limit gaps |
| API security | GraphQL introspection, webhook spoofing/replay, schema validation gaps, mass-assignment indicators, abuse-prevention gaps |
| Infrastructure | TLS/certificate issues, exposed HTTP methods, DNS/email-auth signals, container management exposure |
| Crypto and secrets | weak hash formats, leaked secrets, JWT claim/algorithm issues, certificate hardening gaps |
| DevSecOps | supply-chain review, CI/CD risk areas, dependency and secret-scanning workflows |
| Monitoring | logging quality, detection coverage, canary requests, incident-response evidence |
| Advanced surfaces | AI/LLM prompt injection, mobile/API trust boundaries, IoT/browser/blockchain risk prompts |

## Safety Model

`prod-sec` is built to reduce accidental misuse:

- `--safe-mode` is available on active scripts where applicable.
- Findings distinguish confirmed exploitability from unconfirmed signals.
- Scripts emit JSON snippets for traceable reporting.
- The methodology requires authorization, target scope, excluded actions, rate limits, and minimal proof.
- Reports require redacted secrets, exact payloads, evidence, impact, remediation, and retest commands.

No repository wording can guarantee that every platform or target owner will permit every test. To reduce account, legal, and operational risk, test only systems you control or have written permission to assess, prefer local/staging targets, keep payloads non-destructive, and stop if instability, warnings, or rate limits appear.

## Repository Layout

```text
prod-sec/
|-- SKILL.md
|-- AGENTS.md
|-- AIDER.md
|-- CLAUDE.md
|-- CODEX.md
|-- GEMINI.md
|-- skill.sh
|-- llms.txt
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
|-- skills/
|   |-- llms.txt
|   `-- prod-sec/
|       `-- SKILL.md
`-- .github/
    |-- copilot-instructions.md
    `-- FUNDING.yml
```

## Quick Start

Run probes only against authorized targets.

```bash
# Recon
bash scripts/recon/dns_recon.sh example.com --safe-mode
bash scripts/recon/port_scan.sh example.com --safe-mode
python3 scripts/recon/tech_fingerprint.py https://example.com --safe-mode

# Web and API checks
python3 scripts/web/header_audit.py https://example.com --safe-mode
python3 scripts/web/cors_tester.py https://example.com/api/session --safe-mode
python3 scripts/api/rate_limit_test.py https://example.com/api/session --safe-mode
python3 scripts/web/open_redirect_scan.py 'https://example.com/login?next=/dashboard' --param next --safe-mode

# Reporting
python3 scripts/report/cvss_scorer.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
python3 scripts/report/generate_report.py findings.json --out report
```

## Using As An Agent Skill

Place this folder where your agent can discover skills, then invoke it with scoped prompts:

```text
Use prod-sec to audit my local app at http://localhost:5173 and API at http://localhost:3001.
Use prod-sec to perform an authorized safe-mode security assessment of staging.example.com.
Use prod-sec to generate a security report from these JSON findings.
```

The main entry point is `SKILL.md`. For registry-style tools, run:

```bash
source ./skill.sh prod-sec
```

Detailed testing guidance is loaded progressively from `references/` only when relevant.

## Phased Workflow

1. **Recon**: identify hosts, DNS, ports, technologies, TLS, and exposed services.
2. **Enum**: map routes, forms, APIs, auth flows, headers, CORS, sessions, roles, and data paths.
3. **Attack**: run controlled payloads and active checks inside the approved scope.
4. **Post-Exploit**: validate bounded impact, chainability, privilege boundaries, and detection.
5. **Report**: generate severity-sorted findings with CVSS, PoC, impact, remediation, and retest steps.

## Requirements

- Python 3 standard library
- Bash for shell scripts
- Optional external tools for deeper authorized testing: `curl`, `nmap`, `sqlmap`, `ffuf`, `nuclei`, `nikto`, `wfuzz`, `jwt_tool`
- Optional Python packages for future extensions: `requests`, `beautifulsoup4`, `cryptography`, `pyjwt`

The current Python scripts are intentionally standard-library-first for portability.

## Example Report Workflow

Collect JSON snippets from script output into `findings.json`, then generate Markdown and HTML:

```bash
python3 scripts/report/generate_report.py findings.json --out report
```

The report generator produces:

- Executive summary
- Severity-sorted findings
- Description, proof of concept, impact, CVSS, and remediation
- Coverage matrix
- Retest-oriented structure

## Publishing Checklist

Before publishing or tagging a release:

```bash
python -m compileall -q scripts
bash -lc 'find scripts -name "*.sh" -print0 | xargs -0 -n1 bash -n'
python scripts/report/cvss_scorer.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Also verify:

- `SKILL.md` stays concise and under 200 lines.
- No local reports, caches, virtual environments, `.env` files, tokens, cookies, screenshots, or target-specific evidence are committed.
- Examples use owned, local, staging, or documentation targets only.
- Any discovered secrets are redacted and rotated before publication.

## Status

`prod-sec` is useful for real authorized assessments today, especially as an AI-agent operating framework. It can identify common and subtle security issues when the operator provides valid scope, safe test data, test accounts, and enough target context.

It does not replace written authorization, legal review, production change control, or manual validation of high-impact findings.
