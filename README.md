<div align="center">

# prod-sec

### Defensive production security review for AI agents

`prod-sec` helps AI coding agents review local codebases, configuration, dependencies, secrets, and deployment posture without shipping offensive testing tools.

![Skill](https://img.shields.io/badge/AI_Agent-Skill-111827?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Code_Review-0F766E?style=for-the-badge)
![Mode](https://img.shields.io/badge/Defensive-Only-2563EB?style=for-the-badge)
![OWASP](https://img.shields.io/badge/OWASP-Guided-7C3AED?style=for-the-badge)

</div>

> [!IMPORTANT]
> This repository is a defensive AppSec review skill. It does not include exploit scanners, brute-force tools, recon scripts, payload fuzzers, or code intended for unauthorized access. Use it only on code and systems you own or are explicitly allowed to assess.

## Overview

`prod-sec` turns an AI agent into a structured secure-code-review assistant. It focuses on evidence-backed analysis of source code, framework configuration, dependency manifests, secrets exposure, authentication design, authorization boundaries, data handling, CI/CD, and cloud/deployment posture.

The skill is designed for:

- Secure code review
- GitHub repository security audits
- Dependency and secret exposure review
- OWASP-style application hardening
- Authentication and authorization design review
- CI/CD and supply-chain review
- Security report generation
- Multi-agent distribution through `SKILL.md`, `skill.sh`, `skills/llms.txt`, and platform instruction files

It is intentionally not a penetration-testing toolkit. It guides the agent to inspect code, run local defensive checks, explain risk, and propose exact fixes.

## Install

Install with the skills CLI:

```bash
npx skills add leifiyoo/prod-sec
```

For non-interactive setup across supported agents:

```bash
npx skills add leifiyoo/prod-sec --yes --global
```

Then ask your AI agent to use `prod-sec` against a local repository:

```text
Use prod-sec to review this repository for authentication, authorization, secrets, and dependency risks.
Use prod-sec to audit C:\path\to\my-app and produce a prioritized security report.
Use prod-sec to check this pull request for AppSec regressions.
```

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

## What It Reviews

| Area | Examples |
| --- | --- |
| Application security | authentication, authorization, session handling, input validation, output encoding, error handling |
| Web security | XSS sinks, CSRF-sensitive flows, CORS configuration, CSP and security headers, unsafe redirects |
| Data access | SQL construction, ORM usage, tenant boundaries, migrations, backups, encryption indicators |
| Cryptography and secrets | weak hashes, token handling, JWT validation, secret-like values in source, key management patterns |
| API security | REST/GraphQL authorization, rate-limit design, webhook signature verification, schema validation |
| Supply chain | dependency manifests, lockfiles, CI/CD secrets, artifact integrity, SBOM readiness |
| Infrastructure | container configuration, reverse proxy settings, deployment config, cloud/IAM review prompts |
| Monitoring | audit logs, security event coverage, alertability, incident-response evidence |

## Local Audit Helpers

The included scripts operate on local files only:

```bash
python3 scripts/code/static_code_audit.py PATH_TO_REPO --json-out static-findings.json
python3 scripts/code/secrets_audit.py PATH_TO_REPO --json-out secret-findings.json
python3 scripts/code/dependency_audit.py PATH_TO_REPO --json-out dependency-findings.json
```

Report helpers:

```bash
python3 scripts/report/cvss_scorer.py
python3 scripts/report/generate_report.py findings.json --out report
```

The scripts are intentionally conservative. They surface review signals and redacted evidence; the agent must read the surrounding code before calling a finding confirmed.

## Repository Layout

```text
prod-sec/
|-- SKILL.md
|-- README.md
|-- skill.sh
|-- llms.txt
|-- AGENTS.md
|-- CLAUDE.md
|-- GEMINI.md
|-- CODEX.md
|-- AIDER.md
|-- agents/
|-- references/
|-- scripts/
|   |-- code/
|   |   |-- static_code_audit.py
|   |   |-- secrets_audit.py
|   |   `-- dependency_audit.py
|   `-- report/
|-- skills/
`-- .github/
```

## skills.sh Discovery

This repository is structured for the skills CLI:

```bash
npx skills add leifiyoo/prod-sec
npx skills add leifiyoo/prod-sec --yes --global
```

`skills.sh` listings are driven by anonymous aggregate install telemetry from the skills CLI. A new repository may not appear immediately after publishing; it should become eligible after users install it with `npx skills add leifiyoo/prod-sec` and the leaderboard data refreshes.

To opt out of telemetry during local testing:

```bash
DISABLE_TELEMETRY=1 npx skills add leifiyoo/prod-sec
```

## Reporting

Findings should include:

- Severity and CVSS rationale
- File and line evidence
- Description and impact
- Whether the issue is `Confirmed` or `Needs Review`
- Exact remediation
- Safe retest steps

## Publishing Checklist

Before publishing or tagging a release:

```bash
python -m compileall -q scripts
python scripts/code/static_code_audit.py . --json-out static-findings.json
python scripts/code/secrets_audit.py . --json-out secret-findings.json
python scripts/code/dependency_audit.py . --json-out dependency-findings.json
```

Do not commit generated findings, reports, `.env` files, tokens, cookies, screenshots, or target-specific evidence.

## Topics

`ai-agent`, `agent-skill`, `skills-sh`, `security-code-review`, `appsec`, `secure-coding`, `defensive-security`, `owasp`, `devsecops`, `dependency-audit`, `secrets-scanning`, `threat-modeling`, `vulnerability-management`, `security-automation`

## Status

`prod-sec` is useful for defensive repository security review today. It helps agents find risky source patterns, missing controls, dependency review gaps, and secret exposure signals while keeping the project suitable for public GitHub distribution.
