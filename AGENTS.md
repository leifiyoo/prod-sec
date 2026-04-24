# Agent Instructions: prod-sec

This repository contains `prod-sec`, a defensive secure-code-review skill for AI agents.

## Source Of Truth

- Read `SKILL.md` first.
- Load topic-specific files from `references/` only when needed.
- Run tools from `scripts/code/` only against local repositories or files the user owns or is allowed to assess.
- Use `skill.sh` or `skills/llms.txt` when an agent platform expects a registry.

## Required Behavior

1. Establish repository path, application type, security goals, and excluded files.
2. Run local review helpers where useful.
3. Inspect surrounding source code before confirming a finding.
4. Mark uncertain items as `Needs Review`.
5. Report exact file/line evidence, impact, remediation, and safe retest steps.

## Prohibited Behavior

- Do not run exploit payloads, brute-force attempts, recon, or unauthorized network tests.
- Do not add malware, persistence, evasion, credential theft, destructive actions, or real data exfiltration logic.
- Do not publish secrets, cookies, tokens, screenshots with sensitive data, or target-specific evidence.

## Verification

Before claiming the skill is ready or changed correctly, run:

```bash
python -m compileall -q scripts
python scripts/code/static_code_audit.py . --json-out static-findings.json
python scripts/code/secrets_audit.py . --json-out secret-findings.json
python scripts/code/dependency_audit.py . --json-out dependency-findings.json
```
