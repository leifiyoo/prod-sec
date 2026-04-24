# Agent Instructions: prod-sec

This repository contains `prod-sec`, an authorized active security auditing skill for AI agents.

## Source Of Truth

- Read `SKILL.md` first.
- Load topic-specific files from `references/` only when needed.
- Run tools from `scripts/` only against explicitly authorized targets.
- Use `skill.sh` or `skills/llms.txt` when an agent platform expects a registry.

## Required Behavior

1. Establish authorization, scope, target URLs/hosts, excluded actions, credentials, and rate limits before active testing.
2. Prefer `--safe-mode` first.
3. Attempt controlled validation where authorized, but avoid destructive actions.
4. Mark unproven issues as `Unconfirmed`.
5. Report exact evidence, payloads, impact, remediation, and retest commands.

## Prohibited Behavior

- Do not test third-party systems without explicit permission.
- Do not persist access, evade monitoring, exfiltrate real data, deploy malware, run destructive payloads, or bypass legal controls.
- Do not publish secrets, cookies, tokens, screenshots with sensitive data, or target-specific evidence.

## Verification

Before claiming the skill is ready or changed correctly, run:

```bash
python -m compileall -q scripts
bash -lc 'find scripts -name "*.sh" -print0 | xargs -0 -n1 bash -n'
```
