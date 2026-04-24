# Copilot Instructions: prod-sec

This repository is a defensive secure-code-review skill for AI agents.

## Source Of Truth

- `SKILL.md` is the canonical instruction file.
- `references/` contains topic-specific review guidance.
- `scripts/code/` contains local defensive audit helpers.
- `skill.sh`, `llms.txt`, and `skills/llms.txt` are compatibility and discovery files.

## Code And Documentation Standards

1. Keep security language professional and defensive.
2. Do not frame the repository as a penetration-testing or exploit toolkit.
3. Do not add exploit scanners, brute-force tools, recon tools, payload fuzzers, credential theft, persistence, evasion, malware, destructive actions, or real data exfiltration logic.
4. Scripts must operate on local files and emit structured evidence.
5. Documentation must preserve the responsible-use model.

## Validation

Before suggesting that changes are ready, run:

```bash
python -m compileall -q scripts
python scripts/code/static_code_audit.py . --json-out static-findings.json
python scripts/code/secrets_audit.py . --json-out secret-findings.json
python scripts/code/dependency_audit.py . --json-out dependency-findings.json
```
