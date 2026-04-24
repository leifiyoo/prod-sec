# Copilot Instructions: prod-sec

This repository is an authorized security auditing skill for AI agents.

## Source Of Truth

- `SKILL.md` is the canonical instruction file.
- `references/` contains topic-specific playbooks.
- `scripts/` contains safe-mode-first active validation helpers.
- `skill.sh`, `llms.txt`, and `skills/llms.txt` are compatibility and discovery files.

## Code And Documentation Standards

1. Keep security language professional and authorization-focused.
2. Do not frame the repository as a tool for attacking arbitrary third-party systems.
3. Keep `--safe-mode` behavior and scope controls visible.
4. Do not add credential theft, persistence, evasion, malware, destructive payloads, or real data exfiltration logic.
5. Scripts must handle errors gracefully and emit structured evidence.
6. Documentation must preserve the responsible-use model.

## Validation

Before suggesting that changes are ready, run:

```bash
python -m compileall -q scripts
bash -lc 'find scripts -name "*.sh" -print0 | xargs -0 -n1 bash -n'
```
