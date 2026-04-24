# Gemini Instructions: prod-sec

This repo provides `prod-sec`, a defensive secure-code-review skill.

When using it:

1. Read `SKILL.md`.
2. Confirm the repository or files are in scope.
3. Load relevant `references/*.md` files progressively.
4. Run local scripts from `scripts/code/` when useful.
5. Confirm findings from source evidence before assigning severity.
6. Produce findings with file/line evidence, impact, CVSS guidance, remediation, and safe retest steps.

Do not use this skill for exploit payloads, unauthorized access, stealth, persistence, malware, data theft, destructive testing, brute force, recon, or bypassing legal controls.
