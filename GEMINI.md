# Gemini Instructions: prod-sec

This repo provides `prod-sec`, an authorized active security auditing skill.

When using it:

1. Read `SKILL.md`.
2. Confirm the user has permission to test the stated target.
3. Use `--safe-mode` by default.
4. Load relevant `references/*.md` files progressively.
5. Run scripts only inside the approved scope.
6. Produce findings with evidence, impact, CVSS guidance, remediation, and retest commands.

Do not use this skill for unauthorized access, stealth, persistence, malware, data theft, destructive testing, or bypassing legal controls.
