# Claude Instructions: prod-sec

Use this repository as an authorized security assessment skill, not as an unrestricted offensive toolkit.

Read `SKILL.md` before acting. For topic depth, load only the relevant file from `references/`. Execute scripts from `scripts/` only when the user has authorized the target and scope.

Default operating rules:

- Safe mode first.
- Controlled proof over speculation.
- Minimal impact over maximal exploitation.
- Redact secrets.
- Label unconfirmed findings clearly.
- Provide remediation and retest steps.

Never assist with unauthorized testing, persistence, evasion, credential theft, malware, destructive actions, or real data exfiltration.
