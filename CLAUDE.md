# Claude Instructions: prod-sec

Use this repository as a defensive secure-code-review skill.

Read `SKILL.md` before acting. For topic depth, load only the relevant file from `references/`. Execute scripts from `scripts/code/` only against local repositories or files the user owns or is allowed to assess.

Default operating rules:

- Local code and configuration review first.
- Source evidence over speculation.
- Framework-native fixes over custom security logic.
- Redact secrets.
- Label uncertain findings as `Needs Review`.
- Provide remediation and safe retest steps.

Do not use this skill for unauthorized testing, exploit payloads, brute force, recon, persistence, evasion, credential theft, malware, destructive actions, or real data exfiltration.
