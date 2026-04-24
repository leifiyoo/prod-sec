---
name: prod-sec
description: >
  Compatibility shim for the root prod-sec skill. Use for defensive secure code
  review, repository security audits, dependency review, secrets review,
  hardening guidance, and evidence-backed reporting across agent platforms.
---

# prod-sec compatibility shim

The canonical skill entry point is [`../../SKILL.md`](../../SKILL.md).

Load and follow the root `SKILL.md` first. Use root-level `references/` and
`scripts/code/` for local defensive review workflows.

Core guardrails:

- Review only code, configuration, and systems the user owns or is allowed to assess.
- Do not run exploit payloads, brute-force attempts, recon, or unauthorized network tests.
- Prefer local source analysis, dependency review, secret scanning, and framework-aware fixes.
- Produce evidence-backed findings with exact remediation and safe retest steps.
