---
name: prod-sec
description: >
  Compatibility shim for the root prod-sec skill. Use for authorized active security
  audits, vulnerability assessments, safe-mode penetration testing, API/web security
  reviews, infrastructure hardening, and evidence-backed reporting across agent platforms.
---

# prod-sec compatibility shim

The canonical skill entry point is [`../../SKILL.md`](../../SKILL.md).

Load and follow the root `SKILL.md` first. Use the root-level `references/` and `scripts/`
directories for all workflows and tools.

Core guardrails:

- Test only systems the user owns or is explicitly authorized to assess.
- Start with `--safe-mode`.
- Keep tests scoped, rate-limited, and non-destructive.
- Do not persist access, evade detection, exfiltrate real data, deploy malware, or bypass legal controls.
- Produce evidence-backed findings with remediation and retest steps.
