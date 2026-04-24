# Reporting Template

## What to Check
Ensure every tested domain, executed script, manual payload, exploit result, severity decision, remediation, owner, and retest status is captured. Distinguish confirmed vulnerabilities from unconfirmed hypotheses and defense-in-depth observations.

## How to Test (Active)
1. Collect JSON snippets from scripts into `findings.json`.
2. Score findings:
   `python3 scripts/report/cvss_scorer.py`
3. Generate final artifacts:
   `python3 scripts/report/generate_report.py findings.json --out report`
4. Validate the report includes executive summary, severity-sorted findings, PoC, impact, CVSS, remediation, evidence, and coverage matrix.
5. Retest fixed findings with the exact original payload and command.

## What Good Looks Like (Pass Criteria)
The report is reproducible, evidence-backed, sorted by severity, useful to executives and engineers, and includes tested controls with pass/fail status. Every confirmed issue has a concrete fix and retest command.

## What Bad Looks Like (Fail Criteria)
Generic advice, missing payloads, no proof of exploitability, no affected endpoint, unscored issues, no coverage matrix, no distinction between confirmed and unconfirmed, screenshots without raw evidence, and remediation that cannot be implemented directly.

## Exploitation Proof of Concept
Each finding must include:
```text
Command: curl -isk 'https://target/path?x=PAYLOAD'
Observed: 200 response reflected payload in executable context
Impact: attacker-controlled JavaScript runs in victim session
Retest: rerun command and verify encoded inert output
```

## Edge Cases & Hidden Traps
Low-severity findings can become critical when chained. Reports often understate business logic flaws because no CVE exists. Screenshots without timestamps and request IDs are weak evidence. Retests must verify the root cause, not just the single payload.

## Remediation
Use specific code/config changes, owner, priority, and validation steps. Include short-term containment and long-term prevention. For repeated classes, require secure-by-default framework changes and regression tests.

## References
- CVSS v3.1 Specification: https://www.first.org/cvss/v3.1/specification-document
- OWASP Risk Rating: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- CWE Mapping: https://cwe.mitre.org/
- Common Vulnerability Scoring System: https://www.first.org/cvss/
