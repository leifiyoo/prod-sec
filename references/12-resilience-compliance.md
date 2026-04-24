# Resilience, Recovery, and Compliance

## What to Check
Test backup strategy validation, restore integrity, DDoS posture, ransomware resilience, chaos testing readiness, disaster recovery, GDPR/ISO 27001/SOC 2 indicators, data retention, deletion, breach notification, and governance evidence.

## How to Test (Active)
1. Use safe readiness checks only; do not perform disruptive load or destructive ransomware simulation without explicit written approval.
2. Verify backup metadata, restore logs, encryption, access control, retention, and immutable storage.
3. Request or inspect evidence for last restore test, RTO/RPO, DDoS provider configuration, incident exercises, vendor risk, and compliance controls.
4. Run safe endpoint rate-limit checks:
   `python3 scripts/api/rate_limit_test.py https://target/api/health --safe-mode`
5. Test deletion/export workflows with a test subject account for GDPR-style rights.

## What Good Looks Like (Pass Criteria)
Backups are encrypted, immutable, monitored, regularly restored, and access-controlled. RTO/RPO are defined and tested. DDoS protections exist at network and application layers. Compliance evidence maps controls to owners, logs, retention, and recurring validation.

## What Bad Looks Like (Fail Criteria)
Backups never restored, same credentials can delete production and backups, no immutable copies, undefined RTO/RPO, no DDoS plan, deletion requests leave active data, compliance evidence is stale, and incident exercises have no tracked remediation.

## Exploitation Proof of Concept
Perform a test-account data export and deletion request. Confirm whether all expected stores, logs, analytics profiles, and backups follow the documented policy. For resilience, request a restore of a non-production backup and compare checksums or record counts.

## Edge Cases & Hidden Traps
Ransomware often succeeds through backup consoles, shared admin credentials, snapshot deletion permissions, and CI/CD deploy keys. GDPR deletion may miss search indexes, warehouses, logs, email providers, and third-party processors. DDoS controls can fail on expensive authenticated endpoints.

## Remediation
Implement immutable/offline backups, separate backup admin roles, rotate credentials, test restores, document RTO/RPO, add application-layer throttling, maintain data maps, automate retention/deletion, update vendor DPAs, and keep ISO/SOC 2 evidence tied to live controls.

## References
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- ISO 27001 overview: https://www.iso.org/isoiec-27001-information-security.html
- GDPR text: https://gdpr.eu/
- OWASP DoS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
