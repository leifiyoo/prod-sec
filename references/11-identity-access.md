# Identity and Access Management

## What to Check
Test MFA, PAM, SSO, federation, RBAC/ABAC, Zero Trust controls, credential protection, session tokens, service accounts, API keys, SCIM provisioning, offboarding, break-glass accounts, and privileged workflows.

## How to Test (Active)
1. Run auth/API checks:
   `python3 scripts/auth/mfa_bypass_test.py https://target --safe-mode`
   `python3 scripts/auth/oauth_test.py https://target --safe-mode`
   `python3 scripts/web/jwt_attack.py TOKEN --safe-mode`
2. Compare access for normal, manager, admin, service, and disabled test accounts.
3. Attempt direct API calls to privileged functions with lower roles.
4. Test SCIM or admin user-management endpoints for unauthorized create, role update, deprovision bypass, and invite abuse.
5. Verify service account key age, scope, rotation, and network restrictions.

## What Good Looks Like (Pass Criteria)
MFA enforced for privileged and risky actions, roles are minimal and audited, federation validates issuer/audience/signature, disabled users lose access quickly, service accounts are scoped and rotated, privileged actions require step-up or approval, and session/token revocation propagates.

## What Bad Looks Like (Fail Criteria)
MFA bypass through legacy endpoints, admin APIs callable by normal users, stale sessions after deprovisioning, broad service tokens, shared privileged accounts, SCIM accepting client-controlled roles, weak SSO claim mapping, no PAM controls, and break-glass accounts unmonitored.

## Exploitation Proof of Concept
Use a low-privileged test token:
```bash
curl -isk -X POST 'https://target/api/admin/users' \
  -H 'Authorization: Bearer LOW_PRIV_TOKEN' \
  -H 'Content-Type: application/json' --data '{"email":"ps-test@example.com","role":"admin"}'
```
Any privileged state change or detailed authorization bypass confirms impact.

## Edge Cases & Hidden Traps
Check invite links, group rename effects, nested groups, stale SAML attributes, Just-In-Time provisioning, OAuth app consent, API keys that outlive users, support impersonation, cached permissions, and cross-tenant role confusion.

## Remediation
Centralize identity policy, enforce step-up MFA, deny privileged APIs by default, map SSO claims strictly, rotate service credentials, expire sessions on role/offboarding changes, monitor break-glass use, implement PAM approval, and test every role boundary with automated integration tests.

## References
- OWASP ASVS Access Control: https://owasp.org/www-project-application-security-verification-standard/
- NIST Digital Identity Guidelines: https://pages.nist.gov/800-63-3/
- CWE-266 Incorrect Privilege Assignment: https://cwe.mitre.org/data/definitions/266.html
- OAuth 2.0 Security BCP: https://www.rfc-editor.org/rfc/rfc9700.html
