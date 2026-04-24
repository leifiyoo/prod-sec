# Authentication, Authorization, and Session Management

## What to Check
Test login, signup, password reset, MFA, session issuance, refresh tokens, logout, remember-me, OAuth/OIDC, SSO, RBAC, object authorization, tenant isolation, account recovery, secure defaults, least privilege, defense in depth, and secure error handling.

## How to Test (Active)
1. Run:
   `python3 scripts/auth/bruteforce_sim.py https://target/login --username test@example.com --wordlist small.txt --safe-mode`
   `python3 scripts/auth/session_fixation_test.py https://target --safe-mode`
   `python3 scripts/auth/mfa_bypass_test.py https://target --safe-mode`
   `python3 scripts/auth/oauth_test.py https://target --safe-mode`
2. Use `curl -isk` to compare authenticated and unauthenticated access to sensitive routes.
3. Replay object requests with lower-privileged accounts to test BOLA/IDOR.
4. Attempt safe OAuth abuse: open redirect in `redirect_uri`, missing `state`, token leakage in fragments/logs, algorithm confusion in JWTs.
5. Test logout invalidates server-side session and refresh tokens.

## What Good Looks Like (Pass Criteria)
Uniform errors, lockout or throttling, MFA enforced server-side, session ID regenerated after auth, cookies use `HttpOnly; Secure; SameSite`, refresh tokens rotate, role checks occur per object and per action, OAuth validates issuer/audience/nonce/state/PKCE and exact redirect URI.

## What Bad Looks Like (Fail Criteria)
User enumeration, no rate limit, session ID unchanged after login, MFA only on UI routes, password reset tokens reusable or long-lived, predictable IDs, tenant ID accepted from client, JWT `alg=none` accepted, broad wildcard redirect URIs, cookies missing security attributes, logout only deletes client cookie.

## Exploitation Proof of Concept
Use two authorized test users. Create an object as User A, then request it as User B:
```bash
curl -isk -H 'Cookie: session=USER_B' 'https://target/api/invoices/USER_A_OBJECT_ID'
```
A `200` with User A data proves broken object-level authorization. For fixation, set a pre-login cookie and verify the same session value remains privileged after login.

## Edge Cases & Hidden Traps
Check background APIs used by mobile clients, GraphQL resolvers, export endpoints, websocket channels, cached authorization, soft-deleted objects, cross-tenant search, admin impersonation, stale invite links, password reset race conditions, OAuth mix-up, and MFA bypass through backup codes or legacy endpoints.

## Remediation
Centralize authorization on server-side policy checks. Regenerate sessions on privilege changes. Store sessions server-side or use short-lived signed tokens with rotation. Enforce MFA and recovery policies in backend workflows. Use exact OAuth redirect URI matching, PKCE, nonce/state, strict issuer/audience checks, and refresh-token rotation.

## References
- OWASP ASVS V2/V3/V4: https://owasp.org/www-project-application-security-verification-standard/
- OWASP API1 BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- CWE-287 Improper Authentication: https://cwe.mitre.org/data/definitions/287.html
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
