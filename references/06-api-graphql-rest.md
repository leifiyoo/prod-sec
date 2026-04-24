# API, GraphQL, REST, and Webhooks

## What to Check
Test API authentication, authorization, object and function-level access, schema validation, rate limiting, API gateway policy, OAuth/JWT validation, GraphQL introspection, batching, mass assignment, webhook signatures, abuse prevention, version drift, and secure logging.

## How to Test (Active)
1. Run:
   `python3 scripts/api/rate_limit_test.py https://target/api/login --safe-mode`
   `python3 scripts/api/graphql_introspection.py https://target/graphql --safe-mode`
   `python3 scripts/api/api_fuzz.py https://target/api/resource --safe-mode`
   `python3 scripts/api/webhook_spoof_test.py https://target/webhook --safe-mode`
2. Replay requests across users and roles.
3. Try mass assignment fields: `role`, `isAdmin`, `tenantId`, `price`, `balance`, `status`.
4. For GraphQL, test introspection, aliases for rate-limit bypass, nested query depth, and resolver authorization.
5. For webhooks, omit signature, alter timestamp, replay payload, and use wrong algorithm.

## What Good Looks Like (Pass Criteria)
Authentication on all non-public APIs, deny-by-default authorization per object/action, strict schemas, unknown fields rejected, consistent rate limits by account/IP/token/device, GraphQL depth/complexity limits, introspection disabled or access-controlled in production, webhook HMAC with timestamp and replay prevention.

## What Bad Looks Like (Fail Criteria)
Unauthenticated sensitive routes, BOLA/IDOR, admin functions callable by normal users, client-controlled `tenantId`, accepted unknown fields, unlimited login/API calls, GraphQL introspection exposing private types, batching bypasses limits, webhook accepted without valid signature, and verbose API errors leaking internals.

## Exploitation Proof of Concept
Mass assignment:
```bash
curl -sk -X PATCH 'https://target/api/me' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer USER_TOKEN' \
  --data '{"displayName":"prodsec","role":"admin","tenantId":"other"}'
```
If forbidden fields change or affect authorization, impact is confirmed. Use only test accounts.

## Edge Cases & Hidden Traps
Check old API versions, mobile-only endpoints, GraphQL resolvers that skip service-layer auth, API gateway policies that differ by path casing or trailing slash, HTTP method override, batch endpoints, async jobs, webhook retries, idempotency key reuse, and cache poisoning through API responses.

## Remediation
Centralize API authorization, enforce schemas and reject unknown fields, implement object ownership checks, apply gateway and application rate limits, validate JWT/OAuth claims, sign webhooks with HMAC and timestamp tolerance, block replay, cap GraphQL depth/complexity, and add abuse-case tests.

## References
- OWASP API Security Top 10: https://owasp.org/API-Security/
- GraphQL Security: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- CWE-770 Allocation Without Limits: https://cwe.mitre.org/data/definitions/770.html
