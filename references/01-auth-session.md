# Authentication And Session Review

## What to Check
Review login, registration, password reset, MFA, OAuth/OIDC, cookies, token lifetime, session rotation, logout, privilege checks, and account recovery flows from source and config.

## How to Test (Defensive)
1. Read the relevant source files, routes, handlers, middleware, configuration, and tests.
2. Run local helpers when relevant:
   - `python3 scripts/code/static_code_audit.py PATH_TO_REPO --json-out static-findings.json`
   - `python3 scripts/code/secrets_audit.py PATH_TO_REPO --json-out secret-findings.json`
   - `python3 scripts/code/dependency_audit.py PATH_TO_REPO --json-out dependency-findings.json`
3. Confirm each signal by inspecting surrounding code and framework behavior.
4. Classify uncertain items as `Needs Review`; classify only source-backed issues as `Confirmed`.

## What Good Looks Like (Pass Criteria)
Controls are enforced server-side, framework defaults are used safely, sensitive data is protected, dependencies are maintained, and tests or configuration prove the intended security behavior.

## What Bad Looks Like (Fail Criteria)
Security depends only on client-side checks, user input reaches sensitive sinks without validation or binding, secrets appear in source, authorization is missing at object or tenant boundaries, or configuration disables important protections.

## Proof From Code
Provide minimal source evidence instead of an exploit: file path, line number, relevant snippet, data-flow explanation, affected trust boundary, and why the framework does or does not mitigate the issue.

## Edge Cases & Hidden Traps
Check second-order data flows, background jobs, webhook handlers, admin-only routes, multi-tenant filters, cache keys, generated code, default middleware order, preview deployments, test fixtures, and CI-only behavior.

## Remediation
Use framework-native controls, parameterized APIs, centralized authorization helpers, safe defaults, secret managers, maintained dependencies, tests that fail before the fix, and deployment configuration that enforces the intended control.

## References
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE: https://cwe.mitre.org/
