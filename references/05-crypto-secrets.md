# Cryptography, Secrets, and Data Protection

## What to Check
Test TLS/HTTPS, certificate validity, HSTS, weak ciphers, key management, encryption at rest, password hashing, JWT signing, data integrity, digital signatures, PKI, secrets management, token storage, and post-quantum readiness for long-lived secrets.

## How to Test (Active)
1. Run:
   `bash scripts/infra/tls_audit.sh target.com --safe-mode`
   `bash scripts/crypto/cert_checker.sh target.com --safe-mode`
   `python3 scripts/crypto/hash_strength_test.py hashes.txt --safe-mode`
   `python3 scripts/crypto/secrets_scanner.py ./repo --safe-mode`
   `python3 scripts/web/jwt_attack.py TOKEN --safe-mode`
2. Use `curl -I https://target` to confirm HSTS and no mixed-content downgrade paths.
3. Decode JWTs and verify `alg`, `kid`, `iss`, `aud`, `exp`, `nbf`, key rotation, and server-side revocation.
4. Search repos, CI logs, containers, and front-end bundles for secrets.

## What Good Looks Like (Pass Criteria)
TLS 1.2+ with strong suites, valid certificates, HSTS preload where suitable, no HTTP secrets, Argon2id/bcrypt/scrypt password hashing with per-user salts, managed KMS/HSM, short-lived keys, signed integrity checks, secret scanning in CI, and no tokens in localStorage for high-risk apps.

## What Bad Looks Like (Fail Criteria)
Expired or mismatched certificates, TLS 1.0/1.1, weak ciphers, missing HSTS, secrets in source or JavaScript, unsalted MD5/SHA1 hashes, JWT `none` or weak HMAC secrets, `kid` path traversal, long-lived bearer tokens, encryption keys next to encrypted data, and no key rotation process.

## Exploitation Proof of Concept
For JWT weakness, run:
```bash
python3 scripts/web/jwt_attack.py eyJ... --safe-mode
```
If the script can produce an unsigned token variant or detect weak claims accepted by the application in a test request, document the accepted token and affected endpoint. For secrets, prove only by validating metadata such as key type and repository path, not by using production credentials unless explicitly authorized.

## Edge Cases & Hidden Traps
Secrets often appear in build artifacts, source maps, mobile app bundles, Terraform state, Docker layers, npm package tarballs, CI retry logs, browser crash reports, and analytics snippets. Encryption at rest is weak if app roles can read all data. JWT validation may differ between API gateway and backend. Signature verification can be skipped for cached or websocket paths.

## Remediation
Rotate exposed secrets, remove them from history, enforce CI secret scanning, use managed secret stores, pin JWT algorithms, validate issuer/audience/expiry, use JWKS with rotation, disable weak TLS, enable HSTS, hash passwords with Argon2id/bcrypt/scrypt, separate encryption keys from data, and document crypto ownership.

## References
- OWASP Cryptographic Failures: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- OWASP Secrets Management: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- RFC 8725 JWT Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- CWE-798 Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html
