# Injection Attacks

## What to Check
Test SQL, NoSQL, OS command, LDAP, XML, template, expression language, log, CRLF, header, CSV/formula injection, insecure deserialization, RCE, prototype pollution sinks, memory-safety exposed parsers, and secure error handling.

## How to Test (Active)
1. Run:
   `python3 scripts/web/sqli_test.py https://target/search --param q --safe-mode`
   `python3 scripts/api/api_fuzz.py https://target/api/items --safe-mode`
2. With authorization, invoke sqlmap:
   `sqlmap -u 'https://target/item?id=1' --batch --risk=1 --level=2 --safe-url=https://target/health`
3. Try manual payloads: `' OR '1'='1`, `") || true || ("`, `{"$ne":null}`, `;id`, `| whoami`, `${7*7}`, `{{7*7}}`, `*)(uid=*))(|(uid=*`, `<!ENTITY xxe SYSTEM "file:///etc/hostname">`.
4. Compare status, length, timing, error text, and semantic changes against a baseline.

## What Good Looks Like (Pass Criteria)
Parameterized queries, allowlisted commands, no shell interpolation, safe XML parser settings, schema validation, context-aware escaping, generic errors, structured logs that neutralize control characters, and deserializers restricted to trusted types.

## What Bad Looks Like (Fail Criteria)
Database error messages, time delay on sleep payloads, boolean response differences, command output in responses, template math evaluation, stack traces with query fragments, NoSQL operator acceptance, XML entity expansion, unsafe Java/PHP/Python deserialization markers, and CSV cells beginning with formula characters in exports.

## Exploitation Proof of Concept
Use a non-destructive boolean SQLi check:
```bash
curl -sk 'https://target/item?id=1%20AND%201=1'
curl -sk 'https://target/item?id=1%20AND%201=2'
```
Different data with identical auth and route confirms injection. For time-based proof, use a one-second sleep only with approval and record the baseline delta.

## Edge Cases & Hidden Traps
Second-order injection appears when stored names, filenames, or profile fields are later used in reports or admin SQL. ORMs can be safe until raw query helpers are used. JSON-to-query translators may expose NoSQL operators. Deserialization may be reachable only through queues, cookies, or signed-but-not-encrypted state. Log injection can poison SIEM parsing.

## Remediation
Use parameterized queries and typed query builders. Remove shell execution or pass arguments as arrays with allowlists. Disable XML external entities and DTDs. Reject unknown JSON fields and NoSQL operators from client input. Use safe serializers, signed schema-bound messages, and per-context output encoding. Add regression tests with the exact payloads that reproduced the issue.

## References
- OWASP Injection: https://owasp.org/Top10/A03_2021-Injection/
- CWE-89 SQL Injection: https://cwe.mitre.org/data/definitions/89.html
- CWE-78 OS Command Injection: https://cwe.mitre.org/data/definitions/78.html
- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection
