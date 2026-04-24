# Database Security

## What to Check
Test database access control, network exposure, encryption, query security, row-level security, auditing, backup security, DLP, hardening, monitoring, account privilege, credential storage, migration safety, and data retention.

## How to Test (Active)
1. Use application-level scripts first:
   `python3 scripts/web/sqli_test.py https://target/item --param id --safe-mode`
   `python3 scripts/api/api_fuzz.py https://target/api/search --safe-mode`
2. With approved DB credentials, verify least privilege:
   `SELECT current_user;`
   `SHOW grants;` or DB-specific equivalent.
3. Attempt authorized read/write boundaries with test data only.
4. Check backups, snapshots, replicas, logs, and exports for encryption and access control.
5. Validate audit logs for failed login, privilege change, sensitive read, export, and schema change events.

## What Good Looks Like (Pass Criteria)
DB not internet-exposed, app account has minimal privileges, row-level or tenant constraints enforced, TLS required, backups encrypted and access-controlled, sensitive columns encrypted/tokenized, audit logs immutable, migrations reviewed, and DLP alerts on bulk export.

## What Bad Looks Like (Fail Criteria)
Public database ports, shared admin credentials, app user can alter schema or read all tenants, unencrypted backups, sensitive data in logs, no query audit trail, disabled TLS, weak passwords, snapshots shared publicly, and application filters relied on instead of database constraints.

## Exploitation Proof of Concept
With two tenants and approved credentials, attempt:
```sql
SELECT * FROM invoices WHERE tenant_id = 'other-test-tenant';
```
If data is returned to a role that should not access it, tenant isolation is broken. For app-level proof, use IDOR requests to retrieve another tenant's records.

## Edge Cases & Hidden Traps
Check read replicas, analytics warehouses, materialized views, search indexes, cache stores, message queues, BI exports, support tooling, and admin consoles. Backups may have weaker IAM than production. Soft-delete tables and audit logs often retain sensitive data outside normal authorization paths.

## Remediation
Restrict DB networks, enforce TLS, rotate credentials, split app roles by capability, use row-level security or tenant constraints, encrypt backups with managed keys, audit sensitive operations, redact logs, lock down replicas/exports, and test restore processes with access controls intact.

## References
- OWASP Query Parameterization: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- PostgreSQL RLS: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- CIS Database Benchmarks: https://www.cisecurity.org/cis-benchmarks
- CWE-200 Exposure of Sensitive Information: https://cwe.mitre.org/data/definitions/200.html
