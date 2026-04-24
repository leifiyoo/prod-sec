# SSRF, XXE, LFI, RFI, and File Boundary Attacks

## What to Check
Test URL fetchers, webhooks, importers, image processors, PDF generators, XML parsers, file download endpoints, path traversal, LFI/RFI, archive extraction, symlinks, cloud metadata access, and internal network reachability.

## How to Test (Active)
1. Run:
   `python3 scripts/web/ssrf_probe.py https://target/fetch --param url --safe-mode`
   `python3 scripts/web/lfi_tester.py https://target/download --param file --safe-mode`
2. Try SSRF payloads: `http://127.0.0.1/`, `http://localhost/`, `http://[::1]/`, `http://169.254.169.254/`, decimal/hex IP encodings, DNS rebinding canary domains.
3. Try traversal payloads: `../etc/passwd`, `..%2f..%2fetc%2fpasswd`, `%252e%252e%252f`, `C:\Windows\win.ini`.
4. For XML endpoints, use safe XXE payloads referencing a controlled canary URL or harmless local hostname.
5. Look for response content, timing, DNS callbacks, status differences, metadata headers, or file signatures.

## What Good Looks Like (Pass Criteria)
URL allowlists by scheme/host/IP range, DNS pinning, blocked link-local/private networks, no redirects to disallowed hosts, metadata service protection, XML DTD/entity disabled, canonical path checks, storage object IDs instead of paths, and download authorization per object.

## What Bad Looks Like (Fail Criteria)
Server fetches private IPs, follows redirects to internal hosts, returns metadata tokens, resolves attacker-controlled DNS differently over time, reads `/etc/passwd` or `win.ini`, includes local source code, accepts `file://`/`gopher://`, expands XML entities, or extracts archives outside destination.

## Exploitation Proof of Concept
Safe SSRF proof:
```bash
curl -sk 'https://target/fetch?url=http://127.0.0.1:80/'
```
Different response, local service banner, or timing compared with a public baseline suggests SSRF. For LFI, prove only with harmless OS marker files such as `/etc/hostname` or `C:\Windows\win.ini` when authorized.

## Edge Cases & Hidden Traps
SSRF may occur through PDF renderers, URL previews, avatar import, webhook validation, S3-compatible storage callbacks, and XML stylesheets. Filters may block dotted IPs but miss IPv6, decimal, octal, redirects, userinfo, DNS rebinding, or trailing dots. Traversal can hide in ZIP slip, symlink races, Unicode normalization, and double decoding.

## Remediation
Use outbound proxy enforcement, strict allowlists, resolved IP validation after every redirect, metadata service blocking, short timeouts, no raw response passthrough, disabled XML DTDs/entities, canonical path validation below an allowed root, generated storage keys, and object-level authorization on downloads.

## References
- OWASP SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- CWE-918 SSRF: https://cwe.mitre.org/data/definitions/918.html
- CWE-22 Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- CWE-611 XXE: https://cwe.mitre.org/data/definitions/611.html
