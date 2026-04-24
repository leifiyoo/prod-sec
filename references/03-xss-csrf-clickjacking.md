# XSS, CSRF, Clickjacking, and Browser Attacks

## What to Check
Test reflected, stored, DOM XSS, HTML injection, script gadget abuse, CSP bypasses, CSRF, clickjacking, open redirects, postMessage issues, insecure cookies, mixed content, browser security headers, and prototype pollution.

## How to Test (Active)
1. Run:
   `python3 scripts/web/xss_fuzzer.py https://target/search --param q --safe-mode`
   `python3 scripts/web/csrf_poc_gen.py https://target/account/email --method POST --safe-mode`
   `python3 scripts/web/open_redirect_scan.py https://target/redirect --param next --safe-mode`
   `python3 scripts/web/header_audit.py https://target --safe-mode`
2. Try payloads: `<svg/onload=alert(1)>`, `"><img src=x onerror=alert(1)>`, `javascript:alert(1)`, `</script><script>alert(1)</script>`, `__proto__[polluted]=1`.
3. Use browser devtools or a local HTML harness to confirm execution for reflected/stored/DOM payloads.
4. Submit state-changing forms without the CSRF token and from a foreign origin.

## What Good Looks Like (Pass Criteria)
Contextual output encoding, safe templating, strict CSP with nonces or hashes, no inline event handlers, anti-CSRF tokens bound to session and action, `SameSite` cookies, `frame-ancestors` or `X-Frame-Options`, safe redirect allowlists, and validated postMessage origins.

## What Bad Looks Like (Fail Criteria)
Payload executes, payload stored and later executes for another role, DOM sinks consume URL fragments, missing CSRF token accepted, token not bound to session, framing allowed for sensitive pages, open redirect to attacker domain, CSP has `unsafe-inline`, or JavaScript prototype pollution changes application behavior.

## Exploitation Proof of Concept
For reflected XSS:
```bash
curl -sk 'https://target/search?q=%3Csvg%2Fonload%3Dalert(document.domain)%3E'
```
Then open the URL in a controlled browser and capture execution. For CSRF, generate an HTML form with `csrf_poc_gen.py`, serve it locally, and prove the state change on a test account.

## Edge Cases & Hidden Traps
Stored XSS often hides in admin review screens, emails, PDF exports, markdown previews, file metadata, image EXIF, websocket messages, and analytics dashboards. CSRF can survive token checks when method override, JSON-to-form conversion, CORS preflight gaps, or SameSite downgrade paths exist. Clickjacking can combine with OAuth consent or payment confirmation.

## Remediation
Encode output by context, sanitize rich HTML with a maintained sanitizer, avoid dangerous DOM sinks, enforce nonce-based CSP, bind CSRF tokens to session/action, set `SameSite=Lax` or `Strict`, deny framing except explicit trusted ancestors, validate redirects against exact internal paths, and pin postMessage origins.

## References
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- OWASP CSRF: https://owasp.org/www-community/attacks/csrf
- CWE-79 XSS: https://cwe.mitre.org/data/definitions/79.html
- CWE-352 CSRF: https://cwe.mitre.org/data/definitions/352.html
