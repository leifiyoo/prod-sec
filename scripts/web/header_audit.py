#!/usr/bin/env python3
"""
Audit web security headers and cookie attributes.

The script performs a read-only HTTP request and identifies missing or weak
browser-facing controls. A positive result means a header or cookie setting is
absent, weak, or inconsistent with production hardening expectations.
"""
import argparse
import json
import ssl
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def fetch(url, timeout):
    req = Request(url, method="GET", headers={"User-Agent": "prod-sec-header-audit/1.0"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            return resp.status, dict(resp.headers), resp.read(4096).decode("utf-8", "replace"), None
    except HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(4096).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, "", str(exc)


def header(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def main():
    parser = argparse.ArgumentParser(description="Audit security headers and cookies.")
    parser.add_argument("target_url")
    parser.add_argument("--safe-mode", action="store_true", help="Read-only request mode.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    status, headers, _, error = fetch(args.target_url, args.timeout)
    if error:
        print(f"{RED}[ERROR]{RESET} {error}")
        print("JSON_SNIPPET:", json.dumps({"tool": "header_audit", "target": args.target_url, "error": error}))
        return 2

    checks = [
        ("Strict-Transport-Security", "High" if args.target_url.startswith("https://") else "Info", "Missing HSTS on HTTPS" if args.target_url.startswith("https://") else "HSTS not applicable until HTTPS is used"),
        ("Content-Security-Policy", "Medium", "Missing CSP"),
        ("X-Frame-Options", "Medium", "Missing clickjacking protection; frame-ancestors in CSP also acceptable"),
        ("X-Content-Type-Options", "Low", "Missing nosniff"),
        ("Referrer-Policy", "Low", "Missing referrer policy"),
        ("Permissions-Policy", "Low", "Missing permissions policy"),
    ]

    findings = []
    print(f"{GREEN}[INFO]{RESET} HTTP {status}")
    for name, severity, message in checks:
        value = header(headers, name)
        if value:
            print(f"{GREEN}[PASS]{RESET} {name}: {value}")
        elif name == "X-Frame-Options" and "frame-ancestors" in header(headers, "Content-Security-Policy").lower():
            print(f"{GREEN}[PASS]{RESET} frame-ancestors present in CSP")
        else:
            print(f"{YELLOW}[FINDING]{RESET} {message}")
            findings.append({"title": message, "severity": severity, "evidence": f"{name} not present"})

    cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cookie in cookies:
        lower = cookie.lower()
        name = cookie.split("=", 1)[0]
        missing = []
        for attr in ("httponly", "secure", "samesite"):
            if attr not in lower:
                missing.append(attr)
        if missing:
            findings.append({"title": f"Weak cookie attributes on {name}", "severity": "Medium", "evidence": f"Missing {', '.join(missing)}"})
            print(f"{YELLOW}[FINDING]{RESET} Cookie {name} missing {', '.join(missing)}")
        else:
            print(f"{GREEN}[PASS]{RESET} Cookie {name} has core security attributes")

    print("JSON_SNIPPET:", json.dumps({"tool": "header_audit", "target": args.target_url, "status": status, "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
