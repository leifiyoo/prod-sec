#!/usr/bin/env python3
"""
Probe MFA enforcement surface without attempting account takeover.

The script checks common MFA routes, method handling, response consistency, and
optional authenticated access with a provided token. A positive result requires
server-side access to protected resources without completing MFA.
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


def call(url, method, token, timeout):
    headers = {"User-Agent": "prod-sec-mfa-bypass/1.0", "X-ProdSec-Canary": "mfa"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, method=method, headers=headers)
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(3000).decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body, None
    except HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(3000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, "", str(exc)


def join(base, path):
    return base.rstrip("/") + path


def main():
    parser = argparse.ArgumentParser(description="Probe MFA bypass indicators and route exposure.")
    parser.add_argument("target_url", help="Base URL or MFA endpoint.")
    parser.add_argument("--token", help="Authorized pre-MFA or low-privilege test token.")
    parser.add_argument("--safe-mode", action="store_true", help="Use OPTIONS/GET and no code guessing.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    paths = ["", "/mfa", "/mfa/verify", "/api/mfa/verify", "/api/me", "/api/session"]
    findings = []
    observations = []
    for path in paths:
        url = args.target_url if path == "" else join(args.target_url, path)
        for method in ("OPTIONS", "GET"):
            status, headers, body, error = call(url, method, args.token, args.timeout)
            if error:
                print(f"{RED}[ERROR]{RESET} {url} {method}: {error}")
                continue
            allow = headers.get("Allow") or headers.get("allow") or ""
            marker = "mfa" in body.lower() or "otp" in body.lower() or "totp" in body.lower()
            observations.append({"url": url, "method": method, "status": status, "allow": allow, "mfa_marker": marker})
            print(f"{GREEN}[TEST]{RESET} {method} {url} status={status} allow={allow or '-'} mfa_marker={marker}")
            if args.token and url.endswith(("/api/me", "/api/session")) and status == 200 and not marker:
                findings.append({"title": "Possible MFA enforcement gap", "severity": "High", "evidence": f"{url} returned 200 for supplied token without MFA marker", "status": "Unconfirmed until token state is verified"})

    print("JSON_SNIPPET:", json.dumps({"tool": "mfa_bypass_test", "target": args.target_url, "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
