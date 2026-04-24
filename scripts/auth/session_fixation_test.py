#!/usr/bin/env python3
"""
Probe session fixation and cookie security indicators.

The script sends a preselected session cookie and inspects Set-Cookie behavior.
Full confirmation requires logging in with an authorized test account and
verifying the session identifier changes after authentication.
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


def fetch(url, cookie, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-session-fixation/1.0", "Cookie": cookie, "X-ProdSec-Canary": "session-fixation"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            return resp.status, dict(resp.headers), resp.read(2000).decode("utf-8", "replace"), None
    except HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(2000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, "", str(exc)


def main():
    parser = argparse.ArgumentParser(description="Check session fixation and cookie flags.")
    parser.add_argument("target_url")
    parser.add_argument("--cookie-name", default="session")
    parser.add_argument("--safe-mode", action="store_true", help="Do not submit credentials; inspect pre-auth behavior only.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    fixed_value = "prodsecfixedsession123"
    status, headers, body, error = fetch(args.target_url, f"{args.cookie_name}={fixed_value}", args.timeout)
    if error:
        print(f"{RED}[ERROR]{RESET} {error}")
        print("JSON_SNIPPET:", json.dumps({"tool": "session_fixation_test", "target": args.target_url, "error": error}))
        return 2

    findings = []
    set_cookie = " ".join(v for k, v in headers.items() if k.lower() == "set-cookie")
    print(f"{GREEN}[INFO]{RESET} status={status} set-cookie={set_cookie or '-'}")
    if fixed_value in set_cookie or fixed_value in body:
        findings.append({"title": "Possible session fixation acceptance", "severity": "High", "evidence": "Server reflected or reissued attacker-supplied session value", "status": "Unconfirmed until post-login session is checked"})
        print(f"{YELLOW}[FINDING]{RESET} fixed session value observed in response")
    if set_cookie:
        lower = set_cookie.lower()
        missing = [attr for attr in ("httponly", "secure", "samesite") if attr not in lower]
        if missing:
            findings.append({"title": "Weak session cookie attributes", "severity": "Medium", "evidence": f"Missing {', '.join(missing)}"})
            print(f"{YELLOW}[FINDING]{RESET} cookie missing {', '.join(missing)}")
    else:
        print(f"{YELLOW}[SIGNAL]{RESET} no Set-Cookie observed; test login flow next")

    print("JSON_SNIPPET:", json.dumps({"tool": "session_fixation_test", "target": args.target_url, "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
