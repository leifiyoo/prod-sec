#!/usr/bin/env python3
"""
Simulate a bounded credential attack to validate throttling and lockout.

This is not a credential-stuffing tool. It submits a small number of supplied
test credentials and observes response codes, timing, and rate-limit headers. A
positive result is many failed attempts accepted without lockout, throttling, or
alerting indicators.
"""
import argparse
import json
import ssl
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def request(url, method, username, password, fields, timeout):
    user_field, pass_field = fields
    data = urlencode({user_field: username, pass_field: password, "prodsec_canary": "bruteforce"}).encode()
    req = Request(url, data=data if method == "POST" else None, method=method, headers={
        "User-Agent": "prod-sec-bruteforce-sim/1.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-ProdSec-Canary": "bruteforce",
    })
    if method == "GET":
        req.full_url = url + ("&" if "?" in url else "?") + data.decode()
    start = time.monotonic()
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(2000).decode("utf-8", "replace")
            return resp.status, dict(resp.headers), len(body), time.monotonic() - start, None
    except HTTPError as exc:
        body = exc.read(2000).decode("utf-8", "replace")
        return exc.code, dict(exc.headers), len(body), time.monotonic() - start, None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, 0, time.monotonic() - start, str(exc)


def load_passwords(path, safe_mode):
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                words = [line.strip() for line in handle if line.strip()]
        except OSError as exc:
            print(f"{RED}[ERROR]{RESET} cannot read wordlist: {exc}")
            return []
    else:
        words = ["Password1!", "Spring2026!", "prodsec-invalid", "Welcome1!", "Test1234!"]
    return words[:5 if safe_mode else 20]


def main():
    parser = argparse.ArgumentParser(description="Bounded auth throttling simulation with test credentials.")
    parser.add_argument("target_url")
    parser.add_argument("--username", required=True, help="Authorized test username only.")
    parser.add_argument("--wordlist", help="Small password list for a test account.")
    parser.add_argument("--method", choices=["POST", "GET"], default="POST")
    parser.add_argument("--user-field", default="username")
    parser.add_argument("--pass-field", default="password")
    parser.add_argument("--safe-mode", action="store_true", help="Cap attempts to five.")
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    passwords = load_passwords(args.wordlist, args.safe_mode)
    if not passwords:
        return 2

    observations = []
    blocked = False
    for index, password in enumerate(passwords, 1):
        status, headers, length, elapsed, error = request(args.target_url, args.method, args.username, password, (args.user_field, args.pass_field), args.timeout)
        if error:
            print(f"{RED}[ERROR]{RESET} attempt={index} {error}")
            observations.append({"attempt": index, "error": error})
            continue
        rate_headers = {k: v for k, v in headers.items() if k.lower() in ("retry-after", "x-ratelimit-remaining", "x-ratelimit-limit", "x-rate-limit-remaining")}
        if status in (401, 403, 423, 429):
            blocked = blocked or status in (423, 429)
        print(f"{GREEN if status in (401, 403, 423, 429) else YELLOW}[ATTEMPT]{RESET} #{index} status={status} len={length} time={elapsed:.2f}s rate={rate_headers or '-'}")
        observations.append({"attempt": index, "status": status, "length": length, "time": round(elapsed, 3), "rate_headers": rate_headers})
        time.sleep(args.delay)

    findings = []
    if len([o for o in observations if o.get("status") not in (423, 429)]) == len(passwords) and not blocked:
        findings.append({"title": "Login endpoint lacks observable brute-force throttling", "severity": "Medium", "evidence": f"{len(passwords)} failed attempts did not trigger 423/429 or rate-limit headers", "status": "Unconfirmed until logs/lockout policy are reviewed"})

    print("JSON_SNIPPET:", json.dumps({"tool": "bruteforce_sim", "target": args.target_url, "attempts": len(passwords), "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
