#!/usr/bin/env python3
"""
Actively test endpoint rate-limit behavior with a bounded request burst.

Safe mode caps the burst at five requests. A positive result is no throttling,
no rate-limit headers, and consistent successful responses on an endpoint that
should resist automation or abuse.
"""
import argparse
import json
import ssl
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def call(url, method, timeout):
    req = Request(url, method=method, headers={"User-Agent": "prod-sec-rate-limit/1.0", "X-ProdSec-Canary": "rate-limit"})
    start = time.monotonic()
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            return resp.status, dict(resp.headers), time.monotonic() - start, None
    except HTTPError as exc:
        return exc.code, dict(exc.headers), time.monotonic() - start, None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, time.monotonic() - start, str(exc)


def main():
    parser = argparse.ArgumentParser(description="Bounded rate-limit probe.")
    parser.add_argument("target_url")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--method", choices=["GET", "POST", "HEAD"], default="GET")
    parser.add_argument("--safe-mode", action="store_true", help="Cap to five requests.")
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    count = min(args.count, 5 if args.safe_mode else 100)
    observations = []
    saw_limit = False
    for i in range(1, count + 1):
        status, headers, elapsed, error = call(args.target_url, args.method, args.timeout)
        rate_headers = {k: v for k, v in headers.items() if "ratelimit" in k.lower() or k.lower() == "retry-after"}
        if status == 429 or rate_headers:
            saw_limit = True
        print(f"{GREEN if status != 429 else YELLOW}[REQ]{RESET} #{i} status={status} time={elapsed:.2f}s rate={rate_headers or '-'} error={error or '-'}")
        observations.append({"n": i, "status": status, "time": round(elapsed, 3), "rate_headers": rate_headers, "error": error})
        time.sleep(args.delay)

    findings = []
    if not saw_limit and count >= 5 and all(o.get("status", 0) < 500 for o in observations if not o.get("error")):
        findings.append({"title": "No observable rate limiting", "severity": "Medium", "evidence": f"{count} requests completed without 429 or rate-limit headers", "status": "Unconfirmed until endpoint abuse risk is classified"})

    print("JSON_SNIPPET:", json.dumps({"tool": "rate_limit_test", "target": args.target_url, "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
