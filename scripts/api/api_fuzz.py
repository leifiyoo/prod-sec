#!/usr/bin/env python3
"""
Fuzz REST/API endpoints for validation, mass assignment, and verbose errors.

Safe mode sends a small number of benign payloads. A positive result is accepted
unknown fields, role/tenant field effects, stack traces, or inconsistent auth
behavior.
"""
import argparse
import json
import re
import ssl
import sys
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

ERROR_RX = re.compile(r"(Traceback|Exception|stack trace|TypeError|ReferenceError|NullPointer|SQLSTATE|at [a-zA-Z0-9_.$]+\(.*:\d+)", re.I)


def call(url, method, payload, token, timeout):
    headers = {"User-Agent": "prod-sec-api-fuzz/1.0", "X-ProdSec-Canary": "api-fuzz"}
    data = None
    req_url = url
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if method in ("POST", "PUT", "PATCH"):
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    else:
        req_url = url + ("&" if "?" in url else "?") + urlencode(payload)
    req = Request(req_url, data=data, method=method, headers=headers)
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(100000).decode("utf-8", "replace")
            return resp.status, body, None
    except HTTPError as exc:
        return exc.code, exc.read(100000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, "", str(exc)


def main():
    parser = argparse.ArgumentParser(description="Small active API fuzzing harness.")
    parser.add_argument("target_url")
    parser.add_argument("--method", choices=["GET", "POST", "PUT", "PATCH"], default="GET")
    parser.add_argument("--token")
    parser.add_argument("--safe-mode", action="store_true", help="Limit to benign marker fields.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    payloads = [
        {"prodsec_canary": "api-fuzz"},
        {"role": "admin", "prodsec_canary": "api-fuzz"},
        {"isAdmin": True, "tenantId": "prodsec-other-tenant", "prodsec_canary": "api-fuzz"},
        {"price": -1, "quantity": -1, "prodsec_canary": "api-fuzz"},
    ]
    if args.safe_mode:
        payloads = payloads[:3]

    findings = []
    observations = []
    for payload in payloads:
        status, body, error = call(args.target_url, args.method, payload, args.token, args.timeout)
        if error:
            print(f"{RED}[ERROR]{RESET} payload={payload} error={error}")
            continue
        verbose = bool(ERROR_RX.search(body[:5000]))
        reflected = any(str(v) in body for v in payload.values())
        observations.append({"payload": payload, "status": status, "length": len(body), "verbose_error": verbose, "reflected": reflected})
        print(f"{GREEN if not verbose else YELLOW}[TEST]{RESET} status={status} len={len(body)} verbose={verbose} reflected={reflected} payload={payload}")
        if verbose:
            findings.append({"title": "Verbose API error disclosure", "severity": "Medium", "evidence": f"Stack/error marker returned for payload {payload}"})
        risky_fields = any(k in payload for k in ("role", "isAdmin", "tenantId", "price", "quantity"))
        state_changing = args.method in ("POST", "PUT", "PATCH")
        if state_changing and status in (200, 201, 202, 204) and risky_fields:
            findings.append({"title": "Potential mass assignment or business logic acceptance", "severity": "High", "evidence": f"Privileged/business fields accepted with HTTP {status}: {payload}", "status": "Unconfirmed until state change is verified"})
        elif not state_changing and status in (200, 201, 202, 204) and risky_fields and reflected:
            findings.append({"title": "Potential reflected privileged fields", "severity": "Medium", "evidence": f"Privileged/business fields reflected by read endpoint: {payload}", "status": "Unconfirmed until response semantics are reviewed"})

    print("JSON_SNIPPET:", json.dumps({"tool": "api_fuzz", "target": args.target_url, "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
