#!/usr/bin/env python3
"""
Test CORS policy with hostile and null origins.

A positive result is reflection of an untrusted Origin, wildcard access with
credentials, or permissive preflight behavior that enables cross-site API reads
from attacker-controlled origins.
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


def send(url, origin, method, timeout):
    headers = {
        "User-Agent": "prod-sec-cors-tester/1.0",
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    req = Request(url, method=method, headers=headers)
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            return resp.status, dict(resp.headers), None
    except HTTPError as exc:
        return exc.code, dict(exc.headers), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, str(exc)


def h(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def main():
    parser = argparse.ArgumentParser(description="Test CORS policy with untrusted origins.")
    parser.add_argument("target_url")
    parser.add_argument("--safe-mode", action="store_true", help="Use OPTIONS/GET only.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    origins = ["https://evil.example", "null", "https://sub.evil.example"]
    findings = []
    for origin in origins:
        for method in ("OPTIONS", "GET"):
            status, headers, error = send(args.target_url, origin, method, args.timeout)
            if error:
                print(f"{RED}[ERROR]{RESET} {origin} {method}: {error}")
                continue
            acao = h(headers, "Access-Control-Allow-Origin")
            acac = h(headers, "Access-Control-Allow-Credentials")
            print(f"{GREEN}[INFO]{RESET} {method} origin={origin} status={status} ACAO={acao!r} ACAC={acac!r}")
            if acao == origin or acao == "*":
                severity = "High" if acac.lower() == "true" else "Medium"
                title = "Permissive CORS policy"
                evidence = f"{method} reflected/allowed Origin {origin}; ACAO={acao}; ACAC={acac}"
                findings.append({"title": title, "severity": severity, "evidence": evidence, "poc": f"curl -H 'Origin: {origin}' -i {args.target_url}"})
                print(f"{YELLOW}[FINDING]{RESET} {evidence}")

    print("JSON_SNIPPET:", json.dumps({"tool": "cors_tester", "target": args.target_url, "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
