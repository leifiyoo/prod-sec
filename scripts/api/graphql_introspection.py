#!/usr/bin/env python3
"""
Test GraphQL introspection and basic resolver hardening.

The script posts a standard introspection query and records whether schema
metadata is exposed. A positive result is unauthenticated or low-privilege
schema disclosure in production, especially with sensitive types or mutations.
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

QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
}
"""


def post(url, token, timeout):
    headers = {"User-Agent": "prod-sec-graphql-introspection/1.0", "Content-Type": "application/json", "X-ProdSec-Canary": "graphql"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, data=json.dumps({"query": QUERY}).encode(), method="POST", headers=headers)
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(500000).decode("utf-8", "replace")
            return resp.status, body, None
    except HTTPError as exc:
        return exc.code, exc.read(500000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, "", str(exc)


def main():
    parser = argparse.ArgumentParser(description="GraphQL introspection probe.")
    parser.add_argument("target_url")
    parser.add_argument("--token")
    parser.add_argument("--safe-mode", action="store_true", help="Single introspection request only.")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()

    status, body, error = post(args.target_url, args.token, args.timeout)
    if error:
        print(f"{RED}[ERROR]{RESET} {error}")
        print("JSON_SNIPPET:", json.dumps({"tool": "graphql_introspection", "target": args.target_url, "error": error}))
        return 2

    findings = []
    type_count = 0
    sensitive = []
    try:
        data = json.loads(body)
        types = data.get("data", {}).get("__schema", {}).get("types", []) or []
        type_count = len(types)
        sensitive = [t.get("name") for t in types if t.get("name") and any(s in t.get("name", "").lower() for s in ("admin", "secret", "token", "password", "payment"))]
    except json.JSONDecodeError:
        data = {}

    print(f"{GREEN}[INFO]{RESET} status={status} type_count={type_count} sensitive={sensitive[:10]}")
    if type_count:
        severity = "High" if sensitive else "Medium"
        findings.append({"title": "GraphQL introspection enabled", "severity": severity, "evidence": f"{type_count} types exposed; sensitive={sensitive[:10]}", "status": "Confirmed"})
        print(f"{YELLOW}[FINDING]{RESET} introspection exposed schema")

    print("JSON_SNIPPET:", json.dumps({"tool": "graphql_introspection", "target": args.target_url, "findings": findings, "type_count": type_count, "sensitive_types": sensitive[:25]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
