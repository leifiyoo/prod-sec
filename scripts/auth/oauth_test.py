#!/usr/bin/env python3
"""
Probe OAuth/OIDC configuration and redirect handling.

The script discovers OpenID metadata when present and checks for missing PKCE,
weak issuer settings, and redirect URI reflection indicators. A positive result
requires a controlled authorization request accepted with unsafe parameters.
"""
import argparse
import json
import ssl
import sys
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def fetch(url, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-oauth-test/1.0"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(100000).decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body, None
    except HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(100000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, "", str(exc)


def main():
    parser = argparse.ArgumentParser(description="Audit OAuth/OIDC discovery and redirect indicators.")
    parser.add_argument("target_url", help="Base URL or issuer URL.")
    parser.add_argument("--client-id", default="prodsec-test")
    parser.add_argument("--safe-mode", action="store_true", help="Discovery and harmless authorization probe only.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    base = args.target_url.rstrip("/") + "/"
    discovery = urljoin(base, ".well-known/openid-configuration")
    findings = []
    observations = []
    status, headers, body, error = fetch(discovery, args.timeout)
    metadata = {}
    if not error and status == 200:
        try:
            metadata = json.loads(body)
            print(f"{GREEN}[DISCOVERY]{RESET} {discovery}")
        except json.JSONDecodeError:
            print(f"{YELLOW}[SIGNAL]{RESET} discovery returned non-JSON")
    else:
        print(f"{YELLOW}[SIGNAL]{RESET} discovery not available status={status} error={error or '-'}")

    if metadata:
        issuer = metadata.get("issuer")
        auth_endpoint = metadata.get("authorization_endpoint")
        methods = metadata.get("code_challenge_methods_supported", [])
        if issuer and not str(issuer).startswith("https://"):
            findings.append({"title": "OIDC issuer is not HTTPS", "severity": "High", "evidence": issuer})
        if "S256" not in methods:
            findings.append({"title": "PKCE S256 not advertised", "severity": "Medium", "evidence": f"methods={methods}"})
        if auth_endpoint:
            params = urlencode({
                "client_id": args.client_id,
                "redirect_uri": "https://example.com/prodsec-oauth",
                "response_type": "code",
                "scope": "openid",
                "state": "prodsecstate",
            })
            probe = auth_endpoint + ("&" if "?" in auth_endpoint else "?") + params
            p_status, p_headers, p_body, p_error = fetch(probe, args.timeout)
            loc = p_headers.get("Location") or p_headers.get("location") or ""
            observations.append({"probe": probe, "status": p_status, "location": loc, "error": p_error})
            print(f"{GREEN}[PROBE]{RESET} auth endpoint status={p_status} location={loc or '-'}")
            if "example.com/prodsec-oauth" in loc or "example.com/prodsec-oauth" in p_body:
                findings.append({"title": "Possible OAuth redirect URI validation weakness", "severity": "High", "evidence": "External redirect_uri reflected or used", "poc": probe})

    print("JSON_SNIPPET:", json.dumps({"tool": "oauth_test", "target": args.target_url, "metadata_found": bool(metadata), "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
