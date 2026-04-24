#!/usr/bin/env python3
"""
Actively test open redirect parameters.

The script injects external URL payloads into a chosen parameter and checks
Location headers and response bodies. A positive result is a redirect or client
navigation to an attacker-controlled origin.
"""
import argparse
import json
import ssl
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def mutate(url, param, value):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(qs), parts.fragment))


def fetch(url, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-open-redirect/1.0"})
    opener = build_opener(NoRedirect, HTTPSHandler(context=ssl._create_unverified_context()))
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(2000).decode("utf-8", "replace")
        return resp.status, dict(resp.headers), body, None
    except HTTPError as exc:
        body = exc.read(2000).decode("utf-8", "replace")
        return exc.code, dict(exc.headers), body, None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, "", str(exc)


def main():
    parser = argparse.ArgumentParser(description="Scan one parameter for open redirect.")
    parser.add_argument("target_url")
    parser.add_argument("--param", default="next")
    parser.add_argument("--safe-mode", action="store_true", help="Use harmless example.com payloads only.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    payloads = ["https://example.com/prodsec", "//example.com/prodsec", "///example.com/%2f..", "https:example.com"]
    findings = []
    for payload in payloads:
        url = mutate(args.target_url, args.param, payload)
        status, headers, body, error = fetch(url, args.timeout)
        if error:
            print(f"{RED}[ERROR]{RESET} {payload}: {error}")
            continue
        location = headers.get("Location") or headers.get("location") or ""
        print(f"{GREEN}[INFO]{RESET} payload={payload!r} status={status} location={location!r}")
        if status in (301, 302, 303, 307, 308) and "example.com" in location.lower():
            finding = {"title": "Open redirect", "severity": "Medium", "evidence": f"Payload {payload!r} produced Location {location!r}", "poc": url}
            findings.append(finding)
            print(f"{YELLOW}[FINDING]{RESET} {finding['evidence']}")
        elif "example.com/prodsec" in body.lower():
            finding = {"title": "Possible client-side open redirect", "severity": "Low", "evidence": f"Payload reflected in body: {payload}", "poc": url}
            findings.append(finding)
            print(f"{YELLOW}[SIGNAL]{RESET} {finding['evidence']}")

    print("JSON_SNIPPET:", json.dumps({"tool": "open_redirect_scan", "target": args.target_url, "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
