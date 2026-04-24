#!/usr/bin/env python3
"""
Fingerprint web technology from HTTP responses.

Tests headers, cookies, HTML markers, robots.txt, and sitemap.xml. A positive
result is an observed framework, server, CDN, security control, or exposed file
that changes the audit plan. The script is read-only and safe by default.
"""
import argparse
import json
import re
import ssl
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


class MetaParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.meta = {}
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name"):
            self.meta[attrs.get("name", "").lower()] = attrs.get("content", "")
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])


def fetch(url, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-tech-fingerprint/1.0"})
    ctx = ssl._create_unverified_context()
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(200000).decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body, None
    except HTTPError as exc:
        body = exc.read(200000).decode("utf-8", "replace")
        return exc.code, dict(exc.headers), body, None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, {}, "", str(exc)


def detect(headers, body):
    signals = []
    server = headers.get("Server") or headers.get("server")
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by")
    if server:
        signals.append({"type": "server", "value": server})
    if powered:
        signals.append({"type": "framework", "value": powered})

    cookies = headers.get("Set-Cookie", "")
    cookie_map = {
        "laravel_session": "Laravel",
        "connect.sid": "Express",
        "csrftoken": "Django",
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
    }
    for marker, name in cookie_map.items():
        if marker.lower() in cookies.lower():
            signals.append({"type": "cookie", "value": name, "marker": marker})

    body_markers = {
        "wp-content": "WordPress",
        "__NEXT_DATA__": "Next.js",
        "data-reactroot": "React",
        "ng-version": "Angular",
        "Vue.config": "Vue",
        "webpack": "Webpack",
        "graphql": "GraphQL hint",
    }
    for marker, name in body_markers.items():
        if marker.lower() in body.lower():
            signals.append({"type": "html", "value": name, "marker": marker})

    parser = MetaParser()
    parser.feed(body)
    if parser.meta.get("generator"):
        signals.append({"type": "generator", "value": parser.meta["generator"]})
    for src in parser.scripts[:20]:
        if re.search(r"react|next|angular|vue|webpack|vite|nuxt", src, re.I):
            signals.append({"type": "script", "value": src})
    return signals


def main():
    parser = argparse.ArgumentParser(description="Fingerprint target web technology.")
    parser.add_argument("target_url", help="Target URL, for example https://example.com")
    parser.add_argument("--safe-mode", action="store_true", help="Read-only, low request count mode.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    status, headers, body, error = fetch(args.target_url, args.timeout)
    findings = []
    if error:
        print(f"{RED}[ERROR]{RESET} {error}")
        print("JSON_SNIPPET:", json.dumps({"tool": "tech_fingerprint", "target": args.target_url, "error": error}))
        return 2

    print(f"{GREEN}[INFO]{RESET} {args.target_url} returned HTTP {status}")
    signals = detect(headers, body)
    for sig in signals:
        print(f"{YELLOW}[SIGNAL]{RESET} {sig['type']}: {sig['value']}")

    for path in ("/robots.txt", "/sitemap.xml"):
        probe = urljoin(args.target_url.rstrip("/") + "/", path.lstrip("/"))
        p_status, _, p_body, p_error = fetch(probe, args.timeout)
        if not p_error and p_status < 500 and p_body:
            print(f"{YELLOW}[DISCOVERED]{RESET} {path} status={p_status} bytes={len(p_body)}")
            findings.append({"title": f"Exposed {path}", "severity": "Info", "evidence": f"HTTP {p_status}, {len(p_body)} bytes"})

    if not any(h.lower() == "content-security-policy" for h in headers):
        findings.append({"title": "Missing Content-Security-Policy header", "severity": "Low", "evidence": "Header not present"})

    snippet = {
        "tool": "tech_fingerprint",
        "target": args.target_url,
        "status": status,
        "signals": signals,
        "findings": findings,
    }
    print("JSON_SNIPPET:", json.dumps(snippet, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
