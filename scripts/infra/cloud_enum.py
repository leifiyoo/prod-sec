#!/usr/bin/env python3
"""
Perform safe cloud exposure enumeration from a hostname.

The script checks DNS hints and common public object storage URL patterns using
HEAD/GET without authentication. A positive result is an owned cloud storage or
service endpoint that is public, listable, or misconfigured.
"""
import argparse
import json
import socket
import ssl
import subprocess
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def http_probe(url, timeout):
    req = Request(url, method="GET", headers={"User-Agent": "prod-sec-cloud-enum/1.0"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(4000).decode("utf-8", "replace")
            return resp.status, body, None
    except HTTPError as exc:
        return exc.code, exc.read(4000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, "", str(exc)


def dns_records(host):
    records = []
    try:
        records.append({"type": "A", "values": socket.gethostbyname_ex(host)[2]})
    except OSError:
        pass
    for tool in (["nslookup", "-type=CNAME", host], ["nslookup", "-type=TXT", host]):
        try:
            out = subprocess.run(tool, capture_output=True, text=True, timeout=6)
            if out.stdout:
                records.append({"type": tool[1].split("=")[-1], "raw": out.stdout[-2000:]})
        except Exception:
            pass
    return records


def main():
    parser = argparse.ArgumentParser(description="Safe cloud exposure checks for host-derived names.")
    parser.add_argument("target_host")
    parser.add_argument("--safe-mode", action="store_true", help="Only HEAD/GET public endpoints; no authenticated enumeration.")
    parser.add_argument("--timeout", type=float, default=6)
    args = parser.parse_args()

    host = args.target_host.replace("https://", "").replace("http://", "").split("/")[0]
    base = host.split(":")[0]
    candidates = [
        f"https://{base}.s3.amazonaws.com/",
        f"https://{base}.s3.us-east-1.amazonaws.com/",
        f"https://storage.googleapis.com/{base}/",
        f"https://{base}.blob.core.windows.net/",
    ]
    findings = []
    records = dns_records(base)
    for rec in records:
        print(f"{GREEN}[DNS]{RESET} {rec}")
        raw = json.dumps(rec).lower()
        if any(s in raw for s in ("amazonaws.com", "cloudfront.net", "azure", "googleusercontent", "storage.googleapis.com")):
            findings.append({"title": "Cloud DNS provider signal", "severity": "Info", "evidence": rec})

    for url in candidates:
        status, body, error = http_probe(url, args.timeout)
        print(f"{GREEN if status in (403, 404, 0) else YELLOW}[PROBE]{RESET} {url} status={status} error={error or '-'}")
        if status == 200:
            severity = "High" if "<ListBucketResult" in body or "<EnumerationResults" in body else "Medium"
            findings.append({"title": "Public cloud storage endpoint candidate", "severity": severity, "evidence": f"{url} returned HTTP 200", "poc": url})

    print("JSON_SNIPPET:", json.dumps({"tool": "cloud_enum", "target": args.target_host, "findings": findings, "dns": records}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
