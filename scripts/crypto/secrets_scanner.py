#!/usr/bin/env python3
"""
Scan a local path or URL for high-confidence secret patterns.

The script searches source, configuration, and fetched text for API keys,
private keys, tokens, and cloud credentials. A positive result is a likely
secret value location; do not use discovered credentials unless explicitly
authorized for validation.
"""
import argparse
import json
import os
import re
import ssl
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    "generic_secret_assignment": re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"),
}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}


def fetch_url(url, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-secrets-scanner/1.0"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            return resp.read(1000000).decode("utf-8", "replace"), None
    except HTTPError as exc:
        return exc.read(1000000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return "", str(exc)


def iter_files(root, max_files):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if count >= max_files:
                return
            path = Path(dirpath) / name
            if path.stat().st_size > 2_000_000:
                continue
            count += 1
            yield path


def scan_text(label, text):
    hits = []
    for name, rx in PATTERNS.items():
        for match in rx.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            value = match.group(0)
            hits.append({"type": name, "location": label, "line": line_no, "sample": value[:8] + "..." + value[-4:]})
    return hits


def main():
    parser = argparse.ArgumentParser(description="Scan path or URL for likely secrets.")
    parser.add_argument("target", help="Local path or URL")
    parser.add_argument("--safe-mode", action="store_true", help="Do not validate discovered secrets.")
    parser.add_argument("--max-files", type=int, default=500)
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    hits = []
    if args.target.startswith(("http://", "https://")):
        text, error = fetch_url(args.target, args.timeout)
        if error:
            print(f"{RED}[ERROR]{RESET} {error}")
            return 2
        hits.extend(scan_text(args.target, text))
    else:
        root = Path(args.target)
        if root.is_file():
            hits.extend(scan_text(str(root), root.read_text(encoding="utf-8", errors="ignore")))
        elif root.is_dir():
            for path in iter_files(root, args.max_files):
                try:
                    hits.extend(scan_text(str(path), path.read_text(encoding="utf-8", errors="ignore")))
                except OSError:
                    pass
        else:
            print(f"{RED}[ERROR]{RESET} target not found: {args.target}")
            return 2

    findings = []
    for hit in hits:
        print(f"{YELLOW}[SECRET]{RESET} {hit['type']} {hit['location']}:{hit['line']} sample={hit['sample']}")
        findings.append({"title": f"Potential secret: {hit['type']}", "severity": "High", "evidence": f"{hit['location']}:{hit['line']} sample={hit['sample']}", "status": "Unconfirmed until key is rotated/validated by owner"})
    if not hits:
        print(f"{GREEN}[PASS]{RESET} no high-confidence secrets found")

    print("JSON_SNIPPET:", json.dumps({"tool": "secrets_scanner", "target": args.target, "findings": findings, "hits": hits}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
