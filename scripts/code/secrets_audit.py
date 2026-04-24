#!/usr/bin/env python3
"""
Defensive secret exposure audit helper.

Scans local files for high-signal secret patterns and reports redacted evidence.
It does not validate credentials or contact third-party services. A positive
result means the secret-like value should be rotated if real and removed from
source control history.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


PATTERNS = [
    ("SECRET-AWS-KEY", "High", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SECRET-GITHUB", "High", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("SECRET-JWT", "Medium", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("SECRET-PRIVATE-KEY", "Critical", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("SECRET-ASSIGNMENT", "Medium", re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[^'\"\s]{12,}")),
]

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next", ".venv", "__pycache__"}


def redact(value: str) -> str:
    if len(value) <= 12:
        return "***"
    return value[:6] + "***" + value[-4:]


def scan(root: Path):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line_number, line in enumerate(text.splitlines(), 1):
                for rule_id, severity, pattern in PATTERNS:
                    match = pattern.search(line)
                    if match:
                        findings.append({
                            "id": rule_id,
                            "severity": severity,
                            "file": str(path.relative_to(root)),
                            "line": line_number,
                            "description": "Secret-like value detected in local source.",
                            "evidence": redact(match.group(0)),
                            "remediation": "Rotate the credential if real, remove it from source and history, and move it to a secret manager.",
                        })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a local repository for secret-like values.")
    parser.add_argument("path", help="Local repository or source directory to scan.")
    parser.add_argument("--json-out", help="Write findings as JSON.")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        parser.error(f"path does not exist: {root}")

    findings = scan(root)
    print(json.dumps({"tool": "secrets_audit", "target": str(root), "findings": findings}, indent=2))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
