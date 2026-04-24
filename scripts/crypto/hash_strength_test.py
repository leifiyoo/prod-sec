#!/usr/bin/env python3
"""
Classify password hash formats and flag weak storage patterns.

This script does not crack passwords. It identifies hash algorithms by format
and length. A positive result is unsalted, fast, legacy, or ambiguous hashes
that should be migrated to Argon2id, bcrypt, or scrypt with per-user salts.
"""
import argparse
import json
import re
import sys

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

PATTERNS = [
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), "Pass"),
    ("argon2", re.compile(r"^\$argon2(id|i|d)\$"), "Pass"),
    ("scrypt", re.compile(r"^\$scrypt\$|^scrypt:"), "Pass"),
    ("md5_hex", re.compile(r"^[a-fA-F0-9]{32}$"), "Fail"),
    ("sha1_hex", re.compile(r"^[a-fA-F0-9]{40}$"), "Fail"),
    ("sha256_hex", re.compile(r"^[a-fA-F0-9]{64}$"), "Weak"),
    ("sha512_hex", re.compile(r"^[a-fA-F0-9]{128}$"), "Weak"),
    ("ntlm", re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"), "Fail"),
]


def read_items(target):
    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError:
        return [target.strip()]


def classify(value):
    for name, rx, status in PATTERNS:
        if rx.search(value):
            return name, status
    return "unknown", "Review"


def main():
    parser = argparse.ArgumentParser(description="Classify hash strength without cracking.")
    parser.add_argument("target", help="Hash value or file containing one hash per line.")
    parser.add_argument("--safe-mode", action="store_true", help="Classification only; no cracking.")
    args = parser.parse_args()

    findings = []
    results = []
    for item in read_items(args.target):
        kind, status = classify(item)
        color = GREEN if status == "Pass" else YELLOW
        print(f"{color}[HASH]{RESET} type={kind} status={status} sample={item[:16]}...")
        results.append({"sample": item[:12] + "...", "type": kind, "status": status})
        if status in ("Fail", "Weak"):
            findings.append({"title": f"Weak password hash format: {kind}", "severity": "High" if status == "Fail" else "Medium", "evidence": f"Detected {kind}"})

    print("JSON_SNIPPET:", json.dumps({"tool": "hash_strength_test", "target": args.target, "findings": findings, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
