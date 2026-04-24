#!/usr/bin/env python3
"""
Defensive static security audit helper.

Scans a local source tree for risky coding patterns that commonly lead to
security findings. It does not contact remote targets, exploit applications, or
run payloads. A positive result means a human or AI reviewer should inspect the
referenced line and confirm whether the surrounding code is vulnerable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


RULES = [
    {
        "id": "SEC-EVAL-001",
        "severity": "High",
        "pattern": re.compile(r"\b(eval|exec)\s*\("),
        "description": "Dynamic code execution detected.",
        "remediation": "Replace dynamic execution with explicit parsing or a safe dispatch table.",
    },
    {
        "id": "SEC-SHELL-001",
        "severity": "High",
        "pattern": re.compile(r"(shell\s*=\s*True|child_process\.exec\s*\(|Runtime\.getRuntime\(\)\.exec)"),
        "description": "Shell command execution path detected.",
        "remediation": "Use argument-array execution APIs, strict allowlists, and avoid shell interpolation.",
    },
    {
        "id": "SEC-SQL-001",
        "severity": "High",
        "pattern": re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(\+|f[\"']|%|\$\{)", re.IGNORECASE),
        "description": "Possible string-built SQL query.",
        "remediation": "Use parameterized queries or ORM bind parameters for every untrusted value.",
    },
    {
        "id": "SEC-XSS-001",
        "severity": "Medium",
        "pattern": re.compile(r"(dangerouslySetInnerHTML|innerHTML\s*=|v-html=|bypassSecurityTrustHtml)"),
        "description": "Raw HTML sink detected.",
        "remediation": "Prefer framework escaping; sanitize trusted HTML with a maintained sanitizer.",
    },
    {
        "id": "SEC-CRYPTO-001",
        "severity": "Medium",
        "pattern": re.compile(r"\b(md5|sha1|DES|RC4)\b", re.IGNORECASE),
        "description": "Weak cryptographic primitive detected.",
        "remediation": "Use modern primitives such as Argon2id/bcrypt/scrypt for passwords and SHA-256+ for integrity.",
    },
    {
        "id": "SEC-TLS-001",
        "severity": "High",
        "pattern": re.compile(r"(rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0)"),
        "description": "TLS certificate validation appears disabled.",
        "remediation": "Keep certificate validation enabled and configure trusted CA bundles explicitly.",
    },
]

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next", ".venv", "__pycache__"}
TEXT_EXTS = {
    ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".java", ".go", ".rs", ".cs",
    ".kt", ".swift", ".mjs", ".cjs", ".html", ".vue", ".svelte", ".sql", ".yml", ".yaml",
    ".json", ".env", ".toml", ".ini", ".conf", ".sh", ".ps1",
}


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in TEXT_EXTS or name.startswith(".env"):
                yield path


def scan(root: Path):
    findings = []
    for path in iter_files(root):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            findings.append({
                "id": "SEC-IO-001",
                "severity": "Info",
                "file": str(path),
                "line": 0,
                "description": f"Could not read file: {exc}",
                "remediation": "Check file permissions if this file should be audited.",
            })
            continue
        for number, line in enumerate(lines, 1):
            compact = line.strip()
            if not compact or compact.startswith(("#", "//", "*")):
                continue
            if path.name == "static_code_audit.py" and '"pattern": re.compile' in compact:
                continue
            for rule in RULES:
                if rule["pattern"].search(compact):
                    findings.append({
                        "id": rule["id"],
                        "severity": rule["severity"],
                        "file": str(path.relative_to(root)),
                        "line": number,
                        "description": rule["description"],
                        "evidence": compact[:240],
                        "remediation": rule["remediation"],
                    })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a local codebase for defensive security review signals.")
    parser.add_argument("path", help="Local repository or source directory to scan.")
    parser.add_argument("--json-out", help="Write findings as JSON.")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        parser.error(f"path does not exist: {root}")

    findings = scan(root)
    print(json.dumps({"tool": "static_code_audit", "target": str(root), "findings": findings}, indent=2))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
