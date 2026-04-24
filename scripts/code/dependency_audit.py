#!/usr/bin/env python3
"""
Defensive dependency audit helper.

Inspects local manifest files and prints the package-manager commands an agent
should run for the project. It does not install packages, modify files, or query
remote services by default. A positive result means dependency manifests exist
and should be checked with the listed native audit command.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


MANIFESTS = {
    "package.json": ["npm audit --omit=dev", "pnpm audit --prod", "yarn npm audit --environment production"],
    "requirements.txt": ["pip-audit -r requirements.txt", "python -m pip list --outdated"],
    "pyproject.toml": ["pip-audit", "poetry check"],
    "Pipfile": ["pipenv check"],
    "go.mod": ["govulncheck ./..."],
    "Cargo.toml": ["cargo audit"],
    "Gemfile": ["bundle audit check --update"],
    "composer.json": ["composer audit"],
    "pom.xml": ["mvn org.owasp:dependency-check-maven:check"],
    "build.gradle": ["gradle dependencyCheckAnalyze"],
}


def find_manifests(root: Path):
    matches = []
    for name, commands in MANIFESTS.items():
        for path in root.rglob(name):
            if any(part in {".git", "node_modules", "vendor", "dist", "build"} for part in path.parts):
                continue
            matches.append({
                "file": str(path.relative_to(root)),
                "ecosystem": name,
                "recommended_commands": commands,
                "severity": "Info",
                "description": "Dependency manifest found; run the ecosystem-native audit command.",
                "remediation": "Upgrade vulnerable direct dependencies, regenerate lockfiles, and document accepted transitive risk.",
            })
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Identify dependency manifests and recommended audit commands.")
    parser.add_argument("path", help="Local repository or source directory to inspect.")
    parser.add_argument("--json-out", help="Write findings as JSON.")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        parser.error(f"path does not exist: {root}")

    findings = find_manifests(root)
    print(json.dumps({"tool": "dependency_audit", "target": str(root), "findings": findings}, indent=2))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
