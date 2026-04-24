#!/usr/bin/env python3
"""
Generate Markdown and HTML security reports from JSON findings.

Input may be a JSON list, an object with a findings key, or JSONL containing
script snippets. Output includes executive summary, severity-sorted findings,
proof of concept, impact, CVSS, remediation, and a coverage matrix.
"""
import argparse
import html
import json
import sys
from pathlib import Path

ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
DOMAINS = [
    "Recon", "Authentication", "Authorization", "Session", "Injection", "XSS/CSRF",
    "SSRF/LFI", "Crypto", "API", "Infrastructure", "Cloud", "Database",
    "Supply Chain", "Monitoring", "Identity", "Resilience", "Compliance", "Advanced",
]


def load_findings(path):
    text = Path(path).read_text(encoding="utf-8-sig", errors="ignore")
    findings = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = data.get("findings", [])
            if not findings and "tool" in data:
                findings = data.get("findings", [])
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    findings.extend(item.get("findings", []))
            except json.JSONDecodeError:
                continue
    normalized = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "title": item.get("title", "Untitled finding"),
            "severity": item.get("severity", "Info"),
            "description": item.get("description", item.get("evidence", "")),
            "poc": item.get("poc", ""),
            "impact": item.get("impact", ""),
            "cvss": item.get("cvss", ""),
            "remediation": item.get("remediation", "Implement the control described by the finding and retest with the original payload."),
            "domain": item.get("domain", infer_domain(item)),
            "status": item.get("status", "Confirmed" if item.get("severity") not in ("Info",) else "Observed"),
        })
    return sorted(normalized, key=lambda f: ORDER.get(f["severity"], 5))


def infer_domain(item):
    text = json.dumps(item).lower()
    for needle, domain in [
        ("auth", "Authentication"), ("session", "Session"), ("sqli", "Injection"),
        ("injection", "Injection"), ("xss", "XSS/CSRF"), ("csrf", "XSS/CSRF"),
        ("ssrf", "SSRF/LFI"), ("lfi", "SSRF/LFI"), ("jwt", "Crypto"),
        ("tls", "Crypto"), ("api", "API"), ("graphql", "API"), ("cloud", "Cloud"),
        ("docker", "Infrastructure"), ("secret", "Supply Chain"), ("rate", "API"),
    ]:
        if needle in text:
            return domain
    return "Recon"


def risk_rating(findings):
    if any(f["severity"] == "Critical" for f in findings):
        return "Critical"
    if any(f["severity"] == "High" for f in findings):
        return "High"
    if any(f["severity"] == "Medium" for f in findings):
        return "Medium"
    if any(f["severity"] == "Low" for f in findings):
        return "Low"
    return "Info"


def markdown(findings):
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in ORDER}
    lines = [
        "# Security Assessment Report",
        "",
        "## Executive Summary",
        f"Overall risk rating: **{risk_rating(findings)}**",
        "",
        "Finding counts: " + ", ".join(f"{k}: {v}" for k, v in counts.items()),
        "",
        "## Coverage Matrix",
        "",
        "| Domain | Status |",
        "|---|---|",
    ]
    tested = {f["domain"] for f in findings}
    for domain in DOMAINS:
        lines.append(f"| {domain} | {'Tested' if domain in tested else 'Not evidenced in findings input'} |")
    lines.extend(["", "## Findings", ""])
    for index, finding in enumerate(findings, 1):
        lines.extend([
            f"### {index}. {finding['title']} ({finding['severity']})",
            "",
            f"**Status:** {finding['status']}",
            f"**Domain:** {finding['domain']}",
            f"**CVSS:** {finding['cvss'] or 'Not scored'}",
            "",
            "**Description**",
            finding["description"] or "No description supplied.",
            "",
            "**Proof of Concept**",
            f"```text\n{finding['poc'] or 'No PoC supplied.'}\n```",
            "",
            "**Impact**",
            finding["impact"] or "Impact should be confirmed from affected data, privilege, and exploit chainability.",
            "",
            "**Remediation**",
            finding["remediation"],
            "",
        ])
    return "\n".join(lines)


def html_report(md):
    escaped = html.escape(md)
    body = escaped.replace("\n", "<br>\n")
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Security Assessment Report</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1100px;margin:32px auto;line-height:1.5;color:#1f2937}}
code,pre{{background:#f3f4f6;padding:2px 4px;border-radius:4px}}
h1,h2,h3{{color:#111827}}
</style></head><body>{body}</body></html>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate Markdown and HTML security report.")
    parser.add_argument("findings_json")
    parser.add_argument("--out", default="report", help="Output basename or directory.")
    args = parser.parse_args()

    findings = load_findings(args.findings_json)
    out = Path(args.out)
    if out.suffix:
        base = out.with_suffix("")
        out.parent.mkdir(parents=True, exist_ok=True)
    else:
        out.mkdir(parents=True, exist_ok=True)
        base = out / "security_report"
    md = markdown(findings)
    md_path = base.with_suffix(".md")
    html_path = base.with_suffix(".html")
    md_path.write_text(md, encoding="utf-8")
    html_path.write_text(html_report(md), encoding="utf-8")
    print(f"Wrote {md_path}")
    print(f"Wrote {html_path}")
    print(json.dumps({"tool": "generate_report", "markdown": str(md_path), "html": str(html_path), "finding_count": len(findings), "risk_rating": risk_rating(findings)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
