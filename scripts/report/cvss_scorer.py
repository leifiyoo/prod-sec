#!/usr/bin/env python3
"""
Compute CVSS v3.1 base scores interactively or from a vector.

The script implements the CVSS v3.1 base-score formula. A positive output is a
numeric score, severity band, and vector string suitable for the final report.
"""
import argparse
import math
import sys

METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PRU": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PRC": {"N": 0.85, "L": 0.68, "H": 0.50},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "U", "C": "C"},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def roundup(value):
    return math.ceil(value * 10) / 10.0


def severity(score):
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def parse_vector(vector):
    if vector.startswith("CVSS:3.1/"):
        vector = vector[len("CVSS:3.1/"):]
    parts = {}
    for item in vector.split("/"):
        if ":" in item:
            key, value = item.split(":", 1)
            parts[key] = value
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [m for m in required if m not in parts]
    if missing:
        raise ValueError(f"missing metrics: {', '.join(missing)}")
    return parts


def score(parts):
    scope = parts["S"]
    pr_key = "PRC" if scope == "C" else "PRU"
    isc = 1 - ((1 - METRICS["C"][parts["C"]]) * (1 - METRICS["I"][parts["I"]]) * (1 - METRICS["A"][parts["A"]]))
    impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15) if scope == "C" else 6.42 * isc
    exploitability = 8.22 * METRICS["AV"][parts["AV"]] * METRICS["AC"][parts["AC"]] * METRICS[pr_key][parts["PR"]] * METRICS["UI"][parts["UI"]]
    if impact <= 0:
        return 0.0
    if scope == "C":
        return min(roundup(1.08 * (impact + exploitability)), 10.0)
    return min(roundup(impact + exploitability), 10.0)


def prompt_metric(name, options):
    while True:
        value = input(f"{name} ({'/'.join(options)}): ").strip().upper()
        if value in options:
            return value
        print("Invalid value")


def main():
    parser = argparse.ArgumentParser(description="CVSS v3.1 base score calculator.")
    parser.add_argument("--vector", help="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    args = parser.parse_args()

    if args.vector:
        try:
            parts = parse_vector(args.vector)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return 2
    else:
        parts = {
            "AV": prompt_metric("Attack Vector", ["N", "A", "L", "P"]),
            "AC": prompt_metric("Attack Complexity", ["L", "H"]),
            "PR": prompt_metric("Privileges Required", ["N", "L", "H"]),
            "UI": prompt_metric("User Interaction", ["N", "R"]),
            "S": prompt_metric("Scope", ["U", "C"]),
            "C": prompt_metric("Confidentiality", ["H", "L", "N"]),
            "I": prompt_metric("Integrity", ["H", "L", "N"]),
            "A": prompt_metric("Availability", ["H", "L", "N"]),
        }
    vector = "CVSS:3.1/" + "/".join(f"{k}:{parts[k]}" for k in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"])
    value = score(parts)
    print(f"Vector: {vector}")
    print(f"Score: {value:.1f}")
    print(f"Severity: {severity(value)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
