#!/usr/bin/env python3
"""
Test a URL parameter for SQL injection indicators.

The script sends baseline, quote, boolean, and optional low-delay payloads. A
positive result is a reproducible status/body/timing difference or SQL error
caused by the payload. Safe mode avoids time-delay payloads.
"""
import argparse
import json
import re
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

SQL_ERRORS = re.compile(r"(SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL|SQLite/JDBC|sqlite3\.|ODBC|SQLSTATE|syntax error at or near|Unclosed quotation)", re.I)


def mutate(url, param, value):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    original = qs.get(param, "1")
    qs[param] = f"{original}{value}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(qs), parts.fragment))


def fetch(url, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-sqli-test/1.0"})
    start = time.monotonic()
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            body = resp.read(300000).decode("utf-8", "replace")
            return resp.status, len(body), body[:5000], time.monotonic() - start, None
    except HTTPError as exc:
        body = exc.read(300000).decode("utf-8", "replace")
        return exc.code, len(body), body[:5000], time.monotonic() - start, None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, 0, "", time.monotonic() - start, str(exc)


def main():
    parser = argparse.ArgumentParser(description="Probe SQL injection indicators in a query parameter.")
    parser.add_argument("target_url")
    parser.add_argument("--param", required=True)
    parser.add_argument("--safe-mode", action="store_true", help="Skip time-delay payloads.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    payloads = [("quote", "'"), ("bool_true", "' AND '1'='1"), ("bool_false", "' AND '1'='2"), ("comment", "'--")]
    if not args.safe_mode:
        payloads.append(("time_delay", "' OR SLEEP(1)--"))

    base_status, base_len, base_body, base_time, error = fetch(args.target_url, args.timeout)
    if error:
        print(f"{RED}[ERROR]{RESET} baseline failed: {error}")
        print("JSON_SNIPPET:", json.dumps({"tool": "sqli_test", "target": args.target_url, "error": error}))
        return 2
    print(f"{GREEN}[BASE]{RESET} status={base_status} len={base_len} time={base_time:.2f}s")

    observations = []
    for name, payload in payloads:
        url = mutate(args.target_url, args.param, payload)
        status, length, body, elapsed, err = fetch(url, args.timeout)
        if err:
            print(f"{RED}[ERROR]{RESET} {name}: {err}")
            continue
        evidence = {"payload": payload, "status": status, "length": length, "time": round(elapsed, 3)}
        if SQL_ERRORS.search(body):
            evidence["indicator"] = "sql_error"
        elif abs(length - base_len) > max(50, base_len * 0.15):
            evidence["indicator"] = "body_length_delta"
        elif status != base_status:
            evidence["indicator"] = "status_delta"
        elif name == "time_delay" and elapsed - base_time > 0.8:
            evidence["indicator"] = "time_delta"
        observations.append(evidence)
        marker = YELLOW if evidence.get("indicator") else GREEN
        print(f"{marker}[TEST]{RESET} {name} status={status} len={length} time={elapsed:.2f}s indicator={evidence.get('indicator', '-')}")

    has_bool_split = False
    by_name = {o["payload"]: o for o in observations}
    true_obs = by_name.get("' AND '1'='1")
    false_obs = by_name.get("' AND '1'='2")
    if true_obs and false_obs:
        has_bool_split = abs(true_obs["length"] - false_obs["length"]) > 50 or true_obs["status"] != false_obs["status"]

    findings = []
    if any(o.get("indicator") for o in observations) or has_bool_split:
        findings.append({
            "title": "Possible SQL injection",
            "severity": "High",
            "evidence": "Payloads produced SQL error, status/body delta, timing delta, or boolean split",
            "poc": f"Parameter {args.param}; observations={observations}",
            "status": "Confirmed" if any(o.get("indicator") == "sql_error" for o in observations) or has_bool_split else "Unconfirmed",
        })

    print("JSON_SNIPPET:", json.dumps({"tool": "sqli_test", "target": args.target_url, "param": args.param, "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
