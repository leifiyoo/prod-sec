#!/usr/bin/env python3
"""
Test webhook signature and replay defenses with benign events.

The script sends unsigned, fake-signed, and replayed test webhook events. A
positive result is a 2xx response to unsigned or replayed events where the
endpoint should require HMAC signatures and timestamp freshness.
"""
import argparse
import hashlib
import hmac
import json
import ssl
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def post(url, body, headers, timeout):
    req_headers = {"User-Agent": "prod-sec-webhook-spoof/1.0", "Content-Type": "application/json", "X-ProdSec-Canary": "webhook"}
    req_headers.update(headers)
    req = Request(url, data=body, method="POST", headers=req_headers)
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            return resp.status, resp.read(3000).decode("utf-8", "replace"), None
    except HTTPError as exc:
        return exc.code, exc.read(3000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, "", str(exc)


def main():
    parser = argparse.ArgumentParser(description="Webhook signature/replay probe.")
    parser.add_argument("target_url")
    parser.add_argument("--secret", help="Approved test webhook secret for valid signature control.")
    parser.add_argument("--safe-mode", action="store_true", help="Send canary test events only.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    event = {"id": "prodsec-webhook-001", "type": "prodsec.test", "created": int(time.time()), "data": {"canary": True}}
    body = json.dumps(event, separators=(",", ":")).encode()
    cases = [("unsigned", {})]
    cases.append(("fake_signature", {"X-Signature": "sha256=deadbeef", "X-Webhook-Timestamp": str(event["created"])}))
    if args.secret:
        digest = hmac.new(args.secret.encode(), body, hashlib.sha256).hexdigest()
        cases.append(("valid_signature", {"X-Signature": f"sha256={digest}", "X-Webhook-Timestamp": str(event["created"])}))
        cases.append(("replay_valid_signature", {"X-Signature": f"sha256={digest}", "X-Webhook-Timestamp": str(event["created"])}))

    findings = []
    observations = []
    for name, headers in cases:
        status, response, error = post(args.target_url, body, headers, args.timeout)
        observations.append({"case": name, "status": status, "length": len(response), "error": error})
        print(f"{GREEN if status >= 400 else YELLOW}[TEST]{RESET} {name} status={status} len={len(response)} error={error or '-'}")
        if name in ("unsigned", "fake_signature") and 200 <= status < 300:
            findings.append({"title": "Webhook accepted unsigned or fake-signed event", "severity": "High", "evidence": f"{name} returned HTTP {status}", "status": "Confirmed if endpoint processes the test event"})
        if name == "replay_valid_signature" and 200 <= status < 300:
            findings.append({"title": "Webhook replay may be accepted", "severity": "Medium", "evidence": f"Replay returned HTTP {status}", "status": "Unconfirmed until event side effect/log is checked"})

    print("JSON_SNIPPET:", json.dumps({"tool": "webhook_spoof_test", "target": args.target_url, "findings": findings, "observations": observations}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
