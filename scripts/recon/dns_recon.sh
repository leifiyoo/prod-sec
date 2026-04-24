#!/usr/bin/env bash
# DNS reconnaissance for a target host.
#
# Tests A/AAAA/MX/NS/TXT/DMARC/SPF records and flags takeover/email-auth
# indicators. A positive result is a dangling cloud/provider CNAME, weak email
# authentication, or unexpected DNS exposure. Safe mode performs passive DNS
# queries only.

set -u

GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
RESET="\033[0m"

TARGET=""
SAFE_MODE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --safe-mode) SAFE_MODE=1; shift ;;
    -h|--help)
      echo "Usage: $0 TARGET_HOST [--safe-mode]"
      exit 0
      ;;
    *) TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo -e "${RED}[ERROR]${RESET} TARGET_HOST is required"
  exit 2
fi

HOST="${TARGET#http://}"
HOST="${HOST#https://}"
HOST="${HOST%%/*}"
HOST="${HOST%%:*}"

query_record() {
  local type="$1"
  local name="$2"
  if command -v dig >/dev/null 2>&1; then
    dig +short "$type" "$name" 2>/dev/null
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup -type="$type" "$name" 2>/dev/null
  else
    echo "[WARN] dig/nslookup unavailable"
  fi
}

echo -e "${GREEN}[INFO]${RESET} DNS recon for $HOST safe_mode=$SAFE_MODE"
FINDINGS=()

for type in A AAAA CNAME MX NS TXT; do
  OUT="$(query_record "$type" "$HOST" | sed 's/"/\\"/g')"
  if [[ -n "$OUT" ]]; then
    echo -e "${GREEN}[DNS]${RESET} $type"
    echo "$OUT"
    LOWER="$(echo "$OUT" | tr '[:upper:]' '[:lower:]')"
    if [[ "$type" == "CNAME" ]] && echo "$LOWER" | grep -Eq 'amazonaws.com|azurewebsites.net|cloudapp.net|herokuapp.com|github.io|fastly.net'; then
      echo -e "${YELLOW}[SIGNAL]${RESET} Cloud/provider CNAME requires takeover validation"
      FINDINGS+=("{\"title\":\"Cloud/provider CNAME takeover candidate\",\"severity\":\"Medium\",\"evidence\":\"$OUT\"}")
    fi
  else
    echo -e "${YELLOW}[DNS]${RESET} $type no records observed"
  fi
done

DMARC="$(query_record TXT "_dmarc.$HOST")"
if [[ -z "$DMARC" ]]; then
  echo -e "${YELLOW}[FINDING]${RESET} DMARC record missing"
  FINDINGS+=("{\"title\":\"Missing DMARC record\",\"severity\":\"Low\",\"evidence\":\"_dmarc.$HOST TXT not found\"}")
elif echo "$DMARC" | grep -Eiq 'p=none'; then
  echo -e "${YELLOW}[FINDING]${RESET} DMARC policy is p=none"
  FINDINGS+=("{\"title\":\"Weak DMARC policy\",\"severity\":\"Low\",\"evidence\":\"$DMARC\"}")
fi

SPF="$(query_record TXT "$HOST" | grep -i 'v=spf1' || true)"
if [[ -z "$SPF" ]]; then
  echo -e "${YELLOW}[FINDING]${RESET} SPF record missing"
  FINDINGS+=("{\"title\":\"Missing SPF record\",\"severity\":\"Low\",\"evidence\":\"$HOST TXT v=spf1 not found\"}")
fi

printf 'JSON_SNIPPET: {"tool":"dns_recon","target":"%s","findings":[%s]}\n' "$HOST" "$(IFS=,; echo "${FINDINGS[*]-}")"
