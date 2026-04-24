#!/usr/bin/env bash
# TLS and HTTPS configuration audit.
#
# Tests certificate presentation and protocol support using openssl. A positive
# result is expired/mismatched certificates, weak protocol support, or missing
# TLS hardening signals. Safe mode performs short handshakes only.

set -u

GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
RESET="\033[0m"

TARGET=""
SAFE_MODE=0
PORT=443

while [[ $# -gt 0 ]]; do
  case "$1" in
    --safe-mode) SAFE_MODE=1; shift ;;
    --port) PORT="${2:-443}"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 TARGET_HOST [--port 443] [--safe-mode]"
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
FINDINGS=()

if ! command -v openssl >/dev/null 2>&1; then
  echo -e "${RED}[ERROR]${RESET} openssl is required"
  exit 2
fi

echo -e "${GREEN}[INFO]${RESET} TLS audit for $HOST:$PORT safe_mode=$SAFE_MODE"
CERT="$(echo | openssl s_client -servername "$HOST" -connect "$HOST:$PORT" 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || true)"
if [[ -z "$CERT" ]]; then
  echo -e "${RED}[ERROR]${RESET} certificate not retrieved"
  printf 'JSON_SNIPPET: {"tool":"tls_audit","target":"%s","error":"certificate not retrieved"}\n' "$HOST"
  exit 2
fi
echo "$CERT"

if echo "$CERT" | grep -qi 'notAfter'; then
  END="$(echo "$CERT" | awk -F= '/notAfter/{print $2}')"
  if command -v date >/dev/null 2>&1; then
    end_epoch="$(date -d "$END" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$END" +%s 2>/dev/null || echo 0)"
    now_epoch="$(date +%s)"
    if [[ "$end_epoch" != "0" && "$end_epoch" -lt "$now_epoch" ]]; then
      echo -e "${YELLOW}[FINDING]${RESET} certificate expired"
      FINDINGS+=("{\"title\":\"Expired TLS certificate\",\"severity\":\"High\",\"evidence\":\"notAfter=$END\"}")
    fi
  fi
fi

for proto in tls1 tls1_1 tls1_2 tls1_3; do
  flag="-$proto"
  echo | openssl s_client "$flag" -servername "$HOST" -connect "$HOST:$PORT" >/tmp/prodsec_tls.$$ 2>&1
  if grep -qi 'Cipher is' /tmp/prodsec_tls.$$; then
    echo -e "${YELLOW}[PROTO]${RESET} $proto supported"
    if [[ "$proto" == "tls1" || "$proto" == "tls1_1" ]]; then
      FINDINGS+=("{\"title\":\"Legacy TLS protocol supported\",\"severity\":\"Medium\",\"evidence\":\"$proto\"}")
    fi
  else
    echo -e "${GREEN}[PROTO]${RESET} $proto not supported or handshake failed"
  fi
done
rm -f /tmp/prodsec_tls.$$

printf 'JSON_SNIPPET: {"tool":"tls_audit","target":"%s:%s","findings":[%s]}\n' "$HOST" "$PORT" "$(IFS=,; echo "${FINDINGS[*]-}")"
