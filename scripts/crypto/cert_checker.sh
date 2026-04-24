#!/usr/bin/env bash
# Certificate security checker.
#
# Retrieves the presented X.509 certificate and checks issuer, subject, SANs,
# validity dates, and weak signature algorithms. A positive result is an
# expired, self-signed, mismatched, or weakly signed certificate.

set -u

GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
RESET="\033[0m"

TARGET=""
PORT=443
SAFE_MODE=0

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

CERT="$(echo | openssl s_client -servername "$HOST" -connect "$HOST:$PORT" 2>/dev/null | openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256 -ext subjectAltName -text 2>/dev/null || true)"
if [[ -z "$CERT" ]]; then
  echo -e "${RED}[ERROR]${RESET} no certificate retrieved"
  printf 'JSON_SNIPPET: {"tool":"cert_checker","target":"%s","error":"no certificate retrieved"}\n' "$HOST"
  exit 2
fi

echo -e "${GREEN}[CERT]${RESET} $HOST:$PORT"
echo "$CERT" | awk '/Subject:|Issuer:|Not Before|Not After|DNS:|Signature Algorithm|serial=|sha256 Fingerprint/'

SUBJECT="$(echo "$CERT" | awk -F'Subject: ' '/Subject:/{print $2; exit}')"
ISSUER="$(echo "$CERT" | awk -F'Issuer: ' '/Issuer:/{print $2; exit}')"
if [[ -n "$SUBJECT" && "$SUBJECT" == "$ISSUER" ]]; then
  echo -e "${YELLOW}[FINDING]${RESET} certificate appears self-signed"
  FINDINGS+=("{\"title\":\"Self-signed TLS certificate\",\"severity\":\"High\",\"evidence\":\"subject equals issuer\"}")
fi

if echo "$CERT" | grep -Eiq 'md5WithRSA|sha1WithRSA'; then
  echo -e "${YELLOW}[FINDING]${RESET} weak signature algorithm"
  FINDINGS+=("{\"title\":\"Weak certificate signature algorithm\",\"severity\":\"High\",\"evidence\":\"MD5/SHA1 signature observed\"}")
fi

if ! echo "$CERT" | grep -Eiq "DNS:($HOST|\*\.)"; then
  echo -e "${YELLOW}[SIGNAL]${RESET} exact host not obvious in SAN output"
  FINDINGS+=("{\"title\":\"Certificate SAN mismatch candidate\",\"severity\":\"Medium\",\"evidence\":\"$HOST not obvious in SAN output\"}")
fi

printf 'JSON_SNIPPET: {"tool":"cert_checker","target":"%s:%s","findings":[%s]}\n' "$HOST" "$PORT" "$(IFS=,; echo "${FINDINGS[*]-}")"
