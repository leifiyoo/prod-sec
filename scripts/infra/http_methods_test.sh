#!/usr/bin/env bash
# HTTP method hardening test.
#
# Tests OPTIONS and TRACE in safe mode, and optionally PUT when safe mode is
# disabled. A positive result is TRACE echo, unexpected write methods, or overly
# broad Allow headers.

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
      echo "Usage: $0 TARGET_URL [--safe-mode]"
      exit 0
      ;;
    *) TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo -e "${RED}[ERROR]${RESET} TARGET_URL is required"
  exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
  echo -e "${RED}[ERROR]${RESET} curl is required"
  exit 2
fi

FINDINGS=()
echo -e "${GREEN}[INFO]${RESET} HTTP method test for $TARGET safe_mode=$SAFE_MODE"

OPTIONS="$(curl -sk -i -X OPTIONS --max-time 8 "$TARGET" 2>/dev/null)"
ALLOW="$(echo "$OPTIONS" | awk 'BEGIN{IGNORECASE=1}/^Allow:|^Access-Control-Allow-Methods:/{print}' | tr -d '\r')"
echo -e "${GREEN}[OPTIONS]${RESET} ${ALLOW:-no Allow header}"
if echo "$ALLOW" | grep -Eiq 'PUT|DELETE|PATCH'; then
  FINDINGS+=("{\"title\":\"Potentially dangerous methods advertised\",\"severity\":\"Medium\",\"evidence\":\"$ALLOW\"}")
fi

TRACE="$(curl -sk -i -X TRACE -H 'X-ProdSec-Trace: method-test' --max-time 8 "$TARGET" 2>/dev/null)"
TRACE_CODE="$(echo "$TRACE" | awk 'NR==1{print $2}')"
echo -e "${GREEN}[TRACE]${RESET} status=${TRACE_CODE:-unknown}"
if echo "$TRACE" | grep -q 'X-ProdSec-Trace: method-test'; then
  echo -e "${YELLOW}[FINDING]${RESET} TRACE echoed request header"
  FINDINGS+=("{\"title\":\"TRACE method enabled\",\"severity\":\"Medium\",\"evidence\":\"TRACE echoed X-ProdSec-Trace\"}")
fi

if [[ "$SAFE_MODE" -eq 0 ]]; then
  TEST_URL="${TARGET%/}/prodsec-method-test.txt"
  PUT="$(curl -sk -i -X PUT --max-time 8 --data 'prodsec-test' "$TEST_URL" 2>/dev/null)"
  PUT_CODE="$(echo "$PUT" | awk 'NR==1{print $2}')"
  echo -e "${GREEN}[PUT]${RESET} $TEST_URL status=${PUT_CODE:-unknown}"
  if [[ "$PUT_CODE" =~ ^20[0-9]$ ]]; then
    FINDINGS+=("{\"title\":\"Unauthenticated PUT may be enabled\",\"severity\":\"High\",\"evidence\":\"PUT $TEST_URL returned $PUT_CODE\"}")
  fi
fi

printf 'JSON_SNIPPET: {"tool":"http_methods_test","target":"%s","findings":[%s]}\n' "$TARGET" "$(IFS=,; echo "${FINDINGS[*]-}")"
