#!/usr/bin/env bash
# Bounded TCP port scan for an authorized target.
#
# Uses nmap when available, otherwise falls back to bash TCP connects. A positive
# result is an exposed service that should be enumerated or closed. Safe mode
# scans only common web/admin ports.

set -u

GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
RESET="\033[0m"

TARGET=""
SAFE_MODE=0
PORTS="80,443,8080,8443,22"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --safe-mode) SAFE_MODE=1; shift ;;
    --ports) PORTS="${2:-$PORTS}"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 TARGET_HOST [--ports 80,443] [--safe-mode]"
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

OPEN=()
echo -e "${GREEN}[INFO]${RESET} Port scan for $HOST ports=$PORTS safe_mode=$SAFE_MODE"

if command -v nmap >/dev/null 2>&1; then
  if [[ "$SAFE_MODE" -eq 1 ]]; then
    OUT="$(nmap -Pn -sT --max-retries 1 --host-timeout 30s -p "$PORTS" "$HOST" 2>&1)"
  else
    OUT="$(nmap -Pn -sV --version-light --top-ports 100 "$HOST" 2>&1)"
  fi
  echo "$OUT"
  while read -r line; do
    port="$(echo "$line" | awk -F/ '/open/{print $1}')"
    service="$(echo "$line" | awk '/open/{for(i=3;i<=NF;i++) printf $i " "; print ""}' | sed 's/[[:space:]]*$//')"
    if [[ -n "$port" ]]; then
      OPEN+=("{\"port\":\"$port\",\"service\":\"$service\"}")
    fi
  done <<< "$OUT"
else
  IFS=',' read -ra P <<< "$PORTS"
  for port in "${P[@]}"; do
    timeout 3 bash -c "cat < /dev/null > /dev/tcp/$HOST/$port" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
      echo -e "${YELLOW}[OPEN]${RESET} $HOST:$port"
      OPEN+=("{\"port\":\"$port\",\"service\":\"tcp-open\"}")
    else
      echo -e "${GREEN}[CLOSED]${RESET} $HOST:$port"
    fi
  done
fi

printf 'JSON_SNIPPET: {"tool":"port_scan","target":"%s","open":[%s]}\n' "$HOST" "$(IFS=,; echo "${OPEN[*]-}")"
