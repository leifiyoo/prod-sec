#!/usr/bin/env bash
# Bounded subdomain enumeration for an authorized domain.
#
# Tests a small or supplied wordlist of likely hostnames using DNS resolution.
# A positive result is a live subdomain that expands the attack surface. Safe
# mode uses a short built-in list.

set -u

GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
RESET="\033[0m"

TARGET=""
WORDLIST=""
SAFE_MODE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --safe-mode) SAFE_MODE=1; shift ;;
    --wordlist) WORDLIST="${2:-}"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 TARGET_HOST [--wordlist words.txt] [--safe-mode]"
      exit 0
      ;;
    *) TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo -e "${RED}[ERROR]${RESET} TARGET_HOST is required"
  exit 2
fi

DOMAIN="${TARGET#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"
DOMAIN="${DOMAIN%%:*}"

resolve_host() {
  local host="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short A "$host" 2>/dev/null | head -n 5
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$host" 2>/dev/null | awk '/^Address: /{print $2}' | head -n 5
  elif command -v getent >/dev/null 2>&1; then
    getent hosts "$host" | awk '{print $1}' | head -n 5
  fi
}

if [[ -n "$WORDLIST" && -f "$WORDLIST" && "$SAFE_MODE" -eq 0 ]]; then
  mapfile -t WORDS < "$WORDLIST"
else
  WORDS=(www app api admin dev staging test beta auth login portal cdn assets static)
fi

echo -e "${GREEN}[INFO]${RESET} Enumerating ${#WORDS[@]} candidates for $DOMAIN safe_mode=$SAFE_MODE"
FOUND=()
for word in "${WORDS[@]}"; do
  [[ -z "$word" ]] && continue
  host="${word}.${DOMAIN}"
  ips="$(resolve_host "$host" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  if [[ -n "$ips" ]]; then
    echo -e "${YELLOW}[FOUND]${RESET} $host -> $ips"
    FOUND+=("{\"host\":\"$host\",\"addresses\":\"$ips\"}")
  fi
done

printf 'JSON_SNIPPET: {"tool":"subdomain_enum","target":"%s","found":[%s]}\n' "$DOMAIN" "$(IFS=,; echo "${FOUND[*]-}")"
