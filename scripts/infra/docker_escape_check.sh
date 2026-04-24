#!/usr/bin/env bash
# Remote container management exposure probe.
#
# Checks for exposed Docker/Kubernetes/container management ports and metadata
# endpoints without attempting escape. A positive result is an unauthenticated
# management API or metadata service reachable from the tested context.

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
FINDINGS=()

echo -e "${GREEN}[INFO]${RESET} Container exposure checks for $HOST safe_mode=$SAFE_MODE"

probe_http() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -sk -i --max-time 5 "$url" 2>/dev/null | head -n 20
  fi
}

for url in "http://$HOST:2375/version" "https://$HOST:2376/version" "https://$HOST:6443/version" "http://$HOST:10250/pods"; do
  OUT="$(probe_http "$url")"
  CODE="$(echo "$OUT" | awk 'NR==1{print $2}')"
  echo -e "${GREEN}[PROBE]${RESET} $url status=${CODE:-none}"
  if echo "$OUT" | grep -Eiq '"ApiVersion"|"Version"|"gitVersion"|"pods"'; then
    echo -e "${YELLOW}[FINDING]${RESET} container management API marker observed at $url"
    FINDINGS+=("{\"title\":\"Exposed container management API candidate\",\"severity\":\"Critical\",\"evidence\":\"$url returned management API marker\"}")
  fi
done

if [[ "$HOST" == "127.0.0.1" || "$HOST" == "localhost" ]]; then
  for path in /.dockerenv /run/secrets/kubernetes.io/serviceaccount/token /var/run/docker.sock; do
    if [[ -e "$path" ]]; then
      echo -e "${YELLOW}[LOCAL]${RESET} $path exists"
      FINDINGS+=("{\"title\":\"Local container artifact present\",\"severity\":\"Info\",\"evidence\":\"$path exists\"}")
    fi
  done
fi

printf 'JSON_SNIPPET: {"tool":"docker_escape_check","target":"%s","findings":[%s]}\n' "$HOST" "$(IFS=,; echo "${FINDINGS[*]-}")"
