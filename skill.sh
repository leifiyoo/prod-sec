#!/usr/bin/env bash

# Local skill registry for skills.sh-style consumers and shell-based agents.
# Usage: source ./skill.sh prod-sec

declare -A SKILLS=(
  [prod-sec]="SKILL.md"
)

if [[ $# -eq 0 ]]; then
  echo "Usage: source ./skill.sh <skill-name>"
  echo "Available skills: ${!SKILLS[@]}"
elif [[ -n "${SKILLS[$1]:-}" ]]; then
  echo "${SKILLS[$1]}"
else
  echo "Unknown skill: $1" >&2
  echo "Available skills: ${!SKILLS[@]}" >&2
  return 1 2>/dev/null || exit 1
fi
