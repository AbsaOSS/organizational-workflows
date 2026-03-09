#!/usr/bin/env bash
#
# Copyright 2026 ABSA Group Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Check that required labels exist in a GitHub repo using gh + jq.
# Labels are loaded from labels.yml when available; otherwise built-in
# defaults are used.
#
# Usage:
#   ./check_labels.sh --repo owner/repo
#   ./check_labels.sh --repo owner/repo --label-config /path/to/labels.yml

set -euo pipefail

# -- Built-in defaults (same as labels.yml ships with) --------------------
_DEFAULT_SCOPE_SECURITY="scope:security"
_DEFAULT_TYPE_TECH_DEBT="type:tech-debt"
_DEFAULT_EPIC="epic"
_DEFAULT_ADEPT_TO_CLOSE="sec:adept-to-close"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL_CONFIG=""

repo=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      repo="${2:-}"; shift 2;;
    --label-config)
      LABEL_CONFIG="${2:-}"; shift 2;;
    -h|--help)
      echo "Usage: $0 --repo owner/repo [--label-config path/to/labels.yml]"; exit 0;;
    *)
      echo "Unknown argument: $1" >&2; exit 2;;
  esac
done

if [[ -z "$repo" ]]; then
  echo "ERROR: --repo owner/repo is required" >&2
  exit 2
fi

if [[ -z "$LABEL_CONFIG" ]]; then
  LABEL_CONFIG="$SCRIPT_DIR/labels.yml"
fi

# Helper: read a value from the flat YAML config 
# Usage: _cfg_val <key> <default>
_cfg_val() {
  local key="$1" default="$2"
  if [[ ! -f "$LABEL_CONFIG" ]]; then
    printf '%s' "$default"
    return
  fi

  local val
  val="$(grep -E "^${key}\s*:" "$LABEL_CONFIG" 2>/dev/null | head -1 \
       | sed -E 's/^[^:]+:\s*//; s/^["'"'"']//; s/["'"'"']\s*(#.*)?$//; s/\s*#.*$//' )" || true
  if [[ -n "$val" ]]; then
    printf '%s' "$val"
  else
    printf '%s' "$default"
  fi
}

REQUIRED_LABELS=(
  "$(_cfg_val scope_security "$_DEFAULT_SCOPE_SECURITY")"
  "$(_cfg_val type_tech_debt "$_DEFAULT_TYPE_TECH_DEBT")"
  "$(_cfg_val epic           "$_DEFAULT_EPIC")"
  "$(_cfg_val adept_to_close "$_DEFAULT_ADEPT_TO_CLOSE")"
)

if ! json_out="$(gh label list --repo "$repo" --json name --limit 500 2>/dev/null)"; then
  echo "ERROR: failed to list labels for $repo" >&2
  exit 1
fi

existing_labels=()
while IFS= read -r label; do
  [[ -n "$label" ]] && existing_labels+=("$label")
done < <(printf '%s' "$json_out" | jq -r '.[].name | select(length > 0)')

missing=()
for required in "${REQUIRED_LABELS[@]}"; do
  found="no"
  for existing in "${existing_labels[@]}"; do
    if [[ "$existing" == "$required" ]]; then
      found="yes"; break
    fi
  done
  if [[ "$found" == "no" ]]; then
    missing+=("$required")
  fi
done

if [[ "${#missing[@]}" -eq 0 ]]; then
  echo "All ${#REQUIRED_LABELS[@]} required labels exist in $repo"
  exit 0
fi

{
  echo "ERROR: ${#missing[@]} required label(s) missing in $repo"
  echo "Missing labels:"
  for m in "${missing[@]}"; do
    echo "  - $m"
  done
  echo "All required labels:"
  printf '  %s\n' "${REQUIRED_LABELS[*]}"
} >&2

exit 1
