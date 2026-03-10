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
# Usage:
#   ./check_labels.sh --repo owner/repo

set -euo pipefail

REQUIRED_LABELS=(
  "scope:security"
  "type:tech-debt"
  "epic"
  "sec:adept-to-close"
)

repo=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      repo="${2:-}"; shift 2;;
    -h|--help)
      echo "Usage: $0 --repo owner/repo"; exit 0;;
    *)
      echo "Unknown argument: $1" >&2; exit 2;;
  esac
done

if [[ -z "$repo" ]]; then
  echo "ERROR: --repo owner/repo is required" >&2
  exit 2
fi

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
