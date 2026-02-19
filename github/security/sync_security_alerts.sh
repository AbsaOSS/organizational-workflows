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

set -euo pipefail

REPO=""
STATE="open"            # open | dismissed | fixed | all
OUT_FILE="alerts.json"
ISSUE_LABEL="scope:security"
SEVERITY_PRIORITY_MAP="${SEVERITY_PRIORITY_MAP:-}"
PROJECT_NUMBER="${PROJECT_NUMBER:-}"
TEAMS_WEBHOOK_URL="${TEAMS_WEBHOOK_URL:-}"
SKIP_LABEL_CHECK=0
DRY_RUN=0
VERBOSE=0
FORCE=0

usage() {
  cat <<EOF
Usage: sync_security_alerts.sh --repo <owner/repo> [options]

This is a thin wrapper that runs:
  1) check_labels.sh   -> verify required labels exist
  2) collect_alert.sh  -> writes alerts.json
  3) promote_alerts.py -> creates/updates Issues from alerts.json

Repo selection:
  Provide --repo owner/repo OR set GITHUB_REPOSITORY="<owner>/<repo>".

Options:
  --repo <owner/repo>   GitHub repository (e.g. my-org/my-repo)
  --state <state>       open | dismissed | fixed | all (default: open)
  --out <file>          Output file for alerts JSON (default: alerts.json)
  --issue-label <label> Mine existing issues with this label (default: scope:security)
  --severity-priority-map <map>
                        Comma-separated severity=priority pairs, e.g.
                        'Critical=Blocker,High=Urgent,Medium=Normal,Low=Minor,Unknown=Normal'
                        Only listed severities get a priority; unlisted ones are left empty.
                        When not set at all, priority is skipped for every severity.
                        Priority values must match the option names of the Priority
                        single-select field in the target GitHub Project.
                        (default: \$SEVERITY_PRIORITY_MAP)
  --project-number <N>  GitHub Projects V2 number (org-level) where a Priority
                        single-select field will be set for each promoted issue.
                        Required together with --severity-priority-map.
                        When omitted, project-level priority is skipped.
                        (default: \$PROJECT_NUMBER)
  --dry-run             Do not write issues; only print intended actions
  --verbose             Verbose logs (also enabled by RUNNER_DEBUG=1)
  --teams-webhook-url <url>  Teams Incoming Webhook URL (default: \$TEAMS_WEBHOOK_URL)
  --skip-label-check    Skip the label existence check
  --force               Overwrite --out file if it exists
  -h, --help            Show this help

Examples:
  # Local run
  sync_security_alerts.sh --repo my-org/my-repo

  # Local run with typical flags
  sync_security_alerts.sh --repo my-org/my-repo --state open --out alerts.json

  # Dry-run with verbose body previews
  sync_security_alerts.sh --repo my-org/my-repo --dry-run --verbose

  # Overwrite output file if it already exists
  sync_security_alerts.sh --repo my-org/my-repo --out alerts.json --force

  # GitHub Actions style (repo inferred from GITHUB_REPOSITORY)
  # (GITHUB_REPOSITORY is already set automatically in Actions)
  sync_security_alerts.sh --state open --out alerts.json

  # If you run outside Actions but still want inference:
  GITHUB_REPOSITORY="my-org/my-repo" sync_security_alerts.sh

  # Assign user-defined priority strings per severity (requires a project)
  sync_security_alerts.sh --repo my-org/my-repo --project-number 42 \\
    --severity-priority-map 'Critical=🌋 Urgent,High=High,Medium=Medium,Low=Low,Unknown=Medium'

  # Only set priority for Critical and High; Medium, Low and Unknown will have no priority
  sync_security_alerts.sh --repo my-org/my-repo --project-number 42 \\
    --severity-priority-map 'Critical=🌋 Urgent,High=Important'
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="$2"
      shift 2
      ;;
    --state)
      STATE="$2"
      shift 2
      ;;
    --out)
      OUT_FILE="$2"
      shift 2
      ;;
    --issue-label)
      ISSUE_LABEL="$2"
      shift 2
      ;;
    --severity-priority-map)
      SEVERITY_PRIORITY_MAP="$2"
      shift 2
      ;;
    --project-number)
      PROJECT_NUMBER="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --verbose)
      VERBOSE=1
      shift
      ;;
    --teams-webhook-url)
      TEAMS_WEBHOOK_URL="$2"
      shift 2
      ;;
    --skip-label-check)
      SKIP_LABEL_CHECK=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$REPO" ]]; then
  REPO="${GITHUB_REPOSITORY:-}"
fi

if [[ -z "$REPO" || "$REPO" != */* ]]; then
  echo "ERROR: repo not specified or invalid. Use --repo owner/repo or set GITHUB_REPOSITORY=owner/repo." >&2
  usage
  exit 1
fi

case "$STATE" in
  open|dismissed|fixed|all) ;;
  *)
    echo "ERROR: Invalid --state '$STATE'. Allowed: open | dismissed | fixed | all" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if (( ! SKIP_LABEL_CHECK )); then
  "$SCRIPT_DIR/check_labels.sh" --repo "$REPO"
fi

if [[ -f "$OUT_FILE" ]]; then
  if (( FORCE )); then
    rm -f "$OUT_FILE"
  else
    echo "ERROR: Output file '$OUT_FILE' exists. Delete it, choose a different --out, or pass --force." >&2
    exit 1
  fi
fi

"$SCRIPT_DIR/collect_alert.sh" --repo "$REPO" --state "$STATE" --out "$OUT_FILE"

PROMOTE_ARGS=("$SCRIPT_DIR/promote_alerts.py" --file "$OUT_FILE" --issue-label "$ISSUE_LABEL")
if (( DRY_RUN )); then
  PROMOTE_ARGS+=(--dry-run)
fi
if (( VERBOSE )); then
  PROMOTE_ARGS+=(--verbose)
fi
if [[ -n "$TEAMS_WEBHOOK_URL" ]]; then
  PROMOTE_ARGS+=(--teams-webhook-url "$TEAMS_WEBHOOK_URL")
fi
if [[ -n "$SEVERITY_PRIORITY_MAP" ]]; then
  PROMOTE_ARGS+=(--severity-priority-map "$SEVERITY_PRIORITY_MAP")
fi
if [[ -n "$PROJECT_NUMBER" ]]; then
  PROMOTE_ARGS+=(--project-number "$PROJECT_NUMBER")
fi

python3 "${PROMOTE_ARGS[@]}"
