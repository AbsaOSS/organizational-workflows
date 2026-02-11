#!/usr/bin/env bash
set -euo pipefail

OWNER=""
REPO=""
STATE="open"            # open | dismissed | fixed | all
OUT_FILE="alerts.json"
ISSUE_LABEL="scope:Security"
DRY_RUN="0"
VERBOSE="0"
FORCE="0"

usage() {
  cat <<EOF
Usage: run-all.sh [options]

This is a thin wrapper that runs:
  1) collect_alert.sh  -> writes alerts.json
  2) promote_alerts.py -> creates/updates Issues from alerts.json

Repo selection:
  Provide --owner/--repo OR set GITHUB_REPOSITORY="<owner>/<repo>".

Options:
  --owner <org>         GitHub organization or user
  --repo <repo>         GitHub repository name
  --state <state>       open | dismissed | fixed | all (default: open)
  --out <file>          Output file for alerts JSON (default: alerts.json)
  --issue-label <label> Mine existing issues with this label (default: scope:Security)
  --dry-run             Do not write issues; only print intended actions
  --verbose             Verbose logs (also enabled by RUNNER_DEBUG=1)
  --force               Overwrite --out file if it exists
  -h, --help            Show this help

Examples:
  # Local run (explicit repo selection; required)
  run-all.sh --owner <org-or-user> --repo <repo>

  # Local run (explicit repo selection + typical flags)
  run-all.sh --owner <org-or-user> --repo <repo> --state open --out alerts.json

  # Dry-run with verbose body previews
  run-all.sh --owner <org-or-user> --repo <repo> --dry-run --verbose

  # Overwrite output file if it already exists
  run-all.sh --owner <org-or-user> --repo <repo> --out alerts.json --force

  # GitHub Actions style (repo inferred from GITHUB_REPOSITORY)
  # (GITHUB_REPOSITORY is already set automatically in Actions)
  run-all.sh --state open --out alerts.json

  # If you run outside Actions but still want inference:
  GITHUB_REPOSITORY="<org-or-user>/<repo>" run-all.sh
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --owner)
      OWNER="$2"
      shift 2
      ;;
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
    --dry-run)
      DRY_RUN="1"
      shift
      ;;
    --verbose)
      VERBOSE="1"
      shift
      ;;
    --force)
      FORCE="1"
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

if [[ -z "$OWNER" || -z "$REPO" ]]; then
  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    OWNER="${GITHUB_REPOSITORY%/*}"
    REPO="${GITHUB_REPOSITORY#*/}"
  fi
fi

if [[ -z "$OWNER" || -z "$REPO" ]]; then
  echo "ERROR: repo not specified. Use --owner/--repo or set GITHUB_REPOSITORY=<owner>/<repo>." >&2
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

if [[ -f "$OUT_FILE" ]]; then
  if [[ "$FORCE" == "1" ]]; then
    rm -f "$OUT_FILE"
  else
    echo "ERROR: Output file '$OUT_FILE' exists. Delete it, choose a different --out, or pass --force." >&2
    exit 1
  fi
fi

"$SCRIPT_DIR/collect_alert.sh" --owner "$OWNER" --repo "$REPO" --state "$STATE" --out "$OUT_FILE"

PROMOTE_ARGS=("$SCRIPT_DIR/promote_alerts.py" --file "$OUT_FILE" --issue-label "$ISSUE_LABEL")
if [[ "$DRY_RUN" == "1" ]]; then
  PROMOTE_ARGS+=(--dry-run)
fi
if [[ "$VERBOSE" == "1" ]]; then
  PROMOTE_ARGS+=(--verbose)
fi

python3 "${PROMOTE_ARGS[@]}"
