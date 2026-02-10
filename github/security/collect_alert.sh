#!/usr/bin/env bash
set -euo pipefail

# Configuration + arguments

OWNER=""
REPO=""
STATE="open"              # open | dismissed | fixed | all
OUT_FILE="alerts.json"

usage() {
  cat <<EOF
Usage: $0 --owner <org> --repo <repo> [options]

Required:
  --owner <org>           GitHub organization or user
  --repo <repo>           GitHub repository name

Options:
  --state <state>         open | dismissed | fixed | all (default: open)
  --out <file>            Output file (default: alerts.json)
  -h, --help              Show this help

Examples:
  $0 --owner my-org --repo my-repo
  $0 --owner my-org --repo my-repo --state all
  $0 --owner my-org --repo my-repo --state dismissed --out dismissed.json
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
  echo "ERROR: --owner and --repo are required" >&2
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

if [[ -f $OUT_FILE ]]; then
  echo "Output file ${OUT_FILE} exists. Exiting"
  exit 1
fi

# Preconditions

command -v gh >/dev/null 2>&1 || {
  echo "ERROR: gh CLI is required" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || {
  echo "ERROR: jq is required" >&2
  exit 1
}

gh auth status >/dev/null 2>&1 || {
  echo "ERROR: gh is not authenticated" >&2
  exit 1
}

# Temp files

TMP_ALERTS="$(mktemp)"
TMP_REPO="$(mktemp)"

trap 'rm -f "$TMP_ALERTS" "$TMP_REPO"' EXIT

# Fetch repository metadata

echo "Fetching repository metadata for $OWNER/$REPO..."

gh api \
  -H "Accept: application/vnd.github+json" \
  "/repos/$OWNER/$REPO" \
  > "$TMP_REPO"

# Fetch alerts

echo "Fetching code scanning alerts (state=$STATE)..."

ALERTS_ENDPOINT="/repos/$OWNER/$REPO/code-scanning/alerts?per_page=100"

if [[ "$STATE" != "all" ]]; then
  ALERTS_ENDPOINT="$ALERTS_ENDPOINT&state=$STATE"
fi

gh api \
  -H "Accept: application/vnd.github+json" \
  "$ALERTS_ENDPOINT" \
  --paginate \
  > "$TMP_ALERTS"

# Normalize and assemble

jq -n \
  --slurpfile alerts "$TMP_ALERTS" \
  --slurpfile repo "$TMP_REPO" '
{
  generated_at: (now | todate),
  repo: {
    id: $repo[0].id,
    name: $repo[0].name,
    full_name: $repo[0].full_name,
    private: $repo[0].private,
    html_url: $repo[0].html_url,
    default_branch: $repo[0].default_branch,
    owner: {
      login: $repo[0].owner.login,
      id: $repo[0].owner.id,
      html_url: $repo[0].owner.html_url
    }
  },
  query: {
    state: "'"$STATE"'"
  },
  alerts: [
    $alerts[0][] | {
      alert_number: .number,
      state: .state,
      created_at: .created_at,
      updated_at: .updated_at,
      url: .url,
      alert_url: .html_url,

      rule_id: .rule.id,
      rule_name: .rule.name,
      severity: .rule.security_severity_level,
      confidence: .rule.severity,
      tags: (.rule.tags // []),
      help_uri: .rule.help_uri,

      tool: .tool.name,
      tool_version: .tool.version,

      ref: .most_recent_instance.ref,
      commit_sha: .most_recent_instance.commit_sha,
      message: .most_recent_instance.message.text,
      instance_url: .most_recent_instance.html_url,
      classifications: (.most_recent_instance.classifications // []),

      file: .most_recent_instance.location.path,
      start_line: .most_recent_instance.location.start_line,
      end_line: .most_recent_instance.location.end_line
    }
  ]
}
' > "$OUT_FILE"

# Summary

COUNT="$(jq '.alerts | length' "$OUT_FILE")"

echo "Done."
echo "Repository : $OWNER/$REPO"
echo "State      : $STATE"
echo "Alerts     : $COUNT"
echo "Output     : $OUT_FILE"

