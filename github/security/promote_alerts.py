#!/usr/bin/env python3
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

"""Promote collected Code Scanning alerts JSON into GitHub Issues.

Input:
- JSON produced by `collect_alert.sh` (default: alerts.json)

Design intent:
- One Issue per *finding* (stable identity), not per GitHub alert.
- Match Issues strictly by fingerprint (scanner-provided "Alert hash").
- Store identifiers + lifecycle metadata in a single `secmeta` block in the Issue body.
- Add structured `[sec-event]` comments only for meaningful lifecycle changes (reopen, new occurrence).

Requirements:
- `gh` CLI (authenticated; uses GH_TOKEN in CI)


Draft / debug (no writes):
- Run in dry-run mode to use alert hash, build secmeta, and show intended actions without creating/editing Issues:
    `python3 promote_alerts.py --file alerts.json --verbose --dry-run`

Implementation:
- Business logic lives in the ``utils`` package (one module per concern).
- This file is only the CLI entry-point: argument parsing → wiring → main().
"""

import argparse
import os
import shutil

from utils.alert_parser import load_open_alerts_from_file
from utils.common import parse_runner_debug, set_verbose_enabled, vprint
from utils.constants import LABEL_SCOPE_SECURITY
from utils.github_issues import gh_issue_list_by_label
from utils.issue_sync import sync_alerts_and_issues
from utils.priority import parse_severity_priority_map
from utils.teams import notify_teams, notify_teams_severity_changes


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Promote alerts JSON to GitHub issues using gh CLI")
    p.add_argument(
        "--file",
        "-f",
        default="alerts.json",
        help="alerts JSON file produced by collect_alert.sh (default: alerts.json)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not create/edit/comment/label issues; only read and print intended actions",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logs (also enabled when RUNNER_DEBUG=1)",
    )
    p.add_argument(
        "--issue-label",
        default=LABEL_SCOPE_SECURITY,
        help=f"Only mine issues with this label (default: {LABEL_SCOPE_SECURITY})",
    )
    p.add_argument(
        "--severity-priority-map",
        default=os.environ.get("SEVERITY_PRIORITY_MAP", ""),
        help="Comma-separated severity=priority pairs that define which priority string "
             "to assign for each alert severity. Severities: Critical, High, Medium, Low, Unknown. "
             "Example: 'Critical=Blocker,High=Urgent,Medium=Normal,Low=Minor,Unknown=Normal'. "
             "Only listed severities get a priority; unlisted ones are left empty. "
             "When not set at all, priority is skipped for every severity. "
             "Priority values must match the option names of the Priority single-select field "
             "in the target GitHub Project. "
             "Default: $SEVERITY_PRIORITY_MAP env var.",
    )
    p.add_argument(
        "--project-number",
        type=int,
        default=int(os.environ.get("PROJECT_NUMBER", "0")) or None,
        help="GitHub Projects V2 number (org-level) where a Priority single-select field "
             "will be set for each promoted issue.  Required together with --severity-priority-map. "
             "When omitted, project-level priority is skipped. "
             "Default: $PROJECT_NUMBER env var.",
    )
    p.add_argument(
        "--project-org",
        default=os.environ.get("PROJECT_ORG", ""),
        help="GitHub organisation that owns the Projects V2 board.  "
             "Use this when the project lives in a different org than the scanned repo. "
             "When omitted, the org is derived from the repo name. "
             "Default: $PROJECT_ORG env var.",
    )
    p.add_argument(
        "--teams-webhook-url",
        default=os.environ.get("TEAMS_WEBHOOK_URL"),
        help="Teams Incoming Webhook URL for new/reopened issue alerts (default: $TEAMS_WEBHOOK_URL). "
             "If not set, Teams notification is skipped.",
    )
    return p.parse_args()


def main() -> None:
    if shutil.which("gh") is None:
        raise SystemExit("ERROR: gh CLI is required. Install and authenticate (gh auth login).")
    args = parse_args()

    dry_run = bool(args.dry_run)
    set_verbose_enabled(bool(args.verbose) or parse_runner_debug())

    repo_full, open_alerts = load_open_alerts_from_file(args.file)
    issues = gh_issue_list_by_label(repo_full, str(args.issue_label))

    # Build severity → priority map from user input; empty by default (priority skipped).
    spm = parse_severity_priority_map(str(args.severity_priority_map or ""))

    result = sync_alerts_and_issues(
        open_alerts,
        issues,
        dry_run=dry_run,
        severity_priority_map=spm,
        project_number=args.project_number,
        project_org=str(args.project_org or ""),
    )
    notifications = result.notifications
    severity_changes = result.severity_changes

    webhook_url = str(args.teams_webhook_url or "")
    if (notifications or severity_changes) and not webhook_url:
        vprint("Teams webhook URL not configured - skipping notification")
    else:
        notify_teams(webhook_url, notifications, dry_run=dry_run)
        notify_teams_severity_changes(webhook_url, severity_changes, dry_run=dry_run)


if __name__ == "__main__":
    main()
