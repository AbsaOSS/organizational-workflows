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

"""Teams webhook notification – builds the notification payload and invokes
``send_to_teams.py`` for new / reopened issues.
"""


import os
import subprocess
import sys
import tempfile

from shared.common import vprint

from .models import NotifiedIssue, SeverityChange, severity_direction


def build_teams_notification_body(notifications: list[NotifiedIssue]) -> str:
    """Build a Markdown body summarising new / reopened issues for Teams."""
    new_issues = [n for n in notifications if n.state == "new"]
    reopened_issues = [n for n in notifications if n.state == "reopen"]

    lines: list[str] = []
    lines.append(f"**{len(new_issues)}** new, **{len(reopened_issues)}** reopened\n")

    for n in notifications:
        state_tag = "new" if n.state == "new" else "reopen"
        link = f"https://github.com/{n.repo}/issues/{n.issue_number}"
        issue_ref = f"[Issue #{n.issue_number}]({link})" if n.issue_number else "(pending)"
        lines.append(f"- **[{state_tag}]** *{n.severity}* - {n.category} - {issue_ref} ({n.repo})\n")

    return "\n".join(lines)


def build_severity_change_body(changes: list[SeverityChange]) -> str:
    """Build a Markdown body summarising parent-issue severity changes."""
    lines: list[str] = []
    lines.append(f"**{len(changes)}** parent issue(s) with severity change\n")

    for ch in changes:
        direction = severity_direction(ch.old_severity, ch.new_severity)
        link = f"https://github.com/{ch.repo}/issues/{ch.issue_number}"
        issue_ref = f"[Issue #{ch.issue_number}]({link})"
        lines.append(
            f"- {issue_ref} \u2013 **{ch.old_severity}** \u2192 **{ch.new_severity}** ({direction}) "
            f"\u2013 rule_id=`{ch.rule_id}`\n"
        )

    return "\n".join(lines)


def _post_to_teams(
    webhook_url: str,
    body: str,
    *,
    title: str,
    tmp_prefix: str,
    label: str,
    dry_run: bool = False,
) -> None:
    """Write *body* to a temp file and invoke send_to_teams.py."""
    if dry_run:
        if webhook_url:
            print(f"DRY-RUN: {label} webhook configured; no delivery will occur")
        else:
            print(
                f"DRY-RUN: no Teams Incoming Webhook URL configured. "
                f"No {label.lower()} post to Teams will be made."
            )

    script_dir = os.path.dirname(os.path.abspath(__file__))
    send_script = os.path.join(os.path.dirname(script_dir), "send_to_teams.py")

    if not os.path.exists(send_script):
        print(
            f"WARN: send_to_teams.py not found at {send_script} – skipping {label.lower()}",
            file=sys.stderr,
        )
        return

    body_file: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=tmp_prefix,
            suffix=".md",
            delete=False,
        ) as tmp:
            tmp.write(body)
            body_file = tmp.name

        cmd = [
            sys.executable, send_script,
            "--body-file", body_file,
            "--title", title,
        ]
        if dry_run:
            cmd.append("--dry-run")
        else:
            cmd.extend(["--webhook-url", webhook_url])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"WARN: {label} failed: {result.stderr}", file=sys.stderr)
        else:
            if dry_run:
                print(f"DRY-RUN: send_to_teams.py {label.lower()} output:")
                print(result.stdout)
            else:
                print(f"{label} sent successfully")
    finally:
        if body_file:
            try:
                os.remove(body_file)
            except OSError:
                pass


def notify_teams(
    webhook_url: str,
    notifications: list[NotifiedIssue],
    *,
    dry_run: bool = False,
) -> None:
    """Send a Teams message about new / reopened issues via send_to_teams.py."""
    if not notifications:
        print("No new or reopened issues – skipping Teams notification")
        return

    body = build_teams_notification_body(notifications)
    _post_to_teams(
        webhook_url,
        body,
        title="Aquasec - New/Reopened Security Issues",
        tmp_prefix="teams_notification_",
        label="Teams notification",
        dry_run=dry_run,
    )


def notify_teams_severity_changes(
    webhook_url: str,
    changes: list[SeverityChange],
    *,
    dry_run: bool = False,
) -> None:
    """Send a Teams message about parent severity changes via send_to_teams.py."""
    if not changes:
        vprint("No severity changes – skipping Teams severity-change notification")
        return

    body = build_severity_change_body(changes)
    _post_to_teams(
        webhook_url,
        body,
        title="Aquasec - Parent Severity Changes",
        tmp_prefix="teams_severity_change_",
        label="Teams severity-change notification",
        dry_run=dry_run,
    )
