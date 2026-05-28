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

"""Microsoft Teams notification sender via Incoming Webhook."""

import json
import logging
from typing import Any

import requests

from security.constants import DRY_RUN_PREFIX, HTTP_TIMEOUT, LOGGING_PREFIX
from security.issues.models import NotifiedIssue, SeverityChange, severity_direction
from security.issues.sync import SyncResult

logger = logging.getLogger(__name__)


class NotificationSender:
    """Sends Adaptive Card messages to Microsoft Teams via Incoming Webhook."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def notify(self, result: SyncResult, *, dry_run: bool) -> None:
        """Send Teams notifications for issue activity and severity changes.

        Args:
            result: Sync result containing notifications and severity changes.
            dry_run: If True, log intended notifications without sending.
        """
        if not self.webhook_url:
            logger.info("%sTeams webhook URL not configured: skipping notifications", LOGGING_PREFIX)
            return

        self._notify_issues(result.notifications, dry_run=dry_run)
        self._notify_severity_changes(result.severity_changes, dry_run=dry_run)

    def _notify_issues(self, notifications: list[NotifiedIssue], *, dry_run: bool) -> None:
        """Send a Teams message about new / reopened issues."""
        if not notifications:
            logger.info("%sNo issue activity: skipping Teams notification", LOGGING_PREFIX)
            return

        body = self._build_issues_body(notifications)
        title = "Aquasec - New/Reopened Security Issues"

        if dry_run:
            logger.info("%sWould send Teams notification: %s", DRY_RUN_PREFIX, title)
            self.send_dry_run(body, title=title)
        else:
            self.send(body, title=title)
            logger.info("%sNotification sent: %s", LOGGING_PREFIX, title)

    def _notify_severity_changes(self, changes: list[SeverityChange], *, dry_run: bool) -> None:
        """Send a Teams message about parent severity changes."""
        if not changes:
            logger.info("%sNo severity changes: skipping Teams severity notification", LOGGING_PREFIX)
            return

        body = self._build_severity_body(changes)
        title = "Aquasec - Parent Severity Changes"

        if dry_run:
            logger.info("%sWould send Teams notification: %s", DRY_RUN_PREFIX, title)
            self.send_dry_run(body, title=title)
        else:
            self.send(body, title=title)
            logger.info("%sNotification sent: %s", LOGGING_PREFIX, title)

    @staticmethod
    def _build_issues_body(notifications: list[NotifiedIssue]) -> str:
        """Build a Markdown body summarising new / reopened issues for Teams."""
        new_issues = [n for n in notifications if n.state == "new"]
        reopened_issues = [n for n in notifications if n.state == "reopen"]

        lines: list[str] = [f"**{len(new_issues)}** new, **{len(reopened_issues)}** reopened\n"]

        for n in notifications:
            state_tag = "new" if n.state == "new" else "reopen"
            link = f"https://github.com/{n.repo}/issues/{n.issue_number}"
            issue_ref = f"[Issue #{n.issue_number}]({link})" if n.issue_number else "(pending)"
            lines.append(f"- **[{state_tag}]** *{n.severity}* - {n.category} - {issue_ref} ({n.repo})\n")

        return "\n".join(lines)

    @staticmethod
    def _build_severity_body(changes: list[SeverityChange]) -> str:
        """Build a Markdown body summarising parent-issue severity changes."""
        lines: list[str] = [f"**{len(changes)}** parent issue(s) with severity change\n"]

        for ch in changes:
            direction = severity_direction(ch.old_severity, ch.new_severity)
            link = f"https://github.com/{ch.repo}/issues/{ch.issue_number}"
            issue_ref = f"[Issue #{ch.issue_number}]({link})"
            lines.append(
                f"- {issue_ref} \u2013 **{ch.old_severity}** \u2192 **{ch.new_severity}** ({direction}) "
                f"\u2013 rule_id=`{ch.rule_id}`\n"
            )

        return "\n".join(lines)

    @staticmethod
    def _build_payload(
        body: str,
        title: str | None = None,
        subtitle: str | None = None,
    ) -> dict[str, Any]:
        """Build the full webhook JSON payload (Adaptive Card message)."""
        elements: list[dict[str, Any]] = []

        if title:
            header_items: list[dict[str, Any]] = [
                {"type": "TextBlock", "text": title, "wrap": True, "weight": "Bolder", "size": "Large"},
            ]
            if subtitle:
                header_items.append(
                    {"type": "TextBlock", "text": subtitle, "wrap": True, "isSubtle": True, "spacing": "None"},
                )
            elements.append({"type": "Container", "style": "accent", "bleed": True, "items": header_items})

        elements.append(
            {
                "type": "Container",
                "separator": bool(title),
                "items": [{"type": "TextBlock", "text": body, "wrap": True}],
            }
        )

        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": elements,
                    },
                }
            ],
        }

    def send(self, body: str, *, title: str | None = None, subtitle: str | None = None) -> None:
        """Send a notification to Teams.

        Args:
            body: Markdown body text for the Adaptive Card.
            title: Optional bold title in the card header.
            subtitle: Optional subtle subtitle below the title.

        Raises:
            SystemExit: If the webhook request fails.
        """
        payload = self._build_payload(body, title=title, subtitle=subtitle)

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as e:
            raise SystemExit(f"ERROR: Teams webhook request failed: {e}") from e

        if resp.status_code != 200 or resp.text.strip() not in ("1", ""):
            raise SystemExit(f"ERROR: Teams webhook request failed.\n  Status: {resp.status_code}\n  Body: {resp.text}")

        logger.info("%sMessage sent to Teams successfully.", LOGGING_PREFIX)

    def send_dry_run(self, body: str, *, title: str | None = None, subtitle: str | None = None) -> None:
        """Log the payload that would be sent without actually sending."""
        payload = self._build_payload(body, title=title, subtitle=subtitle)
        logger.info("%sWould send Teams notification:\n%s", DRY_RUN_PREFIX, json.dumps(payload, indent=2))
