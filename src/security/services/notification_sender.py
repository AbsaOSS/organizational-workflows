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

from security.config import SecurityConfig
from security.constants import (
    DRY_RUN_PREFIX,
    HTTP_TIMEOUT,
    LOGGING_PREFIX,
    TEAMS_CARD_MAX_BYTES,
    TEAMS_ISSUE_LIST_CAP,
    TEAMS_SUCCESS_BODIES,
)
from security.issues.models import SyncResult
from security.notifications.card import build_message_payload, build_security_card
from security.notifications.links import NotificationLinks

logger = logging.getLogger(__name__)


class NotificationSender:
    """Sends a single Adaptive Card summarizing a sync run to Microsoft Teams."""

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self.webhook_url = config.teams_webhook_url

    def notify(self, result: SyncResult, *, dry_run: bool) -> bool:
        """Send the Teams notification for a completed sync run.

        A card is only produced when the run actually changed something, so quiet runs stay
        silent instead of posting an empty report.

        Args:
            result: Sync result carrying issue activity and posture.
            dry_run: If True, log the intended notification without sending it.

        Returns:
            False only when a notification was attempted and Teams did not accept it. Skipped
            and dry-run notifications count as success because nothing failed.
        """
        if not self.webhook_url:
            logger.info("%sTeams webhook URL not configured: skipping notification", LOGGING_PREFIX)
            return True

        if not result.issue_changes:
            logger.info("%sNo issue activity: skipping Teams notification", LOGGING_PREFIX)
            return True

        payload = self._build_payload(result)

        if dry_run:
            logger.info(
                "%sWould send a Teams notification: %d issue change(s)",
                DRY_RUN_PREFIX,
                len(result.issue_changes),
            )
            logger.debug(
                "%sTeams notification payload:\n%s", DRY_RUN_PREFIX, json.dumps(payload, indent=2, ensure_ascii=False)
            )
            return True

        logger.info(
            "%sTeams notification sent: %d issue change(s)",
            LOGGING_PREFIX,
            len(result.issue_changes),
        )
        logger.debug(
            "%sTeams notification payload:\n%s", LOGGING_PREFIX, json.dumps(payload, indent=2, ensure_ascii=False)
        )
        return self.send(payload)

    def _build_payload(self, result: SyncResult) -> dict[str, Any]:
        """Build the message payload, shrinking it when it would exceed the Teams limit."""
        links = NotificationLinks.build(
            repo=self.config.repo,
            security_label=self.config.security_label,
            server_url=self.config.github_server_url,
            run_id=self.config.github_run_id,
        )
        payload = build_message_payload(self._build_card(result, links))

        if len(self._encode(payload)) <= TEAMS_CARD_MAX_BYTES:
            return payload

        logger.warning(
            "%sTeams notification exceeds %d bytes: omitting the individual issue list",
            LOGGING_PREFIX,
            TEAMS_CARD_MAX_BYTES,
        )
        return build_message_payload(self._build_card(result, links, issue_cap=0))

    def _build_card(
        self, result: SyncResult, links: NotificationLinks, *, issue_cap: int = TEAMS_ISSUE_LIST_CAP
    ) -> dict[str, Any]:
        """Render the Adaptive Card for a sync result.

        Args:
            result: Sync result carrying issue activity and posture.
            links: Repository and workflow-run links for the card.
            issue_cap: Maximum number of issues listed individually; 0 omits the list.

        Returns:
            The rendered Adaptive Card.
        """
        return build_security_card(
            links=links,
            issue_changes=result.issue_changes,
            posture=result.open_child_issues_by_severity,
            min_severity=self.config.min_severity,
            issue_cap=issue_cap,
        )

    @staticmethod
    def _encode(payload: dict[str, Any]) -> bytes:
        """Serialise *payload* as UTF-8, which Teams requires for emoji to render."""
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def send(self, payload: dict[str, Any]) -> bool:
        """Post a prebuilt payload to the Teams webhook.

        A failed notification never aborts the run: the issue sync has already been written
        to GitHub by this point, so the failure is reported and reported only.

        Args:
            payload: The Teams message payload to send.

        Returns:
            True if Teams accepted the message.
        """
        try:
            resp = requests.post(
                self.webhook_url,
                data=self._encode(payload),
                headers={"Content-Type": "application/json; charset=utf-8"},
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as e:
            logger.error("%sTeams webhook request failed: %s", LOGGING_PREFIX, e)
            return False

        body = (resp.text or "").strip()
        if not resp.ok or body.lower() not in TEAMS_SUCCESS_BODIES:
            logger.error(
                "%sTeams webhook rejected the message. Status: %d, body: %s",
                LOGGING_PREFIX,
                resp.status_code,
                body,
            )
            return False

        return True
