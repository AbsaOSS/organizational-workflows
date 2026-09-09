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

"""Pure Adaptive Card rendering for Microsoft Teams security notifications."""

from typing import Any

from security.constants import (
    GITHUB_BASE_URL,
    SEVERITY_EMOJI,
    TEAMS_ISSUE_LIST_CAP,
)
from security.issues.models import SEVERITY_ORDER, IssueChange
from security.notifications.links import NotificationLinks

# Highest first, matching how humans triage.
_SEVERITY_DISPLAY_ORDER = sorted(SEVERITY_ORDER, key=lambda severity: SEVERITY_ORDER[severity], reverse=True)

# Maps the internal issue state onto its card section heading.
_STATE_SECTIONS: tuple[tuple[str, str], ...] = (
    ("new", "Opened"),
    ("reopen", "Reopened"),
    ("closed", "Closed"),
)

_LIST_SEPARATOR = "\r"


def _severity_emoji(severity: str) -> str:
    """Return the colored dot for *severity*, falling back to the unknown marker."""
    return SEVERITY_EMOJI.get((severity or "").strip().lower(), SEVERITY_EMOJI["unknown"])


def _text_block(text: str, **overrides: Any) -> dict[str, Any]:
    """Build a wrapping ``TextBlock``, the only text primitive Teams renders reliably."""
    block: dict[str, Any] = {"type": "TextBlock", "text": text, "wrap": True}
    block.update(overrides)
    return block


def _issue_url(repo: str, issue_number: int) -> str:
    """Return the GitHub URL for an issue, or an empty string when it has no number yet."""
    if not repo or not issue_number:
        return ""
    return f"{GITHUB_BASE_URL}/{repo}/issues/{issue_number}"


def _issue_row(item: IssueChange) -> str:
    """Render a single issue as a Markdown list item.

    Issues created during a dry run have no number yet, so they are marked as pending
    rather than rendered as a broken link.
    """
    url = _issue_url(item.repo, item.issue_number)
    reference = f"[#{item.issue_number}]({url})" if url else "(pending)"
    descriptor = (item.rule_id or "").strip()
    row = f"- {_severity_emoji(item.severity)} **{item.severity.capitalize()}** - {reference}"
    return f"{row} - {descriptor}" if descriptor else row


def _header(repo: str) -> dict[str, Any]:
    """Build the colored, edge-to-edge card header naming the repository."""
    return {
        "type": "Container",
        "style": "accent",
        "bleed": True,
        "backgroundColor": "#7B83EB",
        "items": [
            _text_block("AquaSec Security Scan", weight="Bolder", size="Large", color="dark"),
            _text_block(repo or "unknown repository", isSubtle=True, spacing="None", color="dark"),
        ],
    }


def _stat_column(label: str, value: int) -> dict[str, Any]:
    """Build one column of a centered, full-width stat row (counters or posture)."""
    return {
        "type": "Column",
        "width": "stretch",
        "items": [
            _text_block(str(value), size="ExtraLarge", weight="Bolder", horizontalAlignment="Center"),
            _text_block(label, isSubtle=True, spacing="None", horizontalAlignment="Center"),
        ],
    }


def _change_counters(issue_changes: list[IssueChange]) -> list[dict[str, Any]]:
    """Build the at-a-glance opened/reopened/closed counters for this run."""
    counts = {state: 0 for state, _ in _STATE_SECTIONS}
    for item in issue_changes:
        if item.state in counts:
            counts[item.state] += 1

    return [
        _text_block("Changes in this run", weight="Bolder", spacing="Medium"),
        {
            "type": "ColumnSet",
            "spacing": "Small",
            "columns": [_stat_column(label, counts[state]) for state, label in _STATE_SECTIONS],
        },
    ]


def _issue_sections(issue_changes: list[IssueChange], *, cap: int) -> list[dict[str, Any]]:
    """Build the per-state issue lists, truncated to *cap* rows in total."""
    elements: list[dict[str, Any]] = []
    remaining = cap

    for state, heading in _STATE_SECTIONS:
        items = [item for item in issue_changes if item.state == state]
        if not items:
            continue

        shown = items[:remaining] if remaining > 0 else []
        if not shown:
            break

        remaining -= len(shown)
        elements.append(_text_block(heading, weight="Bolder", spacing="Medium"))
        elements.append(_text_block(_LIST_SEPARATOR.join(_issue_row(item) for item in shown), spacing="Small"))

    listed = min(cap, len(issue_changes))
    hidden = len(issue_changes) - listed
    if hidden > 0:
        elements.append(_text_block(f"_...and {hidden} more_", isSubtle=True, spacing="Small"))

    return elements


def _posture_severities(min_severity: str) -> list[str]:
    """Return the severities worth reporting, mirroring issue-creation filtering."""
    threshold = SEVERITY_ORDER.get(min_severity, SEVERITY_ORDER["low"])
    return [
        severity
        for severity in _SEVERITY_DISPLAY_ORDER
        if severity != "unknown" and SEVERITY_ORDER[severity] >= threshold
    ]


def _posture_label_column(severity: str) -> dict[str, Any]:
    """Build one label cell of the posture grid's header row."""
    return {
        "type": "Column",
        "width": "stretch",
        "items": [_text_block(f"{_severity_emoji(severity)} {severity.capitalize()}", horizontalAlignment="Center")],
    }


def _posture_value_column(value: int) -> dict[str, Any]:
    """Build one value cell of the posture grid's count row."""
    return {
        "type": "Column",
        "width": "stretch",
        "items": [_text_block(str(value), horizontalAlignment="Center")],
    }


def _posture_section(posture: dict[str, int], min_severity: str) -> list[dict[str, Any]]:
    """Build the footer summarizing currently-open child issues by severity.

    This is secondary, at-a-glance context rather than the main content of the run (that's
    ``_change_counters`` and ``_issue_sections`` above), so it's rendered smaller and subtler:
    a plain heading and default-size counts, not the bold/``ExtraLarge`` styling used for the
    run's own opened/reopened/closed numbers.

    Zero counts are kept so a clean severity reads as explicitly clear rather than missing.
    Rendered as a two-row grid (severities, then counts) using the same ``ColumnSet`` technique
    as the rest of the card, rather than the ``Table`` element, which is unverified for the
    legacy Teams webhook rendering path.
    """
    severities = _posture_severities(min_severity)
    if not severities:
        return []

    return [
        _text_block(f"Open security issues (severity >= {min_severity})", isSubtle=True, spacing="Medium"),
        {"type": "ColumnSet", "spacing": "Small", "columns": [_posture_label_column(s) for s in severities]},
        {
            "type": "ColumnSet",
            "spacing": "None",
            "columns": [_posture_value_column(posture.get(s, 0)) for s in severities],
        },
    ]


def _actions(links: NotificationLinks) -> list[dict[str, Any]]:
    """Build the card's footer buttons as one centered, side-by-side row.

    A single ``ActionSet`` keeps the buttons next to each other at their natural width (unlike
    the top-level card ``actions`` array, whose stretch/orientation is host-controlled, not
    card-controlled); only the row as a whole is centered via ``horizontalAlignment``.
    """
    candidates = (
        ("View workflow run", links.run_url),
        ("Repository issues", links.repo_url),
        ("AquaSec console", links.aqua_url),
    )
    buttons = [{"type": "Action.OpenUrl", "title": title, "url": url} for title, url in candidates if url]
    if not buttons:
        return []

    return [{"type": "ActionSet", "horizontalAlignment": "Center", "spacing": "Medium", "actions": buttons}]


def build_security_card(
    *,
    links: NotificationLinks,
    issue_changes: list[IssueChange],
    posture: dict[str, int],
    min_severity: str,
    issue_cap: int = TEAMS_ISSUE_LIST_CAP,
) -> dict[str, Any]:
    """Render a completed sync run as a Teams Adaptive Card.

    Args:
        links: Repository and workflow-run links for the card header and buttons.
        issue_changes: Child issues opened, reopened or closed during the run.
        posture: Count of currently-open child issues per severity.
        min_severity: Configured issue-creation threshold, used to scope the footer.
        issue_cap: Maximum number of issues listed individually across all sections.

    Returns:
        The Adaptive Card object, ready to be wrapped in a Teams message payload.
    """
    body: list[dict[str, Any]] = [_header(links.repo)]
    body += _change_counters(issue_changes)
    body += _issue_sections(issue_changes, cap=issue_cap)
    body += _posture_section(posture, min_severity)
    body += _actions(links)

    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.5",
        "msteams": {"width": "Full"},
        "body": body,
    }

    return card


def build_message_payload(card: dict[str, Any]) -> dict[str, Any]:
    """Wrap an Adaptive Card in the Teams incoming-webhook message envelope."""
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card,
            }
        ],
    }
