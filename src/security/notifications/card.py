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
    TEAMS_ISSUE_LIST_MIN_PER_STATE,
)
from security.issues.models import SEVERITY_ORDER, IssueChange
from security.notifications.links import NotificationLinks

# Highest first, matching how humans triage.
_SEVERITY_DISPLAY_ORDER = sorted(SEVERITY_ORDER, key=lambda severity: SEVERITY_ORDER[severity], reverse=True)

# Maps the internal issue state onto its card section heading.
_STATE_SECTIONS: tuple[tuple[str, str], ...] = (
    ("new", "Opened"),
    ("reopen", "Reopened"),
    ("closed", "Solved"),
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
    row = f"- {_severity_emoji(item.severity)} **{item.severity.capitalize()}:** {reference}"
    return f"{row} ({descriptor})" if descriptor else row


def _header(repo: str) -> dict[str, Any]:
    """Build the colored, edge-to-edge card header naming the repository."""
    return {
        "type": "Container",
        "style": "attention",
        "bleed": True,
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
        _text_block(
            "Vulnerabilities this run", weight="Bolder", size="Medium", spacing="Medium", horizontalAlignment="Center"
        ),
        {
            "type": "ColumnSet",
            "spacing": "Small",
            "columns": [_stat_column(label, counts[state]) for state, label in _STATE_SECTIONS],
        },
    ]


def _allocate_shown_counts(counts: dict[str, int], *, cap: int, floor: int) -> dict[str, int]:
    """Split *cap* across states so each non-empty state gets at least *floor* before extras.

    Pass 1 gives every state up to ``floor`` items (or all of its items, if it has fewer).
    Pass 2 hands out whatever of ``cap`` is left over to states that still have hidden items,
    greedily in dict-iteration order.
    """
    if cap <= 0:
        return dict.fromkeys(counts, 0)

    shown: dict[str, int] = {}
    remaining = cap
    for state, total in counts.items():
        allotted = min(floor, total, remaining)
        shown[state] = allotted
        remaining -= allotted

    for state, total in counts.items():
        if remaining <= 0:
            break
        extra = min(total - shown[state], remaining)
        shown[state] += extra
        remaining -= extra

    return shown


def _issue_sections(issue_changes: list[IssueChange], *, cap: int) -> list[dict[str, Any]]:
    """Build the per-state issue lists, each keeping a minimum share of the shared cap.

    Issues within a state are shown highest-severity first. Each state reports its own
    "...and N more" note when truncated.
    """
    if cap <= 0:
        if not issue_changes:
            return []
        return [_text_block(f"_...and {len(issue_changes)} more_", isSubtle=True, spacing="Small")]

    by_state = {
        state: sorted(
            (item for item in issue_changes if item.state == state),
            key=lambda item: SEVERITY_ORDER.get((item.severity or "").strip().lower(), 0),
            reverse=True,
        )
        for state, _ in _STATE_SECTIONS
    }
    counts = {state: len(items) for state, items in by_state.items()}
    shown = _allocate_shown_counts(counts, cap=cap, floor=TEAMS_ISSUE_LIST_MIN_PER_STATE)

    elements: list[dict[str, Any]] = []
    for state, heading in _STATE_SECTIONS:
        items = by_state[state]
        if not items:
            continue

        visible = items[: shown[state]]
        elements.append(_text_block(heading, weight="Bolder", spacing="Medium"))
        elements.append(_text_block(_LIST_SEPARATOR.join(_issue_row(item) for item in visible), spacing="Small"))

        hidden = len(items) - len(visible)
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


def _posture_heading_text(min_severity: str) -> str:
    """Return the posture section's heading, qualified by threshold unless it's a no-op."""
    heading = "Vulnerabilities repository"
    if min_severity != "low":
        heading += f" (severity >= {min_severity})"
    return heading


def _posture_section(posture: dict[str, int], min_severity: str) -> list[dict[str, Any]]:
    """Build the footer summarizing currently-open child issues by severity.

    This is secondary, at-a-glance context rather than the main content of the run, so it
    mirrors ``_change_counters``'s stat-column layout: one column per qualifying severity,
    with the count on top and the severity name below.

    Zero counts are kept so a clean severity reads as explicitly clear rather than missing.
    """
    severities = _posture_severities(min_severity)
    if not severities:
        return []

    return [
        _text_block(
            _posture_heading_text(min_severity),
            weight="Bolder",
            size="Medium",
            spacing="Medium",
            horizontalAlignment="Center",
        ),
        {
            "type": "ColumnSet",
            "spacing": "Small",
            "columns": [_stat_column(severity.capitalize(), posture.get(severity, 0)) for severity in severities],
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
