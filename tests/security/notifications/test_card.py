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

"""Unit tests for ``security.notifications.card``."""

from typing import Any

import pytest

from security.issues.models import IssueChange
from security.notifications.card import (
    _issue_row,
    _posture_severities,
    build_message_payload,
    build_security_card,
)
from security.notifications.links import NotificationLinks

REPO = "org/repo"


@pytest.fixture
def links() -> NotificationLinks:
    return NotificationLinks(
        repo=REPO,
        repo_url=f"https://github.com/{REPO}/issues",
        run_url=f"https://github.com/{REPO}/actions/runs/99",
    )


def _issue(number: int, severity: str = "high", state: str = "new", rule_id: str = "AVD-001") -> IssueChange:
    return IssueChange(repo=REPO, issue_number=number, severity=severity, rule_id=rule_id, state=state)


def _texts(card: dict[str, Any]) -> list[str]:
    """Collect every rendered TextBlock string in body order."""
    return [element["text"] for element in card["body"] if element.get("type") == "TextBlock"]


def _build(links: NotificationLinks, **overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "links": links,
        "issue_changes": [],
        "posture": {},
        "min_severity": "low",
    }
    params.update(overrides)
    return build_security_card(**params)


# _issue_row


def test_issue_row_links_and_marks_severity(links: NotificationLinks) -> None:
    """A numbered issue renders an emoji, bold severity, markdown link and rule id."""
    row = _issue_row(_issue(101, severity="critical", rule_id="Secrets"))
    assert "🔴" in row
    assert "**Critical**" in row
    assert f"[#101](https://github.com/{REPO}/issues/101)" in row
    assert row.endswith("Secrets")


def test_issue_row_pending_when_no_number() -> None:
    """Dry-run issues have no number yet, so they render as pending instead of a broken link."""
    row = _issue_row(_issue(0))
    assert "(pending)" in row
    assert "](" not in row


def test_issue_row_omits_empty_rule_id() -> None:
    """A blank rule id leaves no dangling separator."""
    assert not _issue_row(_issue(7, rule_id="")).endswith("- ")


# _posture_severities


@pytest.mark.parametrize(
    "min_severity,expected",
    [
        ("low", ["critical", "high", "medium", "low", "unknown"]),
        ("medium", ["critical", "high", "medium"]),
        ("high", ["critical", "high"]),
        ("critical", ["critical"]),
    ],
)
def test_posture_severities_scoped_by_min_severity(min_severity: str, expected: list[str]) -> None:
    """The footer reports exactly the severities the repository creates issues for."""
    assert expected == _posture_severities(min_severity)


# build_security_card - header and counters


def test_card_header_names_repository_and_is_coloured(links: NotificationLinks) -> None:
    """The header is a bleeding accent container titled with the repository."""
    header = _build(links)["body"][0]
    assert "Container" == header["type"]
    assert "accent" == header["style"]
    assert header["bleed"] is True
    assert REPO == header["items"][1]["text"]


def test_card_counts_each_state(links: NotificationLinks) -> None:
    """Opened / reopened / closed counters reflect the notification states."""
    issue_changes = [_issue(1), _issue(2), _issue(3, state="reopen"), _issue(4, state="closed")]
    columns = next(e for e in _build(links, issue_changes=issue_changes)["body"] if e["type"] == "ColumnSet")["columns"]
    assert ["2", "1", "1"] == [column["items"][0]["text"] for column in columns]
    assert ["Opened", "Reopened", "Closed"] == [column["items"][1]["text"] for column in columns]


# build_security_card - issue sections


def test_card_groups_issues_by_state_with_carriage_return_lists(links: NotificationLinks) -> None:
    """Sections appear per state and list items are joined with \\r, as Teams requires."""
    issue_changes = [_issue(1), _issue(2), _issue(3, state="closed")]
    texts = _texts(_build(links, issue_changes=issue_changes))

    assert "Opened" in texts
    assert "Closed" in texts
    assert "Reopened" not in texts  # no reopened issues, so no empty section

    opened_rows = texts[texts.index("Opened") + 1]
    assert "\r" in opened_rows
    assert "\n" not in opened_rows  # \n\n inside a list wrongly indents the next item


def test_card_caps_issue_list_and_reports_remainder(links: NotificationLinks) -> None:
    """Only *issue_cap* issues are listed; the rest are summarised to protect the size limit."""
    issue_changes = [_issue(n) for n in range(1, 16)]
    texts = _texts(_build(links, issue_changes=issue_changes, issue_cap=10))

    rows = texts[texts.index("Opened") + 1]
    assert 10 == len(rows.split("\r"))
    assert any("...and 5 more" in text for text in texts)


def test_card_cap_zero_omits_rows_but_keeps_counters(links: NotificationLinks) -> None:
    """The degraded card drops individual rows while still reporting the totals."""
    issue_changes = [_issue(n) for n in range(1, 6)]
    card = _build(links, issue_changes=issue_changes, issue_cap=0)
    texts = _texts(card)

    assert "Opened" not in texts
    assert any("...and 5 more" in text for text in texts)
    assert any(element["type"] == "ColumnSet" for element in card["body"])


# build_security_card - posture footer


def test_card_posture_keeps_zero_counts_within_threshold(links: NotificationLinks) -> None:
    """Zero counts are shown so a clean severity reads as explicitly clear."""
    card = _build(links, posture={"high": 22, "low": 9}, min_severity="medium")
    facts = next(e for e in card["body"] if e["type"] == "FactSet")["facts"]

    assert ["🔴 Critical", "🟠 High", "🟡 Medium"] == [fact["title"] for fact in facts]
    assert ["0", "22", "0"] == [fact["value"] for fact in facts]  # 'low' is below the threshold


# build_security_card - actions


def test_card_actions_link_run_repo_and_console(links: NotificationLinks) -> None:
    actions = _build(links)["actions"]
    assert ["View workflow run", "Repository issues", "AquaSec console"] == [a["title"] for a in actions]
    assert all(action["type"] == "Action.OpenUrl" for action in actions)
    assert actions[2]["url"].startswith("https://eu-1.cloud.aquasec.com/")


def test_card_omits_run_button_outside_actions() -> None:
    """Running locally has no run URL, so that button is dropped rather than rendered broken."""
    local = NotificationLinks(repo=REPO, repo_url=f"https://github.com/{REPO}/issues", run_url="")
    assert "View workflow run" not in [action["title"] for action in _build(local)["actions"]]


# build_message_payload


def test_message_payload_wraps_card_in_teams_envelope(links: NotificationLinks) -> None:
    """Teams requires this exact envelope on both the legacy and Workflows webhooks."""
    card = _build(links)
    payload = build_message_payload(card)

    assert "message" == payload["type"]
    attachment = payload["attachments"][0]
    assert "application/vnd.microsoft.card.adaptive" == attachment["contentType"]
    assert attachment["contentUrl"] is None
    assert card is attachment["content"]
    assert "1.5" == card["version"]  # inside every documented Teams bound; the webhook cap is undocumented


def test_card_requests_full_width(links: NotificationLinks) -> None:
    """Full width keeps the counter columns and issue lists readable in the Teams channel."""
    assert {"width": "Full"} == _build(links)["msteams"]
