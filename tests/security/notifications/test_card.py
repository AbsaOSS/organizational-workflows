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
from pytest_mock import MockerFixture

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


def _run_columns(card: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the run-summary columns (Opened/Reopened/Solved) keyed by their label."""
    columns = next(e for e in card["body"] if e["type"] == "ColumnSet")["columns"]
    return {column["items"][1]["text"]: column for column in columns}


def _column_rows(column: dict[str, Any]) -> str | None:
    """Return a run column's bullet-list text, or None if it has no rows."""
    for item in column["items"][2:]:
        if not item["text"].startswith("_...and"):
            return item["text"]
    return None


def _column_overflow(column: dict[str, Any]) -> str | None:
    """Return a run column's "...and N more" note, or None if nothing was hidden."""
    for item in column["items"][2:]:
        if item["text"].startswith("_...and"):
            return item["text"]
    return None


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
    assert "**Critical:**" in row
    assert f"[#101](https://github.com/{REPO}/issues/101)" in row
    assert row.endswith("(Secrets)")


def test_issue_row_pending_when_no_number() -> None:
    """Dry-run issues have no number yet, so they render as pending instead of a broken link."""
    row = _issue_row(_issue(0))
    assert "(pending)" in row
    assert "](" not in row


def test_issue_row_omits_empty_rule_id() -> None:
    """A blank rule id leaves no dangling separator or empty parentheses."""
    row = _issue_row(_issue(7, rule_id=""))
    assert "()" not in row
    assert not row.endswith("(")


# _posture_severities


@pytest.mark.parametrize(
    "min_severity,expected",
    [
        ("low", ["critical", "high", "medium", "low"]),
        ("medium", ["critical", "high", "medium"]),
        ("high", ["critical", "high"]),
        ("critical", ["critical"]),
    ],
)
def test_posture_severities_scoped_by_min_severity(min_severity: str, expected: list[str]) -> None:
    """The footer reports exactly the severities the repository creates issues for, never unknown."""
    assert expected == _posture_severities(min_severity)


# build_security_card - header and counters


def test_card_header_names_repository_and_is_coloured(links: NotificationLinks) -> None:
    header = _build(links)["body"][0]
    assert "Container" == header["type"]
    assert header["bleed"] is True
    assert "backgroundColor" not in header  # Container has no such property; it was always a no-op
    assert REPO == header["items"][1]["text"]
    assert all(item["color"] == "dark" for item in header["items"])


def test_card_counts_each_state(links: NotificationLinks) -> None:
    """Opened / reopened / closed counters reflect the notification states."""
    issue_changes = [_issue(1), _issue(2), _issue(3, state="reopen"), _issue(4, state="closed")]
    card = _build(links, issue_changes=issue_changes)
    columns = next(e for e in card["body"] if e["type"] == "ColumnSet")["columns"]
    assert ["2", "1", "1"] == [column["items"][0]["text"] for column in columns]
    assert ["Opened", "Reopened", "Solved"] == [column["items"][1]["text"] for column in columns]


# build_security_card - issue sections


def test_card_groups_issues_by_state_with_carriage_return_lists(links: NotificationLinks) -> None:
    """Each state's rows live inside that state's column, joined with \\r, as Teams requires."""
    issue_changes = [_issue(1), _issue(2), _issue(3, state="closed")]
    columns = _run_columns(_build(links, issue_changes=issue_changes))

    opened_rows = _column_rows(columns["Opened"])
    assert opened_rows is not None
    assert "\r" in opened_rows
    assert "\n" not in opened_rows  # \n\n inside a list wrongly indents the next item

    assert _column_rows(columns["Solved"]) is not None
    assert _column_rows(columns["Reopened"]) is None  # no reopened issues, so no rows


def test_card_caps_issue_list_per_state_independently(links: NotificationLinks) -> None:
    """Each state is capped on its own -- one state hitting the cap doesn't affect the others."""
    issue_changes = (
        [_issue(n) for n in range(1, 13)]  # 12 opened, exceeds the cap
        + [_issue(n, state="reopen") for n in range(13, 15)]  # 2 reopened, well under the cap
        + [_issue(n, state="closed") for n in range(15, 19)]  # 4 closed, well under the cap
    )
    columns = _run_columns(_build(links, issue_changes=issue_changes, issue_cap=10))

    assert 10 == len(_column_rows(columns["Opened"]).split("\r"))  # type: ignore[union-attr]
    assert 2 == len(_column_rows(columns["Reopened"]).split("\r"))  # type: ignore[union-attr]
    assert 4 == len(_column_rows(columns["Solved"]).split("\r"))  # type: ignore[union-attr]

    assert "_...and 2 more_" == _column_overflow(columns["Opened"])
    assert _column_overflow(columns["Reopened"]) is None
    assert _column_overflow(columns["Solved"]) is None


def test_card_issue_rows_sorted_highest_severity_first(links: NotificationLinks) -> None:
    """Issues within a state render critical-first regardless of input order."""
    issue_changes = [
        _issue(1, severity="low"),
        _issue(2, severity="critical"),
        _issue(3, severity="medium"),
        _issue(4, severity="high"),
    ]
    columns = _run_columns(_build(links, issue_changes=issue_changes))

    opened_rows = _column_rows(columns["Opened"]).split("\r")  # type: ignore[union-attr]
    assert ["#2", "#4", "#3", "#1"] == [row.split("](")[0].split("[")[1] for row in opened_rows]


def test_card_cap_zero_omits_rows_but_keeps_counters(links: NotificationLinks) -> None:
    """The degraded card drops individual rows while still reporting the totals."""
    issue_changes = [_issue(n) for n in range(1, 6)]
    columns = _run_columns(_build(links, issue_changes=issue_changes, issue_cap=0))

    assert "5" == columns["Opened"]["items"][0]["text"]
    assert _column_rows(columns["Opened"]) is None
    assert "_...and 5 more_" == _column_overflow(columns["Opened"])


def test_card_cap_zero_omits_overflow_note_when_no_issues(links: NotificationLinks) -> None:
    """Zero cap with no issue activity renders no overflow note (nothing was actually hidden)."""
    card = _build(links, issue_changes=[], issue_cap=0)
    assert not any("more" in element.get("text", "") for element in card["body"])


# build_security_card - posture footer


def test_card_posture_keeps_zero_counts_within_threshold(links: NotificationLinks) -> None:
    """Zero counts are shown so a clean severity reads as explicitly clear, 'low' is excluded."""
    card = _build(links, posture={"high": 22, "low": 9}, min_severity="medium")
    heading_index = next(
        i for i, e in enumerate(card["body"]) if e.get("text", "").startswith("Repository Vulnerabilities")
    )
    heading = card["body"][heading_index]
    columns = card["body"][heading_index + 1]["columns"]

    assert heading["text"] == "Repository Vulnerabilities (severity >= medium)"
    assert ["Critical", "High", "Medium"] == [column["items"][1]["text"] for column in columns]
    assert ["0", "22", "0"] == [column["items"][0]["text"] for column in columns]


def test_card_posture_omits_threshold_suffix_when_showing_everything(links: NotificationLinks) -> None:
    """'low' means every severity is shown, so the '(severity >= low)' suffix would be redundant."""
    card = _build(links, posture={"high": 1}, min_severity="low")
    heading = next(e for e in card["body"] if e.get("text", "").startswith("Repository Vulnerabilities"))

    assert heading["text"] == "Repository Vulnerabilities"


def test_card_omits_posture_section_when_no_severity_qualifies(links: NotificationLinks, mocker: MockerFixture) -> None:
    """No section is rendered when the configured threshold leaves nothing to report."""
    mocker.patch("security.notifications.card._posture_severities", return_value=[])
    card = _build(links, posture={"high": 1})
    assert not any(e.get("text", "").startswith("Repository vulnerabilities") for e in card["body"])


# build_security_card - actions


def _action_set(card: dict[str, Any]) -> dict[str, Any] | None:
    """Find the card's centered button row, if any."""
    for element in card["body"]:
        if element["type"] == "ActionSet":
            return element
    return None


def test_card_actions_link_run_repo_and_console(links: NotificationLinks) -> None:
    action_set = _action_set(_build(links))
    assert action_set is not None
    assert action_set["horizontalAlignment"] == "Center"
    buttons = action_set["actions"]
    assert ["View workflow run", "Repository issues", "AquaSec console"] == [b["title"] for b in buttons]
    assert all(button["type"] == "Action.OpenUrl" for button in buttons)
    assert buttons[2]["url"].startswith("https://eu-1.cloud.aquasec.com/")


def test_card_omits_run_button_outside_actions() -> None:
    """Running locally has no run URL, so that button is dropped rather than rendered broken."""
    local = NotificationLinks(repo=REPO, repo_url=f"https://github.com/{REPO}/issues", run_url="")
    action_set = _action_set(_build(local))
    assert action_set is not None
    assert "View workflow run" not in [button["title"] for button in action_set["actions"]]


def test_card_omits_action_set_when_no_links_available() -> None:
    """No buttons means no empty action row either."""
    empty = NotificationLinks(repo=REPO, repo_url="", run_url="", aqua_url="")
    assert _action_set(_build(empty)) is None


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
