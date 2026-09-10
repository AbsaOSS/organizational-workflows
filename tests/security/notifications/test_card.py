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
    _allocate_shown_counts,
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


# _allocate_shown_counts


def test_allocate_shown_counts_returns_full_counts_when_under_cap() -> None:
    """No truncation is needed when everything already fits within the cap."""
    counts = {"new": 3, "reopen": 2, "closed": 0}
    assert counts == _allocate_shown_counts(counts, cap=10, floor=3)


def test_allocate_shown_counts_gives_leftover_to_earlier_states_first() -> None:
    """The worked example: 8/2/4 with cap 10, floor 3 -> 5/2/3."""
    counts = {"new": 8, "reopen": 2, "closed": 4}
    assert {"new": 5, "reopen": 2, "closed": 3} == _allocate_shown_counts(counts, cap=10, floor=3)


def test_allocate_shown_counts_skips_empty_states() -> None:
    """A state with zero items contributes nothing and takes nothing."""
    counts = {"new": 12, "reopen": 0, "closed": 0}
    assert {"new": 10, "reopen": 0, "closed": 0} == _allocate_shown_counts(counts, cap=10, floor=3)


def test_allocate_shown_counts_shrinks_floor_when_cap_is_too_small() -> None:
    """When the cap can't cover every state's floor, later states get less than the floor."""
    counts = {"new": 8, "reopen": 2, "closed": 4}
    assert {"new": 3, "reopen": 2, "closed": 0} == _allocate_shown_counts(counts, cap=5, floor=3)


def test_allocate_shown_counts_zero_cap_shows_nothing() -> None:
    """A non-positive cap shows nothing for any state."""
    counts = {"new": 5, "reopen": 1, "closed": 0}
    assert {"new": 0, "reopen": 0, "closed": 0} == _allocate_shown_counts(counts, cap=0, floor=3)


# build_security_card - issue sections


def test_card_groups_issues_by_state_with_carriage_return_lists(links: NotificationLinks) -> None:
    """Sections appear per state and list items are joined with \\r, as Teams requires."""
    issue_changes = [_issue(1), _issue(2), _issue(3, state="closed")]
    texts = _texts(_build(links, issue_changes=issue_changes))

    assert "Opened" in texts
    assert "Solved" in texts
    assert "Reopened" not in texts  # no reopened issues, so no empty section

    opened_rows = texts[texts.index("Opened") + 1]
    assert "\r" in opened_rows
    assert "\n" not in opened_rows  # \n\n inside a list wrongly indents the next item


def test_card_caps_issue_list_and_reports_remainder(links: NotificationLinks) -> None:
    """Each state keeps its own share of the cap and reports its own remainder."""
    issue_changes = (
        [_issue(n) for n in range(1, 9)]
        + [_issue(n, state="reopen") for n in range(9, 11)]
        + [_issue(n, state="closed") for n in range(11, 15)]
    )
    texts = _texts(_build(links, issue_changes=issue_changes, issue_cap=10))

    opened_rows = texts[texts.index("Opened") + 1]
    reopened_rows = texts[texts.index("Reopened") + 1]
    solved_rows = texts[texts.index("Solved") + 1]

    assert 5 == len(opened_rows.split("\r"))
    assert 2 == len(reopened_rows.split("\r"))
    assert 3 == len(solved_rows.split("\r"))

    assert "_...and 3 more_" == texts[texts.index("Opened") + 2]
    assert "_...and 1 more_" == texts[texts.index("Solved") + 2]
    assert not any("more" in text for text in texts[texts.index("Reopened") : texts.index("Solved")])


def test_card_issue_list_never_starves_a_smaller_state(links: NotificationLinks) -> None:
    """A single reopened issue still gets shown even when opened alone exceeds the cap."""
    issue_changes = [_issue(n) for n in range(1, 21)] + [_issue(21, state="reopen")]
    texts = _texts(_build(links, issue_changes=issue_changes, issue_cap=10))

    assert "Reopened" in texts
    reopened_rows = texts[texts.index("Reopened") + 1]
    assert 1 == len(reopened_rows.split("\r"))


def test_card_issue_rows_sorted_highest_severity_first(links: NotificationLinks) -> None:
    """Issues within a state render critical-first regardless of input order."""
    issue_changes = [
        _issue(1, severity="low"),
        _issue(2, severity="critical"),
        _issue(3, severity="medium"),
        _issue(4, severity="high"),
    ]
    texts = _texts(_build(links, issue_changes=issue_changes))

    opened_rows = texts[texts.index("Opened") + 1].split("\r")
    assert ["#2", "#4", "#3", "#1"] == [row.split("](")[0].split("[")[1] for row in opened_rows]


def test_card_cap_zero_omits_rows_but_keeps_counters(links: NotificationLinks) -> None:
    """The degraded card drops individual rows while still reporting the totals."""
    issue_changes = [_issue(n) for n in range(1, 6)]
    card = _build(links, issue_changes=issue_changes, issue_cap=0)
    texts = _texts(card)

    assert "Opened" not in texts
    assert any("...and 5 more" in text for text in texts)
    assert any(element["type"] == "ColumnSet" for element in card["body"])


def test_card_cap_zero_omits_overflow_note_when_no_issues(links: NotificationLinks) -> None:
    """Zero cap with no issue activity renders no overflow note (nothing was actually hidden)."""
    card = _build(links, issue_changes=[], issue_cap=0)
    assert not any("more" in element.get("text", "") for element in card["body"])


# build_security_card - posture footer


def test_card_posture_keeps_zero_counts_within_threshold(links: NotificationLinks) -> None:
    """Zero counts are shown so a clean severity reads as explicitly clear, 'low' is excluded."""
    card = _build(links, posture={"high": 22, "low": 9}, min_severity="medium")
    heading_index = next(
        i for i, e in enumerate(card["body"]) if e.get("text", "").startswith("Vulnerabilities repository")
    )
    heading = card["body"][heading_index]
    columns = card["body"][heading_index + 1]["columns"]

    assert heading["text"] == "Vulnerabilities repository (severity >= medium)"
    assert ["Critical", "High", "Medium"] == [column["items"][1]["text"] for column in columns]
    assert ["0", "22", "0"] == [column["items"][0]["text"] for column in columns]


def test_card_posture_omits_threshold_suffix_when_showing_everything(links: NotificationLinks) -> None:
    """'low' means every severity is shown, so the '(severity >= low)' suffix would be redundant."""
    card = _build(links, posture={"high": 1}, min_severity="low")
    heading = next(e for e in card["body"] if e.get("text", "").startswith("Vulnerabilities repository"))

    assert heading["text"] == "Vulnerabilities repository"


def test_card_omits_posture_section_when_no_severity_qualifies(links: NotificationLinks, mocker: MockerFixture) -> None:
    """No section is rendered when the configured threshold leaves nothing to report."""
    mocker.patch("security.notifications.card._posture_severities", return_value=[])
    card = _build(links, posture={"high": 1})
    assert not any(e.get("text", "").startswith("Vulnerabilities repository") for e in card["body"])


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
