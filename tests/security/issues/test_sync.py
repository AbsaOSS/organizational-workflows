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

"""Unit tests for ``security.issues.sync`` – pure-logic helpers and
orchestration functions with mocked GitHub CLI calls.
"""

import copy
import logging
from typing import Any

import pytest
from pytest_mock import MockerFixture

from core.models import Issue
from security.issues.sync import (
    _record_for_notification,
    _close_resolved_child_issues,
    _close_resolved_parent_issues,
    _count_open_child_issues_by_severity,
    _ensure_child_linked_to_parent,
    _flush_parent_body_updates,
    _handle_new_child_issue,
    _init_priority_sync,
    _log_sync_summary,
    _maybe_reopen_child,
    _meets_min_severity,
    _merge_child_secmeta,
    _rebuild_and_apply_child_body,
    _sync_child_title,
    build_issue_index,
    ensure_issue,
    ensure_parent_issue,
    find_parent_issue,
    maybe_reopen_parent_issue,
    resolve_child_matches,
    sync_alerts_and_issues,
)
from security.alerts.models import Alert
from security.issues.builder import build_issue_title
from security.issues.models import (
    AlertContext,
    IssueIndex,
    IssueChange,
    ParentOriginalBodies,
    SyncContext,
    SyncStats,
)
from security.issues.secmeta import load_secmeta, render_secmeta


# =====================================================================
# helpers – build Issues with embedded secmeta
# =====================================================================

def _issue_with_secmeta(number: int, secmeta: dict[str, str], *, state: str = "open") -> Issue:
    body = render_secmeta(secmeta) + "\nSome body text\n"
    return Issue(number=number, state=state, title=f"Issue #{number}", body=body)


def _alert_with_keys(identity_key: str, alert_hash: str) -> Alert:
    return Alert.from_dict({
        "metadata": {"state": "open"},
        "alert_details": {"identity_key": identity_key, "alert_hash": alert_hash},
        "rule_details": {},
    })


def _make_alert_context(**overrides: Any) -> AlertContext:
    """Build an ``AlertContext`` with sensible defaults, overridable via kwargs."""
    defaults = dict(
        alert=Alert(),
        alert_number=1,
        identity_key="fp_test_123",
        alert_hash="hash_test_123",
        repo="test-org/test-repo",
        tool="AquaSec",
        rule_id="CVE-2026-1234",
        rule_name="sast",
        rule_description="Test finding description",
        severity="high",
        path="src/main.py",
        start_line=10,
        end_line=20,
        commit_sha="abc123def456",
    )
    defaults.update(overrides)
    return AlertContext(**defaults)


def _patch_gh_calls(mocker: MockerFixture) -> Any:
    """Patch the GitHub CLI wrappers used by ``ensure_issue`` and return the body-edit mock."""
    mocker.patch("security.issues.sync.gh_issue_create", return_value=999)
    mocker.patch("security.issues.sync.gh_issue_edit_title", return_value=True)
    mocker.patch("security.issues.sync.gh_issue_get_sub_issue_numbers", return_value=set())
    mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number", return_value=True)
    return mocker.patch("security.issues.sync.gh_issue_edit_body", return_value=True)


def _make_sync_context(
    issues: dict[int, Issue] | None = None,
    issue_index: IssueIndex | None = None,
    *,
    dry_run: bool = False,
    issue_changes: list[IssueChange] | None = None,
) -> SyncContext:
    """Build a ``SyncContext`` with sensible defaults."""
    if issues is None:
        issues = {}
    if issue_index is None:
        issue_index = build_issue_index(issues)
    return SyncContext(
        issues=issues,
        issue_index=issue_index,
        dry_run=dry_run,
        issue_changes=issue_changes if issue_changes is not None else [],
        severity_priority_map={},
        priority_sync=None,
    )


# =====================================================================
# build_issue_index
# =====================================================================


def test_indexes_parent_by_rule_id() -> None:
    parent = _issue_with_secmeta(1, {
        "type": "parent",
        "rule_id": "CVE-2026-1234",
        "severity": "high",
    })
    issues = {1: parent}
    idx = build_issue_index(issues)
    assert "CVE-2026-1234" in idx.parent_by_rule_id
    assert idx.parent_by_rule_id["CVE-2026-1234"] is parent


def test_indexes_child_by_identity_key() -> None:
    child = _issue_with_secmeta(2, {
        "type": "child",
        "fingerprint": "fp_abc123",
        "rule_id": "CVE-2026-1234",
    })
    issues = {2: child}
    idx = build_issue_index(issues)
    assert "fp_abc123" in idx.child_by_identity_key
    assert idx.child_by_identity_key["fp_abc123"] is child


def test_parent_not_in_identity_key_index() -> None:
    parent = _issue_with_secmeta(1, {
        "type": "parent",
        "rule_id": "CVE-2026-1234",
        "fingerprint": "fp_parent",
    })
    issues = {1: parent}
    idx = build_issue_index(issues)
    assert "fp_parent" not in idx.child_by_identity_key


def test_lowest_number_child_wins_regardless_of_order() -> None:
    c1 = _issue_with_secmeta(10, {"type": "child", "fingerprint": "shared_fp"})
    c2 = _issue_with_secmeta(20, {"type": "child", "fingerprint": "shared_fp"})
    idx = build_issue_index({20: c2, 10: c1})
    assert idx.child_by_identity_key["shared_fp"].number == 10


def test_open_child_wins_over_lower_numbered_closed_child() -> None:
    """A survivor migrated onto a reused ordinal is not shadowed by the removed occurrence's closed issue."""
    closed = _issue_with_secmeta(10, {"type": "child", "fingerprint": "shared_fp"}, state="closed")
    survivor = _issue_with_secmeta(20, {"type": "child", "fingerprint": "shared_fp"})
    idx = build_issue_index({10: closed, 20: survivor})
    assert idx.child_by_identity_key["shared_fp"] is survivor
    assert [closed, survivor] == idx.children


def test_lowest_number_parent_wins_regardless_of_order() -> None:
    p1 = _issue_with_secmeta(5, {"type": "parent", "rule_id": "R1"})
    p2 = _issue_with_secmeta(50, {"type": "parent", "rule_id": "R1"})
    idx = build_issue_index({50: p2, 5: p1})
    assert idx.parent_by_rule_id["R1"].number == 5


def test_mixed_issues() -> None:
    parent = _issue_with_secmeta(1, {"type": "parent", "rule_id": "R1"})
    child = _issue_with_secmeta(2, {"type": "child", "fingerprint": "fp1", "rule_id": "R1"})
    issues = {1: parent, 2: child}
    idx = build_issue_index(issues)
    assert "R1" in idx.parent_by_rule_id
    assert "fp1" in idx.child_by_identity_key


def test_empty() -> None:
    idx = build_issue_index({})
    assert idx.child_by_identity_key == {}
    assert idx.parent_by_rule_id == {}


def test_alert_hash_indexed_in_legacy_map() -> None:
    """A child issue with only an alert_hash is keyed in both maps, so closure still reaches it."""
    child = _issue_with_secmeta(5, {"type": "child", "alert_hash": "hash_123"})
    issues = {5: child}
    idx = build_issue_index(issues)
    assert "hash_123" in idx.child_by_alert_hash
    assert "hash_123" in idx.child_by_identity_key


def test_both_keys_indexed_separately() -> None:
    """A child issue carrying both keys appears once in each map."""
    child = _issue_with_secmeta(7, {"type": "child", "fingerprint": "fp_new", "alert_hash": "hash_old"})
    idx = build_issue_index({7: child})
    assert idx.child_by_identity_key["fp_new"].number == 7
    assert idx.child_by_alert_hash["hash_old"].number == 7
    assert "hash_old" not in idx.child_by_identity_key


def test_no_secmeta_skipped() -> None:
    """Issue without secmeta block is silently skipped."""
    issue = Issue(number=99, state="open", title="No meta", body="Plain body\n")
    issues = {99: issue}
    idx = build_issue_index(issues)
    assert idx.child_by_identity_key == {}
    assert idx.parent_by_rule_id == {}


# =====================================================================
# resolve_child_matches
# =====================================================================


def test_resolve_matches_by_identity() -> None:
    child = _issue_with_secmeta(2, {"type": "child", "fingerprint": "fp_abc"})
    idx = build_issue_index({2: child})
    assert {1: child} == resolve_child_matches({1: _alert_with_keys("fp_abc", "hash_x")}, idx)


def test_resolve_matches_nothing() -> None:
    idx = build_issue_index({})
    assert {} == resolve_child_matches({1: _alert_with_keys("missing", "hash_x")}, idx)


def test_resolve_matches_by_legacy_hash_in_identity_map() -> None:
    """A pre-change issue storing its result hash under `fingerprint` is found via the Result Hash."""
    child = _issue_with_secmeta(3, {"type": "child", "fingerprint": "hash_old"})
    idx = build_issue_index({3: child})
    assert {1: child} == resolve_child_matches({1: _alert_with_keys("fp_new", "hash_old")}, idx)


def test_resolve_matches_by_legacy_hash_in_alert_hash_map() -> None:
    """An issue carrying both keys is found when only the Result Hash matches."""
    child = _issue_with_secmeta(4, {"type": "child", "fingerprint": "fp_other", "alert_hash": "hash_old"})
    idx = build_issue_index({4: child})
    assert {1: child} == resolve_child_matches({1: _alert_with_keys("fp_new", "hash_old")}, idx)


def test_resolve_matches_prefers_exact_result_hash_over_reused_ordinal() -> None:
    """An exact Result Hash on another issue outranks a reused AquaSec Fingerprint ordinal."""
    reused_ordinal = _issue_with_secmeta(10, {"type": "child", "fingerprint": "fp_new"})
    exact_hash = _issue_with_secmeta(20, {"type": "child", "fingerprint": "fp_x", "alert_hash": "hash_old"})
    idx = build_issue_index({10: reused_ordinal, 20: exact_hash})
    assert {1: exact_hash} == resolve_child_matches({1: _alert_with_keys("fp_new", "hash_old")}, idx)


def test_resolve_matches_identity_when_result_hash_matches_nothing() -> None:
    """A line shift churns the Result Hash only, so the Finding Identity still decides."""
    shifted = _issue_with_secmeta(10, {"type": "child", "fingerprint": "fp_new", "alert_hash": "hash_before_shift"})
    unrelated = _issue_with_secmeta(20, {"type": "child", "fingerprint": "fp_x", "alert_hash": "hash_other"})
    idx = build_issue_index({10: shifted, 20: unrelated})
    assert {1: shifted} == resolve_child_matches({1: _alert_with_keys("fp_new", "hash_after_shift")}, idx)


def test_resolve_matches_identity_wins_without_aquasec_fingerprint() -> None:
    """Without an AquaSec Fingerprint both values are equal, so the identity map is tried first."""
    matched = _issue_with_secmeta(10, {"type": "child", "fingerprint": "hash_same"})
    other = _issue_with_secmeta(20, {"type": "child", "fingerprint": "fp_x", "alert_hash": "hash_same"})
    idx = build_issue_index({10: matched, 20: other})
    assert {1: matched} == resolve_child_matches({1: _alert_with_keys("hash_same", "hash_same")}, idx)


def test_resolve_matches_claims_each_issue_once() -> None:
    """An issue claimed by its exact Result Hash is not handed to another alert reusing its ordinal."""
    child = _issue_with_secmeta(10, {"type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_existing"})
    idx = build_issue_index({10: child})
    alerts = {1: _alert_with_keys("fp_base_0", "hash_inserted"), 2: _alert_with_keys("fp_base_1", "hash_existing")}
    assert {2: child} == resolve_child_matches(alerts, idx)


def test_resolve_matches_open_identity_beats_closed_exact_hash() -> None:
    """A closed legacy issue whose old hash reappears must not take the finding from its open issue."""
    closed_legacy = _issue_with_secmeta(5, {"type": "child", "fingerprint": "hash_old"}, state="closed")
    open_owner = _issue_with_secmeta(9, {"type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_new"})
    idx = build_issue_index({5: closed_legacy, 9: open_owner})
    assert {1: open_owner} == resolve_child_matches({1: _alert_with_keys("fp_base_0", "hash_old")}, idx)


def test_resolve_matches_reopens_closed_issue_by_exact_hash() -> None:
    """A resolved finding reappearing on its old line is matched to its closed issue."""
    closed = _issue_with_secmeta(
        5, {"type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_a"}, state="closed"
    )
    idx = build_issue_index({5: closed})
    assert {1: closed} == resolve_child_matches({1: _alert_with_keys("fp_base_0", "hash_a")}, idx)


@pytest.mark.parametrize("issue_keys, alert_keys", [
    ([("fp_base_0", "hash_a"), ("fp_base_1", "hash_b")], [("fp_base_0", "hash_b_shifted")]),
    ([("fp_base_0", "hash_a")], [("fp_base_0", "hash_new_shifted"), ("fp_base_1", "hash_a_shifted")]),
], ids=["removed_and_shifted", "inserted_and_shifted"])
def test_resolve_matches_reused_ordinal_with_line_shift_matches_nothing(
    issue_keys: list[tuple[str, str]], alert_keys: list[tuple[str, str]]
) -> None:
    """When the occurrence set changed and lines shifted, a reused ordinal must not transfer an issue."""
    issues = {
        10 + i: _issue_with_secmeta(10 + i, {"type": "child", "fingerprint": fp, "alert_hash": h})
        for i, (fp, h) in enumerate(issue_keys)
    }
    alerts = {i + 1: _alert_with_keys(fp, h) for i, (fp, h) in enumerate(alert_keys)}
    assert {} == resolve_child_matches(alerts, build_issue_index(issues))


def test_resolve_matches_shift_of_all_occurrences_keeps_issues() -> None:
    """A pure line shift of every occurrence keeps the occurrence set, so identities still match."""
    first = _issue_with_secmeta(10, {"type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_a"})
    second = _issue_with_secmeta(11, {"type": "child", "fingerprint": "fp_base_1", "alert_hash": "hash_b"})
    idx = build_issue_index({10: first, 11: second})
    alerts = {1: _alert_with_keys("fp_base_1", "hash_b2"), 2: _alert_with_keys("fp_base_0", "hash_a2")}
    assert {1: second, 2: first} == resolve_child_matches(alerts, idx)


@pytest.mark.parametrize("other_hash, other_state", [
    ("hash_before_shift", "open"),
    ("hash_removed", "closed"),
], ids=["same_finding_duplicate", "closed_historical_owner"])
def test_resolve_matches_line_shift_with_nonconflicting_owners(other_hash: str, other_state: str) -> None:
    owner = _issue_with_secmeta(10, {
        "type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_before_shift",
    })
    other = _issue_with_secmeta(20, {
        "type": "child", "fingerprint": "fp_base_0", "alert_hash": other_hash,
    }, state=other_state)
    alerts = {1: _alert_with_keys("fp_base_0", "hash_after_shift")}

    assert {1: owner} == resolve_child_matches(alerts, build_issue_index({20: other, 10: owner}))


def test_resolve_matches_conflict_settled_by_exact_hash_keeps_shifted_sibling() -> None:
    """Once an exact Result Hash settles a conflicting identity, a sibling that only shifted keeps its issue.

    An interrupted run left #10 (removed occurrence) and #20 (migrated survivor) both open on fp_base_0.
    The survivor kept its line, so its exact Result Hash claims #20 and #10 is left to close. fp_base_1
    only shifted lines - the base's occurrence set is unchanged - so it must keep #30.
    """
    removed = _issue_with_secmeta(10, {"type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_removed"})
    survivor = _issue_with_secmeta(20, {"type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_survivor"})
    sibling = _issue_with_secmeta(30, {"type": "child", "fingerprint": "fp_base_1", "alert_hash": "hash_sibling"})
    idx = build_issue_index({10: removed, 20: survivor, 30: sibling})
    alerts = {
        1: _alert_with_keys("fp_base_0", "hash_survivor"),
        2: _alert_with_keys("fp_base_1", "hash_sibling_shifted"),
    }

    assert {1: survivor, 2: sibling} == resolve_child_matches(alerts, idx)


@pytest.mark.parametrize("first_hash, owner_number", [
    ("hash_existing", 10),
    ("hash_removed", 20),
], ids=["duplicate_of_claimed_finding", "conflicting_claimed_owner"])
@pytest.mark.parametrize("inserted_first", [True, False])
def test_resolve_matches_does_not_reuse_another_open_owner(
    first_hash: str, owner_number: int, inserted_first: bool
) -> None:
    first = _issue_with_secmeta(10, {
        "type": "child", "fingerprint": "fp_base_0", "alert_hash": first_hash,
    })
    second = _issue_with_secmeta(20, {
        "type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_existing",
    })
    existing = _alert_with_keys("fp_base_1", "hash_existing")
    inserted = _alert_with_keys("fp_base_0", "hash_inserted")
    alerts = {2: inserted, 1: existing} if inserted_first else {1: existing, 2: inserted}
    issues = {10: first, 20: second}

    assert {1: issues[owner_number]} == resolve_child_matches(alerts, build_issue_index(issues))


# =====================================================================
# find_parent_issue
# =====================================================================


def test_find_parent_found() -> None:
    parent = _issue_with_secmeta(1, {"type": "parent", "rule_id": "R1"})
    idx = build_issue_index({1: parent})
    result = find_parent_issue(idx, rule_id="R1")
    assert result is not None
    assert result.number == 1


def test_find_parent_not_found() -> None:
    idx = build_issue_index({})
    assert find_parent_issue(idx, rule_id="missing") is None


# =====================================================================
# maybe_reopen_parent_issue
# =====================================================================


def test_reopen_parent_none(mocker: MockerFixture) -> None:
    """No-op when parent_issue is None - no gh call is made."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state")
    maybe_reopen_parent_issue(
        "org/repo", None, rule_id="R1", dry_run=False, stats=SyncStats(),
    )
    mock_edit.assert_not_called()


def test_reopen_parent_already_open() -> None:
    """No-op when parent is already open."""
    parent = Issue(number=1, state="open", title="P", body="b")
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=False, stats=SyncStats(),
    )
    assert parent.state == "open"


def test_reopen_parent_dry_run() -> None:
    """In dry-run mode, sets state to open without calling gh and bumps severity."""
    parent = Issue(number=1, state="closed", title="P", body="b")
    stats = SyncStats()
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=True, stats=stats, severity="high",
    )
    assert parent.state == "open"
    assert {"high": 1} == stats.parents_reopened_by_severity


def test_reopen_parent_real(mocker: MockerFixture) -> None:
    """Non-dry-run reopens issue via state edit and bumps severity."""
    mock_edit_state = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    parent = Issue(number=1, state="closed", title="P", body="b")
    stats = SyncStats()
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=False, stats=stats, severity="high",
    )
    assert parent.state == "open"
    mock_edit_state.assert_called_once_with("org/repo", 1, "open")
    assert {"high": 1} == stats.parents_reopened_by_severity


def test_reopen_parent_severity_falls_back_to_secmeta(mocker: MockerFixture) -> None:
    """When severity isn't passed (blank), falls back to the parent's own secmeta severity."""
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    parent = _issue_with_secmeta(1, {"type": "parent", "rule_id": "R1", "severity": "critical"}, state="closed")
    stats = SyncStats()
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=False, stats=stats, severity="",
    )
    assert {"critical": 1} == stats.parents_reopened_by_severity


def test_reopen_parent_gh_failure(mocker: MockerFixture) -> None:
    """If gh_issue_edit_state fails, state stays closed and no severity is bumped."""
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=False)
    parent = Issue(number=1, state="closed", title="P", body="b")
    stats = SyncStats()
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=False, stats=stats, severity="high",
    )
    assert parent.state == "closed"
    assert {} == stats.parents_reopened_by_severity


# =====================================================================
# _record_for_notification
# =====================================================================


def test_append_notification_active() -> None:
    issue_changes: list[IssueChange] = []
    _record_for_notification(
        issue_changes, repo="org/repo", issue_number=42,
        severity="high", rule_id="AVD-001", state="new",
    )
    assert len(issue_changes) == 1
    assert issue_changes[0].issue_number == 42


def test_append_notification_none() -> None:
    """No-op when issue_changes is None - must not raise."""
    _record_for_notification(
        None, repo="org/repo", issue_number=42,
        severity="high", rule_id="AVD-001", state="new",
    )
    # No assertion needed: the test passes if no exception is raised.


# =====================================================================
# _merge_child_secmeta
# =====================================================================


def test_merge_removes_gh_alert_numbers() -> None:
    """Legacy gh_alert_numbers key is dropped during merge."""
    child = _issue_with_secmeta(1, {
        "type": "child",
        "fingerprint": "fp1",
        "gh_alert_numbers": '["100"]',
    })
    ctx = _make_alert_context(alert_number=200, identity_key="fp1")
    secmeta = _merge_child_secmeta(ctx=ctx, child_issue=child)
    assert "gh_alert_numbers" not in secmeta


def test_merge_preserves_alert_hash() -> None:
    """The legacy alert_hash key is persisted during merge, carrying the fallback forward."""
    child = _issue_with_secmeta(1, {
        "type": "child",
        "alert_hash": "old_hash",
        "fingerprint": "fp1",
    })
    ctx = _make_alert_context(identity_key="fp1", alert_hash="new_hash")
    secmeta = _merge_child_secmeta(ctx=ctx, child_issue=child)
    assert "new_hash" == secmeta["alert_hash"]


def test_merge_strips_legacy_secmeta_keys() -> None:
    """Legacy secmeta keys are stripped during merge, keeping only canonical child keys."""
    child = _issue_with_secmeta(1, {
        "type": "child",
        "fingerprint": "fp1",
        "gh_alert_numbers": '["100"]',
        "category": "vulnerabilities",
        "cve": "CVE-2026-1234",
        "first_seen": "2026-01-01",
        "last_occurrence_fp": "abc123",
        "last_seen": "2026-01-02",
        "last_seen_commit": "deadbeef",
        "occurrence_count": "5",
        "postponed_until": "",
        "schema": "1",
        "source": "code_scanning",
        "tool": "AquaSec",
    })
    ctx = _make_alert_context(alert_number=200, identity_key="fp1")
    secmeta = _merge_child_secmeta(ctx=ctx, child_issue=child)
    expected_keys = {"type", "fingerprint", "alert_hash", "repo", "rule_id", "severity"}
    assert expected_keys == set(secmeta.keys())


# =====================================================================
# _maybe_reopen_child
# =====================================================================


def test_reopen_child_open_issue() -> None:
    """Returns False for an already-open issue."""
    issue = Issue(number=1, state="open", title="T", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context()
    assert _maybe_reopen_child(ctx=ctx, sync=sync, child_issue=issue, parent_issue=None) is False


def test_reopen_child_dry_run() -> None:
    """Dry-run marks reopened=True, appends notification, and bumps severity."""
    body = render_secmeta({"type": "child", "category": "sast"}) + "\nbody"
    issue = Issue(number=1, state="closed", title="T", body=body)
    ctx = _make_alert_context()
    issue_changes: list[IssueChange] = []
    sync = _make_sync_context(dry_run=True, issue_changes=issue_changes)
    result = _maybe_reopen_child(ctx=ctx, sync=sync, child_issue=issue, parent_issue=None)
    assert result is True
    assert len(issue_changes) == 1
    assert issue_changes[0].state == "reopen"
    assert {"high": 1} == sync.stats.children_reopened_by_severity


def test_reopen_child_real(mocker: MockerFixture) -> None:
    """Non-dry-run calls gh_issue_edit_state, appends notification, and bumps severity."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    body = render_secmeta({"type": "child", "category": "sast"}) + "\nbody"
    issue = Issue(number=5, state="closed", title="T", body=body)
    ctx = _make_alert_context()
    issue_changes: list[IssueChange] = []
    sync = _make_sync_context(issue_changes=issue_changes)
    result = _maybe_reopen_child(ctx=ctx, sync=sync, child_issue=issue, parent_issue=None)
    assert result is True
    assert len(issue_changes) == 1
    mock_edit.assert_called_once()
    assert {"high": 1} == sync.stats.children_reopened_by_severity


def test_reopen_child_cascades_to_parent(mocker: MockerFixture) -> None:
    """Reopening child also reopens the closed parent (dry-run)."""
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    body = render_secmeta({"type": "child"}) + "\nbody"
    issue = Issue(number=5, state="closed", title="T", body=body)
    parent = Issue(number=1, state="closed", title="P", body="pb")
    ctx = _make_alert_context()
    sync = _make_sync_context(dry_run=True)
    _maybe_reopen_child(ctx=ctx, sync=sync, child_issue=issue, parent_issue=parent)
    assert parent.state == "open"


def test_reopen_child_dry_run_updates_state() -> None:
    """Dry-run reopen sets issue.state to 'open' in memory."""
    body = render_secmeta({"type": "child"}) + "\nbody"
    issue = Issue(number=1, state="closed", title="T", body=body)
    ctx = _make_alert_context()
    sync = _make_sync_context(dry_run=True)
    _maybe_reopen_child(ctx=ctx, sync=sync, child_issue=issue, parent_issue=None)
    assert "open" == issue.state


def test_reopen_child_real_updates_state(mocker: MockerFixture) -> None:
    """Non-dry-run reopen sets issue.state to 'open' in memory."""
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    body = render_secmeta({"type": "child"}) + "\nbody"
    issue = Issue(number=5, state="closed", title="T", body=body)
    ctx = _make_alert_context()
    sync = _make_sync_context()
    _maybe_reopen_child(ctx=ctx, sync=sync, child_issue=issue, parent_issue=None)
    assert "open" == issue.state


# _maybe_reopen_child waiver labels

def test_reopen_child_leaves_waiver_labels_untouched(mocker: MockerFixture) -> None:
    """Reopening a child issue does not add or remove human-owned waiver labels."""
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    body = render_secmeta({"type": "child", "category": "sast"}) + "\nbody"
    issue = Issue(number=5, state="closed", title="T", body=body, labels=["scope:security", "sec:suppression"])
    ctx = _make_alert_context()
    sync = _make_sync_context()
    result = _maybe_reopen_child(ctx=ctx, sync=sync, child_issue=issue, parent_issue=None)
    assert result is True
    assert "sec:suppression" in issue.labels


# =====================================================================
# _rebuild_and_apply_child_body
# =====================================================================


def test_rebuild_body_changed(mocker: MockerFixture, sast_alert: Alert) -> None:
    """When body changes, gh_issue_edit_body is called and severity is bumped."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_body", return_value=True)
    issue = Issue(number=1, state="open", title="T", body="old body")
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context()
    secmeta = {"schema": "1", "type": "child", "fingerprint": "fp1"}
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, child_issue=issue, secmeta=secmeta)
    mock_edit.assert_called_once()
    assert {"high": 1} == sync.stats.children_body_updated_by_severity


def test_rebuild_body_unchanged(sast_alert: Alert) -> None:
    """When body is identical, no API call is made."""
    from security.issues.builder import build_child_issue_body

    secmeta = {"schema": "1", "type": "child", "fingerprint": "fp1"}
    human_body = build_child_issue_body(sast_alert)
    body = render_secmeta(secmeta) + "\n\n" + human_body
    issue = Issue(number=1, state="open", title="T", body=body)
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context()
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, child_issue=issue, secmeta=secmeta)
    assert {} == sync.stats.children_body_updated_by_severity


def test_rebuild_body_dry_run(sast_alert: Alert) -> None:
    """In dry-run mode, body is not written via API but severity is bumped."""
    issue = Issue(number=1, state="open", title="T", body="old body")
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context(dry_run=True)
    secmeta = {"schema": "1", "type": "child", "fingerprint": "fp1"}
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, child_issue=issue, secmeta=secmeta)
    assert {"high": 1} == sync.stats.children_body_updated_by_severity


# =====================================================================
# _sync_child_title
# =====================================================================


def test_sync_title_drift_corrected(mocker: MockerFixture) -> None:
    """Title is updated when it drifts from the expected format."""
    mock_title = mocker.patch("security.issues.sync.gh_issue_edit_title", return_value=True)
    issue = Issue(number=1, state="open", title="Wrong title", body="b")
    ctx = _make_alert_context(rule_name="sast", rule_id="CVE-2026-1234", identity_key="fp_test_123")
    sync = _make_sync_context()
    _sync_child_title(ctx=ctx, sync=sync, child_issue=issue)
    mock_title.assert_called_once()


def test_sync_title_already_correct(mocker: MockerFixture) -> None:
    """Title is not updated when it matches the expected format."""
    mock_title = mocker.patch("security.issues.sync.gh_issue_edit_title", return_value=True)
    title = build_issue_title("Test finding description", "fp_test_123", "high")
    issue = Issue(number=1, state="open", title=title, body="b")
    ctx = _make_alert_context(rule_name="sast", rule_id="CVE-2026-1234", identity_key="fp_test_123")
    sync = _make_sync_context()
    _sync_child_title(ctx=ctx, sync=sync, child_issue=issue)
    mock_title.assert_not_called()


def test_sync_title_dry_run() -> None:
    """Dry-run mode logs instead of calling gh."""
    issue = Issue(number=1, state="open", title="Wrong", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context(dry_run=True)
    _sync_child_title(ctx=ctx, sync=sync, child_issue=issue)


# =====================================================================
# _handle_new_child_issue
# =====================================================================


def test_handle_new_child_creates_issue(mocker: MockerFixture, sast_alert: Alert) -> None:
    """Creates a new issue, registers it in the issue_index, and bumps severity."""
    mock_create = mocker.patch("security.issues.sync.gh_issue_create", return_value=42)
    ctx = _make_alert_context(alert=sast_alert, rule_name="sast")
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    sync = _make_sync_context(issues=issues, issue_index=issue_index, issue_changes=[])
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)
    mock_create.assert_called_once()
    assert 42 in issues
    assert ctx.identity_key in issue_index.child_by_identity_key
    assert len(sync.issue_changes) == 1
    assert sync.issue_changes[0].state == "new"
    assert {"high": 1} == sync.stats.children_created_by_severity


def test_handle_new_child_persists_both_identity_keys(mocker: MockerFixture, sast_alert: Alert) -> None:
    """A created child carries both secmeta keys, so the next run needs no body rewrite."""
    mock_create = mocker.patch("security.issues.sync.gh_issue_create", return_value=42)
    ctx = _make_alert_context(alert=sast_alert, rule_name="sast")
    sync = _make_sync_context(issue_index=IssueIndex(child_by_identity_key={}, parent_by_rule_id={}))

    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)

    secmeta = load_secmeta(mock_create.call_args.args[2])
    assert ctx.identity_key == secmeta["fingerprint"]
    assert ctx.alert_hash == secmeta["alert_hash"]


def test_handle_new_child_indexes_under_both_keys(mocker: MockerFixture, sast_alert: Alert) -> None:
    """The created issue is enumerated and reachable from both lookup maps."""
    mocker.patch("security.issues.sync.gh_issue_create", return_value=42)
    ctx = _make_alert_context(alert=sast_alert, rule_name="sast")
    sync = _make_sync_context(issue_index=IssueIndex(child_by_identity_key={}, parent_by_rule_id={}))

    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)

    assert 42 == sync.issue_index.child_by_identity_key[ctx.identity_key].number
    assert 42 == sync.issue_index.child_by_alert_hash[ctx.alert_hash].number
    assert [42] == [issue.number for issue in sync.issue_index.children]


def test_handle_new_child_dry_run(sast_alert: Alert) -> None:
    """Dry-run does not call gh_issue_create but records notification."""
    ctx = _make_alert_context(alert=sast_alert)
    issue_changes: list[IssueChange] = []
    sync = _make_sync_context(dry_run=True, issue_changes=issue_changes)
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)
    assert len(issue_changes) == 1
    assert issue_changes[0].issue_number == 0


def test_handle_new_child_dry_run_indexes_the_issue_for_posture(sast_alert: Alert) -> None:
    """Dry-run must index the issue too, or the posture footer understates open findings."""
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context(dry_run=True, issue_changes=[])

    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)

    assert ctx.identity_key in sync.issue_index.child_by_identity_key
    assert {"high": 1} == _count_open_child_issues_by_severity(sync.issue_index)


def test_handle_new_child_dry_run_with_parent_increments_created(sast_alert: Alert) -> None:
    """Dry-run with a parent still bumps children_created (no API-backed link is attempted)."""
    parent = Issue(number=7, state="open", title="P", body="pb")
    ctx = _make_alert_context(alert=sast_alert)
    issue_changes: list[IssueChange] = []
    sync = _make_sync_context(dry_run=True, issue_changes=issue_changes)
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=parent)
    assert 1 == sync.stats.children_created
    assert {"high": 1} == sync.stats.children_created_by_severity


def test_handle_new_child_links_to_parent(mocker: MockerFixture, sast_alert: Alert) -> None:
    """When a parent issue exists and the link succeeds, the child is linked as a sub-issue."""
    mocker.patch("security.issues.sync.gh_issue_create", return_value=42)
    mock_sub = mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number", return_value=True)
    parent = Issue(number=1, state="open", title="P", body="pb")
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context(issue_changes=[])
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=parent)
    mock_sub.assert_called_once_with("test-org/test-repo", 1, 42)


def test_handle_new_child_link_failure_logs_warning(
    mocker: MockerFixture, sast_alert: Alert, caplog: pytest.LogCaptureFixture,
) -> None:
    """When linking a newly created child to its parent fails, a warning is logged."""
    mocker.patch("security.issues.sync.gh_issue_create", return_value=42)
    mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number", return_value=False)
    parent = Issue(number=1, state="open", title="P", body="pb")
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context(issue_changes=[])
    with caplog.at_level(logging.WARNING):
        _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=parent)
    assert any("Failed to link" in r.message for r in caplog.records)


def test_handle_new_child_create_fails(mocker: MockerFixture, sast_alert: Alert) -> None:
    """If gh_issue_create returns None, no crash and no issue_index update."""
    mocker.patch("security.issues.sync.gh_issue_create", return_value=None)
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context(issue_changes=[])
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)
    assert ctx.identity_key not in sync.issue_index.child_by_identity_key


# =====================================================================
# _ensure_child_linked_to_parent
# =====================================================================


def test_ensure_child_linked_already_linked(mocker: MockerFixture) -> None:
    """No-op when the child is already in the parent's sub-issues."""
    mocker.patch("security.issues.sync.gh_issue_get_sub_issue_numbers", return_value={5})
    mock_add = mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number")
    parent = Issue(number=1, state="open", title="P", body="pb")
    child = Issue(number=5, state="open", title="C", body="cb")
    ctx = _make_alert_context()
    sync = _make_sync_context()
    _ensure_child_linked_to_parent(ctx=ctx, sync=sync, child_issue=child, parent_issue=parent)
    mock_add.assert_not_called()
    assert 0 == sync.stats.children_relinked


def test_ensure_child_linked_missing_adds_link(mocker: MockerFixture, caplog: pytest.LogCaptureFixture) -> None:
    """Adds the sub-issue link when the child is missing from the parent, logs, and counts the relink."""
    mocker.patch("security.issues.sync.gh_issue_get_sub_issue_numbers", return_value=set())
    mock_add = mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number", return_value=True)
    parent = Issue(number=1, state="open", title="P", body="pb")
    child = Issue(number=5, state="open", title="C", body="cb")
    ctx = _make_alert_context()
    sync = _make_sync_context()
    with caplog.at_level(logging.INFO):
        _ensure_child_linked_to_parent(ctx=ctx, sync=sync, child_issue=child, parent_issue=parent)
    mock_add.assert_called_once_with("test-org/test-repo", 1, 5)
    assert 1 == sync.stats.children_relinked
    assert any("Relinked child issue #5 to parent #1" in r.message for r in caplog.records)


def test_ensure_child_linked_missing_dry_run(mocker: MockerFixture, caplog: pytest.LogCaptureFixture) -> None:
    """In dry-run mode logs intent, counts the relink, without calling the add-sub-issue API."""
    mocker.patch("security.issues.sync.gh_issue_get_sub_issue_numbers", return_value=set())
    mock_add = mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number")
    parent = Issue(number=1, state="open", title="P", body="pb")
    child = Issue(number=5, state="open", title="C", body="cb")
    ctx = _make_alert_context()
    sync = _make_sync_context(dry_run=True)
    with caplog.at_level(logging.INFO):
        _ensure_child_linked_to_parent(ctx=ctx, sync=sync, child_issue=child, parent_issue=parent)
    mock_add.assert_not_called()
    assert 1 == sync.stats.children_relinked
    assert any("Would relink child issue #5 to parent #1" in r.message for r in caplog.records)


def test_ensure_child_linked_cache_populated(mocker: MockerFixture) -> None:
    """gh_issue_get_sub_issue_numbers is called only once per parent (cached)."""
    mock_list = mocker.patch("security.issues.sync.gh_issue_get_sub_issue_numbers", return_value={5, 6})
    mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number")
    parent = Issue(number=1, state="open", title="P", body="pb")
    child_a = Issue(number=5, state="open", title="A", body="ab")
    child_b = Issue(number=6, state="open", title="B", body="bb")
    ctx_a = _make_alert_context(identity_key="fp_a")
    ctx_b = _make_alert_context(identity_key="fp_b")
    sync = _make_sync_context()
    _ensure_child_linked_to_parent(ctx=ctx_a, sync=sync, child_issue=child_a, parent_issue=parent)
    _ensure_child_linked_to_parent(ctx=ctx_b, sync=sync, child_issue=child_b, parent_issue=parent)
    mock_list.assert_called_once_with("test-org/test-repo", 1)


def test_ensure_child_linked_api_failure_no_cache_update(mocker: MockerFixture, caplog: pytest.LogCaptureFixture) -> None:
    """When the API call to add the link fails, the cache and relinked count are not updated, and a warning is logged."""
    mocker.patch("security.issues.sync.gh_issue_get_sub_issue_numbers", return_value=set())
    mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number", return_value=False)
    parent = Issue(number=1, state="open", title="P", body="pb")
    child = Issue(number=5, state="open", title="C", body="cb")
    ctx = _make_alert_context()
    sync = _make_sync_context()
    with caplog.at_level(logging.WARNING):
        _ensure_child_linked_to_parent(ctx=ctx, sync=sync, child_issue=child, parent_issue=parent)
    assert 5 not in sync.parent_sub_issues_cache.get(1, set())
    assert 0 == sync.stats.children_relinked
    assert any("Failed to relink" in r.message for r in caplog.records)


# =====================================================================
# ensure_parent_issue
# =====================================================================


def test_ensure_parent_creates_new(mocker: MockerFixture, sast_alert: Alert) -> None:
    """Creates a parent issue when none exists for the rule_id."""
    mock_create = mocker.patch("security.issues.sync.gh_issue_create", return_value=99)
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    result = ensure_parent_issue(
        sast_alert, issues, issue_index, dry_run=False, parent_original_bodies={}, stats=SyncStats(),
    )
    assert result is not None
    assert result.number == 99
    mock_create.assert_called_once()
    assert sast_alert.metadata.rule_id in issue_index.parent_by_rule_id


def test_ensure_parent_dry_run(sast_alert: Alert) -> None:
    """Dry-run returns a placeholder issue, registers it in the issue_index, and bumps severity."""
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    stats = SyncStats()
    result = ensure_parent_issue(
        sast_alert, issues, issue_index, dry_run=True, parent_original_bodies={}, stats=stats,
    )
    assert 0 == result.number
    assert sast_alert.metadata.rule_id in issue_index.parent_by_rule_id
    assert 1 == stats.parents_created
    assert {"high": 1} == stats.parents_created_by_severity


def test_ensure_parent_existing_returns_existing(sast_alert: Alert) -> None:
    """Returns the existing parent issue if one already exists."""
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert.metadata.rule_id,
        "severity": "high",
    })
    issues = {10: parent}
    issue_index = build_issue_index(issues)
    result = ensure_parent_issue(
        sast_alert, issues, issue_index, dry_run=True, parent_original_bodies={}, stats=SyncStats(),
    )
    assert result is not None
    assert result.number == 10


def test_ensure_parent_no_rule_id() -> None:
    """Returns None when alert has no rule_id."""
    alert = Alert.from_dict({"metadata": {"rule_id": ""}, "alert_details": {}, "rule_details": {}})
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    assert ensure_parent_issue(
        alert, issues, issue_index, dry_run=False, parent_original_bodies={}, stats=SyncStats(),
    ) is None


def test_ensure_parent_create_fails(mocker: MockerFixture, sast_alert: Alert) -> None:
    """Returns None if gh_issue_create fails."""
    mocker.patch("security.issues.sync.gh_issue_create", return_value=None)
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    result = ensure_parent_issue(
        sast_alert, issues, issue_index, dry_run=False, parent_original_bodies={}, stats=SyncStats(),
    )
    assert result is None


def test_ensure_parent_body_deferred(sast_alert: Alert) -> None:
    """Parent body update is deferred (snapshot captured in parent_original_bodies)."""
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert.metadata.rule_id,
        "severity": "high",
    })
    original_body = parent.body
    issues = {10: parent}
    issue_index = build_issue_index(issues)
    bods: ParentOriginalBodies = {}
    ensure_parent_issue(
        sast_alert, issues, issue_index, dry_run=True, parent_original_bodies=bods, stats=SyncStats(),
    )
    assert 10 in bods
    assert bods[10][1] == original_body


def test_ensure_parent_strips_legacy_secmeta_keys(sast_alert: Alert) -> None:
    """Legacy secmeta keys are stripped from rebuilt parent body."""
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert.metadata.rule_id,
        "severity": "high",
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-02",
        "postponed_until": "",
        "schema": "1",
        "source": "code_scanning",
        "tool": "AquaSec",
    })
    issues = {10: parent}
    issue_index = build_issue_index(issues)
    ensure_parent_issue(
        sast_alert, issues, issue_index, dry_run=True, parent_original_bodies={}, stats=SyncStats(),
    )
    rebuilt_secmeta = load_secmeta(parent.body)
    expected_keys = {"type", "repo", "rule_id", "severity"}
    assert expected_keys == set(rebuilt_secmeta.keys())


def test_ensure_parent_title_drift_corrected(mocker: MockerFixture, sast_alert: Alert) -> None:
    """Title is updated when it drifts from the expected format."""
    mock_title = mocker.patch("security.issues.sync.gh_issue_edit_title", return_value=True)
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert.metadata.rule_id,
        "severity": "high",
    })
    parent.title = "Wrong old title"
    issues = {10: parent}
    issue_index = build_issue_index(issues)
    stats = SyncStats()
    ensure_parent_issue(
        sast_alert, issues, issue_index, dry_run=False, parent_original_bodies={}, stats=stats,
    )
    mock_title.assert_called_once()
    assert 1 == stats.parents_title_updated
    assert {"high": 1} == stats.parents_title_updated_by_severity


def test_ensure_parent_title_drift_dry_run(sast_alert: Alert) -> None:
    """Dry-run increments parents_title_updated without calling the API."""
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert.metadata.rule_id,
        "severity": "high",
    })
    parent.title = "Wrong old title"
    issues = {10: parent}
    issue_index = build_issue_index(issues)
    stats = SyncStats()
    ensure_parent_issue(
        sast_alert, issues, issue_index, dry_run=True, parent_original_bodies={}, stats=stats,
    )
    assert 1 == stats.parents_title_updated
    assert {"high": 1} == stats.parents_title_updated_by_severity


def test_ensure_parent_dry_run_create_not_inflated(sast_alert: Alert) -> None:
    """Dry-run counts parent creation once even when same rule_id is processed twice."""
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    stats = SyncStats()
    bods: ParentOriginalBodies = {}
    kwargs: dict = dict(
        dry_run=True, parent_original_bodies=bods, stats=stats,
    )
    r1 = ensure_parent_issue(sast_alert, issues, issue_index, **kwargs)
    r2 = ensure_parent_issue(sast_alert, issues, issue_index, **kwargs)
    assert 1 == stats.parents_created
    assert r1 is not None
    assert r2 is not None


# =====================================================================
# _flush_parent_body_updates
# =====================================================================


def test_flush_writes_changed_bodies(mocker: MockerFixture) -> None:
    """Writes body when it has changed and bumps severity from the new secmeta."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_body", return_value=True)
    secmeta = render_secmeta({"type": "parent", "rule_id": "R1", "severity": "high"})
    issue = Issue(number=1, state="open", title="T", body=secmeta + "\nnew body")
    bods = {1: ("org/repo", "old body")}
    stats = SyncStats()
    _flush_parent_body_updates(bods, {1: issue}, dry_run=False, stats=stats)
    mock_edit.assert_called_once_with("org/repo", 1, issue.body)
    assert {"high": 1} == stats.parents_body_updated_by_severity


def test_flush_skips_unchanged() -> None:
    """Does not call API if body is unchanged."""
    issue = Issue(number=1, state="open", title="T", body="same body")
    bods = {1: ("org/repo", "same body")}
    _flush_parent_body_updates(bods, {1: issue}, dry_run=False, stats=SyncStats())


def test_flush_dry_run() -> None:
    """Dry-run logs instead of calling API but still bumps severity."""
    secmeta = render_secmeta({"type": "parent", "rule_id": "R1", "severity": "high"})
    issue = Issue(number=1, state="open", title="T", body=secmeta + "\nnew body")
    bods = {1: ("org/repo", "old body")}
    stats = SyncStats()
    _flush_parent_body_updates(bods, {1: issue}, dry_run=True, stats=stats)
    assert {"high": 1} == stats.parents_body_updated_by_severity


def test_flush_missing_issue() -> None:
    """Skips silently if issue is no longer in the dict."""
    bods = {99: ("org/repo", "old body")}
    _flush_parent_body_updates(bods, {}, dry_run=False, stats=SyncStats())


# =====================================================================
# _close_resolved_child_issues
# =====================================================================


def test_close_resolved_child_no_orphans() -> None:
    """No closure when all children have matching alerts."""
    child = _issue_with_secmeta(1, {"type": "child", "fingerprint": "fp1"})
    issue_index = build_issue_index({1: child})
    alerts: dict[int, Alert] = {
        100: Alert.from_dict(
            {"metadata": {"state": "open"}, "alert_details": {"alert_hash": "fp1"}, "rule_details": {}}),
    }
    matched = list(resolve_child_matches(alerts, issue_index).values())
    _close_resolved_child_issues(issue_index.children, matched, dry_run=False, stats=SyncStats())


def test_close_resolved_child_found(mocker: MockerFixture) -> None:
    """Closes child issues that have no matching alert, bumps severity and notifies."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan", "repo": "org/repo", "severity": "high",
        "rule_id": "AVD-PIPELINE-0022",
    })
    issue_index = build_issue_index({1: child})
    stats = SyncStats()
    issue_changes: list[IssueChange] = []
    _close_resolved_child_issues(issue_index.children, [], dry_run=False, stats=stats, issue_changes=issue_changes)
    mock_edit.assert_called_once_with("org/repo", 1, "closed")
    assert 1 == stats.children_closed
    assert "closed" == child.state
    assert {"high": 1} == stats.children_closed_by_severity
    assert [IssueChange(
        repo="org/repo", issue_number=1, severity="high", rule_id="AVD-PIPELINE-0022",
        state="closed",
    )] == issue_changes


def test_close_resolved_child_dry_run(mocker: MockerFixture) -> None:
    """Dry-run: increments stat, marks state and notifies without calling gh."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state")
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan", "repo": "org/repo", "severity": "high",
    })
    issue_index = build_issue_index({1: child})
    stats = SyncStats()
    issue_changes: list[IssueChange] = []
    _close_resolved_child_issues(issue_index.children, [], dry_run=True, stats=stats, issue_changes=issue_changes)
    mock_edit.assert_not_called()
    assert 1 == stats.children_closed
    assert "closed" == child.state
    assert {"high": 1} == stats.children_closed_by_severity
    assert ["closed"] == [n.state for n in issue_changes]


def test_close_resolved_child_skips_closed_issues() -> None:
    """Closed child issues are not treated as unmatched."""
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan", "repo": "org/repo",
    }, state="closed")
    issue_index = build_issue_index({1: child})
    stats = SyncStats()
    _close_resolved_child_issues(issue_index.children, [], dry_run=False, stats=stats)
    assert 0 == stats.children_closed


def test_close_resolved_child_matched_via_legacy_hash(mocker: MockerFixture) -> None:
    """A pre-change issue whose stored hash still matches the scan is not closed."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state")
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "hash_old", "repo": "org/repo", "severity": "high",
    })
    issue_index = build_issue_index({1: child})
    alerts = {
        100: Alert.from_dict({
            "metadata": {"state": "open"},
            "alert_details": {"alert_hash": "hash_old", "identity_key": "fp_new"},
            "rule_details": {},
        }),
    }
    stats = SyncStats()
    matched = list(resolve_child_matches(alerts, issue_index).values())
    _close_resolved_child_issues(issue_index.children, matched, dry_run=False, stats=stats)
    mock_edit.assert_not_called()
    assert 0 == stats.children_closed


def test_close_resolved_child_reachable_under_both_keys_closes_once(mocker: MockerFixture) -> None:
    """An issue reachable under both keys is closed once and counted once."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan", "alert_hash": "hash_orphan",
        "repo": "org/repo", "severity": "high",
    })
    issue_index = build_issue_index({1: child})
    stats = SyncStats()
    issue_changes: list[IssueChange] = []
    _close_resolved_child_issues(issue_index.children, [], dry_run=False, stats=stats, issue_changes=issue_changes)
    mock_edit.assert_called_once_with("org/repo", 1, "closed")
    assert 1 == stats.children_closed
    assert 1 == len(issue_changes)


def test_close_resolved_child_no_repo_in_secmeta(mocker: MockerFixture) -> None:
    """Skips closure if no repo in secmeta."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state")
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan",
    })
    issue_index = build_issue_index({1: child})
    stats = SyncStats()
    _close_resolved_child_issues(issue_index.children, [], dry_run=False, stats=stats)
    mock_edit.assert_not_called()
    assert 0 == stats.children_closed


# =====================================================================
# _count_open_child_issues_by_severity
# =====================================================================


def test_count_open_child_issues_by_severity() -> None:
    """Only still-open children count, grouped by severity with unknown as the fallback."""
    issues = {
        1: _issue_with_secmeta(1, {"type": "child", "fingerprint": "fp1", "severity": "high"}),
        2: _issue_with_secmeta(2, {"type": "child", "fingerprint": "fp2", "severity": "high"}),
        3: _issue_with_secmeta(3, {"type": "child", "fingerprint": "fp3"}),
        4: _issue_with_secmeta(4, {"type": "child", "fingerprint": "fp4", "severity": "low"}, state="closed"),
    }
    issue_index = build_issue_index(issues)

    assert {"high": 2, "unknown": 1} == _count_open_child_issues_by_severity(issue_index)


# =====================================================================
# _close_resolved_parent_issues
# =====================================================================


def test_close_resolved_parent_issue(mocker: MockerFixture) -> None:
    """Closes an open parent when all known children are closed, and bumps severity."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    parent = _issue_with_secmeta(10, {
        "type": "parent", "rule_id": "R1", "repo": "org/repo", "severity": "high",
    })
    child_one = _issue_with_secmeta(11, {
        "type": "child", "rule_id": "R1", "fingerprint": "fp1", "repo": "org/repo",
    }, state="closed")
    child_two = _issue_with_secmeta(12, {
        "type": "child", "rule_id": "R1", "fingerprint": "fp2", "repo": "org/repo",
    }, state="closed")
    issues = {10: parent, 11: child_one, 12: child_two}
    issue_index = build_issue_index(issues)
    stats = SyncStats()

    _close_resolved_parent_issues(issues, issue_index, dry_run=False, stats=stats)

    mock_edit.assert_called_once_with("org/repo", 10, "closed")
    assert parent.state == "closed"
    assert {"high": 1} == stats.parents_closed_by_severity


def test_close_resolved_parent_skips_open_child(mocker: MockerFixture) -> None:
    """Leaves the parent open when any child is still open."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    parent = _issue_with_secmeta(10, {
        "type": "parent", "rule_id": "R1", "repo": "org/repo",
    })
    child = _issue_with_secmeta(11, {
        "type": "child", "rule_id": "R1", "fingerprint": "fp1", "repo": "org/repo",
    }, state="open")
    issues = {10: parent, 11: child}
    issue_index = build_issue_index(issues)

    _close_resolved_parent_issues(issues, issue_index, dry_run=False, stats=SyncStats())

    mock_edit.assert_not_called()
    assert parent.state == "open"


# =====================================================================
# ensure_issue (end-to-end orchestration per alert)
# =====================================================================

def test_ensure_issue_dry_run(sast_alert: Alert) -> None:
    """Dry-run: no gh calls, notification with issue_number=0."""
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    issue_changes: list[IssueChange] = []
    sync = _make_sync_context(issues=issues, issue_index=issue_index, dry_run=True, issue_changes=issue_changes)
    ensure_issue(sast_alert, sync, matched_issue=None)
    assert len(issue_changes) == 1
    assert issue_changes[0].issue_number == 0


def test_ensure_issue_migrates_pre_change_child_in_place(mocker: MockerFixture, sast_alert: Alert) -> None:
    """A pre-change child issue is matched via its legacy hash and gains both keys."""
    mock_body = _patch_gh_calls(mocker)
    sast_alert.alert_details.identity_key = "fp_stable_0"
    legacy_hash = sast_alert.alert_details.alert_hash
    child = _issue_with_secmeta(7, {
        "type": "child", "fingerprint": legacy_hash, "repo": "test-org/test-repo", "severity": "high",
    })
    issues = {7: child}
    sync = _make_sync_context(issues=issues)

    ensure_issue(sast_alert, sync, matched_issue=resolve_child_matches({1: sast_alert}, sync.issue_index).get(1))

    mock_body.assert_called_once()
    assert 0 == sync.stats.children_created
    secmeta = load_secmeta(child.body)
    assert "fp_stable_0" == secmeta["fingerprint"]
    assert legacy_hash == secmeta["alert_hash"]


def test_ensure_issue_line_shift_maps_to_same_child(mocker: MockerFixture, sast_alert: Alert) -> None:
    """A SAST finding whose result hash churns on a line shift keeps its child issue."""
    _patch_gh_calls(mocker)
    child = _issue_with_secmeta(8, {
        "type": "child", "fingerprint": "fp_stable_0", "alert_hash": "hash_before_shift",
        "repo": "test-org/test-repo", "severity": "high",
    })
    sast_alert.alert_details.identity_key = "fp_stable_0"
    sast_alert.alert_details.alert_hash = "hash_after_shift"
    sync = _make_sync_context(issues={8: child})

    ensure_issue(sast_alert, sync, matched_issue=resolve_child_matches({1: sast_alert}, sync.issue_index).get(1))

    assert 0 == sync.stats.children_created
    assert "hash_after_shift" == load_secmeta(child.body)["alert_hash"]


def test_ensure_issue_without_aquasec_fingerprint_keys_off_result_hash(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """A finding with no AquaSec fingerprint still matches on its result hash."""
    _patch_gh_calls(mocker)
    sast_alert.alert_details.identity_key = sast_alert.alert_details.alert_hash
    child = _issue_with_secmeta(9, {
        "type": "child", "fingerprint": sast_alert.alert_details.alert_hash,
        "repo": "test-org/test-repo", "severity": "high",
    })
    sync = _make_sync_context(issues={9: child})

    ensure_issue(sast_alert, sync, matched_issue=resolve_child_matches({1: sast_alert}, sync.issue_index).get(1))

    assert 0 == sync.stats.children_created


def test_ensure_issue_missing_alert_hash_raises() -> None:
    """Raises SystemExit when the Finding Identity is missing."""
    alert = Alert.from_dict({
        "metadata": {"alert_number": 1, "state": "open", "rule_id": "R1", "severity": "high"},
        "alert_details": {},
        "rule_details": {},
    }, repo="org/repo")
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    with pytest.raises(SystemExit, match="missing Finding Identity"):
        ensure_issue(
            alert, _make_sync_context(issues=issues, issue_index=issue_index, dry_run=True), matched_issue=None
        )


def test_ensure_issue_missing_alert_details_raises() -> None:
    """Raises SystemExit when alert_details yields no Finding Identity."""
    alert = Alert.from_dict({
        "metadata": {"alert_number": 1, "state": "open"},
        "alert_details": {},
        "rule_details": {},
    }, repo="org/repo")
    issues: dict[int, Issue] = {}
    issue_index = IssueIndex(child_by_identity_key={}, parent_by_rule_id={})
    with pytest.raises(SystemExit, match="missing Finding Identity"):
        ensure_issue(
            alert, _make_sync_context(issues=issues, issue_index=issue_index, dry_run=True), matched_issue=None
        )


# =====================================================================
# sync_alerts_and_issues (top-level orchestrator)
# =====================================================================


def test_sync_empty() -> None:
    """Empty alerts produce empty result."""
    result = sync_alerts_and_issues({}, {}, dry_run=True)
    assert result.issue_changes == []


def test_sync_dry_run_single_alert(sast_alert: Alert) -> None:
    """Single alert dry-run produces a notification."""
    alerts = {303: sast_alert}
    result = sync_alerts_and_issues(alerts, {}, dry_run=True)
    assert len(result.issue_changes) == 1


def test_sync_closes_parent_when_all_children_closed(mocker: MockerFixture) -> None:
    """Closes a parent during sync when its children are already closed."""
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    parent = _issue_with_secmeta(10, {
        "type": "parent", "rule_id": "R1", "repo": "org/repo",
    })
    child = _issue_with_secmeta(11, {
        "type": "child", "rule_id": "R1", "fingerprint": "fp1", "repo": "org/repo",
    }, state="closed")
    issues = {10: parent, 11: child}

    result = sync_alerts_and_issues({}, issues, dry_run=False)

    assert result.issue_changes == []
    mock_edit.assert_called_once_with("org/repo", 10, "closed")
    assert parent.state == "closed"


def test_sync_resolved_child_cascades_parent_close_same_run(mocker: MockerFixture) -> None:
    """An open child resolved this run closes, then its parent closes in the SAME run."""
    edits: list[tuple[int, str]] = []
    mocker.patch(
        "security.issues.sync.gh_issue_edit_state",
        side_effect=lambda repo, num, state: (edits.append((num, state)) or True),
    )
    parent = _issue_with_secmeta(10, {
        "type": "parent", "rule_id": "R1", "repo": "org/repo",
    })
    child = _issue_with_secmeta(11, {
        "type": "child", "rule_id": "R1", "fingerprint": "fp1", "repo": "org/repo",
    })
    issues = {10: parent, 11: child}

    sync_alerts_and_issues({}, issues, dry_run=False)

    assert (11, "closed") in edits
    assert (10, "closed") in edits
    assert child.state == "closed"
    assert parent.state == "closed"


def test_sync_reopened_child_prevents_parent_close(mocker: MockerFixture, sast_alert: Alert) -> None:
    """Reopened child keeps parent open - resolved-parent check must not re-close it."""
    mocker.patch("security.issues.sync.gh_issue_get_sub_issue_numbers", return_value=set())
    rule_id = sast_alert.metadata.rule_id
    identity_key = sast_alert.alert_details.alert_hash
    parent = _issue_with_secmeta(169, {
        "type": "parent", "rule_id": rule_id, "repo": "test-org/test-repo",
    }, state="closed")
    child = _issue_with_secmeta(170, {
        "type": "child", "rule_id": rule_id, "fingerprint": identity_key, "repo": "test-org/test-repo",
    }, state="closed")
    issues = {169: parent, 170: child}

    result = sync_alerts_and_issues({303: sast_alert}, issues, dry_run=True)

    assert "open" == parent.state
    assert "open" == child.state
    assert len(result.issue_changes) == 1
    assert result.issue_changes[0].state == "reopen"


def test_sync_matches_renumbered_finding_by_result_hash(mocker: MockerFixture, sast_alert: Alert) -> None:
    """A matching old Result Hash must disambiguate a reused SAST ordinal."""
    _patch_gh_calls(mocker)
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    sast_alert.alert_details.identity_key = "fp_base_0"
    sast_alert.alert_details.alert_hash = "hash_survivor"
    removed_occurrence = _issue_with_secmeta(10, {
        "type": "child",
        "fingerprint": "fp_base_0",
        "alert_hash": "hash_removed",
        "repo": "test-org/test-repo",
        "rule_id": sast_alert.metadata.rule_id,
        "severity": "high",
    })
    surviving_occurrence = _issue_with_secmeta(20, {
        "type": "child",
        "fingerprint": "fp_base_1",
        "alert_hash": "hash_survivor",
        "repo": "test-org/test-repo",
        "rule_id": sast_alert.metadata.rule_id,
        "severity": "high",
    })

    sync_alerts_and_issues({303: sast_alert}, {10: removed_occurrence, 20: surviving_occurrence})

    assert removed_occurrence.state == "closed"
    assert surviving_occurrence.state == "open"
    assert load_secmeta(surviving_occurrence.body)["fingerprint"] == "fp_base_0"


def _renumbered_sast_issues(sast_alert: Alert) -> tuple[dict[int, Issue], Issue]:
    """Issues for a removed occurrence whose ordinal the surviving one inherits; returns (issues, survivor)."""
    sast_alert.alert_details.identity_key = "fp_base_0"
    sast_alert.alert_details.alert_hash = "hash_survivor"
    rule_id = sast_alert.metadata.rule_id
    parent = _issue_with_secmeta(1, {
        "type": "parent", "rule_id": rule_id, "repo": "test-org/test-repo", "severity": "high",
    })
    removed_occurrence = _issue_with_secmeta(10, {
        "type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_removed",
        "repo": "test-org/test-repo", "rule_id": rule_id, "severity": "high",
    })
    surviving_occurrence = _issue_with_secmeta(20, {
        "type": "child", "fingerprint": "fp_base_1", "alert_hash": "hash_survivor",
        "repo": "test-org/test-repo", "rule_id": rule_id, "severity": "high",
    })
    return {1: parent, 10: removed_occurrence, 20: surviving_occurrence}, surviving_occurrence


@pytest.mark.parametrize("reverse_issue_order", [False, True])
def test_sync_failed_closure_then_line_shift_refuses_reused_identity(
    mocker: MockerFixture, sast_alert: Alert, reverse_issue_order: bool
) -> None:
    mock_body = _patch_gh_calls(mocker)
    mocker.patch("security.issues.sync.gh_issue_edit_state", side_effect=[False, True, True])
    issues, survivor = _renumbered_sast_issues(sast_alert)
    if reverse_issue_order:
        issues = dict(reversed(list(issues.items())))
    removed = issues[10]
    removed.labels = ["sec:suppression"]
    original_removed_body = removed.body
    original_removed_title = removed.title

    sync_alerts_and_issues({303: sast_alert}, issues)

    assert "open" == removed.state
    assert "fp_base_0" == load_secmeta(survivor.body)["fingerprint"]
    survivor_body = survivor.body
    mock_body.reset_mock()
    sast_alert.alert_details.alert_hash = "hash_after_shift"

    result = sync_alerts_and_issues({303: sast_alert}, issues)

    assert original_removed_body == removed.body
    assert original_removed_title == removed.title
    assert ["sec:suppression"] == removed.labels
    assert survivor_body == survivor.body
    assert [(10, "closed"), (20, "closed"), (999, "new")] == sorted(
        (change.issue_number, change.state) for change in result.issue_changes
    )
    assert "hash_after_shift" == load_secmeta(issues[999].body)["alert_hash"]
    assert all(call.args[1] not in {10, 20} for call in mock_body.call_args_list)


def test_sync_conflicting_owners_preserves_exact_result_hash(mocker: MockerFixture, sast_alert: Alert) -> None:
    _patch_gh_calls(mocker)
    mock_state = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    issues, survivor = _renumbered_sast_issues(sast_alert)
    survivor.body = survivor.body.replace("fingerprint=fp_base_1", "fingerprint=fp_base_0")

    result = sync_alerts_and_issues({303: sast_alert}, issues)

    mock_state.assert_called_once_with("test-org/test-repo", 10, "closed")
    assert "open" == survivor.state
    assert [(10, "closed")] == [(change.issue_number, change.state) for change in result.issue_changes]


def test_sync_renumbered_survivor_still_counted_on_next_run(mocker: MockerFixture, sast_alert: Alert) -> None:
    """The migrated survivor shares its identity with the closed issue, yet the next run must still count it."""
    _patch_gh_calls(mocker)
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    issues, _ = _renumbered_sast_issues(sast_alert)

    sync_alerts_and_issues({303: sast_alert}, issues)
    result = sync_alerts_and_issues({303: sast_alert}, issues)

    assert {"high": 1} == result.open_child_issues_by_severity


def test_sync_renumbered_survivor_closed_once_resolved(mocker: MockerFixture, sast_alert: Alert) -> None:
    """The migrated survivor shares its identity with the closed issue, yet must close once its finding is fixed."""
    _patch_gh_calls(mocker)
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    issues, surviving_occurrence = _renumbered_sast_issues(sast_alert)

    sync_alerts_and_issues({303: sast_alert}, issues)
    sync_alerts_and_issues({}, issues)

    assert "closed" == surviving_occurrence.state


@pytest.mark.parametrize("inserted_first", [True, False], ids=["inserted_first", "existing_first"])
def test_sync_inserted_sast_occurrence_gets_own_issue(
    mocker: MockerFixture, sast_alert: Alert, inserted_first: bool
) -> None:
    """A new occurrence inserted ahead of an existing one takes over its ordinal.

    The existing finding keeps its Result Hash, so its issue must stay with it, while the inserted
    finding gets a new issue - never inheriting the existing issue's history or waiver labels.
    """
    _patch_gh_calls(mocker)
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    rule_id = sast_alert.metadata.rule_id
    existing = sast_alert
    existing.alert_details.identity_key = "fp_base_1"
    existing.alert_details.alert_hash = "hash_existing"
    inserted = copy.deepcopy(sast_alert)
    inserted.metadata.alert_number = 304
    inserted.alert_details.identity_key = "fp_base_0"
    inserted.alert_details.alert_hash = "hash_inserted"
    parent = _issue_with_secmeta(1, {
        "type": "parent", "rule_id": rule_id, "repo": "test-org/test-repo", "severity": "high",
    })
    existing_issue = _issue_with_secmeta(10, {
        "type": "child", "fingerprint": "fp_base_0", "alert_hash": "hash_existing",
        "repo": "test-org/test-repo", "rule_id": rule_id, "severity": "high",
    })
    alerts = {304: inserted, 303: existing} if inserted_first else {303: existing, 304: inserted}

    result = sync_alerts_and_issues(alerts, {1: parent, 10: existing_issue})

    assert ["new"] == [change.state for change in result.issue_changes]
    secmeta = load_secmeta(existing_issue.body)
    assert "fp_base_1" == secmeta["fingerprint"]
    assert "hash_existing" == secmeta["alert_hash"]


def test_sync_closes_duplicate_child_and_keeps_oldest_open(mocker: MockerFixture, sast_alert: Alert) -> None:
    """Pre-existing duplicates sharing a key are closed once, the oldest open issue keeps the finding."""
    _patch_gh_calls(mocker)
    mock_state = mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    meta = {
        "type": "child", "fingerprint": sast_alert.alert_details.alert_hash,
        "repo": "test-org/test-repo", "rule_id": sast_alert.metadata.rule_id, "severity": "high",
    }
    oldest = _issue_with_secmeta(5, meta)
    duplicate = _issue_with_secmeta(9, meta)

    result = sync_alerts_and_issues({303: sast_alert}, {5: oldest, 9: duplicate})

    mock_state.assert_called_once_with("test-org/test-repo", 9, "closed")
    assert "open" == oldest.state
    assert {"high": 1} == result.open_child_issues_by_severity


# =====================================================================
# _init_priority_sync
# =====================================================================


def test_init_priority_sync_no_map() -> None:
    """Returns None when severity_priority_map is empty."""
    result = _init_priority_sync(
        {}, severity_priority_map={}, project_number=42, project_org="org", dry_run=False,
    )
    assert result is None


def test_init_priority_sync_no_project_number() -> None:
    """Returns None when project_number is falsy (0 or None)."""
    result = _init_priority_sync(
        {}, severity_priority_map={"high": "Urgent"}, project_number=None, project_org="org", dry_run=False,
    )
    assert result is None


def test_init_priority_sync_no_org_returns_none() -> None:
    """Returns None with warning when org cannot be determined."""
    alerts = {1: Alert.from_dict({"_repo": ""})}
    result = _init_priority_sync(
        alerts, severity_priority_map={"high": "Urgent"}, project_number=7,
        project_org="", dry_run=False,
    )
    assert result is None


def test_init_priority_sync_field_lookup_fails(mocker: MockerFixture) -> None:
    """Returns None when gh_project_get_priority_field fails."""
    mocker.patch("security.issues.sync.gh_project_get_priority_field", return_value=None)
    result = _init_priority_sync(
        {}, severity_priority_map={"high": "Urgent"}, project_number=7,
        project_org="org", dry_run=False,
    )
    assert result is None


# =====================================================================
# _log_sync_summary
# =====================================================================


@pytest.mark.parametrize("dry_run,prefix", [
    (False, "Security - "),
    (True, "Security [DRY-RUN] - "),
])
def test_log_sync_summary(caplog: pytest.LogCaptureFixture, dry_run: bool, prefix: str) -> None:
    """Summary emits exactly one log record with the right prefix on every line and a grouped table."""
    # Empty stats → single "no changes" record with the right prefix
    with caplog.at_level(logging.INFO):
        _log_sync_summary(SyncStats(), dry_run=dry_run)
    assert len(caplog.records) == 1
    message = caplog.records[0].message
    assert message.startswith(prefix)
    assert "no changes" in message
    caplog.clear()

    # Full stats + label activity → grouped table with severity breakdowns; zero groups omitted
    stats = SyncStats(
        parents_created=2, parents_created_by_severity={"high": 2},
        parents_title_updated=1, parents_title_updated_by_severity={"high": 1},
        children_created=15, children_created_by_severity={"high": 15},
        children_reopened=1, children_reopened_by_severity={"high": 1},
        children_title_updated=2, children_body_updated=3,
        children_relinked=1,
    )
    with caplog.at_level(logging.INFO):
        _log_sync_summary(stats, dry_run=dry_run)
    assert len(caplog.records) == 1
    message = caplog.records[0].message
    lines = message.split("\n")
    assert all(line.startswith(prefix) for line in lines)
    assert prefix + "Sync complete:" == lines[0]
    assert "Parent issues" in message and "created: 2 (high: 2)" in message and "title updated: 1" in message
    assert "Child issues" in message and "created: 15 (high: 15)" in message and "reopened: 1" in message
    assert "title updated: 2" in message and "body updated: 3" in message and "relinked: 1" in message
    assert "Labels" not in message


# =====================================================================
# _meets_min_severity
# =====================================================================


@pytest.mark.parametrize("severity,min_severity,expected", [
    # min=low: everything passes, including unknown
    ("critical", "low", True),
    ("high",     "low", True),
    ("medium",   "low", True),
    ("low",      "low", True),
    ("unknown",  "low", True),
    # min=medium
    ("critical", "medium", True),
    ("high",     "medium", True),
    ("medium",   "medium", True),
    ("low",      "medium", False),
    ("unknown",  "medium", False),
    # min=high
    ("critical", "high", True),
    ("high",     "high", True),
    ("medium",   "high", False),
    ("low",      "high", False),
    ("unknown",  "high", False),
    # min=critical
    ("critical", "critical", True),
    ("high",     "critical", False),
    ("medium",   "critical", False),
    ("low",      "critical", False),
    ("unknown",  "critical", False),
])
def test_meets_min_severity(severity: str, min_severity: str, expected: bool) -> None:
    assert _meets_min_severity(severity, min_severity) is expected


def test_meets_min_severity_case_insensitive() -> None:
    assert _meets_min_severity("HIGH", "medium") is True
    assert _meets_min_severity("LOW", "medium") is False


# =====================================================================
# sync_alerts_and_issues – min_severity filtering
# =====================================================================


def test_sync_skips_creation_for_below_threshold_alerts(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """Alerts below min_severity do not create issues."""
    sast_alert.metadata.severity = "low"
    mock_ensure = mocker.patch("security.issues.sync.ensure_issue")

    sync_alerts_and_issues({1: sast_alert}, {}, dry_run=True, min_severity="high")

    mock_ensure.assert_not_called()


def test_sync_creates_issue_at_exact_threshold(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """An alert exactly at min_severity is processed."""
    sast_alert.metadata.severity = "high"
    mock_ensure = mocker.patch("security.issues.sync.ensure_issue")

    sync_alerts_and_issues({1: sast_alert}, {}, dry_run=True, min_severity="high")

    mock_ensure.assert_called_once()


def test_sync_creates_issue_above_threshold(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """An alert above min_severity is processed."""
    sast_alert.metadata.severity = "critical"
    mock_ensure = mocker.patch("security.issues.sync.ensure_issue")

    sync_alerts_and_issues({1: sast_alert}, {}, dry_run=True, min_severity="high")

    mock_ensure.assert_called_once()


def test_sync_resolved_close_still_runs_for_below_threshold_alerts(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """Resolved-alert closure uses all alerts regardless of min_severity threshold.

    An existing open issue whose alert is below the threshold must NOT be
    incorrectly closed just because it was filtered from creation.
    """
    sast_alert.metadata.severity = "low"
    fp = sast_alert.alert_details.alert_hash

    existing_child = _issue_with_secmeta(
        99,
        {"type": "child", "fingerprint": fp, "alert_hash": fp,
         "repo": "test-org/test-repo", "rule_id": "r1", "severity": "low"},
    )
    mock_edit = mocker.patch("security.issues.sync.gh_issue_edit_state")

    sync_alerts_and_issues(
        {1: sast_alert}, {99: existing_child}, dry_run=False, min_severity="high"
    )

    # The alert is still active, so the issue must NOT have been closed.
    mock_edit.assert_not_called()


def test_sync_below_threshold_retains_renumbered_survivor_across_line_shift(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    mock_body = _patch_gh_calls(mocker)
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    mock_ensure = mocker.patch("security.issues.sync.ensure_issue")
    issues, survivor = _renumbered_sast_issues(sast_alert)
    sast_alert.metadata.severity = "medium"
    survivor.body = survivor.body.replace("\n-->", "\ncustom=preserved\n-->")
    survivor.labels = ["sec:false-positive"]
    original_body = survivor.body
    original_title = survivor.title

    sync_alerts_and_issues({303: sast_alert}, issues, min_severity="high")
    assert "fp_base_0" == load_secmeta(survivor.body)["fingerprint"]
    sast_alert.alert_details.alert_hash = "hash_after_shift"
    shifted = sync_alerts_and_issues({303: sast_alert}, issues, min_severity="high")
    repeated = sync_alerts_and_issues({303: sast_alert}, issues, min_severity="high")

    assert "open" == survivor.state
    assert original_body.replace("fingerprint=fp_base_1", "fingerprint=fp_base_0").replace(
        "alert_hash=hash_survivor", "alert_hash=hash_after_shift"
    ) == survivor.body
    assert original_title == survivor.title
    assert ["sec:false-positive"] == survivor.labels
    assert [20, 20] == [call.args[1] for call in mock_body.call_args_list]
    assert [] == shifted.issue_changes == repeated.issue_changes
    mock_ensure.assert_not_called()

    resolved = sync_alerts_and_issues({}, issues, min_severity="high")

    assert "closed" == survivor.state
    assert "closed" == issues[1].state
    assert [(20, "closed")] == [(change.issue_number, change.state) for change in resolved.issue_changes]


@pytest.mark.parametrize("dry_run", [False, True])
def test_sync_below_threshold_migrates_legacy_identity_only(
    mocker: MockerFixture, sast_alert: Alert, dry_run: bool, caplog: pytest.LogCaptureFixture
) -> None:
    mock_body = _patch_gh_calls(mocker)
    mock_state = mocker.patch("security.issues.sync.gh_issue_edit_state")
    mock_ensure = mocker.patch("security.issues.sync.ensure_issue")
    sast_alert.metadata.severity = "medium"
    sast_alert.alert_details.identity_key = "fp_base_0"
    child = _issue_with_secmeta(7, {
        "type": "child", "fingerprint": sast_alert.alert_details.alert_hash,
        "repo": "test-org/test-repo", "severity": "high", "custom": "preserved",
    })
    child.labels = ["sec:suppression"]
    original_title = child.title
    original_secmeta = load_secmeta(child.body)
    original_notes = child.body[child.body.index("-->") + 3:]

    with caplog.at_level(logging.INFO):
        result = sync_alerts_and_issues({303: sast_alert}, {7: child}, dry_run=dry_run, min_severity="high")

    expected_secmeta = {
        **original_secmeta,
        "fingerprint": "fp_base_0",
        "alert_hash": sast_alert.alert_details.alert_hash,
    }
    assert render_secmeta(expected_secmeta) + original_notes == child.body
    assert original_title == child.title
    assert ["sec:suppression"] == child.labels
    assert [] == result.issue_changes
    mock_ensure.assert_not_called()
    mock_state.assert_not_called()
    if dry_run:
        mock_body.assert_not_called()
        assert "Security [DRY-RUN] - Would update child issue #7 identity bookkeeping" in caplog.text
    else:
        mock_body.assert_called_once_with("test-org/test-repo", 7, child.body)

    sync_alerts_and_issues({303: sast_alert}, {7: child}, dry_run=dry_run, min_severity="high")

    assert (0 if dry_run else 1) == mock_body.call_count


def test_sync_below_threshold_does_not_refresh_closed_child(mocker: MockerFixture, sast_alert: Alert) -> None:
    mock_body = _patch_gh_calls(mocker)
    mock_state = mocker.patch("security.issues.sync.gh_issue_edit_state")
    sast_alert.metadata.severity = "medium"
    child = _issue_with_secmeta(7, {
        "type": "child", "fingerprint": sast_alert.alert_details.alert_hash,
        "repo": "test-org/test-repo", "severity": "high",
    }, state="closed")
    original_body = child.body

    result = sync_alerts_and_issues({303: sast_alert}, {7: child}, min_severity="high")

    assert original_body == child.body
    assert "closed" == child.state
    assert [] == result.issue_changes
    mock_body.assert_not_called()
    mock_state.assert_not_called()


def test_sync_below_threshold_identity_write_failure_keeps_processing_other_alerts(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """A failed bookkeeping write on one frozen issue must not drop the rest of the scan."""
    mock_body = _patch_gh_calls(mocker)
    mock_body.return_value = False
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)
    issues, _ = _renumbered_sast_issues(sast_alert)
    sast_alert.metadata.severity = "medium"
    unrelated = copy.deepcopy(sast_alert)
    unrelated.metadata.alert_number = 304
    unrelated.metadata.severity = "high"
    unrelated.alert_details.identity_key = "fp_other_0"
    unrelated.alert_details.alert_hash = "hash_other"

    result = sync_alerts_and_issues({303: sast_alert, 304: unrelated}, issues, min_severity="high")

    assert (999, "new") in [(change.issue_number, change.state) for change in result.issue_changes]


def test_sync_identity_write_failure_handled_same_below_and_above_threshold(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """A failed identity write is tolerated above min-severity, so it must be tolerated below it too."""
    mock_body = _patch_gh_calls(mocker)
    mock_body.return_value = False
    mocker.patch("security.issues.sync.gh_issue_edit_state", return_value=True)

    outcomes = {}
    for severity in ("high", "medium"):
        alert = copy.deepcopy(sast_alert)
        alert.metadata.severity = severity
        issues, survivor = _renumbered_sast_issues(alert)
        result = sync_alerts_and_issues({303: alert}, issues, min_severity="high")
        outcomes[severity] = ([(change.issue_number, change.state) for change in result.issue_changes], survivor.state)

    assert outcomes["high"] == outcomes["medium"]


def test_sync_unknown_severity_passes_at_min_low(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """Unknown severity is created when min_severity=low (the default)."""
    sast_alert.metadata.severity = "unknown"
    mock_ensure = mocker.patch("security.issues.sync.ensure_issue")

    sync_alerts_and_issues({1: sast_alert}, {}, dry_run=True, min_severity="low")

    mock_ensure.assert_called_once()


def test_sync_unknown_severity_filtered_above_min_low(
    mocker: MockerFixture, sast_alert: Alert
) -> None:
    """Unknown severity is skipped when min_severity is above low."""
    sast_alert.metadata.severity = "unknown"
    mock_ensure = mocker.patch("security.issues.sync.ensure_issue")

    sync_alerts_and_issues({1: sast_alert}, {}, dry_run=True, min_severity="medium")

    mock_ensure.assert_not_called()
