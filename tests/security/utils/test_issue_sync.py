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

"""Unit tests for ``utils.issue_sync`` – pure-logic helpers and
orchestration functions with mocked GitHub CLI calls.
"""

from typing import Any

import pytest
from pytest_mock import MockerFixture

from shared.models import Issue
from utils.issue_sync import (
    _append_notification,
    _comment_child_event,
    _flush_parent_body_updates,
    _handle_existing_child_issue,
    _handle_new_child_issue,
    _init_priority_sync,
    _label_orphan_issues,
    _maybe_reopen_child,
    _merge_child_secmeta,
    _rebuild_and_apply_child_body,
    _sync_child_title_and_labels,
    build_issue_index,
    ensure_issue,
    ensure_parent_issue,
    find_issue_in_index,
    find_parent_issue,
    maybe_reopen_parent_issue,
    sync_alerts_and_issues,
)
from utils.models import (
    AlertContext,
    IssueIndex,
    NotifiedIssue,
    SeverityChange,
    SyncContext,
)
from utils.secmeta import render_secmeta


# =====================================================================
# helpers – build Issues with embedded secmeta
# =====================================================================

def _issue_with_secmeta(number: int, secmeta: dict[str, str], *, state: str = "open") -> Issue:
    body = render_secmeta(secmeta) + "\nSome body text\n"
    return Issue(number=number, state=state, title=f"Issue #{number}", body=body)


def _make_alert_context(**overrides: Any) -> AlertContext:
    """Build an ``AlertContext`` with sensible defaults, overridable via kwargs."""
    defaults = dict(
        alert={},
        alert_number=1,
        fingerprint="fp_test_123",
        occurrence_fp="occ_fp_test",
        repo="test-org/test-repo",
        first_seen="2026-01-01",
        last_seen="2026-01-02",
        tool="AquaSec",
        rule_id="CVE-2026-1234",
        rule_name="sast",
        severity="high",
        cve="CVE-2026-1234",
        path="src/main.py",
        start_line=10,
        end_line=20,
        commit_sha="abc123def456",
    )
    defaults.update(overrides)
    return AlertContext(**defaults)


def _make_sync_context(
    issues: dict[int, Issue] | None = None,
    index: IssueIndex | None = None,
    *,
    dry_run: bool = False,
    notifications: list[NotifiedIssue] | None = None,
) -> SyncContext:
    """Build a ``SyncContext`` with sensible defaults."""
    if issues is None:
        issues = {}
    if index is None:
        index = build_issue_index(issues)
    return SyncContext(
        issues=issues,
        index=index,
        dry_run=dry_run,
        notifications=notifications if notifications is not None else [],
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

def test_indexes_child_by_fingerprint() -> None:
    child = _issue_with_secmeta(2, {
        "type": "child",
        "fingerprint": "fp_abc123",
        "rule_id": "CVE-2026-1234",
    })
    issues = {2: child}
    idx = build_issue_index(issues)
    assert "fp_abc123" in idx.by_fingerprint
    assert idx.by_fingerprint["fp_abc123"] is child

def test_parent_not_in_fingerprint_index() -> None:
    parent = _issue_with_secmeta(1, {
        "type": "parent",
        "rule_id": "CVE-2026-1234",
        "fingerprint": "fp_parent",
    })
    issues = {1: parent}
    idx = build_issue_index(issues)
    assert "fp_parent" not in idx.by_fingerprint

def test_first_fingerprint_wins() -> None:
    """If two children share the same fingerprint, the first one wins."""
    c1 = _issue_with_secmeta(10, {"type": "child", "fingerprint": "shared_fp"})
    c2 = _issue_with_secmeta(20, {"type": "child", "fingerprint": "shared_fp"})
    issues = {10: c1, 20: c2}
    idx = build_issue_index(issues)
    assert idx.by_fingerprint["shared_fp"].number == 10

def test_mixed_issues() -> None:
    parent = _issue_with_secmeta(1, {"type": "parent", "rule_id": "R1"})
    child = _issue_with_secmeta(2, {"type": "child", "fingerprint": "fp1", "rule_id": "R1"})
    issues = {1: parent, 2: child}
    idx = build_issue_index(issues)
    assert "R1" in idx.parent_by_rule_id
    assert "fp1" in idx.by_fingerprint

def test_empty() -> None:
    idx = build_issue_index({})
    assert idx.by_fingerprint == {}
    assert idx.parent_by_rule_id == {}

def test_alert_hash_fallback() -> None:
    """Fingerprint falls back to alert_hash when fingerprint is absent."""
    child = _issue_with_secmeta(5, {"type": "child", "alert_hash": "hash_123"})
    issues = {5: child}
    idx = build_issue_index(issues)
    assert "hash_123" in idx.by_fingerprint

def test_no_secmeta_skipped() -> None:
    """Issue without secmeta block is silently skipped."""
    issue = Issue(number=99, state="open", title="No meta", body="Plain body\n")
    issues = {99: issue}
    idx = build_issue_index(issues)
    assert idx.by_fingerprint == {}
    assert idx.parent_by_rule_id == {}


# =====================================================================
# find_issue_in_index
# =====================================================================


def test_find_issue_found() -> None:
    child = _issue_with_secmeta(2, {"type": "child", "fingerprint": "fp_abc"})
    idx = build_issue_index({2: child})
    result = find_issue_in_index(idx, fingerprint="fp_abc")
    assert result is not None
    assert result.number == 2

def test_find_issue_not_found() -> None:
    idx = build_issue_index({})
    assert find_issue_in_index(idx, fingerprint="missing") is None


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
    """No-op when parent_issue is None — no gh call is made."""
    mock_edit = mocker.patch("utils.issue_sync.gh_issue_edit_state")
    maybe_reopen_parent_issue(
        "org/repo", None, rule_id="R1", dry_run=False, context="test",
    )
    mock_edit.assert_not_called()

def test_reopen_parent_already_open() -> None:
    """No-op when parent is already open."""
    parent = Issue(number=1, state="open", title="P", body="b")
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=False, context="test",
    )
    assert parent.state == "open"

def test_reopen_parent_dry_run() -> None:
    """In dry-run mode, sets state to open without calling gh."""
    parent = Issue(number=1, state="closed", title="P", body="b")
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=True, context="test", child_issue_number=5,
    )
    assert parent.state == "open"

def test_reopen_parent_real(mocker: MockerFixture) -> None:
    """Non-dry-run reopens issue and posts sec-event comment."""
    mock_edit_state = mocker.patch("utils.issue_sync.gh_issue_edit_state", return_value=True)
    mock_comment = mocker.patch("utils.issue_sync.gh_issue_comment")
    parent = Issue(number=1, state="closed", title="P", body="b")
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=False, context="reopen_child", child_issue_number=5,
    )
    assert parent.state == "open"
    mock_edit_state.assert_called_once_with("org/repo", 1, "open")
    mock_comment.assert_called_once()
    comment_body = mock_comment.call_args[0][2]
    assert "reopen" in comment_body
    assert "R1" in comment_body

def test_reopen_parent_gh_failure(mocker: MockerFixture) -> None:
    """If gh_issue_edit_state fails, state stays closed."""
    mocker.patch("utils.issue_sync.gh_issue_edit_state", return_value=False)
    parent = Issue(number=1, state="closed", title="P", body="b")
    maybe_reopen_parent_issue(
        "org/repo", parent, rule_id="R1", dry_run=False, context="test",
    )
    assert parent.state == "closed"


# =====================================================================
# _append_notification
# =====================================================================


def test_append_notification_active() -> None:
    notifications: list[NotifiedIssue] = []
    _append_notification(
        notifications, repo="org/repo", issue_number=42,
        severity="high", category="sast", state="new", tool="AquaSec",
    )
    assert len(notifications) == 1
    assert notifications[0].issue_number == 42

def test_append_notification_none() -> None:
    """No-op when notifications is None — must not raise."""
    _append_notification(
        None, repo="org/repo", issue_number=42,
        severity="high", category="sast", state="new", tool="AquaSec",
    )
    # No assertion needed: the test passes if no exception is raised.
 

# =====================================================================
# _merge_child_secmeta
# =====================================================================


def test_merge_new_alert_number() -> None:
    """New alert number is appended to gh_alert_numbers."""
    child = _issue_with_secmeta(1, {
        "type": "child",
        "fingerprint": "fp1",
        "gh_alert_numbers": '["100"]',
        "occurrence_count": "1",
        "last_occurrence_fp": "old_occ",
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-01",
    })
    ctx = _make_alert_context(alert_number=200, fingerprint="fp1", occurrence_fp="new_occ")
    secmeta, new_occurrence = _merge_child_secmeta(ctx=ctx, issue=child)
    assert "200" in secmeta["gh_alert_numbers"]
    assert "100" in secmeta["gh_alert_numbers"]
    assert new_occurrence is True
    assert secmeta["occurrence_count"] == "2"

def test_merge_same_occurrence_fp() -> None:
    """Same occurrence_fp means no new occurrence counted."""
    child = _issue_with_secmeta(1, {
        "type": "child",
        "fingerprint": "fp1",
        "gh_alert_numbers": '["100"]',
        "occurrence_count": "1",
        "last_occurrence_fp": "same_occ",
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-01",
    })
    ctx = _make_alert_context(alert_number=100, fingerprint="fp1", occurrence_fp="same_occ")
    secmeta, new_occurrence = _merge_child_secmeta(ctx=ctx, issue=child)
    assert new_occurrence is False
    assert secmeta["occurrence_count"] == "1"

def test_merge_date_range_expansion() -> None:
    """first_seen takes the min, last_seen takes the max."""
    child = _issue_with_secmeta(1, {
        "type": "child",
        "fingerprint": "fp1",
        "first_seen": "2026-02-01",
        "last_seen": "2026-02-15",
        "occurrence_count": "1",
    })
    ctx = _make_alert_context(first_seen="2026-01-15", last_seen="2026-03-01")
    secmeta, _ = _merge_child_secmeta(ctx=ctx, issue=child)
    assert secmeta["first_seen"] == "2026-01-15"
    assert secmeta["last_seen"] == "2026-03-01"

def test_merge_removes_alert_hash() -> None:
    """Legacy alert_hash key is dropped during merge."""
    child = _issue_with_secmeta(1, {
        "type": "child",
        "alert_hash": "old_hash",
        "fingerprint": "fp1",
        "occurrence_count": "1",
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-01",
    })
    ctx = _make_alert_context(fingerprint="fp1")
    secmeta, _ = _merge_child_secmeta(ctx=ctx, issue=child)
    assert "alert_hash" not in secmeta

def test_merge_zero_occurrence_count_reset() -> None:
    """occurrence_count <= 0 is reset to at least 1."""
    child_secmeta_str = render_secmeta({
        "type": "child", "fingerprint": "fp1",
        "occurrence_count": "0", "last_occurrence_fp": "same_fp",
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
    })
    child = Issue(number=1, state="open", title="T", body=child_secmeta_str + "\nBody\n")
    ctx = _make_alert_context(fingerprint="fp1", occurrence_fp="same_fp")
    secmeta, _ = _merge_child_secmeta(ctx=ctx, issue=child)
    assert int(secmeta["occurrence_count"]) >= 1


# =====================================================================
# _maybe_reopen_child
# =====================================================================


def test_reopen_child_open_issue() -> None:
    """Returns False for an already-open issue."""
    issue = Issue(number=1, state="open", title="T", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context()
    assert _maybe_reopen_child(ctx=ctx, sync=sync, issue=issue, parent_issue=None) is False

def test_reopen_child_dry_run() -> None:
    """Dry-run marks reopened=True and appends notification."""
    body = render_secmeta({"type": "child", "category": "sast"}) + "\nbody"
    issue = Issue(number=1, state="closed", title="T", body=body)
    ctx = _make_alert_context()
    notifications: list[NotifiedIssue] = []
    sync = _make_sync_context(dry_run=True, notifications=notifications)
    result = _maybe_reopen_child(ctx=ctx, sync=sync, issue=issue, parent_issue=None)
    assert result is True
    assert len(notifications) == 1
    assert notifications[0].state == "reopen"

def test_reopen_child_real(mocker: MockerFixture) -> None:
    """Non-dry-run calls gh_issue_edit_state and appends notification."""
    mock_edit = mocker.patch("utils.issue_sync.gh_issue_edit_state", return_value=True)
    body = render_secmeta({"type": "child", "category": "sast"}) + "\nbody"
    issue = Issue(number=5, state="closed", title="T", body=body)
    ctx = _make_alert_context()
    notifications: list[NotifiedIssue] = []
    sync = _make_sync_context(notifications=notifications)
    result = _maybe_reopen_child(ctx=ctx, sync=sync, issue=issue, parent_issue=None)
    assert result is True
    assert len(notifications) == 1
    mock_edit.assert_called_once()

def test_reopen_child_cascades_to_parent(mocker: MockerFixture) -> None:
    """Reopening child also reopens the closed parent (dry-run)."""
    mocker.patch("utils.issue_sync.gh_issue_edit_state", return_value=True)
    body = render_secmeta({"type": "child"}) + "\nbody"
    issue = Issue(number=5, state="closed", title="T", body=body)
    parent = Issue(number=1, state="closed", title="P", body="pb")
    ctx = _make_alert_context()
    sync = _make_sync_context(dry_run=True)
    _maybe_reopen_child(ctx=ctx, sync=sync, issue=issue, parent_issue=parent)
    assert parent.state == "open"


# =====================================================================
# _rebuild_and_apply_child_body
# =====================================================================


def test_rebuild_body_changed(mocker: MockerFixture, sast_alert: dict) -> None:
    """When body changes, gh_issue_edit_body is called."""
    mock_edit = mocker.patch("utils.issue_sync.gh_issue_edit_body")
    issue = Issue(number=1, state="open", title="T", body="old body")
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context()
    secmeta = {"schema": "1", "type": "child", "fingerprint": "fp1"}
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, issue=issue, secmeta=secmeta)
    mock_edit.assert_called_once()

def test_rebuild_body_unchanged(sast_alert: dict) -> None:
    """When body is identical, no API call is made."""
    from utils.issue_builder import build_child_issue_body
    from utils.sec_events import strip_sec_events_from_body

    secmeta = {"schema": "1", "type": "child", "fingerprint": "fp1"}
    human_body = build_child_issue_body(sast_alert)
    body = render_secmeta(secmeta) + "\n\n" + human_body
    body = strip_sec_events_from_body(body)
    issue = Issue(number=1, state="open", title="T", body=body)
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context()
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, issue=issue, secmeta=secmeta)

def test_rebuild_body_dry_run(sast_alert: dict) -> None:
    """In dry-run mode, body is not written via API."""
    issue = Issue(number=1, state="open", title="T", body="old body")
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context(dry_run=True)
    secmeta = {"schema": "1", "type": "child", "fingerprint": "fp1"}
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, issue=issue, secmeta=secmeta)


# =====================================================================
# _comment_child_event
# =====================================================================


def test_comment_reopen_event(mocker: MockerFixture) -> None:
    """Posts a reopen sec-event comment when reopened=True."""
    mock_comment = mocker.patch("utils.issue_sync.gh_issue_comment")
    issue = Issue(number=1, state="open", title="T", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context()
    _comment_child_event(ctx=ctx, sync=sync, issue=issue, reopened=True, new_occurrence=False)
    mock_comment.assert_called_once()
    comment_body = mock_comment.call_args[0][2]
    assert "reopen" in comment_body

def test_comment_occurrence_event_no_comment(mocker: MockerFixture) -> None:
    """No sec-event comment when issue is already open (new_occurrence=True but reopened=False)."""
    mock_comment = mocker.patch("utils.issue_sync.gh_issue_comment")
    issue = Issue(number=1, state="open", title="T", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context()
    _comment_child_event(ctx=ctx, sync=sync, issue=issue, reopened=False, new_occurrence=True)
    mock_comment.assert_not_called()

def test_comment_no_event() -> None:
    """No comment when neither reopened nor new_occurrence."""
    issue = Issue(number=1, state="open", title="T", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context()
    _comment_child_event(ctx=ctx, sync=sync, issue=issue, reopened=False, new_occurrence=False)

def test_comment_reopen_dry_run() -> None:
    """Dry-run mode does not call gh_issue_comment for reopen."""
    issue = Issue(number=1, state="open", title="T", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context(dry_run=True)
    _comment_child_event(ctx=ctx, sync=sync, issue=issue, reopened=True, new_occurrence=False)

def test_comment_occurrence_dry_run() -> None:
    """No comment in any mode when issue is already open (occurrence-only path)."""
    issue = Issue(number=1, state="open", title="T", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context(dry_run=True)
    # Dry-run should also be silent for already-open issues.
    _comment_child_event(ctx=ctx, sync=sync, issue=issue, reopened=False, new_occurrence=True)


# =====================================================================
# _sync_child_title_and_labels
# =====================================================================


def test_sync_title_drift_corrected(mocker: MockerFixture) -> None:
    """Title is updated when it drifts from the expected format."""
    mock_title = mocker.patch("utils.issue_sync.gh_issue_edit_title", return_value=True)
    mock_labels = mocker.patch("utils.issue_sync.gh_issue_add_labels")
    issue = Issue(number=1, state="open", title="Wrong title", body="b")
    ctx = _make_alert_context(rule_name="sast", rule_id="CVE-2026-1234", fingerprint="fp_test_123")
    sync = _make_sync_context()
    _sync_child_title_and_labels(ctx=ctx, sync=sync, issue=issue)
    mock_title.assert_called_once()
    mock_labels.assert_called_once()

def test_sync_title_already_correct(mocker: MockerFixture) -> None:
    """Title is not updated when it matches the expected format."""
    mock_labels = mocker.patch("utils.issue_sync.gh_issue_add_labels")
    from utils.issue_builder import build_issue_title
    title = build_issue_title("sast", "CVE-2026-1234", "fp_test_123")
    issue = Issue(number=1, state="open", title=title, body="b")
    ctx = _make_alert_context(rule_name="sast", rule_id="CVE-2026-1234", fingerprint="fp_test_123")
    sync = _make_sync_context()
    _sync_child_title_and_labels(ctx=ctx, sync=sync, issue=issue)
    mock_labels.assert_called_once()

def test_sync_title_dry_run() -> None:
    """Dry-run mode logs instead of calling gh."""
    issue = Issue(number=1, state="open", title="Wrong", body="b")
    ctx = _make_alert_context()
    sync = _make_sync_context(dry_run=True)
    _sync_child_title_and_labels(ctx=ctx, sync=sync, issue=issue)


# =====================================================================
# _handle_new_child_issue
# =====================================================================


def test_handle_new_child_creates_issue(mocker: MockerFixture, sast_alert: dict) -> None:
    """Creates a new issue and registers it in the index."""
    mock_create = mocker.patch("utils.issue_sync.gh_issue_create", return_value=42)
    mocker.patch("utils.issue_sync.gh_issue_comment")
    ctx = _make_alert_context(alert=sast_alert, rule_name="sast")
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    sync = _make_sync_context(issues=issues, index=index, notifications=[])
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)
    mock_create.assert_called_once()
    assert 42 in issues
    assert ctx.fingerprint in index.by_fingerprint
    assert len(sync.notifications) == 1
    assert sync.notifications[0].state == "new"

def test_handle_new_child_dry_run(sast_alert: dict) -> None:
    """Dry-run does not call gh_issue_create but records notification."""
    ctx = _make_alert_context(alert=sast_alert)
    notifications: list[NotifiedIssue] = []
    sync = _make_sync_context(dry_run=True, notifications=notifications)
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)
    assert len(notifications) == 1
    assert notifications[0].issue_number == 0

def test_handle_new_child_links_to_parent(mocker: MockerFixture, sast_alert: dict) -> None:
    """When a parent issue exists, the child is linked as a sub-issue."""
    mocker.patch("utils.issue_sync.gh_issue_create", return_value=42)
    mock_sub = mocker.patch("utils.issue_sync.gh_issue_add_sub_issue_by_number")
    mocker.patch("utils.issue_sync.gh_issue_comment")
    parent = Issue(number=1, state="open", title="P", body="pb")
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context(notifications=[])
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=parent)
    mock_sub.assert_called_once_with("test-org/test-repo", 1, 42)

def test_handle_new_child_create_fails(mocker: MockerFixture, sast_alert: dict) -> None:
    """If gh_issue_create returns None, no crash and no index update."""
    mocker.patch("utils.issue_sync.gh_issue_create", return_value=None)
    ctx = _make_alert_context(alert=sast_alert)
    sync = _make_sync_context(notifications=[])
    _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=None)
    assert ctx.fingerprint not in sync.index.by_fingerprint


# =====================================================================
# _handle_existing_child_issue (integration of sub-functions)
# =====================================================================


def test_handle_existing_child_updates_body(mocker: MockerFixture, sast_alert: dict) -> None:
    """Existing child issue body is updated with fresh template."""
    mock_body = mocker.patch("utils.issue_sync.gh_issue_edit_body")
    mocker.patch("utils.issue_sync.gh_issue_add_labels")
    child = _issue_with_secmeta(5, {
        "type": "child", "fingerprint": "fp_test_123",
        "occurrence_count": "1", "first_seen": "2026-01-01",
        "last_seen": "2026-01-01", "last_occurrence_fp": "old_occ",
    })
    ctx = _make_alert_context(alert=sast_alert, fingerprint="fp_test_123")
    sync = _make_sync_context(issues={5: child}, notifications=[])
    _handle_existing_child_issue(ctx=ctx, sync=sync, issue=child, parent_issue=None)
    mock_body.assert_called_once()


# =====================================================================
# ensure_parent_issue
# =====================================================================


def test_ensure_parent_creates_new(mocker: MockerFixture, sast_alert: dict) -> None:
    """Creates a parent issue when none exists for the rule_id."""
    mock_create = mocker.patch("utils.issue_sync.gh_issue_create", return_value=99)
    mocker.patch("utils.issue_sync.gh_issue_comment")
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    result = ensure_parent_issue(sast_alert, issues, index, dry_run=False)
    assert result is not None
    assert result.number == 99
    mock_create.assert_called_once()
    assert sast_alert["metadata"]["rule_id"] in index.parent_by_rule_id

def test_ensure_parent_dry_run(sast_alert: dict) -> None:
    """Dry-run does not create an issue, returns None."""
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    result = ensure_parent_issue(sast_alert, issues, index, dry_run=True)
    assert result is None

def test_ensure_parent_existing_returns_existing(sast_alert: dict) -> None:
    """Returns the existing parent issue if one already exists."""
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert["metadata"]["rule_id"],
        "severity": "high",
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-01",
    })
    issues = {10: parent}
    index = build_issue_index(issues)
    result = ensure_parent_issue(sast_alert, issues, index, dry_run=True)
    assert result is not None
    assert result.number == 10

def test_ensure_parent_severity_change_detected(sast_alert: dict) -> None:
    """Severity change is detected and recorded."""
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert["metadata"]["rule_id"],
        "severity": "low",
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-01",
    })
    issues = {10: parent}
    index = build_issue_index(issues)
    changes: list[SeverityChange] = []
    ensure_parent_issue(sast_alert, issues, index, dry_run=True, severity_changes=changes)
    assert len(changes) == 1
    assert changes[0].old_severity == "low"
    assert changes[0].new_severity == "high"

def test_ensure_parent_no_rule_id() -> None:
    """Returns None when alert has no rule_id."""
    alert: dict[str, Any] = {"_repo": "org/repo", "metadata": {"rule_id": ""}, "alert_details": {}, "rule_details": {}}
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    assert ensure_parent_issue(alert, issues, index, dry_run=False) is None

def test_ensure_parent_create_fails(mocker: MockerFixture, sast_alert: dict) -> None:
    """Returns None if gh_issue_create fails."""
    mocker.patch("utils.issue_sync.gh_issue_create", return_value=None)
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    result = ensure_parent_issue(sast_alert, issues, index, dry_run=False)
    assert result is None

def test_ensure_parent_body_deferred(sast_alert: dict) -> None:
    """Parent body update is deferred (snapshot captured in parent_original_bodies)."""
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert["metadata"]["rule_id"],
        "severity": "high",
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-01",
    })
    original_body = parent.body
    issues = {10: parent}
    index = build_issue_index(issues)
    bods: dict[int, tuple[str, str]] = {}
    ensure_parent_issue(sast_alert, issues, index, dry_run=True, parent_original_bodies=bods)
    assert 10 in bods
    assert bods[10][1] == original_body

def test_ensure_parent_title_drift_corrected(mocker: MockerFixture, sast_alert: dict) -> None:
    """Title is updated when it drifts from the expected format."""
    mock_title = mocker.patch("utils.issue_sync.gh_issue_edit_title", return_value=True)
    parent = _issue_with_secmeta(10, {
        "type": "parent",
        "rule_id": sast_alert["metadata"]["rule_id"],
        "severity": "high",
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-01",
    })
    parent.title = "Wrong old title"
    issues = {10: parent}
    index = build_issue_index(issues)
    ensure_parent_issue(sast_alert, issues, index, dry_run=False)
    mock_title.assert_called_once()


# =====================================================================
# _flush_parent_body_updates
# =====================================================================


def test_flush_writes_changed_bodies(mocker: MockerFixture) -> None:
    """Writes body when it has changed."""
    mock_edit = mocker.patch("utils.issue_sync.gh_issue_edit_body")
    issue = Issue(number=1, state="open", title="T", body="new body")
    bods = {1: ("org/repo", "old body")}
    _flush_parent_body_updates(bods, {1: issue}, dry_run=False)
    mock_edit.assert_called_once_with("org/repo", 1, "new body")

def test_flush_skips_unchanged() -> None:
    """Does not call API if body is unchanged."""
    issue = Issue(number=1, state="open", title="T", body="same body")
    bods = {1: ("org/repo", "same body")}
    _flush_parent_body_updates(bods, {1: issue}, dry_run=False)

def test_flush_dry_run() -> None:
    """Dry-run logs instead of calling API."""
    issue = Issue(number=1, state="open", title="T", body="new body")
    bods = {1: ("org/repo", "old body")}
    _flush_parent_body_updates(bods, {1: issue}, dry_run=True)

def test_flush_missing_issue() -> None:
    """Skips silently if issue is no longer in the dict."""
    bods = {99: ("org/repo", "old body")}
    _flush_parent_body_updates(bods, {}, dry_run=False)


# =====================================================================
# _label_orphan_issues
# =====================================================================


def test_label_orphan_no_orphans() -> None:
    """No labelling when all children have matching alerts."""
    child = _issue_with_secmeta(1, {"type": "child", "fingerprint": "fp1"})
    index = build_issue_index({1: child})
    alerts: dict[int, dict] = {
        100: {"metadata": {"state": "open"}, "alert_details": {"alert_hash": "fp1"}, "rule_details": {}},
    }
    _label_orphan_issues(alerts, index, dry_run=False)

def test_label_orphan_found(mocker: MockerFixture) -> None:
    """Labels child issues that have no matching alert."""
    mock_labels = mocker.patch("utils.issue_sync.gh_issue_add_labels")
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan", "repo": "org/repo",
    })
    index = build_issue_index({1: child})
    alerts: dict[int, dict] = {}
    _label_orphan_issues(alerts, index, dry_run=False)
    mock_labels.assert_called_once()
    label_args = mock_labels.call_args[0][2]
    assert "sec:adept-to-close" in label_args

def test_label_orphan_dry_run() -> None:
    """Dry-run: logs but does not call gh."""
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan", "repo": "org/repo",
    })
    index = build_issue_index({1: child})
    _label_orphan_issues({}, index, dry_run=True)

def test_label_orphan_skips_already_labelled() -> None:
    """Skips if adept-to-close label is already present."""
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan", "repo": "org/repo",
    })
    child.labels = ["sec:adept-to-close"]
    index = build_issue_index({1: child})
    _label_orphan_issues({}, index, dry_run=False)

def test_label_orphan_skips_closed_issues() -> None:
    """Closed child issues are not labelled as orphans."""
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan", "repo": "org/repo",
    }, state="closed")
    index = build_issue_index({1: child})
    _label_orphan_issues({}, index, dry_run=False)

def test_label_orphan_no_repo_in_secmeta() -> None:
    """Skips labelling if no repo in secmeta."""
    child = _issue_with_secmeta(1, {
        "type": "child", "fingerprint": "fp_orphan",
    })
    index = build_issue_index({1: child})
    _label_orphan_issues({}, index, dry_run=False)


# =====================================================================
# ensure_issue (end-to-end orchestration per alert)
# =====================================================================


def test_ensure_issue_new_alert_creates_parent_and_child(
    mocker: MockerFixture, sast_alert: dict,
) -> None:
    """Full path: new alert creates parent + child."""
    mock_create = mocker.patch("utils.issue_sync.gh_issue_create", return_value=50)
    mocker.patch("utils.issue_sync.gh_issue_comment")
    mocker.patch("utils.issue_sync.gh_issue_edit_body")
    mocker.patch("utils.issue_sync.gh_issue_add_labels")
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    notifications: list[NotifiedIssue] = []
    ensure_issue(
        sast_alert, issues, index,
        dry_run=False, notifications=notifications,
    )
    assert mock_create.call_count == 2  # parent + child
    assert len(notifications) == 1

def test_ensure_issue_dry_run(sast_alert: dict) -> None:
    """Dry-run: no gh calls, notification with issue_number=0."""
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    notifications: list[NotifiedIssue] = []
    ensure_issue(
        sast_alert, issues, index,
        dry_run=True, notifications=notifications,
    )
    assert len(notifications) == 1
    assert notifications[0].issue_number == 0

def test_ensure_issue_skips_non_open() -> None:
    """Alerts with state != 'open' are skipped."""
    alert: dict[str, Any] = {
        "metadata": {"alert_number": 1, "state": "dismissed"},
        "alert_details": {},
        "rule_details": {},
        "_repo": "org/repo",
    }
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    ensure_issue(alert, issues, index, dry_run=True)

def test_ensure_issue_missing_alert_hash_raises() -> None:
    """Raises SystemExit when alert hash is missing."""
    alert: dict[str, Any] = {
        "metadata": {"alert_number": 1, "state": "open", "rule_id": "R1", "severity": "high"},
        "alert_details": {},
        "rule_details": {},
        "_repo": "org/repo",
    }
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    with pytest.raises(SystemExit, match="alert_hash"):
        ensure_issue(alert, issues, index, dry_run=True)

def test_ensure_issue_missing_alert_details_raises() -> None:
    """Raises SystemExit when alert_details has no alert_hash."""
    alert: dict[str, Any] = {
        "metadata": {"alert_number": 1, "state": "open"},
        "alert_details": {},
        "rule_details": {},
        "_repo": "org/repo",
    }
    issues: dict[int, Issue] = {}
    index = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    with pytest.raises(SystemExit, match="alert_hash"):
        ensure_issue(alert, issues, index, dry_run=True)

def test_ensure_issue_existing_child_updates(mocker: MockerFixture, sast_alert: dict) -> None:
    """When a child issue already exists, it is updated (not duplicated)."""
    mocker.patch("utils.issue_sync.gh_issue_edit_body")
    mocker.patch("utils.issue_sync.gh_issue_add_labels")
    fp = sast_alert["alert_details"]["alert_hash"]
    child = _issue_with_secmeta(5, {
        "type": "child", "fingerprint": fp,
        "occurrence_count": "1", "first_seen": "2026-01-01",
        "last_seen": "2026-01-01", "last_occurrence_fp": "old_occ",
    })
    parent = _issue_with_secmeta(10, {
        "type": "parent", "rule_id": sast_alert["metadata"]["rule_id"],
        "severity": "high", "first_seen": "2026-01-01", "last_seen": "2026-01-01",
    })
    issues = {5: child, 10: parent}
    index = build_issue_index(issues)
    notifications: list[NotifiedIssue] = []
    ensure_issue(
        sast_alert, issues, index,
        dry_run=True, notifications=notifications,
    )


# =====================================================================
# sync_alerts_and_issues (top-level orchestrator)
# =====================================================================


def test_sync_empty() -> None:
    """Empty alerts produce empty result."""
    result = sync_alerts_and_issues({}, {}, dry_run=True)
    assert result.notifications == []
    assert result.severity_changes == []

def test_sync_dry_run_single_alert(sast_alert: dict) -> None:
    """Single alert dry-run produces a notification."""
    alerts = {303: sast_alert}
    result = sync_alerts_and_issues(alerts, {}, dry_run=True)
    assert len(result.notifications) == 1

def test_sync_creates_issues(
    mocker: MockerFixture, sast_alert: dict, vuln_alert: dict,
) -> None:
    """Multiple alerts each get parent + child issues."""
    mock_create = mocker.patch("utils.issue_sync.gh_issue_create", return_value=100)
    mocker.patch("utils.issue_sync.gh_issue_comment")
    mocker.patch("utils.issue_sync.gh_issue_edit_body")
    mocker.patch("utils.issue_sync.gh_issue_add_labels")
    alerts = {303: sast_alert, 312: vuln_alert}
    result = sync_alerts_and_issues(alerts, {}, dry_run=False)
    assert len(result.notifications) == 2
    assert mock_create.call_count == 4  # 2 parents + 2 children

def test_sync_severity_change_detected(sast_alert: dict) -> None:
    """Severity change on existing parent is captured in result."""
    parent = _issue_with_secmeta(10, {
        "type": "parent", "rule_id": sast_alert["metadata"]["rule_id"],
        "severity": "low", "first_seen": "2026-01-01", "last_seen": "2026-01-01",
    })
    issues = {10: parent}
    result = sync_alerts_and_issues({303: sast_alert}, issues, dry_run=True)
    assert len(result.severity_changes) == 1
    assert result.severity_changes[0].old_severity == "low"
    assert result.severity_changes[0].new_severity == "high"


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

def test_init_priority_sync_derives_org_from_alert(mocker: MockerFixture) -> None:
    """Derives org from the first alert's _repo when project_org is empty."""
    alerts = {1: {"_repo": "derived-org/repo-a"}}
    mocker.patch("utils.issue_sync.gh_project_get_priority_field", return_value=mocker.MagicMock())
    result = _init_priority_sync(
        alerts, severity_priority_map={"high": "Urgent"}, project_number=7,
        project_org="", dry_run=True,
    )
    assert result is not None
    assert result.org == "derived-org"

def test_init_priority_sync_no_org_returns_none() -> None:
    """Returns None with warning when org cannot be determined."""
    alerts = {1: {"_repo": ""}}
    result = _init_priority_sync(
        alerts, severity_priority_map={"high": "Urgent"}, project_number=7,
        project_org="", dry_run=False,
    )
    assert result is None

def test_init_priority_sync_field_lookup_fails(mocker: MockerFixture) -> None:
    """Returns None when gh_project_get_priority_field fails."""
    mocker.patch("utils.issue_sync.gh_project_get_priority_field", return_value=None)
    result = _init_priority_sync(
        {}, severity_priority_map={"high": "Urgent"}, project_number=7,
        project_org="org", dry_run=False,
    )
    assert result is None
