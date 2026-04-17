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

"""Unit tests for ``utils.teams``."""


import logging
import types

import pytest

from security.issues.models import NotifiedIssue, SeverityChange
from security.notifications.teams import (
    build_severity_change_body,
    build_teams_notification_body,
    notify_teams,
    notify_teams_severity_changes,
)


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def sample_notifications() -> list[NotifiedIssue]:
    return [
        NotifiedIssue(
            repo="org/repo-a", issue_number=10, severity="high",
            category="sast", state="new", tool="AquaSec",
        ),
        NotifiedIssue(
            repo="org/repo-b", issue_number=20, severity="medium",
            category="sca", state="reopen", tool="AquaSec",
        ),
    ]


@pytest.fixture
def sample_changes() -> list[SeverityChange]:
    return [
        SeverityChange(
            repo="org/repo-a", issue_number=5, rule_id="CVE-2026-1234",
            old_severity="medium", new_severity="critical",
        ),
    ]


# =====================================================================
# build_teams_notification_body
# =====================================================================


def test_counts_new_and_reopened(sample_notifications: list[NotifiedIssue]) -> None:
    body = build_teams_notification_body(sample_notifications)
    assert "**1** new" in body
    assert "**1** reopened" in body

def test_contains_issue_links(sample_notifications: list[NotifiedIssue]) -> None:
    body = build_teams_notification_body(sample_notifications)
    assert "https://github.com/org/repo-a/issues/10" in body
    assert "https://github.com/org/repo-b/issues/20" in body

def test_contains_severity(sample_notifications: list[NotifiedIssue]) -> None:
    body = build_teams_notification_body(sample_notifications)
    assert "*high*" in body
    assert "*medium*" in body

def test_contains_state_tag(sample_notifications: list[NotifiedIssue]) -> None:
    body = build_teams_notification_body(sample_notifications)
    assert "[new]" in body
    assert "[reopen]" in body

def test_empty_notifications() -> None:
    body = build_teams_notification_body([])
    assert "**0** new" in body
    assert "**0** reopened" in body

def test_pending_issue_number_zero() -> None:
    """issue_number=0 produces a '(pending)' fallback instead of an issue link."""
    n = NotifiedIssue(
        repo="org/repo-a", issue_number=0, severity="high",
        category="sast", state="new", tool="AquaSec",
    )
    body = build_teams_notification_body([n])
    assert "(pending)" in body
    assert "issues/0" not in body


# =====================================================================
# build_severity_change_body
# =====================================================================


def test_counts_changes(sample_changes: list[SeverityChange]) -> None:
    body = build_severity_change_body(sample_changes)
    assert "**1** parent issue(s)" in body

def test_contains_issue_link(sample_changes: list[SeverityChange]) -> None:
    body = build_severity_change_body(sample_changes)
    assert "https://github.com/org/repo-a/issues/5" in body

def test_contains_direction(sample_changes: list[SeverityChange]) -> None:
    body = build_severity_change_body(sample_changes)
    assert "escalated" in body

def test_contains_severities(sample_changes: list[SeverityChange]) -> None:
    body = build_severity_change_body(sample_changes)
    assert "**medium**" in body
    assert "**critical**" in body

def test_contains_rule_id(sample_changes: list[SeverityChange]) -> None:
    body = build_severity_change_body(sample_changes)
    assert "CVE-2026-1234" in body


@pytest.fixture
def _mock_subprocess_ok(monkeypatch: pytest.MonkeyPatch):
    """Patch subprocess.run to succeed and os.path.exists to return True."""
    calls: list[tuple] = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("security.notifications.teams.subprocess.run", fake_run)
    monkeypatch.setattr("security.notifications.teams.os.path.exists", lambda _: True)
    return calls


# =====================================================================
# notify_teams – subprocess interactions (mocked)
# =====================================================================


def test_skips_when_empty(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        notify_teams("https://hook", [], dry_run=False)
    assert any("skipping" in r.message.lower() for r in caplog.records)

def test_notify_teams_dry_run_calls_subprocess(
    sample_notifications: list[NotifiedIssue],
    _mock_subprocess_ok: list[tuple],
) -> None:
    notify_teams("https://hook", sample_notifications, dry_run=True)
    assert len(_mock_subprocess_ok) == 1
    cmd = _mock_subprocess_ok[0][0]
    assert "--dry-run" in cmd

def test_notify_teams_skips_when_script_not_found(
    monkeypatch: pytest.MonkeyPatch,
    sample_notifications: list[NotifiedIssue],
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list = []
    monkeypatch.setattr("security.notifications.teams.subprocess.run", lambda cmd, **kw: calls.append(cmd))
    monkeypatch.setattr("security.notifications.teams.os.path.exists", lambda _: False)
    with caplog.at_level(logging.WARNING):
        notify_teams("https://hook", sample_notifications, dry_run=False)
    assert len(calls) == 0
    assert any("not found" in r.message.lower() for r in caplog.records)


def test_notify_teams_real_sends_webhook(
    sample_notifications: list[NotifiedIssue],
    _mock_subprocess_ok: list[tuple],
) -> None:
    """Non-dry-run path passes --webhook-url to subprocess."""
    notify_teams("https://hook", sample_notifications, dry_run=False)
    assert len(_mock_subprocess_ok) == 1
    cmd = _mock_subprocess_ok[0][0]
    assert "--webhook-url" in cmd
    assert "--dry-run" not in cmd


def test_notify_teams_subprocess_failure(
    monkeypatch: pytest.MonkeyPatch,
    sample_notifications: list[NotifiedIssue],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Subprocess failure logs a warning and does not raise."""
    def fake_run(cmd, **kwargs):
        return types.SimpleNamespace(returncode=1, stdout="", stderr="send failed")

    monkeypatch.setattr("security.notifications.teams.subprocess.run", fake_run)
    monkeypatch.setattr("security.notifications.teams.os.path.exists", lambda _: True)
    with caplog.at_level(logging.WARNING):
        notify_teams("https://hook", sample_notifications, dry_run=False)
    assert any("failed" in r.message.lower() for r in caplog.records)


# =====================================================================
# notify_teams_severity_changes – subprocess interactions (mocked)
# =====================================================================


def test_severity_changes_skips_when_empty() -> None:
    """Empty list is silently accepted — no subprocess call."""
    notify_teams_severity_changes("https://hook", [], dry_run=False)

def test_severity_changes_dry_run(
    sample_changes: list[SeverityChange],
    _mock_subprocess_ok: list[tuple],
) -> None:
    notify_teams_severity_changes("https://hook", sample_changes, dry_run=True)
    assert len(_mock_subprocess_ok) == 1
    cmd = _mock_subprocess_ok[0][0]
    assert "--dry-run" in cmd
