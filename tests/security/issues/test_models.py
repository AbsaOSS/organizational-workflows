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

"""Unit tests for ``security.issues.models``."""

import pytest

from security.issues.models import (
    AlertContext,
    IssueIndex,
    NotifiedIssue,
    SEVERITY_ORDER,
    SeverityChange,
    SyncContext,
    SyncResult,
    bump_severity,
    severity_direction,
)


# =====================================================================
# severity_direction
# =====================================================================


def test_escalated() -> None:
    assert "escalated" in severity_direction("low", "high")

def test_de_escalated() -> None:
    assert "de-escalated" in severity_direction("critical", "medium")

def test_unchanged() -> None:
    assert "unchanged" in severity_direction("high", "high")

def test_case_insensitive() -> None:
    assert "escalated" in severity_direction("LOW", "HIGH")

def test_unknown_old() -> None:
    result = severity_direction("unknown", "high")
    assert "escalated" in result

def test_unknown_both() -> None:
    result = severity_direction("unknown", "unknown")
    assert "unchanged" in result


# =====================================================================
# SEVERITY_ORDER
# =====================================================================


def test_order() -> None:
    assert SEVERITY_ORDER["unknown"] < SEVERITY_ORDER["low"]
    assert SEVERITY_ORDER["low"] < SEVERITY_ORDER["medium"]
    assert SEVERITY_ORDER["medium"] < SEVERITY_ORDER["high"]
    assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["critical"]

def test_all_keys_present() -> None:
    expected = {"unknown", "low", "medium", "high", "critical"}
    assert set(SEVERITY_ORDER.keys()) == expected


# =====================================================================
# Data classes
# =====================================================================


def test_notified_issue_creation() -> None:
    n = NotifiedIssue(
        repo="org/repo", issue_number=42, severity="high",
        category="sast", state="new", tool="AquaSec",
    )
    assert n.repo == "org/repo"
    assert n.issue_number == 42
    assert n.state == "new"


def test_severity_change_creation() -> None:
    sc = SeverityChange(
        repo="org/repo", issue_number=1, rule_id="CVE-123",
        old_severity="medium", new_severity="critical",
    )
    assert sc.old_severity == "medium"
    assert sc.new_severity == "critical"


def test_sync_result_creation() -> None:
    sr = SyncResult(notifications=[], severity_changes=[])
    assert sr.notifications == []
    assert sr.severity_changes == []


def test_issue_index_creation() -> None:
    idx = IssueIndex(by_fingerprint={}, parent_by_rule_id={})
    assert idx.by_fingerprint == {}
    assert idx.parent_by_rule_id == {}


def test_alert_context_creation() -> None:
    ctx = AlertContext(
        alert={}, alert_number=1, fingerprint="fp",
        repo="org/repo",
        tool="AquaSec", rule_id="R1", rule_name="sast",
        rule_description="Test finding description",
        severity="high", path="src/f.py",
        start_line=10, end_line=20, commit_sha="abc123",
    )
    assert ctx.alert_number == 1
    assert ctx.severity == "high"


def test_sync_context_creation() -> None:
    sc = SyncContext(
        issues={}, index=IssueIndex({}, {}), dry_run=True,
        notifications=[], severity_priority_map={}, priority_sync=None,
    )
    assert sc.dry_run is True


# =====================================================================
# bump_severity
# =====================================================================


def test_bump_severity_increments_new_and_existing_key() -> None:
    """First bump of a severity creates the key at 1; a second bump increments it."""
    counter: dict[str, int] = {}
    bump_severity(counter, "high")
    assert {"high": 1} == counter
    bump_severity(counter, "high")
    assert {"high": 2} == counter


@pytest.mark.parametrize("severity,expected_key", [
    (None, "unknown"),
    ("", "unknown"),
    ("   ", "unknown"),
    ("HIGH", "high"),
    ("  High  ", "high"),
])
def test_bump_severity_normalizes_blank_and_case(severity: str | None, expected_key: str) -> None:
    """Blank/None severities collapse to 'unknown'; casing/whitespace is normalized."""
    counter: dict[str, int] = {}
    bump_severity(counter, severity)
    assert {expected_key: 1} == counter
