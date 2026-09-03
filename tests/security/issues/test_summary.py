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

"""Unit tests for ``security.issues.summary``."""

from security.issues.models import SyncStats
from security.issues.summary import (
    LabelMigrationSummary,
    _format_severity_breakdown,
    _format_stat_line,
    _render_issue_section,
    _render_label_section,
    render_sync_summary,
)


# =====================================================================
# _format_severity_breakdown
# =====================================================================


def test_format_severity_breakdown_orders_and_filters_zero() -> None:
    """Renders severities in critical->high->medium->low->unknown order, omitting zero counts."""
    counter = {"low": 1, "critical": 1, "high": 2, "medium": 0, "unknown": 3}
    assert "critical: 1, high: 2, low: 1, unknown: 3" == _format_severity_breakdown(counter)


def test_format_severity_breakdown_empty() -> None:
    """An empty counter renders as an empty string."""
    assert "" == _format_severity_breakdown({})


# =====================================================================
# _format_stat_line
# =====================================================================


def test_format_stat_line_zero_total_returns_none() -> None:
    """A zero total renders nothing, regardless of the counter's content."""
    assert _format_stat_line("created", 0, {"high": 5}) is None


def test_format_stat_line_with_and_without_breakdown() -> None:
    """A populated counter appends a breakdown; an empty counter renders the bare total."""
    assert "created: 3 (high: 2, low: 1)" == _format_stat_line("created", 3, {"high": 2, "low": 1})
    assert "created: 3" == _format_stat_line("created", 3, {})


# =====================================================================
# _render_issue_section
# =====================================================================


def test_render_issue_section_empty_and_filtered() -> None:
    """All-None rows render nothing; a mix renders the title plus only the non-None rows, indented."""
    assert [] == _render_issue_section("Parent issues", [None, None])
    assert [
        "Parent issues:",
        "  created: 2",
        "  closed: 1",
    ] == _render_issue_section("Parent issues", ["created: 2", None, "closed: 1"])


# =====================================================================
# _render_label_section
# MIGRATION-PHASE-2-REMOVE: delete this test once the label migration sweep is retired.
# =====================================================================


def test_render_label_section_zero_and_migrated() -> None:
    """No migration activity renders a one-line explicit no-op; activity renders counts."""
    assert ["Labels: no repository label action needed"] == _render_label_section(LabelMigrationSummary())
    assert [
        "Labels:",
        "  migrated: 3 issue(s) (added: 4, removed: 1)",
    ] == _render_label_section(LabelMigrationSummary(issues_migrated=3, labels_added=4, labels_removed=1))


# =====================================================================
# render_sync_summary
# =====================================================================


def test_render_sync_summary_no_changes() -> None:
    """Empty stats and an empty label summary render the no-changes line plus the label no-op line."""
    lines = render_sync_summary(SyncStats(), LabelMigrationSummary())
    assert "Sync complete: no changes" == lines[0]
    # MIGRATION-PHASE-2-REMOVE: delete this assertion once the label migration sweep is retired.
    assert "Labels: no repository label action needed" == lines[1]


def test_render_sync_summary_full_activity() -> None:
    """Populated stats render grouped parent/child sections with breakdowns; relinked has no breakdown."""
    stats = SyncStats(
        parents_created=2, parents_created_by_severity={"high": 2},
        parents_title_updated=1, parents_title_updated_by_severity={"high": 1},
        children_created=15, children_created_by_severity={"high": 15},
        children_reopened=1, children_reopened_by_severity={"critical": 1},
        children_relinked=1,
    )
    label_summary = LabelMigrationSummary(issues_migrated=4, labels_added=5, labels_removed=2)

    lines = render_sync_summary(stats, label_summary)

    assert lines == [
        "Sync complete:",
        "Parent issues:",
        "  created: 2 (high: 2)",
        "  title updated: 1 (high: 1)",
        "Child issues:",
        "  created: 15 (high: 15)",
        "  reopened: 1 (critical: 1)",
        "  relinked: 1",
        "Labels:",
        # MIGRATION-PHASE-2-REMOVE: delete this line once the label migration sweep is retired.
        "  migrated: 4 issue(s) (added: 5, removed: 2)",
    ]
