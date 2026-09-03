"""Pure rendering of a completed sync run into plain-text summary lines.

The functions here take no dependency on ``logging`` and bake in no prefix
(e.g. no ``[DRY-RUN]``) so the exact same lines can back the sync-summary log
output today and a future Teams-notification body without duplicating the
rendering logic.
"""

from dataclasses import dataclass

from .models import SEVERITY_ORDER, SyncStats

_SEVERITY_DISPLAY_ORDER = sorted(SEVERITY_ORDER, key=lambda severity: SEVERITY_ORDER[severity], reverse=True)


@dataclass
class LabelMigrationSummary:
    """Repo-level label-sweep outcome for a single sync run.

    MIGRATION-PHASE-2-REMOVE: entire dataclass, once the tech-debt -> aquasec
    label migration sweep is retired.
    """

    issues_migrated: int = 0
    labels_added: int = 0
    labels_removed: int = 0


def _format_severity_breakdown(counter: dict[str, int]) -> str:
    """Render a per-severity breakdown, e.g. ``critical: 1, high: 2``."""
    parts = [f"{severity}: {counter[severity]}" for severity in _SEVERITY_DISPLAY_ORDER if counter.get(severity)]
    return ", ".join(parts)


def _format_stat_line(event: str, total: int, counter: dict[str, int]) -> str | None:
    """Render one lifecycle stat line."""
    if not total:
        return None
    breakdown = _format_severity_breakdown(counter)
    return f"{event}: {total} ({breakdown})" if breakdown else f"{event}: {total}"


def _render_issue_section(title: str, rows: list[str | None]) -> list[str]:
    """Render a titled section."""
    parts = [row for row in rows if row]
    if not parts:
        return []
    return [f"{title}:"] + [f"  {part}" for part in parts]


def _render_label_section(label_summary: LabelMigrationSummary) -> list[str]:
    """Render the label-sweep section, always present so the outcome is explicit.

    MIGRATION-PHASE-2-REMOVE: entire function, once the label migration sweep
    is retired.
    """
    if not label_summary.issues_migrated:
        return ["Labels: no repository label action needed"]

    return [
        "Labels:",
        f"  migrated: {label_summary.issues_migrated} issue(s) "
        f"(added: {label_summary.labels_added}, removed: {label_summary.labels_removed})",
    ]


def render_sync_summary(stats: SyncStats, label_summary: LabelMigrationSummary) -> list[str]:
    """Render the full sync summary as plain, prefix-free lines.

    Args:
        stats: Lifecycle counters (including per-severity breakdowns) for the run.
        label_summary: Outcome of the repo-level label migration sweep for the run.

    Returns:
        Plain text lines (no logging prefix) ready to be logged as-is or reused
        as the body of a future notification.
    """
    parent_lines = _render_issue_section(
        "Parent issues",
        [
            _format_stat_line("created", stats.parents_created, stats.parents_created_by_severity),
            _format_stat_line("reopened", stats.parents_reopened, stats.parents_reopened_by_severity),
            _format_stat_line("closed", stats.parents_closed, stats.parents_closed_by_severity),
            _format_stat_line("title updated", stats.parents_title_updated, stats.parents_title_updated_by_severity),
            _format_stat_line("body updated", stats.parents_body_updated, stats.parents_body_updated_by_severity),
        ],
    )

    child_lines = _render_issue_section(
        "Child issues",
        [
            _format_stat_line("created", stats.children_created, stats.children_created_by_severity),
            _format_stat_line("reopened", stats.children_reopened, stats.children_reopened_by_severity),
            _format_stat_line("closed", stats.children_closed, stats.children_closed_by_severity),
            _format_stat_line("title updated", stats.children_title_updated, stats.children_title_updated_by_severity),
            _format_stat_line("body updated", stats.children_body_updated, stats.children_body_updated_by_severity),
            _format_stat_line("relinked", stats.children_relinked, {}),
        ],
    )

    if parent_lines or child_lines:
        lines = ["Sync complete:", *parent_lines, *child_lines]
    else:
        lines = ["Sync complete: no changes"]

    lines += _render_label_section(label_summary)
    return lines
