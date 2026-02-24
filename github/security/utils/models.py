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

"""Security-specific data models."""

from dataclasses import dataclass
from typing import Any

from shared.github_projects import ProjectPrioritySync
from shared.models import Issue


@dataclass
class IssueIndex:
    by_fingerprint: dict[str, Issue]
    parent_by_rule_id: dict[str, Issue]


@dataclass
class NotifiedIssue:
    """Tracks a new or reopened child issue for Teams notification."""
    repo: str
    issue_number: int
    severity: str
    category: str
    state: str          # "new" or "reopen"
    tool: str


@dataclass
class SeverityChange:
    """Records a parent issue whose severity changed between syncs."""
    repo: str
    issue_number: int
    rule_id: str
    old_severity: str
    new_severity: str


# Ordered from lowest to highest so we can compute direction.
SEVERITY_ORDER: dict[str, int] = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_direction(old: str, new: str) -> str:
    """Return a human-readable arrow indicating the change direction."""
    old_rank = SEVERITY_ORDER.get(old.lower(), -1)
    new_rank = SEVERITY_ORDER.get(new.lower(), -1)
    if new_rank > old_rank:
        return "⬆️ escalated"
    if new_rank < old_rank:
        return "⬇️ de-escalated"
    return "↔️ unchanged"


@dataclass
class SyncResult:
    """Aggregated output of a full sync run."""
    notifications: list[NotifiedIssue]
    severity_changes: list[SeverityChange]


@dataclass
class AlertContext:
    """Per-alert data extracted in ``ensure_issue`` and passed to child handlers."""
    alert: dict[str, Any]
    alert_number: int
    fingerprint: str
    occurrence_fp: str
    repo: str
    first_seen: str
    last_seen: str
    tool: str
    rule_id: str
    rule_name: str
    severity: str
    cwe: str
    path: str
    start_line: Any
    end_line: Any
    commit_sha: str


@dataclass
class SyncContext:
    """Shared orchestration state for the sync run."""
    issues: dict[int, Issue]
    index: IssueIndex
    dry_run: bool
    notifications: list[NotifiedIssue] | None
    severity_priority_map: dict[str, str]
    priority_sync: ProjectPrioritySync | None
