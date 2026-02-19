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

"""Core data classes – plain dataclass definitions shared across modules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Issue:
    number: int
    state: str
    title: str
    body: str
    labels: list[str] | None = None


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
