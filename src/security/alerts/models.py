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

"""Alert-specific data models."""

from dataclasses import dataclass, field
from typing import Any

from security.constants import NOT_AVAILABLE


@dataclass
class AlertMetadata:
    """Parsed from the ``metadata`` section of a raw alert entry."""

    alert_number: int = 0
    state: str = ""
    created_at: str = ""
    updated_at: str = ""
    url: str = ""
    alert_url: str = ""
    rule_id: str = ""
    rule_name: str = ""
    rule_description: str = ""
    severity: str = ""
    confidence: str = ""
    tags: list[str] = field(default_factory=list)
    help_uri: str | None = None
    tool: str = ""
    tool_version: str = ""
    ref: str = ""
    commit_sha: str = ""
    instance_url: str | None = None
    classifications: list = field(default_factory=list)
    file: str = ""
    start_line: int | None = None
    end_line: int | None = None

    def __post_init__(self) -> None:
        self.rule_id = (self.rule_id or "").strip()
        self.rule_name = (self.rule_name or "").strip()
        self.rule_description = (self.rule_description or "").strip()
        self.severity = (self.severity or "").strip() or "unknown"
        self.state = (self.state or "").lower().strip()
        self.tool = (self.tool or "").strip()


@dataclass
class AlertDetails:
    """Parsed from the ``alert_details`` section of a raw alert entry."""

    alert_hash: str = ""
    artifact: str = ""
    type: str = ""
    vulnerability: str = ""
    severity: str = ""
    repository: str = ""
    reachable: str = ""
    scan_date: str = ""
    first_seen: str = ""
    scm_file: str = ""
    installed_version: str = ""
    start_line: str = ""
    end_line: str = ""
    message: str = ""

    def __post_init__(self) -> None:
        self.alert_hash = self.alert_hash.strip()
        # Normalize optional display fields; callers never need to supply NOT_AVAILABLE defaults.
        for _f in ("repository", "scm_file", "message", "installed_version", "reachable"):
            if not getattr(self, _f):
                setattr(self, _f, NOT_AVAILABLE)


@dataclass
class RuleDetails:
    """Parsed from the ``rule_details`` section of a raw alert entry."""

    type: str = ""
    severity: str = ""
    cwe: str = ""
    fixed_version: str = ""
    published_date: str = ""
    package_name: str = ""
    category: str = ""
    impact: str = ""
    confidence: str = ""
    likelihood: str = ""
    remediation: str = ""
    owasp: str = ""
    references: str = ""

    def __post_init__(self) -> None:
        # Normalize all empty display fields; callers never need to supply NOT_AVAILABLE defaults.
        for _f in (
            "fixed_version",
            "published_date",
            "package_name",
            "impact",
            "confidence",
            "likelihood",
            "remediation",
            "owasp",
            "references",
        ):
            if not getattr(self, _f):
                setattr(self, _f, NOT_AVAILABLE)


@dataclass
class Alert:
    """A single code-scanning alert with its metadata, details, and rule info."""

    metadata: AlertMetadata = field(default_factory=AlertMetadata)
    alert_details: AlertDetails = field(default_factory=AlertDetails)
    rule_details: RuleDetails = field(default_factory=RuleDetails)
    repo: str = ""  # injected by load_open_alerts_from_file (was _repo)

    def __post_init__(self) -> None:
        self.repo = self.repo.strip()

    @classmethod
    def from_dict(cls, d: dict[str, Any], *, repo: str = "") -> "Alert":
        """Construct an Alert from the nested raw dict produced by collect_alert.py."""
        md = d.get("metadata") or {}
        ad = d.get("alert_details") or {}
        rd = d.get("rule_details") or {}
        return cls(
            metadata=AlertMetadata(**{k: v for k, v in md.items() if k in AlertMetadata.__dataclass_fields__}),
            alert_details=AlertDetails(**{k: v for k, v in ad.items() if k in AlertDetails.__dataclass_fields__}),
            rule_details=RuleDetails(**{k: v for k, v in rd.items() if k in RuleDetails.__dataclass_fields__}),
            repo=repo or str(d.get("_repo", "")),
        )


@dataclass
class LoadedAlerts:
    """Result of loading the alerts JSON produced by collect_alert.py."""

    repo_full: str
    open_by_number: dict[int, Alert]
