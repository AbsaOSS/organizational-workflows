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

"""Parse AquaSec Night Scan JSON output into Alert dataclasses."""

import logging
from typing import Any

from security.alerts.models import Alert, AlertDetails, AlertMetadata, LoadedAlerts, RuleDetails
from security.constants import LOGGING_PREFIX, SEVERITY_MAP

logger = logging.getLogger(__name__)


def _map_severity(numeric_severity: int) -> str:
    """Map numeric AquaSec severity to lowercase string."""
    return SEVERITY_MAP.get(numeric_severity, "unknown")


def _format_bullet_list(items: list[str] | None) -> str:
    """Format a list of strings as a Markdown bullet list."""
    if not items:
        return ""
    return "\n".join(f"- {item}" for item in items)


def _parse_item(item: dict[str, Any], repo: str) -> Alert:
    """Map a single AquaSec JSON item to an Alert dataclass."""
    extra = item.get("extraData") or {}
    severity_str = _map_severity(item.get("severity", 0))
    references_list = extra.get("references") or []

    metadata = AlertMetadata(
        alert_number=0,
        state="open",
        created_at=item.get("first_seen", ""),
        updated_at=item.get("scan_date", ""),
        url="",
        alert_url="",
        rule_id=item.get("avd_id", ""),
        rule_name=item.get("category", ""),
        rule_description=item.get("title", ""),
        severity=severity_str,
        confidence="",
        tags=[],
        help_uri=references_list[0] if references_list else "",
        tool="AquaSec",
        tool_version="",
        ref="",
        commit_sha="",
        instance_url=None,
        classifications=[],
        file=item.get("target_file", ""),
        start_line=item.get("target_start_line") or None,
        end_line=item.get("target_end_line") or None,
    )

    alert_details = AlertDetails(
        alert_hash=item.get("result_hash", ""),
        artifact=item.get("target_file", ""),
        type=item.get("category", ""),
        vulnerability=item.get("avd_id", ""),
        severity=severity_str.upper(),
        repository=item.get("repository_full_name", ""),
        reachable=str(item.get("reachable", False)),
        scan_date=item.get("scan_date", ""),
        first_seen=item.get("first_seen", ""),
        scm_file=item.get("scm_file", ""),
        installed_version=item.get("installed_version", ""),
        start_line=str(item.get("target_start_line", "") or ""),
        end_line=str(item.get("target_end_line", "") or ""),
        message=item.get("message", ""),
    )

    owasp_list = extra.get("owasp")

    rule_details = RuleDetails(
        type=item.get("category", ""),
        severity=severity_str.upper(),
        cwe=extra.get("cwe", ""),
        fixed_version=item.get("fixed_version", ""),
        published_date=item.get("published_date", ""),
        package_name=item.get("package_name", ""),
        category=extra.get("category", ""),
        impact=extra.get("impact", ""),
        confidence=extra.get("confidence", ""),
        likelihood=extra.get("likelihood", ""),
        remediation=extra.get("remediation", ""),
        owasp=_format_bullet_list(owasp_list) if isinstance(owasp_list, list) else str(owasp_list or ""),
        references=(
            _format_bullet_list(references_list) if isinstance(references_list, list) else str(references_list or "")
        ),
    )

    return Alert(metadata=metadata, alert_details=alert_details, rule_details=rule_details, repo=repo)


class AquaSecParser:
    """Parses AquaSec scan results into typed Alert objects."""

    def __init__(self, repo: str) -> None:
        self.repo = repo

    def parse(self, data: dict[str, Any]) -> LoadedAlerts:
        """Parse AquaSec scan response dict and return LoadedAlerts.

        Args:
            data: AquaSec API response dict with 'total' and 'data' keys.

        Returns:
            LoadedAlerts with all parsed alerts indexed by position.
        """
        items = data.get("data", [])
        logger.info("%sLoaded %d findings from AquaSec response", LOGGING_PREFIX, len(items))

        open_by_number: dict[int, Alert] = {}
        for idx, item in enumerate(items, start=1):
            alert = _parse_item(item, self.repo)
            alert.metadata.alert_number = idx
            open_by_number[idx] = alert

        logger.info("%sParsed %d alerts for repo %s", LOGGING_PREFIX, len(open_by_number), self.repo)
        return LoadedAlerts(repo_full=self.repo, open_by_number=open_by_number)
