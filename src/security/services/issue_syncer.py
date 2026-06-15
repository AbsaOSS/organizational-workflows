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

"""Issue synchronization service to sync parsed alerts to GitHub Issues."""

import logging

from core.github.issues import gh_issue_list_by_label
from core.priority import parse_severity_priority_map

from security.alerts.models import Alert
from security.constants import LOGGING_PREFIX, MIN_SEVERITY_DEFAULT
from security.issues.sync import SyncResult, sync_alerts_and_issues
from security.config import SecurityConfig

logger = logging.getLogger(__name__)


class IssueSyncer:
    """Synchronizes parsed alerts to GitHub Issues."""

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config

    def sync(self, open_alerts: dict[int, Alert], *, dry_run: bool) -> SyncResult:
        """Sync alerts to GitHub Issues and return the result.

        Args:
            open_alerts: Parsed alerts indexed by position.
            dry_run: If True, no changes are made.

        Returns:
            SyncResult with notifications and severity changes.
        """
        config = self.config
        repo = config.repo

        issues = gh_issue_list_by_label(repo, config.issue_label)
        logger.info("%sLoaded %d existing security issues for synchronization", LOGGING_PREFIX, len(issues))

        spm = parse_severity_priority_map(config.severity_priority_map)

        if config.min_severity != MIN_SEVERITY_DEFAULT:
            logger.info(
                "%sStarting promotion of alerts to GitHub issues (severity >= %s)",
                LOGGING_PREFIX,
                config.min_severity,
            )
        else:
            logger.info("%sStarting promotion of alerts to GitHub issues", LOGGING_PREFIX)

        result = sync_alerts_and_issues(
            open_alerts,
            issues,
            dry_run=dry_run,
            severity_priority_map=spm,
            project_number=config.project_number,
            project_org=config.project_org,
            min_severity=config.min_severity,
        )

        logger.info("%sCompleted promotion of alerts to GitHub issues", LOGGING_PREFIX)

        return result
