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

"""Security pipeline configuration model."""

import argparse
import logging
import os
import uuid
from dataclasses import dataclass, field

from security.constants import LABEL_SCOPE_SECURITY, LOGGING_PREFIX, MIN_SEVERITY_DEFAULT, VALID_SEVERITIES

logger = logging.getLogger(__name__)


@dataclass
class SecurityConfig:
    """Central configuration for the Security pipeline.

    Loaded from environment variables and CLI arguments, validated upfront.
    """

    aqua_key: str
    aqua_secret: str
    aqua_group_id: str
    aqua_repository_id: str
    repo: str
    dry_run: bool = False
    verbose: bool = False
    issue_label: str = field(default=LABEL_SCOPE_SECURITY)
    severity_priority_map: str = ""
    project_number: int | None = None
    project_org: str = ""
    teams_webhook_url: str = ""
    min_severity: str = MIN_SEVERITY_DEFAULT
    scan_output: str = ""

    @classmethod
    def load(cls, args: argparse.Namespace) -> "SecurityConfig":
        """Load config from CLI args and environment variables."""
        project_number_raw = args.project_number or os.environ.get("PROJECT_NUMBER", "")
        project_number: int | None = None

        if project_number_raw:
            try:
                project_number = int(project_number_raw)
            except (ValueError, TypeError):  # fmt: skip
                project_number = None

        raw_min_severity = args.min_severity or os.environ.get("MIN_SEVERITY", "")
        min_severity = raw_min_severity.lower() if raw_min_severity else MIN_SEVERITY_DEFAULT

        return cls(
            aqua_key=os.environ.get("AQUA_KEY", ""),
            aqua_secret=os.environ.get("AQUA_SECRET", ""),
            aqua_group_id=os.environ.get("AQUA_GROUP_ID", ""),
            aqua_repository_id=os.environ.get("AQUA_REPOSITORY_ID", ""),
            repo=args.repo or os.environ.get("GITHUB_REPOSITORY", ""),
            dry_run=bool(args.dry_run),
            verbose=bool(args.verbose),
            issue_label=args.issue_label,
            severity_priority_map=args.severity_priority_map or os.environ.get("SEVERITY_PRIORITY_MAP", ""),
            project_number=project_number,
            project_org=args.project_org or os.environ.get("PROJECT_ORG", ""),
            teams_webhook_url=args.teams_webhook_url or os.environ.get("TEAMS_WEBHOOK_URL", ""),
            min_severity=min_severity,
            scan_output=args.scan_output,
        )

    def validate(self) -> None:
        """Validate configuration and raise SystemExit on failure."""
        errors: list[str] = []

        if not self.aqua_key:
            errors.append("AQUA_KEY: not provided.")
        if not self.aqua_secret:
            errors.append("AQUA_SECRET: not provided.")
        if not self.aqua_group_id:
            errors.append("AQUA_GROUP_ID: not provided.")
        if not self.aqua_repository_id:
            errors.append("AQUA_REPOSITORY_ID: not provided.")
        else:
            try:
                uuid.UUID(self.aqua_repository_id)
            except ValueError:
                errors.append("AQUA_REPOSITORY_ID: invalid UUID format.")
        if not self.repo or "/" not in self.repo:
            errors.append("repo: not specified or invalid. Use --repo owner/repo.")

        if self.min_severity not in VALID_SEVERITIES:
            errors.append(f"Only allowed values for MIN_SEVERITY input: {', '.join(sorted(VALID_SEVERITIES))}.")

        if errors:
            for err in errors:
                logger.error("%sConfig validation failed: %s", LOGGING_PREFIX, err)
            raise SystemExit("ERROR: Security config validation failed. See errors above.")
