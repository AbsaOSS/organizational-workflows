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

"""Ensures the labels the security pipeline relies on exist in a GitHub repository."""

import logging

from core.github.client import run_gh
from core.github.issues import gh_label_create
from security.constants import DRY_RUN_PREFIX, LOGGING_PREFIX, REQUIRED_LABEL_SPECS

logger = logging.getLogger(__name__)


class LabelCreator:
    """Ensures required labels exist in a GitHub repository, creating any that are missing."""

    def __init__(self, repo: str) -> None:
        self.repo = repo

    def ensure_labels(self, *, dry_run: bool = False) -> list[str]:
        """Create any missing required labels.

        Args:
            dry_run: When ``True``, log the intended creations without performing them.

        Returns:
            Label names that remain missing after the creation attempt, which the caller
            treats as a fatal misconfiguration. A dry run creates nothing and always
            reports nothing as missing, so it never fails the run.
        """
        existing_labels = set(self._fetch_labels())
        missing_labels = [label for label in REQUIRED_LABEL_SPECS if label.name not in existing_labels]
        if not missing_labels:
            if dry_run:
                logger.info("%sWould check all required labels are present", DRY_RUN_PREFIX)
            else:
                logger.info("%sAll required labels are present", LOGGING_PREFIX)
            return []

        if dry_run:
            for missing_label in missing_labels:
                logger.info("%sWould create label '%s' (missing)", DRY_RUN_PREFIX, missing_label.name)
            return []

        still_missing: list[str] = []
        for missing_label in missing_labels:
            if gh_label_create(
                self.repo, missing_label.name, color=missing_label.color, description=missing_label.description
            ):
                logger.info("%sCreated label '%s' (missing)", LOGGING_PREFIX, missing_label.name)
            else:
                still_missing.append(missing_label.name)

        return still_missing

    def _fetch_labels(self) -> list[str]:
        """Return all label names in the repository via the paginated GitHub API.

        Returns:
            List of label names.

        Raises:
            SystemExit: If the ``gh`` CLI call fails.
        """
        result = run_gh(["api", "--paginate", f"repos/{self.repo}/labels", "--jq", ".[].name"])
        if result.returncode != 0:
            logger.error("%sgh api repos/{repo}/labels failed:\n%s", LOGGING_PREFIX, result.stderr)
            raise SystemExit(1)
        return [label for label in result.stdout.splitlines() if label]
