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

"""Label existence checker for GitHub repositories."""

import json
import logging

from core.github.client import run_gh
from security.constants import LOGGING_PREFIX, REQUIRED_LABELS

logger = logging.getLogger(__name__)


class LabelChecker:
    """Checks that required labels exist in a GitHub repository."""

    def __init__(self, repo: str, required: list[str] | None = None) -> None:
        self.repo = repo
        self.required = required if required is not None else REQUIRED_LABELS

    def check_labels(self) -> list[str]:
        """Return a list of missing labels. Empty list means all labels exist.

        Returns:
            List of label names that are missing from the repository.
        """
        existing = set(self._fetch_labels())
        return [label for label in self.required if label not in existing]

    def _fetch_labels(self) -> list[str]:
        """Return all label names in the repository via ``gh label list``.

        Returns:
            List of label names.

        Raises:
            SystemExit: If the ``gh`` CLI call fails.
        """
        result = run_gh(["label", "list", "--repo", self.repo, "--json", "name", "--limit", "500"])
        if result.returncode != 0:
            logger.error("%sgh label list failed for %s:\n%s", LOGGING_PREFIX, self.repo, result.stderr)
            raise SystemExit(1)
        labels = json.loads(result.stdout)
        return [entry["name"] for entry in labels if entry.get("name")]
