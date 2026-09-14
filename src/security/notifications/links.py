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

"""Links displayed on the Teams notification card."""

from dataclasses import dataclass
from urllib.parse import quote

from security.constants import AQUA_PLATFORM_URL, GITHUB_BASE_URL


@dataclass
class NotificationLinks:
    """The repository name and the links rendered on the notification card.

    Attributes:
        repo: Full ``owner/name`` of the scanned repository, shown in the card header.
        repo_url: Link to the repository's open security issues.
        run_url: Link to the workflow run, empty when not running in GitHub Actions.
        aqua_url: Link to the AquaSec GUI.
    """

    repo: str
    repo_url: str
    run_url: str
    aqua_url: str = AQUA_PLATFORM_URL

    @classmethod
    def build(cls, *, repo: str, security_label: str, server_url: str, run_id: str) -> "NotificationLinks":
        """Build the card links from already-resolved configuration values.

        Args:
            repo: Full ``owner/name`` of the scanned repository.
            security_label: Label used to filter the repository's security issues.
            server_url: GitHub server URL. Falls back to ``github.com`` when empty.
            run_id: Workflow run identifier. When empty the run link is omitted.

        Returns:
            The links to render on the card.
        """
        server = server_url or GITHUB_BASE_URL
        run_url = f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ""

        query = quote(f"is:issue is:open label:{security_label}")
        repo_url = f"{server}/{repo}/issues?q={query}" if repo else ""

        return cls(repo=repo, repo_url=repo_url, run_url=run_url)
