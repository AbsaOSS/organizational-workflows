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

"""Fetch an AquaSec repository UUID from its GitHub identity."""

import json
import logging
import time
import uuid
from typing import Any

import requests

from security.constants import AQUA_REPOSITORIES_URL, FETCH_SLEEP_SECONDS, HTTP_TIMEOUT, LOGGING_PREFIX

logger = logging.getLogger(__name__)


class RepositoryFetcher:
    """Discover the AquaSec repository matching an exact GitHub full name."""

    def __init__(self, bearer_token: str) -> None:
        self.bearer_token = bearer_token

    def fetch_repository_id(self, repo: str) -> str:
        """Fetch one distinct AquaSec repository UUID for a GitHub owner/repo.

        Args:
            repo: GitHub repository full name (org/repo).

        Returns:
            Matching AquaSec repository UUID.

        Raises:
            SystemExit: If discovery fails or the repository is absent or ambiguous.
        """
        logger.info("%sRepository discovery starting for %s", LOGGING_PREFIX, repo)

        repository_ids: set[uuid.UUID] = set()
        page_num = 1
        received = 0
        total_expected: int | None = None

        while True:
            page_data, total_count = self._fetch_page(repo, page_num)
            if total_expected is None:
                total_expected = total_count
            received += len(page_data)
            if (
                total_count != total_expected
                or received > total_expected
                or (not page_data and received < total_expected)
            ):
                raise SystemExit(f"ERROR: AquaSec repository discovery returned inconsistent pagination for {repo}.")

            for candidate in page_data:
                if candidate.get("full_name") != repo:
                    continue
                repository_id = candidate.get("repository_id")
                try:
                    if not isinstance(repository_id, str):
                        raise ValueError("Expected a UUID string.")
                    repository_ids.add(uuid.UUID(repository_id))
                except ValueError as e:
                    raise SystemExit(f"ERROR: AquaSec repository discovery returned an invalid UUID for {repo}.") from e

            if received == total_expected:
                break
            page_num += 1
            time.sleep(FETCH_SLEEP_SECONDS)

        if not repository_ids:
            raise SystemExit(f"ERROR: AquaSec repository not found for GitHub repository {repo}.")
        if len(repository_ids) != 1:
            raise SystemExit(f"ERROR: Multiple AquaSec repository UUIDs found for GitHub repository {repo}.")

        logger.info("%sRepository discovery successful for %s", LOGGING_PREFIX, repo)
        return str(next(iter(repository_ids)))

    def _fetch_page(self, repo: str, page_num: int) -> tuple[list[dict[str, Any]], int]:
        """Fetch and validate one filtered repository page."""
        logger.info("%sFetching repository ID for %s", LOGGING_PREFIX, repo)
        params: dict[str, str | int] = {
            "name": repo.rsplit("/", 1)[-1],
            "page": page_num,
            "page_size": 25,
        }
        try:
            response = requests.get(
                AQUA_REPOSITORIES_URL,
                headers={"Authorization": f"Bearer {self.bearer_token}", "Accept": "application/json"},
                params=params,
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as e:
            raise SystemExit(f"ERROR: AquaSec repository discovery request failed for {repo}: {e}") from e

        if response.status_code != 200:
            raise SystemExit(f"ERROR: AquaSec repository discovery failed for {repo}. Status {response.status_code}.")
        try:
            payload = response.json()
        except json.JSONDecodeError as e:
            raise SystemExit(f"ERROR: Invalid JSON response from AquaSec repository discovery for {repo}.") from e

        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise SystemExit(f"ERROR: Invalid AquaSec repository discovery response for {repo}.")
        page_data = payload["data"]
        counts = [payload.get(key) for key in ("current_page", "returned_count", "total_count")]
        if (
            any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts)
            or payload["current_page"] != page_num
            or payload["returned_count"] != len(page_data)
            or any(not isinstance(candidate, dict) for candidate in page_data)
        ):
            raise SystemExit(f"ERROR: Invalid AquaSec repository discovery pagination or data for {repo}.")
        return page_data, payload["total_count"]
