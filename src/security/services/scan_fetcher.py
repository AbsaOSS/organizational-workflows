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

"""AquaSec scan results fetcher with pagination support."""

import json
import logging
import time
from typing import Any

import requests

from security.constants import AQUA_SCAN_URL, FETCH_PAGE_SIZE, FETCH_SLEEP_SECONDS, HTTP_TIMEOUT, LOGGING_PREFIX

logger = logging.getLogger(__name__)


class ScanFetcher:
    """Fetches security scan findings from AquaSec API with pagination."""

    def __init__(self, bearer_token: str, repository_id: str) -> None:
        self.bearer_token = bearer_token
        self.repository_id = repository_id

    def fetch_findings(self) -> dict[str, Any]:
        """Fetch all security findings from AquaSec API with pagination.

        Returns:
            Dictionary with 'total' count and 'data' list of findings.

        Raises:
            SystemExit: If fetching fails.
        """
        logger.info("%sScan findings fetch starting.", LOGGING_PREFIX)

        findings: list[dict[str, Any]] = []
        page_num = 1
        total_expected = 0
        headers = {"Authorization": f"Bearer {self.bearer_token}", "Accept": "application/json"}

        while True:
            logger.info("%sFetching page %d...", LOGGING_PREFIX, page_num)

            fetch_endpoint = (
                f"{AQUA_SCAN_URL}?repositoryIds={self.repository_id}&size={FETCH_PAGE_SIZE}&page={page_num}"
            )

            try:
                response = requests.get(fetch_endpoint, headers=headers, timeout=HTTP_TIMEOUT)
            except requests.RequestException as e:
                raise SystemExit(f"ERROR: AquaSec scan fetch request failed: {e}") from e

            if response.status_code != 200:
                raise SystemExit(f"ERROR: AquaSec scan fetch failed. Status {response.status_code}: {response.text}")

            try:
                page_response = response.json()
            except json.JSONDecodeError as e:
                raise SystemExit(f"ERROR: Invalid JSON response from AquaSec API: {e}") from e

            if page_num == 1:
                total_expected = page_response.get("total", 0)
                logger.debug("Expected %d total findings.", total_expected)

            page_data = page_response.get("data", [])
            findings.extend(page_data)

            if len(findings) >= total_expected or len(page_data) == 0:
                break

            page_num += 1
            time.sleep(FETCH_SLEEP_SECONDS)

        findings_total = len(findings)
        logger.info("%sScan findings fetch successful (%d total).", LOGGING_PREFIX, findings_total)

        return {"total": findings_total, "data": findings}
