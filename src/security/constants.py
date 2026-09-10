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

"""Shared constants used across the security workflow utilities."""

LABEL_SCOPE_SECURITY = "scope:security"
LABEL_TYPE_AQUASEC = "type:aquasec"
LABEL_EPIC = "epic"

# MIGRATION-PHASE-2-REMOVE: deprecated tech-debt label, replaced by type:aquasec.
LABEL_TYPE_TECH_DEBT = "type:tech-debt"
LABEL_TYPE_AQUASEC_COLOR = "79bf8f"
LABEL_TYPE_AQUASEC_DESCRIPTION = "AquaSec generated security finding"

REQUIRED_LABELS: list[str] = [
    LABEL_SCOPE_SECURITY,
    LABEL_TYPE_AQUASEC,
    LABEL_EPIC,
]

SECMETA_KEYS_PARENT = {"type", "repo", "rule_id", "severity"}
SECMETA_KEYS_CHILD = {"type", "fingerprint", "repo", "rule_id", "severity"}
SECMETA_TYPE_PARENT = "parent"
SECMETA_TYPE_CHILD = "child"

SECURITY_FINDING_DEFAULT = "Security finding"
NOT_AVAILABLE = "N/A"

GITHUB_BASE_URL = "https://github.com"
DEFAULT_SCM_REF = "HEAD"

LOGGING_PREFIX = "Security - "
DRY_RUN_PREFIX = "Security [DRY-RUN] - "

# AquaSec API
AQUA_AUTH_URL = "https://eu-1.api.cloudsploit.com"
AQUA_SCAN_URL = "https://eu-1.codesec.aquasec.com/api/v1/scans/results"
HTTP_TIMEOUT = 30
FETCH_PAGE_SIZE = 100
FETCH_SLEEP_SECONDS = 2

# Teams Adaptive Card rendering
AQUA_PLATFORM_URL = "https://eu-1.cloud.aquasec.com/ah/#/supplychain/codeRepositories/repositories"
TEAMS_CARD_MAX_BYTES = 24_000
TEAMS_ISSUE_LIST_CAP = 10
TEAMS_ISSUE_LIST_MIN_PER_STATE = 3
TEAMS_SUCCESS_BODIES: frozenset[str] = frozenset({"", "1"})

SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "unknown": "⚪",
}

# Severity mapping (AquaSec numeric → lowercase string)
SEVERITY_MAP: dict[int, str] = {1: "low", 2: "medium", 3: "high", 4: "critical"}

MIN_SEVERITY_DEFAULT = "low"
VALID_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})
