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

"""Alert data parsing – extracting structured fields from raw alert dicts
(message parameters, CWE, occurrence fingerprint) and loading the alerts
JSON file produced by ``collect_alert.sh``.
"""


import json
import os
import re
import sys
from enum import Enum
from typing import Any
from enum import StrEnum

from .common import sha256_hex

# ---------------------------------------------------------------------------
# AlertMessageKey enum
# ---------------------------------------------------------------------------

class AlertMessageKey(StrEnum):
    ARTIFACT = "artifact"
    TYPE = "type"
    VULNERABILITY = "vulnerability"
    SEVERITY = "severity"
    MESSAGE = "message"
    ALERT_HASH = "alert hash"


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------

def parse_alert_message_params(message: str | None) -> dict[str, str]:
    """Parse key/value parameters from a multi-line alert message.

    Lines are expected in the form:
      <Key>: <Value>

    Keys are normalized to lowercase (and internal whitespace collapsed).
    Unknown keys are still included (in lowercase) for debugging.
    """

    params: dict[str, str] = {}
    for raw_line in (message or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key_raw, value_raw = line.split(":", 1)
        key = key_raw.strip()
        if not key:
            continue
        value = value_raw.strip()
        key_norm = " ".join(key.lower().split())
        params[key_norm] = value

    return params


def extract_cwe(alert: dict[str, Any]) -> str | None:
    """Best-effort CWE extraction.

    Not all code scanning alerts include CWE mapping.
    - If ``alert["cwe"]`` is present, use it.
    - Otherwise try to parse a CWE token from tags like ``"CWE-79"``.
    """

    raw = alert.get("cwe")
    if raw:
        s = str(raw).strip()
        return s or None

    tags = alert.get("tags")
    if isinstance(tags, list):
        for t in tags:
            m = re.search(r"\bCWE-(\d+)\b", str(t), flags=re.IGNORECASE)
            if m:
                return f"CWE-{m.group(1)}"
    return None


def compute_occurrence_fp(commit_sha: str, path: str, start_line: int | None, end_line: int | None) -> str:
    # Works without git; used to record distinct sightings over time.
    return sha256_hex(f"{commit_sha}|{path}|{start_line or ''}|{end_line or ''}")


def load_open_alerts_from_file(path: str) -> tuple[str, dict[int, dict[str, Any]]]:
    """Read alerts JSON and return (repo_full, open_alerts_by_number)."""

    if not os.path.exists(path):
        raise SystemExit(f"ERROR: alerts file not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    repo_meta = data.get("repo") or {}

    repo_full = repo_meta.get("full_name")
    if not repo_full:
        raise SystemExit(f"ERROR: repo.full_name not found in {path}")

    alerts = data.get("alerts", [])
    print(f"Loaded {len(alerts)} alerts from {path} (repo={repo_full})")

    open_alerts = [a for a in alerts if str((a.get("state") or "")).lower() == "open"]
    print(f"Found {len(open_alerts)} open alerts")

    open_by_number: dict[int, dict[str, Any]] = {}
    for alert in open_alerts:
        alert_number = alert.get("alert_number")
        if alert_number is None:
            print(f"WARN: skipping alert with missing alert_number: {alert}")
            continue

        try:
            alert_number_int = int(alert_number)
        except Exception:
            print(f"WARN: skipping alert with invalid alert_number: {alert_number}")
            continue

        # stash repo on the alert for convenience
        alert["_repo"] = repo_full

        # Parse structured parameters embedded in the message string.
        alert["_message_params"] = parse_alert_message_params(alert.get("message"))
        open_by_number[alert_number_int] = alert

        if os.getenv("DEBUG_ALERTS") == "1":
            print(
                f"DEBUG: full alert payload for alert_number={alert_number_int}:\n"
                + json.dumps(alert, indent=2, sort_keys=True)
            )

    return str(repo_full), open_by_number
