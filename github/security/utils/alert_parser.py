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
from enum import StrEnum
from typing import Any

from shared.common import sha256_hex

# ---------------------------------------------------------------------------
# AlertMessageKey enum
# ---------------------------------------------------------------------------

class AlertMessageKey(StrEnum):
    """Known keys parsed from the multi-line alert message.

    Each value corresponds to the normalised (lowercased, whitespace-collapsed)
    key emitted by the AquaSec scan-results action.
    """
    ARTIFACT = "artifact"
    TYPE = "type"
    VULNERABILITY = "vulnerability"
    SEVERITY = "severity"
    MESSAGE = "message"
    REPOSITORY = "repository"
    REACHABLE = "reachable"
    SCAN_DATE = "scan date"
    FIRST_SEEN = "first seen"
    SCM_FILE = "scm file"
    INSTALLED_VERSION = "installed version"
    START_LINE = "start line"
    END_LINE = "end line"
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

    # Try to extract CWE from help_uri (e.g. cwe.mitre.org/data/definitions/78.html)
    help_uri = str(alert.get("help_uri") or "")
    m = re.search(r"cwe\.mitre\.org/data/definitions/(\d+)", help_uri, flags=re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"

    return None


def extract_cve(alert: dict[str, Any]) -> str | None:
    """Best-effort CVE extraction.

    Returns a CVE identifier when ``rule_id`` or ``help_uri`` contains one.
    """
    for field in ("rule_id", "help_uri"):
        val = str(alert.get(field) or "")
        m = re.search(r"\b(CVE-\d{4}-\d+)\b", val, flags=re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


# ---------------------------------------------------------------------------
# Fixed-version extraction from advisory free text
# ---------------------------------------------------------------------------

# Semver-like token: digits.digits with optional pre-release suffix
_VERSION_RE = r"\d+(?:\.\d+)+(?:[-.]\w+)*"

# Common verb group shared across patterns.
_FIX_VERBS = r"(?:fixed|patched|resolved|addressed)"

# Ordered list of patterns – first match wins.
_FIX_VERSION_PATTERNS: list[re.Pattern[str]] = [
    # "fixed in version 10.2.1"  /  "patched in version 4.1.124.Final"
    # "resolved in version 3.0.0" / "addressed in version 2.1.0"
    re.compile(
        rf"{_FIX_VERBS}\s+in\s+versions?\s+({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "patched on 4.17.23"
    re.compile(
        rf"{_FIX_VERBS}\s+on\s+({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "fixed in jsPDF@4.2.0"  /  "fixed in jspdf@4.1.0"
    re.compile(
        rf"{_FIX_VERBS}\s+in\s+\S+@({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "fixed in jsPDF 4.2.0"  (package-space-version, no @)
    re.compile(
        rf"{_FIX_VERBS}\s+in\s+[A-Za-z][\w-]*\s+({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "fixed in 1.10.1"  (bare version right after "in")
    re.compile(
        rf"{_FIX_VERBS}\s+in\s+({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "upgrade/upgrading to version 2.0" / "update/updating to version 2.0"
    re.compile(
        rf"(?:upgrad|updat)(?:e|ing)\s+to\s+version\s+({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "upgrade to 2.0" / "update to 2.0"  (no "version" keyword)
    re.compile(
        rf"(?:upgrad|updat)(?:e|ing)\s+to\s+({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "first patched version: 4.3.0" / "first_patched_version: 4.3.0"
    # (GitHub Dependabot / advisory format)
    re.compile(
        rf"first[_\s]patched[_\s]version[:\s]+({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "fix available in 3.2.1" / "fix is available in version 3.2.1"
    re.compile(
        rf"fix\s+(?:is\s+)?available\s+in\s+(?:version\s+)?({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "remediation: upgrade to 2.1.0" (Snyk-style)
    re.compile(
        rf"remediation[:\s]+(?:upgrad|updat)(?:e|ing)\s+to\s+(?:version\s+)?({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # ">= 1.5.0" / ">=1.5.0"  (version-constraint notation)
    re.compile(
        rf">=\s*({_VERSION_RE})",
        re.IGNORECASE,
    ),
    # "versions 3.0.0 and later are not affected"
    re.compile(
        rf"versions?\s+({_VERSION_RE})\s+and\s+(?:later|above|newer)\s+(?:are\s+)?not\s+affected",
        re.IGNORECASE,
    ),
    # "starting from version 2.4.0" / "starting from 2.4.0"
    re.compile(
        rf"starting\s+from\s+(?:version\s+)?({_VERSION_RE})",
        re.IGNORECASE,
    ),
]


def extract_fixed_version(message: str) -> str | None:
    """Best-effort extraction of a fix version from advisory free text.

    Scans the raw ``message`` field for phrases like
    *"fixed in version 10.2.1"*, *"patched in jsPDF@4.2.0"*, etc.
    Returns the **first** version token found, or ``None``.

    Only the first match is returned because the parent issue aggregates
    alerts by ``rule_id`` – all children share the same CVE / advisory
    and therefore the same fix version.
    """
    for pat in _FIX_VERSION_PATTERNS:
        m = pat.search(message or "")
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Risk assessment derivation
# ---------------------------------------------------------------------------

# Mapping: (reachable, severity) → likelihood label.
_LIKELIHOOD_MAP: dict[tuple[bool | None, str], str] = {
    # Reachable = True
    (True, "critical"): "High",
    (True, "high"):     "High",
    (True, "medium"):   "Medium",
    (True, "low"):      "Medium",
    # Reachable = False
    (False, "critical"): "Medium",
    (False, "high"):     "Low",
    (False, "medium"):   "Low",
    (False, "low"):      "Low",
    # Reachable unknown – fall back to severity alone
    (None, "critical"): "High",
    (None, "high"):     "Medium",
    (None, "medium"):   "Low",
    (None, "low"):      "Low",
}

# Mapping: (severity, rule_name) → impact label.
# ``rule_name`` distinguishes exploitable vulnerabilities from config issues.
_IMPACT_MATRIX: dict[tuple[str, str], str] = {
    ("critical", "vulnerabilities"): "Critical",
    ("critical", "sast"):            "Critical",
    ("high",     "vulnerabilities"): "High",
    ("high",     "sast"):            "High",
    ("high",     "iacMisconfigurations"): "Medium",
    ("high",     "pipelineMisconfigurations"): "Medium",
    ("medium",   "vulnerabilities"): "Medium",
    ("medium",   "sast"):            "Medium",
    ("medium",   "iacMisconfigurations"): "Low",
    ("medium",   "pipelineMisconfigurations"): "Low",
    ("low",      "vulnerabilities"): "Low",
    ("low",      "sast"):            "Low",
    ("low",      "iacMisconfigurations"): "Low",
    ("low",      "pipelineMisconfigurations"): "Low",
}

# Confidence normalization mapping (GitHub code scanning values → labels).
_CONFIDENCE_LABEL: dict[str, str] = {
    "error":   "High",
    "warning": "Medium",
    "note":    "Low",
}


def _parse_reachable(alert: dict[str, Any]) -> bool | None:
    """Return ``True``/``False`` if the *Reachable* flag is present, else ``None``."""
    # 1. Top-level field (normalised by collector)
    r = alert.get("reachable")
    if r is not None:
        return str(r).strip().lower() in ("true", "1", "yes")
    # 2. Embedded message param
    params = alert.get("_message_params")
    if isinstance(params, dict):
        val = params.get(AlertMessageKey.REACHABLE, "").strip().lower()
        if val:
            return val in ("true", "1", "yes")
    return None


def assess_impact(alert: dict[str, Any]) -> str:
    """Derive an impact rating from ``severity`` and ``rule_name``."""
    severity = str(alert.get("severity") or "unknown").lower()
    rule_name = str(alert.get("rule_name") or "").strip()
    label = _IMPACT_MATRIX.get((severity, rule_name))
    if label:
        return label
    # Fallback: severity alone determines impact
    return {
        "critical": "Critical",
        "high":     "High",
        "medium":   "Medium",
        "low":      "Low",
    }.get(severity, "Unknown")


def assess_likelihood(alert: dict[str, Any]) -> str:
    """Derive a likelihood rating from ``Reachable`` and ``severity``."""
    reachable = _parse_reachable(alert)
    severity = str(alert.get("severity") or "unknown").lower()
    label = _LIKELIHOOD_MAP.get((reachable, severity))
    if label:
        return label
    # Fallback when severity is completely unknown
    if reachable is True:
        return "Medium"
    return "Low"


def normalize_confidence(alert: dict[str, Any]) -> str:
    """Normalize the raw ``confidence`` value to a human-readable label."""
    raw = str(alert.get("confidence") or "").strip().lower()
    return _CONFIDENCE_LABEL.get(raw, raw.title() or "Unknown")


def compute_occurrence_fp(commit_sha: str, path: str, start_line: int | None, end_line: int | None) -> str:
    """Compute a fingerprint for a specific occurrence (commit + location)."""
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
