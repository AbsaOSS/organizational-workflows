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

"""Issue title / body construction from alert dicts."""


from typing import Any

from shared.common import iso_date
from shared.templates import render_markdown_template

from .alert_parser import (
    AlertMessageKey,
    assess_impact,
    assess_likelihood,
    extract_cve,
    extract_cwe,
    extract_fixed_version,
    normalize_confidence,
)
from .constants import SECMETA_TYPE_PARENT
from .secmeta import render_secmeta
from .templates import CHILD_BODY_TEMPLATE, PARENT_BODY_TEMPLATE

# ---------------------------------------------------------------------------
# Severity → vendor scoring mapping
# ---------------------------------------------------------------------------

SEVERITY_SCORE_MAP: dict[str, str] = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "2.0",
}


# ---------------------------------------------------------------------------
# Alert-value helpers
# ---------------------------------------------------------------------------

def alert_extra_data(alert: dict[str, Any]) -> dict[str, Any]:
    """Return the ``extraData`` sub-dict from *alert*, or ``{}``."""
    extra = alert.get("extraData")
    if isinstance(extra, dict):
        return extra
    return {}


def alert_value(alert: dict[str, Any], *keys: str) -> str:
    """Return the first non-empty string value found under *keys*."""
    for k in keys:
        if not k:
            continue
        v = alert.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def _msg_param(alert: dict[str, Any], key: str) -> str:
    """Return a single parsed message parameter, or ``""``."""
    params = alert.get("_message_params")
    if isinstance(params, dict):
        return str(params.get(key, "")).strip()
    return ""


def _alert_or_msg(alert: dict[str, Any], alert_keys: tuple[str, ...], msg_key: str) -> str:
    """Try top-level alert keys first, then fall back to the parsed message param."""
    v = alert_value(alert, *alert_keys)
    if v:
        return v
    return _msg_param(alert, msg_key)


def classify_category(alert: dict[str, Any]) -> str:
    """Derive a category from ``rule_name``."""
    return str(alert.get("rule_name") or "").strip()


def _fmt_bullet(text: str) -> str:
    """Prefix *text* with ``- `` so it renders as a Markdown bullet point."""
    return f"- {text}" if text else ""


def build_parent_issue_title(rule_id: str, severity: str = "") -> str:
    """Build the title string for a parent issue."""
    sev_tag = f"[{severity.upper()}] " if severity else ""
    return f"{sev_tag}Security Alert – {rule_id}".strip()


def build_parent_template_values(alert: dict[str, Any], *, rule_id: str, severity: str) -> dict[str, Any]:
    """Build the template-value dict for the parent issue body.

    Shared by both *create* and *update* paths so the value-mapping
    logic is defined in one place.
    """
    category = (
        alert_value(alert, "category", "rule_name")
        or _msg_param(alert, AlertMessageKey.TYPE)
    )

    avd_id = (
        alert_value(alert, "avd_id", "rule_id")
        or _msg_param(alert, AlertMessageKey.VULNERABILITY)
        or rule_id
    )

    title = alert_value(alert, "title", "rule_name", "rule_id") or rule_id

    published_date_raw = (
        alert_value(alert, "published_date", "publishedDate")
        or _msg_param(alert, AlertMessageKey.FIRST_SEEN)
        or alert_value(alert, "created_at")
    )

    vendor_scoring = (
        alert_value(alert, "vendor_scoring", "vendorScoring")
        or SEVERITY_SCORE_MAP.get(severity.lower(), "")
    )

    # May be absent for SAST-only findings.
    package_name = (
        alert_value(alert, "package_name", "packageName")
        or _msg_param(alert, AlertMessageKey.ARTIFACT)
    )
    fixed_version = (
        alert_value(alert, "fixed_version", "fixedVersion")
        or extract_fixed_version(alert_value(alert, "message"))
    )

    extra = alert_extra_data(alert)
    if not extra:
        help_uri = alert_value(alert, "help_uri")
        cwe = extract_cwe(alert) or ""
        cve = extract_cve(alert) or ""
        owasp = help_uri if "owasp" in (help_uri or "").lower() else ""
        extra = {
            "cwe": cwe or cve or "N/A",
            "owasp": owasp or "N/A",
            "category": alert_value(alert, "rule_name") or "N/A",
            "impact": assess_impact(alert),
            "likelihood": assess_likelihood(alert),
            "confidence": normalize_confidence(alert),
            "remediation": _fmt_bullet(_msg_param(alert, AlertMessageKey.MESSAGE)),
            "references": help_uri or alert_value(alert, "alert_url", "url"),
        }

    return {
        "category": category,
        "avd_id": avd_id,
        "title": title,
        "severity": severity,
        "published_date": iso_date(published_date_raw),
        "vendor_scoring": vendor_scoring,
        "package_name": package_name or "N/A",
        "fixed_version": fixed_version or "N/A",
        "extraData": extra,
    }


def build_parent_issue_body(alert: dict[str, Any]) -> str:
    """Construct the full body (secmeta + rendered template) for a new parent issue."""
    rule_id = str(alert.get("rule_id") or "").strip()
    tool = str(alert.get("tool") or "").strip()
    severity = str((alert.get("severity") or "unknown")).lower()
    repo_full = str(alert.get("_repo") or "").strip()

    secmeta: dict[str, str] = {
        "schema": "1",
        "type": SECMETA_TYPE_PARENT,
        "repo": repo_full,
        "source": "code_scanning",
        "tool": tool,
        "severity": severity,
        "rule_id": rule_id,
        "first_seen": iso_date(alert.get("created_at")),
        "last_seen": iso_date(alert.get("updated_at")),
        "postponed_until": "",
    }

    values = build_parent_template_values(alert, rule_id=rule_id, severity=severity)
    human_body = render_markdown_template(PARENT_BODY_TEMPLATE, values).strip() + "\n"
    return render_secmeta(secmeta) + "\n\n" + human_body


def build_issue_title(rule_name: str | None, rule_id: str, fingerprint: str) -> str:
    """Build the title string for a child issue."""
    prefix = fingerprint[:8] if fingerprint else "unknown"
    summary = (rule_name or rule_id or "Security finding").strip() or "Security finding"
    return f"[SEC][FP={prefix}] {summary}"


def build_child_issue_body(alert: dict[str, Any]) -> str:
    """Render the human-readable body for a child issue from alert data."""
    repo_full = str(alert.get("_repo") or "").strip()

    avd_id = (
        alert_value(alert, "avd_id", "rule_id")
        or _msg_param(alert, AlertMessageKey.VULNERABILITY)
    )
    title = alert_value(alert, "title", "rule_name", "rule_id")

    # SCM file: prefer the parsed "SCM file:" message param (full URL)
    # over the plain repo-relative path stored in "file".
    scm_file = (
        _msg_param(alert, AlertMessageKey.SCM_FILE)
        or alert_value(alert, "file", "scm_file")
    )

    target_line = alert_value(alert, "target_line", "start_line")
    if not target_line:
        target_line = _msg_param(alert, AlertMessageKey.START_LINE)

    package_name = (
        alert_value(alert, "package_name", "packageName")
        or _msg_param(alert, AlertMessageKey.ARTIFACT)
    )
    installed_version = _alert_or_msg(
        alert,
        ("installed_version", "installedVersion"),
        AlertMessageKey.INSTALLED_VERSION,
    )
    fixed_version = (
        alert_value(alert, "fixed_version", "fixedVersion")
        or extract_fixed_version(alert_value(alert, "message"))
    )
    reachable = _alert_or_msg(alert, ("reachable",), AlertMessageKey.REACHABLE)

    scan_date = (
        alert_value(alert, "scan_date", "scanDate")
        or _msg_param(alert, AlertMessageKey.SCAN_DATE)
        or alert_value(alert, "updated_at")
    )
    first_seen = (
        alert_value(alert, "first_seen")
        or _msg_param(alert, AlertMessageKey.FIRST_SEEN)
        or alert_value(alert, "created_at")
    )

    msg_params = alert.get("_message_params")
    alert_hash = ""
    if isinstance(msg_params, dict):
        alert_hash = str(msg_params.get(AlertMessageKey.ALERT_HASH, "")).strip()

    message = alert_value(alert, "message")

    if not repo_full:
        repo_full = _msg_param(alert, AlertMessageKey.REPOSITORY)

    values: dict[str, Any] = {
        "avd_id": avd_id,
        "alert_hash": alert_hash,
        "title": title,
        "message": message,
        "repository_full_name": repo_full,
        "scm_file": scm_file,
        "target_line": target_line,
        "package_name": package_name or "N/A",
        "installed_version": installed_version or "N/A",
        "fixed_version": fixed_version or "N/A",
        "reachable": reachable or "N/A",
        "scan_date": iso_date(scan_date),
        "first_seen": iso_date(first_seen),
    }
    return render_markdown_template(CHILD_BODY_TEMPLATE, values).strip() + "\n"
