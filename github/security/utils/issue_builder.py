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

from __future__ import annotations

from typing import Any

from .alert_parser import AlertMessageKey
from .common import iso_date
from .constants import SECMETA_TYPE_PARENT
from .secmeta import render_secmeta
from .templates import (
    CHILD_BODY_TEMPLATE,
    PARENT_BODY_TEMPLATE,
    render_markdown_template,
)


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


def classify_category(alert: dict[str, Any]) -> str:
    """Derive a category from ``rule_name``."""
    return str(alert.get("rule_name") or "").strip()


def build_parent_issue_title(rule_id: str) -> str:
    return f"Security Alert – {rule_id}".strip()


def build_parent_template_values(alert: dict[str, Any], *, rule_id: str, severity: str) -> dict[str, Any]:
    """Build the template-value dict for the parent issue body.

    Shared by both *create* and *update* paths so the value-mapping
    logic is defined in one place.
    """
    return {
        "category": alert_value(alert, "category"),
        "avd_id": alert_value(alert, "avd_id", "rule_id") or rule_id,
        "title": alert_value(alert, "title", "rule_name", "rule_id") or rule_id,
        "severity": severity,
        "published_date": iso_date(alert_value(alert, "published_date", "publishedDate", "created_at")),
        "vendor_scoring": alert_value(alert, "vendor_scoring", "vendorScoring"),
        "package_name": alert_value(alert, "package_name", "packageName"),
        "fixed_version": alert_value(alert, "fixed_version", "fixedVersion"),
        "extraData": alert_extra_data(alert),
    }


def build_parent_issue_body(alert: dict[str, Any]) -> str:
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
    prefix = fingerprint[:8] if fingerprint else "unknown"
    summary = (rule_name or rule_id or "Security finding").strip() or "Security finding"
    return f"[SEC][FP={prefix}] {summary}"


def build_child_issue_body(alert: dict[str, Any]) -> str:
    repo_full = str(alert.get("_repo") or "").strip()
    avd_id = alert_value(alert, "avd_id", "rule_id")
    title = alert_value(alert, "title", "rule_name", "rule_id")
    scm_file = alert_value(alert, "file", "scm_file")
    target_line = alert_value(alert, "target_line")
    if not target_line:
        target_line = alert_value(alert, "start_line")

    package_name = alert_value(alert, "package_name", "packageName")
    installed_version = alert_value(alert, "installed_version", "installedVersion")
    fixed_version = alert_value(alert, "fixed_version", "fixedVersion")
    reachable = alert_value(alert, "reachable")

    scan_date = alert_value(alert, "scan_date", "scanDate", "updated_at")
    first_seen = alert_value(alert, "first_seen", "created_at")

    msg_params = alert.get("_message_params")
    alert_hash = ""
    if isinstance(msg_params, dict):
        alert_hash = str(msg_params.get(AlertMessageKey.ALERT_HASH.value) or "").strip()
    message = alert_value(alert, "message")

    values: dict[str, Any] = {
        "avd_id": avd_id,
        "alert_hash": alert_hash,
        "title": title,
        "message": message,
        "repository_full_name": repo_full,
        "scm_file": scm_file,
        "target_line": target_line,
        "package_name": package_name,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "reachable": reachable,
        "scan_date": iso_date(scan_date),
        "first_seen": iso_date(first_seen),
    }
    return render_markdown_template(CHILD_BODY_TEMPLATE, values).strip() + "\n"
