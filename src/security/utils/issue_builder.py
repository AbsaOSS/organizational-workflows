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

from .constants import NOT_AVAILABLE, SECMETA_TYPE_PARENT
from .secmeta import render_secmeta
from .templates import CHILD_BODY_TEMPLATE, PARENT_BODY_TEMPLATE


def alert_extra_data(alert: dict[str, Any]) -> dict[str, Any]:
    """Build the extra-data dict for parent issue templates from nested alert data."""
    metadata = alert.get("metadata") or {}
    rule_details = alert.get("rule_details") or {}

    rule_id = str(metadata.get("rule_id") or "")

    return {
        "cve": rule_id if rule_id.upper().startswith("CVE-") else NOT_AVAILABLE,
        "owasp": str(rule_details.get("owasp") or NOT_AVAILABLE),
        "category": str(metadata.get("rule_name") or NOT_AVAILABLE),
        "impact": str(rule_details.get("impact") or NOT_AVAILABLE),
        "likelihood": str(rule_details.get("likelihood") or NOT_AVAILABLE),
        "confidence": str(rule_details.get("confidence") or NOT_AVAILABLE),
        "remediation": str(rule_details.get("remediation") or NOT_AVAILABLE),
        "references": str(rule_details.get("references") or NOT_AVAILABLE),
    }


def classify_category(alert: dict[str, Any]) -> str:
    """Return the alert category (e.g. ``sast``, ``vulnerabilities``)."""
    metadata = alert.get("metadata") or {}
    return str(metadata.get("rule_name") or "").strip()


def build_parent_issue_title(rule_id: str, severity: str = "") -> str:
    """Build the title string for a parent issue."""
    sev_tag = f"[{severity.upper()}] " if severity else ""
    return f"{sev_tag}Security Alert – {rule_id}".strip()


def build_parent_template_values(alert: dict[str, Any], *, rule_id: str, severity: str) -> dict[str, Any]:
    """Build the template-value dict for the parent issue body.

    Shared by both *create* and *update* paths so the value-mapping
    logic is defined in one place.
    """
    metadata = alert.get("metadata") or {}
    alert_details = alert.get("alert_details") or {}
    rule_details = alert.get("rule_details") or {}

    extra = alert_extra_data(alert)

    return {
        "category": str(metadata.get("rule_name") or NOT_AVAILABLE),
        "avd_id": str(alert_details.get("vulnerability") or rule_id),
        "title": rule_id,
        "severity": severity,
        "published_date": iso_date(rule_details.get("published_date")),
        "package_name": str(rule_details.get("package_name") or NOT_AVAILABLE),
        "fixed_version": str(rule_details.get("fixed_version") or NOT_AVAILABLE),
        "extraData": extra,
    }


def build_parent_issue_body(alert: dict[str, Any]) -> str:
    """Construct the full body (secmeta + rendered template) for a new parent issue."""
    metadata = alert.get("metadata") or {}

    rule_id = str(metadata.get("rule_id") or "").strip()
    tool = str(metadata.get("tool") or "").strip()
    severity = str(metadata.get("severity") or NOT_AVAILABLE)
    repo_full = str(alert.get("_repo") or "").strip()

    secmeta: dict[str, str] = {
        "schema": "1",
        "type": SECMETA_TYPE_PARENT,
        "repo": repo_full,
        "source": "code_scanning",
        "tool": tool,
        "severity": severity,
        "rule_id": rule_id,
        "first_seen": iso_date(metadata.get("created_at")),
        "last_seen": iso_date(metadata.get("updated_at")),
        "postponed_until": "",
    }

    values = build_parent_template_values(alert, rule_id=rule_id, severity=severity)
    human_body = render_markdown_template(PARENT_BODY_TEMPLATE, values).strip() + "\n"
    return render_secmeta(secmeta) + "\n\n" + human_body


def build_issue_title(rule_name: str | None, rule_id: str, fingerprint: str) -> str:
    """Build the title string for a child issue."""
    prefix = fingerprint[:8] if fingerprint else NOT_AVAILABLE
    summary = (rule_name or rule_id or "Security finding").strip() or "Security finding"
    return f"[SEC][FP={prefix}] {summary}"


def build_child_issue_body(alert: dict[str, Any]) -> str:
    """Render the human-readable body for a child issue from alert data."""
    metadata = alert.get("metadata") or {}
    alert_details = alert.get("alert_details") or {}
    rule_details = alert.get("rule_details") or {}

    repo_full = str(alert.get("_repo") or "").strip()
    if not repo_full:
        repo_full = str(alert_details.get("repository") or NOT_AVAILABLE)

    vulnerability = str(alert_details.get("vulnerability") or "")
    avd_id = vulnerability if vulnerability.startswith("AVD-") else NOT_AVAILABLE

    title = str(metadata.get("rule_id") or "")

    scm_file = str(alert_details.get("scm_file") or NOT_AVAILABLE)
    start_line = metadata.get("start_line")
    start_line_str = str(start_line) if start_line is not None else ""

    # Build a display name (filename only) and permalink with #L anchor
    file_name = scm_file.rsplit("/", 1)[-1] if scm_file and scm_file != NOT_AVAILABLE else None
    if scm_file and scm_file != NOT_AVAILABLE and start_line_str:
        file_permalink = f"{scm_file}#L{start_line_str}"
        file_display = f"{file_name}#L{start_line_str}"
    else:
        file_permalink = scm_file if scm_file != NOT_AVAILABLE else ""
        file_display = file_name or NOT_AVAILABLE

    alert_hash = str(alert_details.get("alert_hash") or "")
    message = str(alert_details.get("message") or NOT_AVAILABLE)

    category = classify_category(alert)

    values: dict[str, Any] = {
        "category": category or NOT_AVAILABLE,
        "avd_id": avd_id,
        "alert_hash": alert_hash,
        "title": title,
        "message": message,
        "repository_full_name": repo_full,
        "file_display": file_display,
        "file_permalink": file_permalink,
        "package_name": str(rule_details.get("package_name") or NOT_AVAILABLE),
        "installed_version": str(alert_details.get("installed_version") or NOT_AVAILABLE),
        "fixed_version": str(rule_details.get("fixed_version") or NOT_AVAILABLE),
        "reachable": str(alert_details.get("reachable") or NOT_AVAILABLE),
        "scan_date": iso_date(alert_details.get("scan_date")),
        "first_seen": iso_date(alert_details.get("first_seen")),
    }
    return render_markdown_template(CHILD_BODY_TEMPLATE, values).strip() + "\n"
