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

"""Issue title / body construction from Alert dataclasses."""

from typing import Any

from core.helpers import iso_date, sanitize_markdown
from core.rendering import render_markdown_template, strip_na_sections

from security.constants import NOT_AVAILABLE, SECMETA_TYPE_PARENT
from security.alerts.models import Alert
from security.issues.secmeta import render_secmeta
from security.issues.templates import CHILD_BODY_TEMPLATE, PARENT_BODY_TEMPLATE


def _synthesize_references(alert: Alert) -> str:
    """Build a Markdown bullet list from metadata URLs when rule_details.references is absent."""
    lines = []
    if alert.metadata.help_uri:
        lines.append(f"- {alert.metadata.help_uri}")
    if alert.metadata.alert_url:
        lines.append(f"- {alert.metadata.alert_url}")
    return "\n".join(lines) if lines else NOT_AVAILABLE


def _synthesize_owasp(alert: Alert) -> str:
    """Build a Markdown bullet list from OWASP-related tags when rule_details.owasp is absent."""
    lines = [f"- {tag}" for tag in alert.metadata.tags if "owasp" in tag.lower()]
    return "\n".join(lines) if lines else NOT_AVAILABLE


def alert_extra_data(alert: Alert) -> dict[str, Any]:
    """Build the extra-data dict for parent issue templates from nested alert data."""
    references = alert.rule_details.references
    if references == NOT_AVAILABLE:
        references = _synthesize_references(alert)
    owasp = alert.rule_details.owasp
    if owasp == NOT_AVAILABLE:
        owasp = _synthesize_owasp(alert)

    return {
        "rule": alert.metadata.rule_id,
        "owasp": owasp,
        "category": alert.metadata.rule_name or NOT_AVAILABLE,
        "advisory_url": alert.metadata.help_uri or NOT_AVAILABLE,
        "impact": sanitize_markdown(alert.rule_details.impact),
        "likelihood": sanitize_markdown(alert.rule_details.likelihood),
        "confidence": sanitize_markdown(alert.rule_details.confidence),
        "remediation": sanitize_markdown(alert.rule_details.remediation),
        "references": references,
    }


def classify_category(alert: Alert) -> str:
    """Return the alert category (e.g. ``sast``, ``vulnerabilities``)."""
    return alert.metadata.rule_name


def build_parent_issue_title(rule_id: str, severity: str = "") -> str:
    """Build the title string for a parent issue."""
    sev_tag = f"[{severity.upper()}] " if severity else ""
    return f"{sev_tag}Security Alert – {rule_id}".strip()


def build_parent_template_values(alert: Alert, *, rule_id: str, severity: str) -> dict[str, Any]:
    """Build the template-value dict for the parent issue body.

    Shared by both *create* and *update* paths so the value-mapping
    logic is defined in one place.
    """
    extra = alert_extra_data(alert)

    return {
        "title": sanitize_markdown(alert.metadata.rule_description or rule_id),
        "category": alert.metadata.rule_name or NOT_AVAILABLE,
        "severity": severity,
        "published_date": iso_date(alert.rule_details.published_date or NOT_AVAILABLE),
        "short_description": sanitize_markdown(alert.metadata.rule_description or NOT_AVAILABLE),
        "package_name": alert.rule_details.package_name,
        "fixed_version": alert.rule_details.fixed_version,
        "extraData": extra,
    }


def build_parent_issue_body(alert: Alert) -> str:
    """Construct the full body (secmeta + rendered template) for a new parent issue."""
    rule_id = alert.metadata.rule_id
    severity = alert.metadata.severity
    repo_full = alert.repo

    secmeta: dict[str, str] = {
        "type": SECMETA_TYPE_PARENT,
        "repo": repo_full,
        "rule_id": rule_id,
        "severity": severity,
    }

    values = build_parent_template_values(alert, rule_id=rule_id, severity=severity)
    human_body = strip_na_sections(render_markdown_template(PARENT_BODY_TEMPLATE, values)).strip() + "\n"
    return render_secmeta(secmeta) + "\n\n" + human_body


def build_issue_title(
    rule_description: str | None,
    rule_name: str | None,
    rule_id: str,
    fingerprint: str,
) -> str:
    """Build the title string for a child issue."""
    prefix = fingerprint[:8] if fingerprint else NOT_AVAILABLE
    summary = (rule_description or rule_name or rule_id or "Security finding").strip()
    return f"[SEC][FP={prefix}] {summary}"


def build_child_issue_body(alert: Alert) -> str:
    """Render the human-readable body for a child issue from alert data."""
    repo_full = alert.repo.strip()
    if not repo_full:
        repo_full = alert.alert_details.repository

    title = sanitize_markdown(alert.metadata.rule_description or alert.metadata.rule_id)

    # Use artifact as the display file name, fall back to scm_file basename
    artifact = alert.alert_details.artifact
    scm_file = alert.alert_details.scm_file

    if artifact and artifact != NOT_AVAILABLE:
        file_display = artifact.rsplit("/", 1)[-1] if "/" in artifact else artifact
    elif scm_file and scm_file != NOT_AVAILABLE:
        file_display = scm_file.rsplit("/", 1)[-1]
    else:
        file_display = NOT_AVAILABLE

    start_line = alert.metadata.start_line
    start_line_str = str(start_line) if start_line is not None else ""

    if scm_file and scm_file != NOT_AVAILABLE and start_line_str:
        file_permalink = f"{scm_file}#L{start_line_str}"
    else:
        file_permalink = scm_file if scm_file != NOT_AVAILABLE else ""

    # Start/End line logic
    end_line = alert.metadata.end_line
    if start_line is not None:
        start_line_val = str(start_line)
        end_line_val = str(end_line) if end_line is not None else start_line_val
    else:
        start_line_val = NOT_AVAILABLE
        end_line_val = NOT_AVAILABLE

    alert_hash = alert.alert_details.alert_hash
    message = sanitize_markdown(alert.alert_details.message)

    category = classify_category(alert)

    values: dict[str, Any] = {
        "category": category or NOT_AVAILABLE,
        "rule_id": alert.metadata.rule_id,
        "alert_hash": alert_hash,
        "title": title,
        "first_seen": iso_date(alert.alert_details.first_seen or alert.metadata.created_at),
        "message": message,
        "repository_full_name": repo_full,
        "file_display": file_display,
        "file_permalink": file_permalink,
        "start_line": start_line_val,
        "end_line": end_line_val,
        "package_name": alert.rule_details.package_name,
        "installed_version": alert.alert_details.installed_version,
        "fixed_version": alert.rule_details.fixed_version,
        "reachable": alert.alert_details.reachable,
    }
    return strip_na_sections(render_markdown_template(CHILD_BODY_TEMPLATE, values)).strip() + "\n"
