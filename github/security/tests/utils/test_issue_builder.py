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

"""Unit tests for ``utils.issue_builder``."""

import pytest

from utils.issue_builder import (
    _msg_param,
    alert_extra_data,
    alert_value,
    build_child_issue_body,
    build_issue_title,
    build_parent_issue_body,
    build_parent_issue_title,
    build_parent_template_values,
    classify_category,
)


# =====================================================================
# Low-level helpers
# =====================================================================


def test_returns_first_hit() -> None:
    alert = {"a": "", "b": "hello", "c": "world"}
    assert alert_value(alert, "a", "b", "c") == "hello"

def test_missing_keys() -> None:
    assert alert_value({}, "x", "y") == ""

def test_strips_whitespace() -> None:
    assert alert_value({"k": "  padded  "}, "k") == "padded"

def test_skips_none() -> None:
    assert alert_value({"k": None, "j": "val"}, "k", "j") == "val"


def test_extracts_value(sast_alert: dict) -> None:
    assert _msg_param(sast_alert, "repository") == "test-org/test-repo"

def test_missing_key(sast_alert: dict) -> None:
    result = _msg_param(sast_alert, "nonexistent")
    assert result == "N/A"

def test_no_params_dict() -> None:
    result = _msg_param({}, "anything")
    assert result == "N/A"


def test_returns_dict() -> None:
    assert alert_extra_data({"extraData": {"cwe": "CWE-79"}}) == {"cwe": "CWE-79"}

def test_synthesises_extra_data_when_missing() -> None:
    """When no extraData sub-dict exists, fields are synthesised."""
    alert = {
        "rule_id": "CVE-123",
        "rule_name": "sast",
        "confidence": "error",
        "help_uri": "https://owasp.org/Top10/A07",
        "alert_url": "https://example.com/alert",
        "_message_params": {"message": "some remediation"},
    }
    extra = alert_extra_data(alert)
    assert isinstance(extra, dict)
    assert extra["cve"] == "CVE-123"
    assert extra["confidence"] == "error"
    assert extra["category"] == "sast"


def test_sast(sast_alert: dict) -> None:
    assert classify_category(sast_alert) == "sast"

def test_vuln(vuln_alert: dict) -> None:
    assert classify_category(vuln_alert) == "vulnerabilities"

def test_empty() -> None:
    assert classify_category({}) == ""


# =====================================================================
# Parent issue builders
# =====================================================================


def test_with_severity() -> None:
    assert build_parent_issue_title("CVE-2026-25755", "high") == (
        "[HIGH] Security Alert \u2013 CVE-2026-25755"
    )

def test_without_severity() -> None:
    assert build_parent_issue_title("CVE-2026-25755") == (
        "Security Alert \u2013 CVE-2026-25755"
    )


def test_sast_category_from_rule_name(sast_alert: dict) -> None:
    vals = build_parent_template_values(
        sast_alert, rule_id="req-with-very-false-aquasec-python", severity="high"
    )
    assert vals["category"] == "sast"

def test_vuln_category_from_rule_name(vuln_alert: dict) -> None:
    vals = build_parent_template_values(
        vuln_alert, rule_id="CVE-2026-25755", severity="high"
    )
    assert vals["category"] == "vulnerabilities"

def test_avd_id_uses_rule_id(sast_alert: dict) -> None:
    vals = build_parent_template_values(
        sast_alert, rule_id="req-with-very-false-aquasec-python", severity="high"
    )
    assert vals["avd_id"] == "req-with-very-false-aquasec-python"

def test_published_date_from_first_seen_msg(sast_alert: dict) -> None:
    """Published date should fall back to message 'First seen' \u2192 date portion."""
    vals = build_parent_template_values(
        sast_alert, rule_id="test", severity="high"
    )
    assert vals["published_date"] == "2025-09-17"

def test_extra_data_synthesised(sast_alert: dict) -> None:
    """When no extraData sub-dict exists, fields are synthesised from the alert."""
    vals = build_parent_template_values(
        sast_alert, rule_id="test", severity="high"
    )
    extra = vals["extraData"]
    assert isinstance(extra, dict)
    assert extra["confidence"] == "error"
    assert extra["category"] == "sast"
    # OWASP reference derived from help_uri
    assert "owasp" in extra["owasp"].lower()

def test_extra_data_references_from_help_uri(vuln_alert: dict) -> None:
    vals = build_parent_template_values(
        vuln_alert, rule_id="CVE-2026-25755", severity="high"
    )
    refs = vals["extraData"]["references"]
    assert "redhat.com" in refs

def test_existing_extra_data_preserved() -> None:
    """When extraData sub-dict is present on the alert, it is used as-is."""
    alert = {
        "rule_id": "X",
        "rule_name": "sast",
        "severity": "low",
        "extraData": {"cve": "CVE-999", "custom": "value"},
        "_message_params": {},
    }
    vals = build_parent_template_values(alert, rule_id="X", severity="low")
    assert vals["extraData"]["cve"] == "CVE-999"
    assert vals["extraData"]["custom"] == "value"

def test_all_template_keys_present(sast_alert: dict) -> None:
    """Every placeholder in PARENT_BODY_TEMPLATE has a corresponding value."""
    vals = build_parent_template_values(
        sast_alert, rule_id="test", severity="high"
    )
    required = {
        "category", "avd_id", "title", "severity",
        "published_date", "package_name",
        "fixed_version", "extraData",
    }
    assert required.issubset(vals.keys())

def test_extra_data_sub_keys(sast_alert: dict) -> None:
    """All extraData keys referenced in the template are present."""
    vals = build_parent_template_values(
        sast_alert, rule_id="test", severity="high"
    )
    extra = vals["extraData"]
    required_extra = {
        "cve", "owasp", "category", "impact",
        "likelihood", "confidence", "remediation", "references",
    }
    assert required_extra.issubset(extra.keys())


# =====================================================================
# Parent issue body (full render)
# =====================================================================


def test_contains_secmeta_block(sast_alert: dict) -> None:
    body = build_parent_issue_body(sast_alert)
    assert "<!--secmeta" in body
    assert "type=parent" in body

def test_contains_severity(sast_alert: dict) -> None:
    body = build_parent_issue_body(sast_alert)
    assert "high" in body.lower()

def test_contains_rule_id(sast_alert: dict) -> None:
    body = build_parent_issue_body(sast_alert)
    assert "req-with-very-false-aquasec-python" in body

def test_contains_category_section(sast_alert: dict) -> None:
    body = build_parent_issue_body(sast_alert)
    assert "**Category:** sast" in body

def test_contains_owasp_reference(sast_alert: dict) -> None:
    body = build_parent_issue_body(sast_alert)
    assert "owasp.org" in body

def test_contains_confidence(vuln_alert: dict) -> None:
    body = build_parent_issue_body(vuln_alert)
    assert "error" in body


# =====================================================================
# Child issue title
# =====================================================================


def test_format() -> None:
    fp = "a1b2c3d4e5f6"
    title = build_issue_title("sast", "rule-123", fp)
    assert title == "[SEC][FP=a1b2c3d4] sast"

def test_fallback_to_rule_id() -> None:
    title = build_issue_title(None, "rule-123", "abcdef12")
    assert "rule-123" in title

def test_fallback_to_default() -> None:
    title = build_issue_title(None, "", "abcdef12")
    assert "Security finding" in title

def test_empty_fingerprint() -> None:
    title = build_issue_title("sast", "rule-123", "")
    assert "N/A" in title


# =====================================================================
# Child issue body
# =====================================================================


# SAST alert (303)

def test_sast_avd_id(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "req-with-very-false-aquasec-python" in body

def test_sast_alert_hash(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "3e9c8c338f318e0d06647c2f79406fd4" in body

def test_sast_title(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "sast" in body

def test_sast_message_present(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "verify=False" in body

def test_sast_repository(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "test-org/test-repo" in body

def test_sast_scm_file_full_url(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "https://github.com/test-org/test-repo/blob/" in body

def test_sast_target_line(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "95" in body

def test_sast_reachable_from_msg(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "False" in body

def test_sast_scan_date(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "2026-02-24" in body

def test_sast_first_seen(sast_alert: dict) -> None:
    body = build_child_issue_body(sast_alert)
    assert "2025-09-17" in body

# Vulnerability alert (312)

def test_vuln_avd_id(vuln_alert: dict) -> None:
    body = build_child_issue_body(vuln_alert)
    assert "CVE-2026-25755" in body

def test_vuln_installed_version(vuln_alert: dict) -> None:
    body = build_child_issue_body(vuln_alert)
    assert "3.0.3" in body

def test_vuln_reachable(vuln_alert: dict) -> None:
    body = build_child_issue_body(vuln_alert)
    assert "True" in body

def test_vuln_scm_file(vuln_alert: dict) -> None:
    body = build_child_issue_body(vuln_alert)
    assert "aul-ui/package.json" in body

def test_vuln_alert_hash(vuln_alert: dict) -> None:
    body = build_child_issue_body(vuln_alert)
    assert "068f963657211cd416dac1f9b30d606c" in body

def test_vuln_first_seen(vuln_alert: dict) -> None:
    body = build_child_issue_body(vuln_alert)
    assert "2026-02-20" in body

# Pipeline alert (317)

def test_pipeline_category(pipeline_alert: dict) -> None:
    body = build_child_issue_body(pipeline_alert)
    assert "pipelineMisconfigurations" in body

def test_pipeline_no_installed_version(pipeline_alert: dict) -> None:
    body = build_child_issue_body(pipeline_alert)
    assert "**Installed version:**" in body

def test_pipeline_reachable(pipeline_alert: dict) -> None:
    body = build_child_issue_body(pipeline_alert)
    assert "False" in body

# Edge cases

def test_minimal_alert() -> None:
    minimal: dict = {
        "rule_id": "UNKNOWN",
        "_repo": "",
        "_message_params": {},
    }
    body = build_child_issue_body(minimal)
    assert "UNKNOWN" in body

def test_repo_fallback_to_msg_param() -> None:
    alert: dict = {
        "rule_id": "X",
        "_repo": "",
        "_message_params": {"repository": "org/repo-from-msg"},
        "message": "Repository: org/repo-from-msg",
    }
    body = build_child_issue_body(alert)
    assert "org/repo-from-msg" in body

def test_all_template_sections_rendered(vuln_alert: dict) -> None:
    body = build_child_issue_body(vuln_alert)
    assert "## General Information" in body
    assert "## Vulnerability Description" in body
    assert "## Location" in body
    assert "## Dependency Details" in body
    assert "## Detection Timeline" in body
