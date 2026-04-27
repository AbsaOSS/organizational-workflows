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

import pytest

from security.issues.builder import (
    alert_extra_data,
    build_child_issue_body,
    build_issue_title,
    build_parent_issue_body,
    build_parent_issue_title,
    build_parent_template_values,
    classify_category,
)
from security.alerts.models import Alert


# =====================================================================
# alert_extra_data
# =====================================================================


def test_extra_data_from_nested() -> None:
    """Extra data is synthesised from nested metadata + rule_details."""
    alert = Alert.from_dict({
        "metadata": {"rule_id": "CVE-123", "rule_name": "sast"},
        "rule_details": {
            "confidence": "error",
            "owasp": "https://owasp.org/Top10/A07",
            "remediation": "some remediation",
            "impact": "N/A",
            "likelihood": "N/A",
            "references": "- https://example.com/alert\n- https://owasp.org/Top10/A07",
        },
    })
    extra = alert_extra_data(alert)
    assert isinstance(extra, dict)
    assert extra["rule"] == "CVE-123"
    assert extra["confidence"] == "error"
    assert extra["category"] == "sast"


def test_extra_data_non_cve() -> None:
    """Non-CVE rule_id still appears as the rule field."""
    alert = Alert.from_dict({"metadata": {"rule_id": "RULE-1", "rule_name": "sast"}, "rule_details": {}})
    assert alert_extra_data(alert)["rule"] == "RULE-1"


# =====================================================================
# classify_category
# =====================================================================


@pytest.mark.parametrize("raw, expected", [
    ({"metadata": {"rule_name": "sast"}}, "sast"),
    ({"metadata": {"rule_name": "vulnerabilities"}}, "vulnerabilities"),
    ({}, ""),
], ids=["sast", "vulnerabilities", "empty"])
def test_classify_category(raw: dict, expected: str) -> None:
    assert expected == classify_category(Alert.from_dict(raw))


# =====================================================================
# build_parent_issue_title
# =====================================================================


@pytest.mark.parametrize("severity, expected", [
    ("high", "[HIGH] Security Alert \u2013 CVE-2026-25755"),
    ("", "Security Alert \u2013 CVE-2026-25755"),
], ids=["with_severity", "without_severity"])
def test_build_parent_issue_title(severity: str, expected: str) -> None:
    assert expected == build_parent_issue_title("CVE-2026-25755", severity)


# =====================================================================
# build_parent_template_values
# =====================================================================


def test_sast_category_from_rule_name(sast_alert: Alert) -> None:
    vals = build_parent_template_values(sast_alert, rule_id="req-with-very-false-aquasec-python", severity="high")
    assert vals["category"] == "sast"


def test_vuln_category_from_rule_name(vuln_alert: Alert) -> None:
    vals = build_parent_template_values(vuln_alert, rule_id="CVE-2026-25755", severity="high")
    assert vals["category"] == "vulnerabilities"


def test_avd_id_removed_from_values(sast_alert: Alert) -> None:
    vals = build_parent_template_values(sast_alert, rule_id="req-with-very-false-aquasec-python", severity="high")
    assert "avd_id" not in vals


@pytest.mark.parametrize("rule_details", [
    {"published_date": None},
    {},
], ids=["published_date_none", "published_date_absent"])
def test_published_date_yields_na(rule_details: dict) -> None:
    alert = Alert.from_dict({"metadata": {"rule_id": "x", "severity": "low"}, "rule_details": rule_details})
    assert "N/A" == build_parent_template_values(alert, rule_id="x", severity="low")["published_date"]


def test_extra_data_synthesised(sast_alert: Alert) -> None:
    extra = build_parent_template_values(sast_alert, rule_id="test", severity="high")["extraData"]
    assert isinstance(extra, dict)
    assert extra["confidence"] == "error"
    assert extra["category"] == "sast"
    assert "owasp" in extra["owasp"].lower()


def test_extra_data_references(vuln_alert: Alert) -> None:
    refs = build_parent_template_values(vuln_alert, rule_id="CVE-2026-25755", severity="high")["extraData"]["references"]
    assert "redhat.com" in refs


def test_all_template_keys_present(sast_alert: Alert) -> None:
    vals = build_parent_template_values(sast_alert, rule_id="test", severity="high")
    required = {"category", "title", "severity", "published_date", "short_description", "package_name", "fixed_version", "extraData"}
    assert required.issubset(vals.keys())


def test_extra_data_sub_keys(sast_alert: Alert) -> None:
    extra = build_parent_template_values(sast_alert, rule_id="test", severity="high")["extraData"]
    required_extra = {"rule", "owasp", "category", "advisory_url", "impact", "likelihood", "confidence", "remediation", "references"}
    assert required_extra.issubset(extra.keys())


# =====================================================================
# References fallback (_synthesize_references)
# =====================================================================


def test_references_fallback_to_both_urls() -> None:
    """When rule_details.references is absent, both help_uri and alert_url are included."""
    alert = Alert.from_dict({
        "metadata": {
            "rule_id": "RULE-1",
            "help_uri": "https://example.com/rule",
            "alert_url": "https://github.com/org/repo/security/code-scanning/1",
        },
        "rule_details": {},
    })
    refs = alert_extra_data(alert)["references"]
    assert "https://example.com/rule" in refs
    assert "https://github.com/org/repo/security/code-scanning/1" in refs


@pytest.mark.parametrize("metadata, expected", [
    ({"rule_id": "RULE-2", "help_uri": "https://docs.example.com/cve"}, "https://docs.example.com/cve"),
    ({"rule_id": "RULE-3"}, "N/A"),
], ids=["help_uri_only", "no_urls_yields_na"])
def test_references_fallback(metadata: dict, expected: str) -> None:
    alert = Alert.from_dict({"metadata": metadata, "rule_details": {}})
    assert expected in alert_extra_data(alert)["references"]


def test_references_not_overridden_when_present() -> None:
    """rule_details.references is used as-is; metadata URLs are ignored."""
    alert = Alert.from_dict({
        "metadata": {"rule_id": "RULE-4", "help_uri": "https://should-not-appear.example.com"},
        "rule_details": {"references": "- https://explicit-ref.example.com"},
    })
    refs = alert_extra_data(alert)["references"]
    assert "https://explicit-ref.example.com" in refs
    assert "should-not-appear" not in refs


# =====================================================================
# build_parent_issue_body
# =====================================================================


@pytest.mark.parametrize("expected", [
    "<!--secmeta",
    "type=parent",
    "req-with-very-false-aquasec-python",
    "**Category:** sast",
    "owasp.org",
], ids=["secmeta_block", "secmeta_type", "rule_id", "category_section", "owasp_reference"])
def test_parent_body_contains(sast_alert: Alert, expected: str) -> None:
    assert expected in build_parent_issue_body(sast_alert)


def test_parent_body_contains_severity(sast_alert: Alert) -> None:
    assert "high" in build_parent_issue_body(sast_alert).lower()


def test_parent_body_confidence(vuln_alert: Alert) -> None:
    assert "error" in build_parent_issue_body(vuln_alert)


# =====================================================================
# build_issue_title (child title)
# =====================================================================


@pytest.mark.parametrize("description, rule_name, rule_id, fingerprint, expected", [
    ("A description", "sast", "rule-123", "a1b2c3d4e5f6", "[SEC][FP=a1b2c3d4] A description"),
    (None, "sast", "rule-123", "abcdef12", "[SEC][FP=abcdef12] sast"),
    (None, None, "rule-123", "abcdef12", "[SEC][FP=abcdef12] rule-123"),
    (None, None, "", "abcdef12", "[SEC][FP=abcdef12] Security finding"),
    ("A description", "sast", "rule-123", "", "[SEC][FP=N/A] A description"),
], ids=["full_format", "fallback_rule_name", "fallback_rule_id", "fallback_default", "empty_fingerprint"])
def test_build_issue_title(
    description: str | None, rule_name: str | None, rule_id: str, fingerprint: str, expected: str
) -> None:
    assert expected == build_issue_title(description, rule_name, rule_id, fingerprint)


# =====================================================================
# build_child_issue_body
# =====================================================================


# SAST alert (303)

@pytest.mark.parametrize("expected", [
    "Requests with verify=False",
    "3e9c8c338f318e0d06647c2f79406fd4",
    "verify=False",
    "test-org/test-repo",
    "https://github.com/test-org/test-repo/blob/",
    "95",
    "False",
    "2025-09-17",
], ids=["title", "alert_hash", "message", "repository", "scm_url", "target_line", "reachable", "first_seen"])
def test_sast_child_body_contains(sast_alert: Alert, expected: str) -> None:
    assert expected in build_child_issue_body(sast_alert)


# Vulnerability alert (312)

@pytest.mark.parametrize("expected", [
    "jsPDF PDF object injection",
    "3.0.3",
    "True",
    "aul-ui/package.json",
    "068f963657211cd416dac1f9b30d606c",
    "2026-02-20",
    "## General Information",
    "## Description",
    "## Location",
    "## Dependency Details",
], ids=["title", "installed_version", "reachable", "scm_file", "alert_hash", "first_seen",
        "section_general", "section_description", "section_location", "section_dependency"])
def test_vuln_child_body_contains(vuln_alert: Alert, expected: str) -> None:
    assert expected in build_child_issue_body(vuln_alert)


# Pipeline alert (317)

@pytest.mark.parametrize("expected", [
    "pipelineMisconfigurations",
    "**Reachable:**",
    "False",
], ids=["category", "reachable_label", "reachable"])
def test_pipeline_child_body_contains(pipeline_alert: Alert, expected: str) -> None:
    assert expected in build_child_issue_body(pipeline_alert)


# Edge cases

def test_minimal_alert() -> None:
    minimal = Alert.from_dict({"metadata": {"rule_id": "UNKNOWN"}, "alert_details": {}, "rule_details": {}})
    assert "UNKNOWN" in build_child_issue_body(minimal)


def test_repo_fallback_to_alert_details() -> None:
    alert = Alert.from_dict({
        "metadata": {"rule_id": "X"},
        "alert_details": {"repository": "org/repo-from-details"},
        "rule_details": {},
    })
    assert "org/repo-from-details" in build_child_issue_body(alert)


def test_first_seen_falls_back_to_metadata_created_at() -> None:
    """When alert_details.first_seen is absent, fall back to metadata.created_at."""
    alert = Alert.from_dict({
        "metadata": {
            "rule_id": "X",
            "updated_at": "2026-01-15T10:00:00Z",
            "created_at": "2025-12-01T08:00:00Z",
        },
        "alert_details": {},
        "rule_details": {},
    })
    assert "2025-12-01" in build_child_issue_body(alert)


def test_first_seen_yields_na_when_no_fallback() -> None:
    """When neither alert_details nor metadata provide dates, render N/A."""
    alert = Alert.from_dict({"metadata": {"rule_id": "X"}, "alert_details": {}, "rule_details": {}})
    assert build_child_issue_body(alert).count("N/A") >= 1


# =====================================================================
# Markdown sanitisation in rendered bodies
# =====================================================================


def test_message_with_heading_is_escaped() -> None:
    """Markdown headings in the message field must not create real headings."""
    alert = Alert.from_dict({
        "metadata": {"rule_id": "CVE-TEST", "rule_description": "Test vuln"},
        "alert_details": {"message": "## Black is the uncompromising formatter."},
        "rule_details": {},
    })
    body = build_child_issue_body(alert)
    assert not any(line.strip().startswith("## Black") for line in body.split("\n")), "Message heading should be escaped"
    assert r"\## Black" in body


def test_parent_remediation_heading_is_escaped() -> None:
    """Markdown headings in remediation must be escaped in the parent body."""
    alert = Alert.from_dict({
        "metadata": {"rule_id": "CVE-PARENT", "severity": "high", "rule_name": "sast"},
        "rule_details": {"remediation": "## Step 1\nDo something **important**."},
    }, repo="org/repo")
    body = build_parent_issue_body(alert)
    assert not any(line.strip() == "## Step 1" for line in body.split("\n")), "Remediation heading should be escaped"
    assert r"\## Step 1" in body
