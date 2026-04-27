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

"""Unit tests for ``utils.templates``."""

from core.rendering import render_markdown_template
from security.issues.templates import CHILD_BODY_TEMPLATE, PARENT_BODY_TEMPLATE


# =====================================================================
# Template structure
# =====================================================================


def test_contains_required_sections() -> None:
    assert "## General Information" in PARENT_BODY_TEMPLATE
    assert "## Affected Package" in PARENT_BODY_TEMPLATE
    assert "## Classification" in PARENT_BODY_TEMPLATE
    assert "## Risk Assessment" in PARENT_BODY_TEMPLATE
    assert "## Remediation" in PARENT_BODY_TEMPLATE
    assert "## References" in PARENT_BODY_TEMPLATE
    assert "## OWASP" in PARENT_BODY_TEMPLATE

def test_contains_all_placeholders() -> None:
    """All documented placeholders are present."""
    expected_placeholders = [
        "{{ category }}", "{{ title }}", "{{ severity }}",
        "{{ published_date }}", "{{ short_description }}", "{{ package_name }}",
        "{{ fixed_version }}", "{{ extraData.rule }}", "{{ extraData.owasp }}",
        "{{ extraData.category }}", "{{ extraData.advisory_url }}",
        "{{ extraData.impact }}",
        "{{ extraData.likelihood }}", "{{ extraData.confidence }}",
        "{{ extraData.remediation }}", "{{ extraData.references }}",
    ]
    for ph in expected_placeholders:
        assert ph in PARENT_BODY_TEMPLATE, f"Missing placeholder: {ph}"

def test_renders_without_error() -> None:
    """Template renders successfully with minimal values."""
    values = {
        "category": "sast",
        "title": "Test",
        "severity": "high",
        "published_date": "2026-01-01",
        "short_description": "Test short desc",
        "package_name": "pkg",
        "fixed_version": "2.0",
        "extraData": {
            "rule": "CVE-123",
            "owasp": "A07",
            "category": "sast",
            "advisory_url": "https://example.com/advisory",
            "impact": "high",
            "likelihood": "medium",
            "confidence": "high",
            "remediation": "upgrade",
            "references": "https://example.com",
        },
    }
    result = render_markdown_template(PARENT_BODY_TEMPLATE, values)
    assert "CVE-123" in result
    assert "A07" in result

def test_renders_impact_and_likelihood() -> None:
    """impact and likelihood values appear in the rendered parent template."""
    values = {
        "category": "sast", "title": "T",
        "severity": "high", "published_date": "2026-01-01",
        "short_description": "desc",
        "package_name": "pkg", "fixed_version": "2.0",
        "extraData": {
            "rule": "N/A", "owasp": "N/A", "category": "sast",
            "advisory_url": "N/A",
            "impact": "medium", "likelihood": "medium",
            "confidence": "error", "remediation": "upgrade",
            "references": "https://example.com",
        },
    }
    result = render_markdown_template(PARENT_BODY_TEMPLATE, values)
    assert "medium" in result
    # Both fields should render (impact and likelihood are both "medium")
    assert result.count("medium") >= 2


def test_child_contains_required_sections() -> None:
    assert "## General Information" in CHILD_BODY_TEMPLATE
    assert "## Description" in CHILD_BODY_TEMPLATE
    assert "## Location" in CHILD_BODY_TEMPLATE
    assert "## Dependency Details" in CHILD_BODY_TEMPLATE

def test_child_contains_all_placeholders() -> None:
    expected_placeholders = [
        "{{ rule_id }}", "{{ alert_hash }}", "{{ title }}", "{{ message }}",
        "{{ repository_full_name }}", "{{ file_display }}", "{{ file_permalink }}",
        "{{ package_name }}", "{{ installed_version }}", "{{ fixed_version }}",
        "{{ reachable }}", "{{ first_seen }}", "{{ start_line }}", "{{ end_line }}",
    ]
    for ph in expected_placeholders:
        assert ph in CHILD_BODY_TEMPLATE, f"Missing placeholder: {ph}"

def test_child_renders_without_error() -> None:
    values = {
        "rule_id": "CVE-123",
        "alert_hash": "abc",
        "title": "Test",
        "message": "msg",
        "first_seen": "2026-01-01",
        "repository_full_name": "org/repo",
        "file_display": "file.py",
        "file_permalink": "https://example.com/file.py#L10",
        "start_line": "10",
        "end_line": "10",
        "package_name": "pkg",
        "installed_version": "1.0",
        "fixed_version": "2.0",
        "reachable": "True",
    }
    result = render_markdown_template(CHILD_BODY_TEMPLATE, values)
    assert "CVE-123" in result
    assert "org/repo" in result
