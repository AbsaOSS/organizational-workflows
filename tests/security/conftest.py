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

"""Shared test fixtures — real alert payloads taken from synthetic alert payloads.

Each fixture returns a *mutable copy* so tests can modify it freely.
Alerts use the nested schema (``metadata`` / ``alert_details`` / ``rule_details``)
produced by ``collect_alert.py``.
"""

import pytest

from security.alerts.models import Alert


# ── Raw alert payloads (read-only module-level originals) ──────────────

_SAST_ALERT_303: dict = {
    "metadata": {
        "alert_number": 303,
        "state": "open",
        "created_at": "2026-02-25T08:25:18Z",
        "updated_at": "2026-02-25T14:11:06Z",
        "url": "https://api.github.com/repos/test-org/test-repo/code-scanning/alerts/303",
        "alert_url": "https://github.com/test-org/test-repo/security/code-scanning/303",
        "rule_id": "req-with-very-false-aquasec-python",
        "rule_name": "sast",
        "rule_description": "Requests with verify=False",
        "severity": "high",
        "confidence": "error",
        "tags": ["HIGH", "sast", "security"],
        "help_uri": "https://owasp.org/Top10/A07_2021-Injection/",
        "tool": "AquaSec",
        "tool_version": "1.0.0",
        "ref": "refs/heads/master",
        "commit_sha": "d28cb4b49c437fdc4e26471ced2b128c63839d0e",
        "instance_url": None,
        "classifications": [],
        "file": "scripts/create_catalog_tables_and_refresh_partitions/list_domains.py",
        "start_line": 95,
        "end_line": 95,
    },
    "alert_details": {
        "alert_hash": "3e9c8c338f318e0d06647c2f79406fd4",
        "artifact": "scripts/create_catalog_tables_and_refresh_partitions/list_domains.py",
        "type": "sast",
        "vulnerability": "req-with-very-false-aquasec-python",
        "severity": "HIGH",
        "repository": "test-org/test-repo",
        "reachable": "False",
        "scan_date": "2026-02-24T19:24:35.755Z",
        "first_seen": "2025-09-17T12:46:48.271Z",
        "scm_file": (
            "https://github.com/test-org/test-repo/blob/"
            "64c62d98a7db5dbd80ae8b0affd531099cf54280/"
            "scripts/create_catalog_tables_and_refresh_partitions/list_domains.py"
        ),
        "start_line": "95",
        "end_line": "95",
        "message": (
            "Detected the use of the requests module with verify=False, "
            "which disables server certificate validation. This can allow an adversary "
            "to intercept sensitive information or transmit malicious data. It is highly "
            "recommended to either remove the verify=False argument or set verify=True "
            "in each requests call to ensure secure connections and prevent potential "
            "security breaches."
        ),
    },
    "rule_details": {
        "type": "sast",
        "severity": "HIGH",
        "cwe": None,
        "fixed_version": None,
        "published_date": None,
        "package_name": None,
        "category": None,
        "impact": "medium",
        "confidence": "error",
        "likelihood": "medium",
        "remediation": None,
        "owasp": "https://owasp.org/Top10/A07_2021-Injection/",
        "references": (
            "- https://github.com/test-org/test-repo/security/code-scanning/303\n"
            "- https://owasp.org/Top10/A07_2021-Injection/"
        ),
    },
}

_VULN_ALERT_312: dict = {
    "metadata": {
        "alert_number": 312,
        "state": "open",
        "created_at": "2026-02-25T08:25:18Z",
        "updated_at": "2026-02-25T14:11:06Z",
        "url": "https://api.github.com/repos/test-org/test-repo/code-scanning/alerts/312",
        "alert_url": "https://github.com/test-org/test-repo/security/code-scanning/312",
        "rule_id": "CVE-2026-25755",
        "rule_name": "vulnerabilities",
        "rule_description": "jsPDF PDF object injection",
        "severity": "high",
        "confidence": "error",
        "tags": ["HIGH", "security", "vulnerabilities"],
        "help_uri": "https://access.redhat.com/security/cve/CVE-2026-25755",
        "tool": "AquaSec",
        "tool_version": "1.0.0",
        "ref": "refs/heads/master",
        "commit_sha": "d28cb4b49c437fdc4e26471ced2b128c63839d0e",
        "instance_url": None,
        "classifications": [],
        "file": "aul-ui/package.json",
        "start_line": 54,
        "end_line": 54,
    },
    "alert_details": {
        "alert_hash": "068f963657211cd416dac1f9b30d606c",
        "artifact": "aul-ui/package.json",
        "type": "vulnerabilities",
        "vulnerability": "CVE-2026-25755",
        "severity": "HIGH",
        "repository": "test-org/test-repo",
        "reachable": "True",
        "scan_date": "2026-02-24T19:24:35.755Z",
        "first_seen": "2026-02-20T18:30:18.304Z",
        "scm_file": (
            "https://github.com/test-org/test-repo/blob/"
            "64c62d98a7db5dbd80ae8b0affd531099cf54280/aul-ui/package.json"
        ),
        "installed_version": "3.0.3",
        "start_line": "54",
        "end_line": "54",
        "message": (
            "jsPDF is a library to generate PDFs in JavaScript. "
            "Prior to 4.2.0, user control of the argument of the `addJS` method "
            "allows an attacker to inject arbitrary PDF objects into the generated "
            "document. By crafting a payload that escapes the JavaScript string "
            "delimiter, an attacker can execute malicious actions or alter the "
            "document structure, impacting any user who opens the generated PDF. "
            "The vulnerability has been fixed in jspdf@4.2.0. As a workaround, "
            "escape parentheses in user-provided JavaScript code before passing "
            "them to the `addJS` method.\n"
            "(This package is used under: jspdf@3.0.3)"
        ),
    },
    "rule_details": {
        "type": "vulnerabilities",
        "severity": "HIGH",
        "cwe": None,
        "fixed_version": "4.2.0",
        "published_date": "2026-02-20T18:30:18.304Z",
        "package_name": "jspdf",
        "category": None,
        "impact": "high",
        "confidence": "error",
        "likelihood": "high",
        "remediation": None,
        "owasp": None,
        "references": "- https://access.redhat.com/security/cve/CVE-2026-25755",
    },
}

_PIPELINE_ALERT_317: dict = {
    "metadata": {
        "alert_number": 317,
        "state": "open",
        "created_at": "2026-02-25T08:25:18Z",
        "updated_at": "2026-02-25T14:11:06Z",
        "url": "https://api.github.com/repos/test-org/test-repo/code-scanning/alerts/317",
        "alert_url": "https://github.com/test-org/test-repo/security/code-scanning/317",
        "rule_id": "AVD-PIPELINE-0008",
        "rule_name": "pipelineMisconfigurations",
        "rule_description": "Dependency not pinned to commit SHA",
        "severity": "medium",
        "confidence": "warning",
        "tags": ["MEDIUM", "pipelineMisconfigurations", "security"],
        "help_uri": None,
        "tool": "AquaSec",
        "tool_version": "1.0.0",
        "ref": "refs/heads/master",
        "commit_sha": "d28cb4b49c437fdc4e26471ced2b128c63839d0e",
        "instance_url": None,
        "classifications": [],
        "file": ".github/workflows/aquasec-night-scan-example.yml",
        "start_line": 21,
        "end_line": None,
    },
    "alert_details": {
        "alert_hash": "bed23a624d7f1f07f56a07c6349bcd8b",
        "artifact": ".github/workflows/aquasec-night-scan-example.yml",
        "type": "pipelineMisconfigurations",
        "vulnerability": "AVD-PIPELINE-0008",
        "severity": "MEDIUM",
        "repository": "test-org/test-repo",
        "reachable": "False",
        "scan_date": "2026-02-24T19:24:35.755Z",
        "first_seen": "2026-02-09T15:51:33.454Z",
        "scm_file": (
            "https://github.com/test-org/test-repo/blob/"
            "64c62d98a7db5dbd80ae8b0affd531099cf54280/"
            ".github/workflows/aquasec-night-scan-example.yml"
        ),
        "start_line": "21",
        "message": (
            "Dependency AbsaOSS/aquasec-scan-results master version "
            "should be pinned to the commit sha"
        ),
    },
    "rule_details": {
        "type": "pipelineMisconfigurations",
        "severity": "MEDIUM",
        "cwe": None,
        "fixed_version": None,
        "published_date": None,
        "package_name": None,
        "category": None,
        "impact": "low",
        "confidence": "warning",
        "likelihood": "medium",
        "remediation": None,
        "owasp": None,
        "references": None,
    },
}


def _enrich(raw: dict) -> Alert:
    """Simulate the enrichment that ``load_open_alerts_from_file`` performs."""
    return Alert.from_dict(raw, repo="test-org/test-repo")


# ── Public fixtures ────────────────────────────────────────────────────

@pytest.fixture()
def sast_alert() -> Alert:
    """SAST finding (alert 303) — ``verify=False`` in Python requests."""
    return _enrich(_SAST_ALERT_303)


@pytest.fixture()
def vuln_alert() -> Alert:
    """Vulnerability finding (alert 312) — jsPDF CVE with installed version."""
    return _enrich(_VULN_ALERT_312)


@pytest.fixture()
def pipeline_alert() -> Alert:
    """Pipeline misconfiguration finding (alert 317) — unpinned action."""
    return _enrich(_PIPELINE_ALERT_317)
