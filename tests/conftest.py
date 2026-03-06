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
The ``_message_params`` key is pre-populated by
``parse_alert_message_params`` exactly as the production loader does.
"""

import copy
import sys
import os

import pytest

# ------------------------------------------------------------------
# Ensure the ``security/`` directory is on sys.path so that both
# ``utils.*`` and ``shared.*`` can be imported in tests exactly the
# same way as they are in production code.
# ------------------------------------------------------------------
_SECURITY_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_GITHUB_DIR = os.path.normpath(os.path.join(_SECURITY_DIR, ".."))
for _p in (_SECURITY_DIR, _GITHUB_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from utils.alert_parser import parse_alert_message_params


# ── Raw alert payloads (read-only module-level originals) ──────────────

_SAST_ALERT_303: dict = {
    "alert_number": 303,
    "state": "open",
    "created_at": "2026-02-25T08:25:18Z",
    "updated_at": "2026-02-25T14:11:06Z",
    "url": "https://api.github.com/repos/test-org/test-repo/code-scanning/alerts/303",
    "alert_url": "https://github.com/test-org/test-repo/security/code-scanning/303",
    "rule_id": "req-with-very-false-aquasec-python",
    "rule_name": "sast",
    "severity": "high",
    "confidence": "error",
    "impact": "medium",
    "likelihood": "medium",
    "tags": ["HIGH", "sast", "security"],
    "help_uri": "https://owasp.org/Top10/A07_2021-Injection/",
    "tool": "AquaSec",
    "tool_version": "1.0.0",
    "ref": "refs/heads/master",
    "commit_sha": "d28cb4b49c437fdc4e26471ced2b128c63839d0e",
    "message": (
        "Artifact: scripts/create_catalog_tables_and_refresh_partitions/list_domains.py\n"
        "Type: sast\n"
        "Vulnerability: req-with-very-false-aquasec-python\n"
        "Severity: HIGH\n"
        "Message: Detected the use of the requests module with verify=False, "
        "which disables server certificate validation. This can allow an adversary "
        "to intercept sensitive information or transmit malicious data. It is highly "
        "recommended to either remove the verify=False argument or set verify=True "
        "in each requests call to ensure secure connections and prevent potential "
        "security breaches.\n"
        "Repository: test-org/test-repo\n"
        "Reachable: False\n"
        "Scan date: 2026-02-24T19:24:35.755Z\n"
        "First seen: 2025-09-17T12:46:48.271Z\n"
        "SCM file: https://github.com/test-org/test-repo/blob/"
        "64c62d98a7db5dbd80ae8b0affd531099cf54280/"
        "scripts/create_catalog_tables_and_refresh_partitions/list_domains.py\n"
        "Start line: 95\n"
        "End line: 95\n"
        "Alert hash: 3e9c8c338f318e0d06647c2f79406fd4"
    ),
    "instance_url": None,
    "classifications": [],
    "file": "scripts/create_catalog_tables_and_refresh_partitions/list_domains.py",
    "start_line": 95,
    "end_line": 95,
}

_VULN_ALERT_312: dict = {
    "alert_number": 312,
    "state": "open",
    "created_at": "2026-02-25T08:25:18Z",
    "updated_at": "2026-02-25T14:11:06Z",
    "url": "https://api.github.com/repos/test-org/test-repo/code-scanning/alerts/312",
    "alert_url": "https://github.com/test-org/test-repo/security/code-scanning/312",
    "rule_id": "CVE-2026-25755",
    "rule_name": "vulnerabilities",
    "severity": "high",
    "confidence": "error",
    "impact": "high",
    "likelihood": "high",
    "tags": ["HIGH", "security", "vulnerabilities"],
    "help_uri": "https://access.redhat.com/security/cve/CVE-2026-25755",
    "tool": "AquaSec",
    "tool_version": "1.0.0",
    "ref": "refs/heads/master",
    "commit_sha": "d28cb4b49c437fdc4e26471ced2b128c63839d0e",
    "message": (
        "Artifact: aul-ui/package.json\n"
        "Type: vulnerabilities\n"
        "Vulnerability: CVE-2026-25755\n"
        "Severity: HIGH\n"
        "Message: jsPDF is a library to generate PDFs in JavaScript. "
        "Prior to 4.2.0, user control of the argument of the `addJS` method "
        "allows an attacker to inject arbitrary PDF objects into the generated "
        "document. By crafting a payload that escapes the JavaScript string "
        "delimiter, an attacker can execute malicious actions or alter the "
        "document structure, impacting any user who opens the generated PDF. "
        "The vulnerability has been fixed in jspdf@4.2.0. As a workaround, "
        "escape parentheses in user-provided JavaScript code before passing "
        "them to the `addJS` method.\n"
        "(This package is used under: jspdf@3.0.3)\n"
        "Repository: test-org/test-repo\n"
        "Reachable: True\n"
        "Scan date: 2026-02-24T19:24:35.755Z\n"
        "First seen: 2026-02-20T18:30:18.304Z\n"
        "SCM file: https://github.com/test-org/test-repo/blob/"
        "64c62d98a7db5dbd80ae8b0affd531099cf54280/aul-ui/package.json\n"
        "Installed version: 3.0.3\n"
        "Start line: 54\n"
        "End line: 54\n"
        "Alert hash: 068f963657211cd416dac1f9b30d606c"
    ),
    "instance_url": None,
    "classifications": [],
    "file": "aul-ui/package.json",
    "start_line": 54,
    "end_line": 54,
}

_PIPELINE_ALERT_317: dict = {
    "alert_number": 317,
    "state": "open",
    "created_at": "2026-02-25T08:25:18Z",
    "updated_at": "2026-02-25T14:11:06Z",
    "url": "https://api.github.com/repos/test-org/test-repo/code-scanning/alerts/317",
    "alert_url": "https://github.com/test-org/test-repo/security/code-scanning/317",
    "rule_id": "AVD-PIPELINE-0008",
    "rule_name": "pipelineMisconfigurations",
    "severity": "medium",
    "confidence": "warning",
    "impact": "low",
    "likelihood": "medium",
    "tags": ["MEDIUM", "pipelineMisconfigurations", "security"],
    "help_uri": None,
    "tool": "AquaSec",
    "tool_version": "1.0.0",
    "ref": "refs/heads/master",
    "commit_sha": "d28cb4b49c437fdc4e26471ced2b128c63839d0e",
    "message": (
        "Artifact: .github/workflows/aquasec-night-scan.yml\n"
        "Type: pipelineMisconfigurations\n"
        "Vulnerability: AVD-PIPELINE-0008\n"
        "Severity: MEDIUM\n"
        "Message: Dependency AbsaOSS/aquasec-scan-results master version "
        "should be pinned to the commit sha\n"
        "Repository: test-org/test-repo\n"
        "Reachable: False\n"
        "Scan date: 2026-02-24T19:24:35.755Z\n"
        "First seen: 2026-02-09T15:51:33.454Z\n"
        "SCM file: https://github.com/test-org/test-repo/blob/"
        "64c62d98a7db5dbd80ae8b0affd531099cf54280/"
        ".github/workflows/aquasec-night-scan.yml\n"
        "Start line: 21\n"
        "Alert hash: bed23a624d7f1f07f56a07c6349bcd8b"
    ),
    "instance_url": None,
    "classifications": [],
    "file": ".github/workflows/aquasec-night-scan.yml",
    "start_line": 21,
    "end_line": 21,
}


def _enrich(raw: dict) -> dict:
    """Simulate the enrichment that ``load_open_alerts_from_file`` performs."""
    alert = copy.deepcopy(raw)
    alert["_repo"] = "test-org/test-repo"
    alert["_message_params"] = parse_alert_message_params(alert.get("message"))
    return alert


# ── Public fixtures ────────────────────────────────────────────────────

@pytest.fixture()
def sast_alert() -> dict:
    """SAST finding (alert 303) — ``verify=False`` in Python requests."""
    return _enrich(_SAST_ALERT_303)


@pytest.fixture()
def vuln_alert() -> dict:
    """Vulnerability finding (alert 312) — jsPDF CVE with installed version."""
    return _enrich(_VULN_ALERT_312)


@pytest.fixture()
def pipeline_alert() -> dict:
    """Pipeline misconfiguration finding (alert 317) — unpinned action."""
    return _enrich(_PIPELINE_ALERT_317)
