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

"""Unit tests for ``security.alerts.aquasec_parser``."""

import pytest

from security.alerts.aquasec_parser import (
    AquaSecParser,
    _format_bullet_list,
    _map_severity,
    _parse_item,
)


_VULN_ITEM = {
    "category": "vulnerabilities",
    "repository_name": "AUL",
    "repository_id": "9da7a2cb-6c6e-438d-8bef-afb5aced96e5",
    "scan_date": "2026-04-17T22:52:09.391Z",
    "target_file": "shared-http-client/pom.xml",
    "scm_file": "https://github.com/absa-group/AUL/blob/abc123/shared-http-client/pom.xml",
    "scm_link": "",
    "target_start_line": 0,
    "target_end_line": 0,
    "repository_integration_name": "absa-group",
    "is_dev_dependency": False,
    "repository_full_name": "absa-group/AUL",
    "avd_id": "CVE-2026-33870",
    "title": "netty-codec-http: Request smuggling via chunked transfer",
    "severity": 2,
    "resource": "",
    "fixed_version": "4.1.132.Final",
    "reachable": False,
    "message": "Netty incorrectly parses quoted strings in HTTP/1.1 chunked transfer.",
    "published_date": "2026-03-27T20:16:34.000Z",
    "installed_version": "4.1.100.Final",
    "vendor_scoring": {},
    "package_name": "io.netty:netty-codec-http",
    "branch": "master",
    "is_archived": False,
    "source": "github",
    "extraData": {
        "Fix": {},
        "cwe": "CWE-444: HTTP Request Smuggling",
        "CISA": {},
        "EPSS": {"date": "2026-04-16", "score": 0.0004},
        "owasp": ["A03:2017 - Sensitive Data Exposure"],
        "impact": "HIGH",
        "category": "security/audit",
        "confidence": "MEDIUM",
        "likelihood": "LOW",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-33870",
            "https://github.com/netty/netty/security/advisories/GHSA-pwqr-wmgm-9rr8",
        ],
        "remediation": "Upgrade to 4.1.132.Final or 4.2.10.Final.",
    },
    "result_hash": "4a692eb0032260a83dffe57ff99187c7",
    "first_seen": "2026-03-27T22:51:04.976Z",
    "fingerprint": "",
}

_SAST_ITEM = {
    "category": "sast",
    "repository_name": "AUL",
    "repository_id": "9da7a2cb-6c6e-438d-8bef-afb5aced96e5",
    "scan_date": "2026-04-17T22:52:09.391Z",
    "target_file": "scripts/list_domains.py",
    "scm_file": "https://github.com/absa-group/AUL/blob/abc123/scripts/list_domains.py",
    "scm_link": "https://github.com/absa-group/AUL/blob/abc123/scripts/list_domains.py#L29-L29",
    "target_start_line": 29,
    "target_end_line": 29,
    "repository_integration_name": "absa-group",
    "is_dev_dependency": False,
    "repository_full_name": "absa-group/AUL",
    "avd_id": "insecure-disable-cert-verification-aquasec-python",
    "title": "insecure disable cert verification",
    "severity": 3,
    "resource": "",
    "fixed_version": "",
    "reachable": False,
    "message": "TLS certificate verification is disabled.",
    "published_date": "",
    "installed_version": "",
    "vendor_scoring": {},
    "package_name": "",
    "branch": "master",
    "is_archived": False,
    "source": "github",
    "extraData": {
        "Fix": {},
        "cwe": "CWE-295: Improper Certificate Validation",
        "CISA": {},
        "EPSS": {},
        "owasp": [
            "A03:2017 - Sensitive Data Exposure",
            "A07:2021 - Identification and Authentication Failures",
        ],
        "impact": "LOW",
        "category": "security/audit",
        "confidence": "LOW",
        "likelihood": "LOW",
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://cwe.mitre.org/data/definitions/295.html",
        ],
        "remediation": "Do not disable certificate verification in production code.",
    },
    "result_hash": "9837b494fe9d15ff6152d6291c2da860",
    "first_seen": "2025-09-17T12:46:48.271Z",
    "fingerprint": "67529c72212987bef9797e0c8e343fcb09a89e6455493c93a8419620c2a735cc",
}


# _map_severity

@pytest.mark.parametrize("numeric,expected", [
    (1, "low"),
    (2, "medium"),
    (3, "high"),
    (4, "critical"),
    (99, "unknown"),
    (0, "unknown"),
])
def test_map_severity(numeric, expected) -> None:
    assert _map_severity(numeric) == expected


# _format_bullet_list

def test_format_bullet_list_with_items() -> None:
    assert _format_bullet_list(["a", "b"]) == "- a\n- b"


def test_format_bullet_list_empty() -> None:
    assert _format_bullet_list([]) == ""


def test_format_bullet_list_none() -> None:
    assert _format_bullet_list(None) == ""


# _parse_item

def test_parse_vulnerability_item() -> None:
    alert = _parse_item(_VULN_ITEM, "target-org/target-repo")

    assert alert.repo == "target-org/target-repo"
    assert alert.metadata.rule_id == "CVE-2026-33870"
    assert alert.metadata.rule_name == "vulnerabilities"
    assert alert.metadata.rule_description == "netty-codec-http: Request smuggling via chunked transfer"
    assert alert.metadata.severity == "medium"
    assert alert.metadata.file == "shared-http-client/pom.xml"
    assert alert.metadata.start_line is None  # 0 maps to None
    assert alert.metadata.tool == "AquaSec"
    assert alert.metadata.state == "open"
    assert alert.metadata.help_uri == "https://nvd.nist.gov/vuln/detail/CVE-2026-33870"

    assert alert.alert_details.alert_hash == "4a692eb0032260a83dffe57ff99187c7"
    assert alert.alert_details.artifact == "shared-http-client/pom.xml"
    assert alert.alert_details.type == "vulnerabilities"
    assert alert.alert_details.vulnerability == "CVE-2026-33870"
    assert alert.alert_details.installed_version == "4.1.100.Final"
    assert alert.alert_details.reachable == "False"
    assert alert.alert_details.repository == "absa-group/AUL"

    assert alert.rule_details.fixed_version == "4.1.132.Final"
    assert alert.rule_details.package_name == "io.netty:netty-codec-http"
    assert alert.rule_details.cwe == "CWE-444: HTTP Request Smuggling"
    assert alert.rule_details.impact == "HIGH"
    assert "- https://nvd.nist.gov/vuln/detail/CVE-2026-33870" in alert.rule_details.references
    assert alert.rule_details.remediation == "Upgrade to 4.1.132.Final or 4.2.10.Final."


def test_parse_sast_item() -> None:
    alert = _parse_item(_SAST_ITEM, "target-org/target-repo")

    assert alert.metadata.rule_id == "insecure-disable-cert-verification-aquasec-python"
    assert alert.metadata.severity == "high"
    assert alert.metadata.start_line == 29
    assert alert.metadata.end_line == 29

    assert alert.alert_details.alert_hash == "9837b494fe9d15ff6152d6291c2da860"
    assert "- A03:2017 - Sensitive Data Exposure" in alert.rule_details.owasp
    assert "- A07:2021 - Identification and Authentication Failures" in alert.rule_details.owasp


def test_parse_item_empty_extra_data() -> None:
    item = {**_VULN_ITEM, "extraData": {}}
    alert = _parse_item(item, "org/repo")
    assert alert.rule_details.cwe == ""
    assert alert.rule_details.owasp == "N/A"
    assert alert.rule_details.references == "N/A"
    assert alert.metadata.help_uri == ""


def test_parse_item_reachable_true() -> None:
    item = {**_VULN_ITEM, "reachable": True}
    alert = _parse_item(item, "org/repo")
    assert alert.alert_details.reachable == "True"


# AquaSecParser.parse

def test_parse_in_memory() -> None:
    data = {"total": 1, "data": [_VULN_ITEM]}
    parser = AquaSecParser("org/repo")
    result = parser.parse(data)
    assert len(result.open_by_number) == 1
    assert result.open_by_number[1].metadata.rule_id == "CVE-2026-33870"
