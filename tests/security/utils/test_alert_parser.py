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

"""Unit tests for ``utils.alert_parser``."""

import json
import os
import tempfile

import pytest

from utils.alert_parser import (
    AlertMessageKey,
    compute_occurrence_fp,
    load_open_alerts_from_file,
    parse_alert_message_params,
)


# =====================================================================
# parse_alert_message_params
# =====================================================================


def test_sast_message_all_keys(sast_alert: dict) -> None:
    """All expected keys are extracted from a SAST alert message."""
    params = parse_alert_message_params(sast_alert["message"])

    assert params["artifact"] == (
        "scripts/create_catalog_tables_and_refresh_partitions/list_domains.py"
    )
    assert params["type"] == "sast"
    assert params["vulnerability"] == "req-with-very-false-aquasec-python"
    assert params["severity"] == "HIGH"
    assert "verify=False" in params["message"]
    assert params["repository"] == "test-org/test-repo"
    assert params["reachable"] == "False"
    assert params["scan date"] == "2026-02-24T19:24:35.755Z"
    assert params["first seen"] == "2025-09-17T12:46:48.271Z"
    assert params["scm file"].startswith("https://github.com/test-org/test-repo/blob/")
    assert params["start line"] == "95"
    assert params["end line"] == "95"
    assert params["alert hash"] == "3e9c8c338f318e0d06647c2f79406fd4"

def test_vuln_message_installed_version(vuln_alert: dict) -> None:
    """Vulnerability alert messages include 'Installed version'."""
    params = parse_alert_message_params(vuln_alert["message"])

    assert params["installed version"] == "3.0.3"
    assert params["vulnerability"] == "CVE-2026-25755"
    assert params["reachable"] == "True"
    assert params["alert hash"] == "068f963657211cd416dac1f9b30d606c"

def test_pipeline_message_no_installed_version(pipeline_alert: dict) -> None:
    """Pipeline misconfiguration alerts have no 'Installed version' or 'End line'."""
    params = parse_alert_message_params(pipeline_alert["message"])

    assert "installed version" not in params
    assert "end line" not in params
    assert params["type"] == "pipelineMisconfigurations"
    assert params["start line"] == "21"

def test_none_message() -> None:
    assert parse_alert_message_params(None) == {}

def test_empty_message() -> None:
    assert parse_alert_message_params("") == {}

def test_message_without_colon() -> None:
    assert parse_alert_message_params("no colon here") == {}

def test_key_normalisation() -> None:
    """Keys are lowercased and internal whitespace is collapsed."""
    params = parse_alert_message_params("  Alert  Hash : abc123  ")
    assert params["alert hash"] == "abc123"


# =====================================================================
# AlertMessageKey enum completeness
# =====================================================================


_EXPECTED_KEYS = {
    "artifact", "type", "vulnerability", "severity", "message",
    "repository", "reachable", "scan date", "first seen",
    "scm file", "installed version", "start line", "end line",
    "alert hash",
}

def test_all_documented_keys_present() -> None:
    enum_values = {member.value for member in AlertMessageKey}
    assert enum_values == _EXPECTED_KEYS

def test_sast_message_keys_subset(sast_alert: dict) -> None:
    """Every enum value that appears in a SAST message is parseable."""
    params = parse_alert_message_params(sast_alert["message"])
    for key in AlertMessageKey:
        if key.value in params:
            assert params[key.value], f"Key '{key.value}' parsed but empty"


# =====================================================================
# compute_occurrence_fp
# =====================================================================


def test_deterministic() -> None:
    fp1 = compute_occurrence_fp("abc123", "src/main.py", 10, 20)
    fp2 = compute_occurrence_fp("abc123", "src/main.py", 10, 20)
    assert fp1 == fp2

def test_differs_on_commit() -> None:
    fp1 = compute_occurrence_fp("abc123", "src/main.py", 10, 20)
    fp2 = compute_occurrence_fp("def456", "src/main.py", 10, 20)
    assert fp1 != fp2

def test_none_lines() -> None:
    """None line numbers should not raise."""
    fp = compute_occurrence_fp("abc123", "src/main.py", None, None)
    assert isinstance(fp, str) and len(fp) == 64


# =====================================================================
# load_open_alerts_from_file
# =====================================================================


def _write_alerts_file(alerts: list[dict], repo_full: str = "org/repo") -> str:
    """Write a minimal alerts JSON to a temp file and return the path."""
    data = {
        "repo": {"full_name": repo_full},
        "alerts": alerts,
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path

def test_loads_open_alerts() -> None:
    path = _write_alerts_file([
        {"alert_number": 1, "state": "open", "message": "Alert hash: abc\nType: sast"},
        {"alert_number": 2, "state": "dismissed", "message": "Alert hash: def\nType: sast"},
    ])
    try:
        repo, alerts = load_open_alerts_from_file(path)
        assert repo == "org/repo"
        assert 1 in alerts
        assert 2 not in alerts
    finally:
        os.unlink(path)

def test_enriches_repo_and_message_params() -> None:
    path = _write_alerts_file([
        {"alert_number": 10, "state": "open", "message": "Alert hash: xyz\nSeverity: HIGH"},
    ])
    try:
        repo, alerts = load_open_alerts_from_file(path)
        alert = alerts[10]
        assert alert["_repo"] == "org/repo"
        assert isinstance(alert["_message_params"], dict)
        assert alert["_message_params"]["alert hash"] == "xyz"
    finally:
        os.unlink(path)

def test_missing_file_exits() -> None:
    with pytest.raises(SystemExit):
        load_open_alerts_from_file("/nonexistent/path.json")

def test_missing_repo_full_name_exits() -> None:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump({"repo": {}, "alerts": []}, fh)
    try:
        with pytest.raises(SystemExit):
            load_open_alerts_from_file(path)
    finally:
        os.unlink(path)

def test_skips_alert_without_number() -> None:
    path = _write_alerts_file([
        {"state": "open", "message": "no number"},
    ])
    try:
        _, alerts = load_open_alerts_from_file(path)
        assert len(alerts) == 0
    finally:
        os.unlink(path)

def test_skips_alert_with_invalid_number() -> None:
    """Non-integer alert_number values are skipped with a warning."""
    path = _write_alerts_file([
        {"alert_number": "not-a-number", "state": "open", "message": "Type: sast"},
    ])
    try:
        _, alerts = load_open_alerts_from_file(path)
        assert len(alerts) == 0
    finally:
        os.unlink(path)
