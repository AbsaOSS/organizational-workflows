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

"""Unit tests for ``collect_alert.py``."""

import json
import subprocess

import pytest
from pytest_mock import MockerFixture

from collect_alert import (
    RULE_DETAIL_KEYS,
    VALID_STATES,
    _gh_api_json,
    _gh_api_paginate,
    _normalise_alert,
    _parse_alert_details,
    _parse_rule_details,
    _snake_case,
    _help_value,
    main,
    parse_args,
)


REPO = "my-org/my-repo"

_RAW_ALERT: dict = {
    "number": 303,
    "state": "open",
    "created_at": "2026-02-25T08:25:18Z",
    "updated_at": "2026-02-25T14:11:06Z",
    "url": "https://api.github.com/repos/org/repo/code-scanning/alerts/303",
    "html_url": "https://github.com/org/repo/security/code-scanning/303",
    "rule": {
        "id": "rule-1",
        "name": "sast",
        "security_severity_level": "high",
        "severity": "error",
        "tags": ["HIGH", "sast"],
        "help_uri": "https://example.com",
        "help": "**Type:** sast\n**Severity:** HIGH\n**Impact:** medium",
    },
    "tool": {"name": "AquaSec", "version": "1.0.0"},
    "most_recent_instance": {
        "ref": "refs/heads/master",
        "commit_sha": "abc123",
        "html_url": "https://github.com/org/repo/instance/1",
        "classifications": ["library"],
        "location": {"path": "src/main.py", "start_line": 10, "end_line": 20},
        "message": {"text": "Type: sast\nSeverity: HIGH\nAlert hash: abc123hash"},
    },
}


def _mock_happy_path(mocker: MockerFixture, repo_data: dict | None = None, raw_alerts: list | None = None):
    """Set up mocks for a successful main() run."""
    mocker.patch("collect_alert.shutil.which", return_value="/usr/bin/gh")
    mocker.patch(
        "collect_alert.run_gh",
        return_value=_gh_ok("Logged in"),
    )
    mocker.patch(
        "collect_alert._gh_api_json",
        return_value=repo_data or {
            "id": 1,
            "name": "my-repo",
            "full_name": "my-org/my-repo",
            "private": False,
            "html_url": "https://github.com/my-org/my-repo",
            "default_branch": "main",
            "owner": {"login": "my-org", "id": 100, "html_url": "https://github.com/my-org"},
        },
    )
    mocker.patch(
        "collect_alert._gh_api_paginate",
        return_value=raw_alerts if raw_alerts is not None else [],
    )


def _gh_ok(stdout: str) -> subprocess.CompletedProcess:
    """Build a successful ``run_gh`` return value."""
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def _gh_fail(stderr: str = "error") -> subprocess.CompletedProcess:
    """Build a failed ``run_gh`` return value."""
    return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=stderr)


def test_snake_case_simple() -> None:
    assert _snake_case("Fixed version") == "fixed_version"


def test_snake_case_single_word() -> None:
    assert _snake_case("Severity") == "severity"


def test_snake_case_strips_whitespace() -> None:
    assert _snake_case("  Package name  ") == "package_name"


def test_snake_case_already_lower() -> None:
    assert _snake_case("impact") == "impact"


def test_help_value_found() -> None:
    text = "Some preamble\n**Severity:** HIGH\nMore text"
    assert _help_value(text, "Severity") == "HIGH"


def test_help_value_not_found() -> None:
    assert _help_value("no match here", "Severity") is None


def test_help_value_case_insensitive() -> None:
    text = "**severity:** medium"
    assert _help_value(text, "Severity") == "medium"


def test_help_value_with_extra_spacing() -> None:
    text = "**CWE:**   CWE-79"
    assert _help_value(text, "CWE") == "CWE-79"


def test_help_value_stops_at_newline() -> None:
    text = "**Type:** sast\n**Severity:** HIGH"
    assert _help_value(text, "Type") == "sast"


def test_parse_rule_details_extracts_fields() -> None:
    rule_help = (
        "**Type:** sast\n"
        "**Severity:** HIGH\n"
        "**CWE:** CWE-295\n"
        "**Impact:** medium\n"
        "**Confidence:** high\n"
        "**Likelihood:** medium\n"
    )
    details = _parse_rule_details(rule_help)
    assert details["type"] == "sast"
    assert details["severity"] == "HIGH"
    assert details["cwe"] == "CWE-295"
    assert details["impact"] == "medium"
    assert details["confidence"] == "high"
    assert details["likelihood"] == "medium"


def test_parse_rule_details_missing_fields_are_none() -> None:
    details = _parse_rule_details("")
    assert all(details[_snake_case(k)] is None for k in RULE_DETAIL_KEYS)


def test_parse_rule_details_returns_all_keys() -> None:
    details = _parse_rule_details("")
    assert set(details.keys()) == {_snake_case(k) for k in RULE_DETAIL_KEYS}


def test_parse_alert_details_basic() -> None:
    message = (
        "Artifact: src/main.py\n"
        "Type: sast\n"
        "Severity: HIGH\n"
        "Message: Something bad\n"
    )
    details = _parse_alert_details(message)
    assert details["artifact"] == "src/main.py"
    assert details["type"] == "sast"
    assert details["severity"] == "HIGH"
    assert details["message"] == "Something bad"


def test_parse_alert_details_empty_input() -> None:
    assert _parse_alert_details("") == {}


def test_parse_alert_details_no_matching_lines() -> None:
    assert _parse_alert_details("just some text without colons\nanother line") == {}


def test_parse_alert_details_multiword_key() -> None:
    message = "Start line: 42\nEnd line: 50\n"
    details = _parse_alert_details(message)
    assert details["start_line"] == "42"
    assert details["end_line"] == "50"


def test_parse_alert_details_strips_carriage_return() -> None:
    message = "Type: sast\r\nSeverity: HIGH\r\n"
    details = _parse_alert_details(message)
    assert details["type"] == "sast"
    assert details["severity"] == "HIGH"


def test_parse_alert_details_value_with_colon() -> None:
    message = "SCM file: https://github.com/org/repo/blob/abc/file.py\n"
    details = _parse_alert_details(message)
    assert details["scm_file"] == "https://github.com/org/repo/blob/abc/file.py"


def test_gh_api_json_success(mocker: MockerFixture) -> None:
    payload = {"id": 123, "name": "my-repo"}
    mocker.patch("collect_alert.run_gh", return_value=_gh_ok(json.dumps(payload)))
    assert _gh_api_json("/repos/my-org/my-repo") == payload


def test_gh_api_json_failure_exits(mocker: MockerFixture) -> None:
    mocker.patch("collect_alert.run_gh", return_value=_gh_fail("not found"))
    with pytest.raises(SystemExit):
        _gh_api_json("/repos/my-org/my-repo")


def test_gh_api_paginate_single_page(mocker: MockerFixture) -> None:
    alerts = [{"number": 1}, {"number": 2}]
    mocker.patch("collect_alert.run_gh", return_value=_gh_ok(json.dumps(alerts)))
    assert _gh_api_paginate("/repos/org/repo/alerts") == alerts


def test_gh_api_paginate_multiple_pages(mocker: MockerFixture) -> None:
    page1 = json.dumps([{"number": 1}])
    page2 = json.dumps([{"number": 2}])
    stdout = page1 + "\n" + page2
    mocker.patch("collect_alert.run_gh", return_value=_gh_ok(stdout))
    result = _gh_api_paginate("/repos/org/repo/alerts")
    assert result == [{"number": 1}, {"number": 2}]


def test_gh_api_paginate_single_object(mocker: MockerFixture) -> None:
    mocker.patch("collect_alert.run_gh", return_value=_gh_ok(json.dumps({"key": "val"})))
    result = _gh_api_paginate("/endpoint")
    assert result == [{"key": "val"}]


def test_gh_api_paginate_empty_array(mocker: MockerFixture) -> None:
    mocker.patch("collect_alert.run_gh", return_value=_gh_ok("[]"))
    assert _gh_api_paginate("/endpoint") == []


def test_gh_api_paginate_failure_exits(mocker: MockerFixture) -> None:
    mocker.patch("collect_alert.run_gh", return_value=_gh_fail("error"))
    with pytest.raises(SystemExit):
        _gh_api_paginate("/endpoint")


def test_normalise_alert_metadata() -> None:
    result = _normalise_alert(_RAW_ALERT)
    meta = result["metadata"]
    assert meta["alert_number"] == 303
    assert meta["state"] == "open"
    assert meta["rule_id"] == "rule-1"
    assert meta["rule_name"] == "sast"
    assert meta["severity"] == "high"
    assert meta["confidence"] == "error"
    assert meta["tags"] == ["HIGH", "sast"]
    assert meta["tool"] == "AquaSec"
    assert meta["tool_version"] == "1.0.0"
    assert meta["ref"] == "refs/heads/master"
    assert meta["commit_sha"] == "abc123"
    assert meta["file"] == "src/main.py"
    assert meta["start_line"] == 10
    assert meta["end_line"] == 20
    assert meta["classifications"] == ["library"]


def test_normalise_alert_alert_details() -> None:
    result = _normalise_alert(_RAW_ALERT)
    ad = result["alert_details"]
    assert ad["type"] == "sast"
    assert ad["severity"] == "HIGH"
    assert ad["alert_hash"] == "abc123hash"


def test_normalise_alert_rule_details() -> None:
    result = _normalise_alert(_RAW_ALERT)
    rd = result["rule_details"]
    assert rd["type"] == "sast"
    assert rd["severity"] == "HIGH"
    assert rd["impact"] == "medium"


def test_normalise_alert_minimal() -> None:
    result = _normalise_alert({})
    meta = result["metadata"]
    assert meta["alert_number"] is None
    assert meta["state"] is None
    assert meta["rule_id"] is None
    assert meta["tool"] is None
    assert meta["file"] is None
    assert meta["tags"] == []
    assert meta["classifications"] == []
    assert result["alert_details"] == {}


def test_normalise_alert_missing_message() -> None:
    alert = {
        "most_recent_instance": {"message": None},
    }
    result = _normalise_alert(alert)
    assert result["alert_details"] == {}


def test_normalise_alert_missing_rule_help() -> None:
    alert = {"rule": {"help": None}}
    result = _normalise_alert(alert)
    assert all(v is None for v in result["rule_details"].values())


def test_parse_args_defaults() -> None:
    args = parse_args(["--repo", REPO])
    assert args.repo == REPO
    assert args.state == "open"
    assert args.out_file == "alerts.json"
    assert args.verbose is False


def test_parse_args_all_options() -> None:
    args = parse_args(["--repo", REPO, "--state", "dismissed", "--out", "out.json", "--verbose"])
    assert args.state == "dismissed"
    assert args.out_file == "out.json"
    assert args.verbose is True


def test_parse_args_state_choices() -> None:
    for state in sorted(VALID_STATES):
        args = parse_args(["--repo", REPO, "--state", state])
        assert args.state == state


def test_parse_args_invalid_state_rejected() -> None:
    with pytest.raises(SystemExit):
        parse_args(["--repo", REPO, "--state", "bogus"])


def test_parse_args_repo_required() -> None:
    with pytest.raises(SystemExit):
        parse_args([])


def test_main_writes_json(mocker: MockerFixture, tmp_path) -> None:
    _mock_happy_path(mocker)
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--out", out])
    data = json.loads((tmp_path / "alerts.json").read_text())
    assert data["repo"]["full_name"] == "my-org/my-repo"
    assert data["query"]["state"] == "open"
    assert data["alerts"] == []
    assert "generated_at" in data


def test_main_writes_normalised_alerts(mocker: MockerFixture, tmp_path) -> None:
    _mock_happy_path(mocker, raw_alerts=[_RAW_ALERT])
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--out", out])
    data = json.loads((tmp_path / "alerts.json").read_text())
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["metadata"]["alert_number"] == 303


def test_main_repo_metadata_in_output(mocker: MockerFixture, tmp_path) -> None:
    _mock_happy_path(mocker)
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--out", out])
    data = json.loads((tmp_path / "alerts.json").read_text())
    repo_section = data["repo"]
    assert repo_section["id"] == 1
    assert repo_section["name"] == "my-repo"
    assert repo_section["private"] is False
    assert repo_section["default_branch"] == "main"
    assert repo_section["owner"]["login"] == "my-org"


def test_main_state_forwarded_to_paginate(mocker: MockerFixture, tmp_path) -> None:
    _mock_happy_path(mocker)
    mock_paginate = mocker.patch("collect_alert._gh_api_paginate", return_value=[])
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--state", "dismissed", "--out", out])
    endpoint = mock_paginate.call_args[0][0]
    assert "state=dismissed" in endpoint


def test_main_state_all_omits_state_param(mocker: MockerFixture, tmp_path) -> None:
    _mock_happy_path(mocker)
    mock_paginate = mocker.patch("collect_alert._gh_api_paginate", return_value=[])
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--state", "all", "--out", out])
    endpoint = mock_paginate.call_args[0][0]
    assert "state=" not in endpoint


def test_main_invalid_repo_format_exits(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("collect_alert.shutil.which", return_value="/usr/bin/gh")
    mocker.patch("collect_alert.run_gh", return_value=_gh_ok("ok"))
    out = str(tmp_path / "alerts.json")
    with pytest.raises(SystemExit):
        main(["--repo", "noslash", "--out", out])


def test_main_gh_not_found_exits(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("collect_alert.shutil.which", return_value=None)
    out = str(tmp_path / "alerts.json")
    with pytest.raises(SystemExit):
        main(["--repo", REPO, "--out", out])


def test_main_gh_not_authenticated_exits(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("collect_alert.shutil.which", return_value="/usr/bin/gh")
    mocker.patch("collect_alert.run_gh", return_value=_gh_fail("not logged in"))
    out = str(tmp_path / "alerts.json")
    with pytest.raises(SystemExit):
        main(["--repo", REPO, "--out", out])


def test_main_refuses_overwrite(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("collect_alert.shutil.which", return_value="/usr/bin/gh")
    mocker.patch("collect_alert.run_gh", return_value=_gh_ok("ok"))
    out = tmp_path / "alerts.json"
    out.write_text("{}")
    with pytest.raises(SystemExit):
        main(["--repo", REPO, "--out", str(out)])


def test_main_verbose_via_flag(mocker: MockerFixture, tmp_path) -> None:
    _mock_happy_path(mocker)
    mock_setup = mocker.patch("collect_alert.setup_logging")
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--out", out, "--verbose"])
    mock_setup.assert_called_once_with(True)


def test_main_verbose_via_runner_debug(mocker: MockerFixture, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUNNER_DEBUG", "1")
    _mock_happy_path(mocker)
    mock_setup = mocker.patch("collect_alert.setup_logging")
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--out", out])
    mock_setup.assert_called_once_with(True)


def test_main_output_ends_with_newline(mocker: MockerFixture, tmp_path) -> None:
    _mock_happy_path(mocker)
    out = tmp_path / "alerts.json"
    main(["--repo", REPO, "--out", str(out)])
    assert out.read_text().endswith("\n")
