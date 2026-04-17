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

"""Unit tests for ``security.main``."""

import pytest
from pytest_mock import MockerFixture

from security.main import VALID_STATES, _resolve_repo, main, parse_args


REPO = "my-org/my-repo"


def _run_promote(mocker: MockerFixture, tmp_path, extra_args: list[str] | None = None) -> list[str]:
    """Helper: run main() with mocked pipeline and return the argv passed to promote_alerts."""
    mocker.patch("security.main.check_labels", return_value=[])
    mocker.patch("security.main.collect_alert_main")
    mock_promote = mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "alerts.json")
    argv = ["--repo", REPO, "--out", out] + (extra_args or [])
    main(argv)
    return mock_promote.call_args[0][0]


def test_parse_args_defaults() -> None:
    args = parse_args(["--repo", REPO])
    assert args.repo == REPO
    assert args.state == "open"
    assert args.out_file == "alerts.json"
    assert args.issue_label == "scope:security"
    assert args.dry_run is False
    assert args.verbose is False
    assert args.force is False
    assert args.skip_label_check is False


def test_parse_args_all_flags() -> None:
    args = parse_args([
        "--repo", REPO,
        "--state", "dismissed",
        "--out", "out.json",
        "--issue-label", "custom-label",
        "--severity-priority-map", "Critical=Blocker",
        "--project-number", "42",
        "--project-org", "other-org",
        "--teams-webhook-url", "https://example.com/webhook",
        "--skip-label-check",
        "--dry-run",
        "--verbose",
        "--force",
    ])
    assert args.repo == REPO
    assert args.state == "dismissed"
    assert args.out_file == "out.json"
    assert args.issue_label == "custom-label"
    assert args.severity_priority_map == "Critical=Blocker"
    assert args.project_number == "42"
    assert args.project_org == "other-org"
    assert args.teams_webhook_url == "https://example.com/webhook"
    assert args.skip_label_check is True
    assert args.dry_run is True
    assert args.verbose is True
    assert args.force is True


def test_parse_args_state_choices() -> None:
    for state in sorted(VALID_STATES):
        args = parse_args(["--repo", REPO, "--state", state])
        assert args.state == state


def test_parse_args_invalid_state_rejected() -> None:
    with pytest.raises(SystemExit):
        parse_args(["--repo", REPO, "--state", "bogus"])


def test_parse_args_env_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEVERITY_PRIORITY_MAP", "High=Urgent")
    monkeypatch.setenv("PROJECT_NUMBER", "99")
    monkeypatch.setenv("PROJECT_ORG", "env-org")
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://env.example.com")
    args = parse_args(["--repo", REPO])
    assert args.severity_priority_map == "High=Urgent"
    assert args.project_number == "99"
    assert args.project_org == "env-org"
    assert args.teams_webhook_url == "https://env.example.com"


def test_parse_args_cli_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROJECT_NUMBER", "99")
    args = parse_args(["--repo", REPO, "--project-number", "42"])
    assert args.project_number == "42"


def test_resolve_repo_cli_value() -> None:
    assert _resolve_repo("my-org/my-repo") == "my-org/my-repo"


def test_resolve_repo_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "env-org/env-repo")
    assert _resolve_repo("") == "env-org/env-repo"


def test_resolve_repo_empty_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    with pytest.raises(SystemExit, match="repo not specified"):
        _resolve_repo("")


def test_resolve_repo_no_slash_raises() -> None:
    with pytest.raises(SystemExit, match="repo not specified"):
        _resolve_repo("noslash")


def test_missing_labels_returns_1(mocker: MockerFixture) -> None:
    mocker.patch("security.main.check_labels", return_value=["epic"])
    rc = main(["--repo", REPO])
    assert rc == 1


def test_skip_label_check(mocker: MockerFixture, tmp_path) -> None:
    mock_check = mocker.patch("security.main.check_labels")
    mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "alerts.json")
    rc = main(["--repo", REPO, "--skip-label-check", "--out", out])
    mock_check.assert_not_called()
    assert rc == 0


def test_labels_ok_proceeds(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "alerts.json")
    rc = main(["--repo", REPO, "--out", out])
    assert rc == 0


def test_existing_file_without_force_returns_1(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    out = tmp_path / "alerts.json"
    out.write_text("{}")
    rc = main(["--repo", REPO, "--out", str(out)])
    assert rc == 1


def test_existing_file_with_force_removes_it(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = tmp_path / "alerts.json"
    out.write_text("{}")
    rc = main(["--repo", REPO, "--out", str(out), "--force"])
    assert rc == 0
    assert not out.exists()


def test_nonexistent_file_proceeds(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "new.json")
    rc = main(["--repo", REPO, "--out", out])
    assert rc == 0


def test_collect_called_with_basic_args(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    mock_collect = mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--state", "fixed", "--out", out])
    call_args = mock_collect.call_args[0][0]
    assert "--repo" in call_args
    assert REPO in call_args
    assert "--state" in call_args
    assert "fixed" in call_args
    assert "--out" in call_args
    assert out in call_args


def test_verbose_forwarded_to_collect(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    mock_collect = mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--verbose", "--out", out])
    call_args = mock_collect.call_args[0][0]
    assert "--verbose" in call_args


def test_promote_basic_args(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path)
    assert "--file" in call_args
    assert "--issue-label" in call_args
    assert "scope:security" in call_args


def test_promote_dry_run_forwarded(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path, ["--dry-run"])
    assert "--dry-run" in call_args


def test_promote_verbose_forwarded(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path, ["--verbose"])
    assert "--verbose" in call_args


def test_promote_teams_webhook_forwarded(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path, ["--teams-webhook-url", "https://x.com/wh"])
    assert "--teams-webhook-url" in call_args
    assert "https://x.com/wh" in call_args


def test_promote_severity_priority_map_forwarded(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path, ["--severity-priority-map", "Critical=Blocker"])
    assert "--severity-priority-map" in call_args
    assert "Critical=Blocker" in call_args


def test_promote_project_number_forwarded(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path, ["--project-number", "42"])
    assert "--project-number" in call_args
    assert "42" in call_args


def test_promote_project_org_forwarded(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path, ["--project-org", "other-org"])
    assert "--project-org" in call_args
    assert "other-org" in call_args


def test_promote_issue_label_forwarded(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path, ["--issue-label", "custom"])
    assert "--issue-label" in call_args
    assert "custom" in call_args


def test_promote_empty_optionals_not_forwarded(mocker: MockerFixture, tmp_path) -> None:
    call_args = _run_promote(mocker, tmp_path)
    assert "--teams-webhook-url" not in call_args
    assert "--severity-priority-map" not in call_args
    assert "--project-number" not in call_args
    assert "--project-org" not in call_args


def test_pipeline_success_returns_0(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "alerts.json")
    assert main(["--repo", REPO, "--out", out]) == 0


def test_collect_error_propagates(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    mocker.patch("security.main.collect_alert_main", side_effect=SystemExit(1))
    out = str(tmp_path / "alerts.json")
    with pytest.raises(SystemExit):
        main(["--repo", REPO, "--out", out])


def test_promote_error_propagates(mocker: MockerFixture, tmp_path) -> None:
    mocker.patch("security.main.check_labels", return_value=[])
    mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main", side_effect=SystemExit(1))
    out = str(tmp_path / "alerts.json")
    with pytest.raises(SystemExit):
        main(["--repo", REPO, "--out", out])


def test_pipeline_call_order(mocker: MockerFixture, tmp_path) -> None:
    call_order: list[str] = []
    mocker.patch(
        "security.main.check_labels",
        return_value=[],
        side_effect=lambda *a, **k: (call_order.append("check"), [])[-1],
    )
    mocker.patch(
        "security.main.collect_alert_main",
        side_effect=lambda *a, **k: call_order.append("collect"),
    )
    mocker.patch(
        "security.main.promote_alerts_main",
        side_effect=lambda *a, **k: call_order.append("promote"),
    )
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--out", out])
    assert call_order == ["check", "collect", "promote"]


def test_env_repo_fallback(mocker: MockerFixture, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    mocker.patch("security.main.check_labels", return_value=[])
    mock_collect = mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "alerts.json")
    assert main(["--out", out]) == 0
    call_args = mock_collect.call_args[0][0]
    assert REPO in call_args


def test_no_repo_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    with pytest.raises(SystemExit, match="repo not specified"):
        main([])


def test_verbose_via_runner_debug(mocker: MockerFixture, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUNNER_DEBUG", "1")
    mocker.patch("security.main.check_labels", return_value=[])
    mock_collect = mocker.patch("security.main.collect_alert_main")
    mocker.patch("security.main.promote_alerts_main")
    out = str(tmp_path / "alerts.json")
    main(["--repo", REPO, "--out", out])
    call_args = mock_collect.call_args[0][0]
    assert "--verbose" in call_args
