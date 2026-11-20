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

from security.main import main, parse_args
from security.services.label_creator import LabelCreator
from security.services.notification_sender import NotificationSender


REPO = "my-org/my-repo"
REPOSITORY_ID = "00000000-0000-0000-0000-000000000001"



@pytest.fixture(autouse=True)
def _aqua_env(monkeypatch):
    """Set required AquaSec env vars for all tests."""
    monkeypatch.setenv("AQUA_KEY", "test-key")
    monkeypatch.setenv("AQUA_SECRET", "test-secret")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/gh")


def _mock_pipeline_stages(mocker: MockerFixture):
    """Mock external dependencies downstream of the label ensure step."""
    mock_auth = mocker.patch("security.main.AquaSecAuthenticator")
    mock_auth.return_value.authenticate.return_value = "token"
    mock_repository_fetcher = mocker.patch("security.main.RepositoryFetcher")
    mock_repository_fetcher.return_value.fetch_repository_id.return_value = REPOSITORY_ID
    mock_fetcher = mocker.patch("security.main.ScanFetcher")
    mock_fetcher.return_value.fetch_findings.return_value = {"total": 0, "data": []}
    mock_parser = mocker.patch("security.main.AquaSecParser")
    mock_parser.return_value.parse.return_value = mocker.Mock(open_by_number={})
    mock_syncer = mocker.patch("security.main.IssueSyncer")
    mock_syncer.return_value.sync.return_value = mocker.Mock()
    mock_notifier = mocker.patch.object(NotificationSender, "notify")
    return {
        "auth": mock_auth,
        "repository_fetcher": mock_repository_fetcher,
        "fetcher": mock_fetcher,
        "parser": mock_parser,
        "syncer": mock_syncer,
        "notifier": mock_notifier,
    }


def _mock_pipeline(mocker: MockerFixture):
    """Mock external dependencies in the pipeline, including the label ensure step."""
    mocker.patch.object(LabelCreator, "ensure_labels", return_value=[])
    return _mock_pipeline_stages(mocker)


# parse_args


def test_parse_args_defaults():
    args = parse_args(["--repo", REPO])
    assert args.repo == REPO
    assert args.dry_run is False
    assert args.verbose is False
    assert args.scan_output == ""


def test_parse_args_all_flags():
    args = parse_args([
        "--repo", REPO,
        "--severity-priority-map", "Critical=Blocker",
        "--project-number", "42",
        "--project-org", "other-org",
        "--teams-webhook-url", "https://example.com/webhook",
        "--scan-output", "aquasec_scan.json",
        "--dry-run",
        "--verbose",
    ])
    assert args.repo == REPO
    assert args.severity_priority_map == "Critical=Blocker"
    assert args.project_number == "42"
    assert args.project_org == "other-org"
    assert args.teams_webhook_url == "https://example.com/webhook"
    assert args.scan_output == "aquasec_scan.json"
    assert args.dry_run is True
    assert args.verbose is True


# main - config validation


def test_no_repo_raises_system_exit(monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    with pytest.raises(SystemExit):
        main([])


def test_env_repo_fallback(mocker, monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    mocks = _mock_pipeline(mocker)
    assert main([]) == 0
    mocks["auth"].assert_called_once()
    mocks["repository_fetcher"].return_value.fetch_repository_id.assert_called_once_with(REPO)


# main - required labels


def test_labels_that_could_not_be_created_return_1(mocker):
    """A label that cannot be created is a permissions problem: fail fast, before authenticating."""
    mocker.patch.object(LabelCreator, "ensure_labels", return_value=["epic"])
    mocks = _mock_pipeline_stages(mocker)

    assert main(["--repo", REPO]) == 1
    mocks["auth"].assert_not_called()


def test_labels_all_ensured_lets_the_run_continue(mocker):
    ensure = mocker.patch.object(LabelCreator, "ensure_labels", return_value=[])
    mocks = _mock_pipeline_stages(mocker)

    assert main(["--repo", REPO]) == 0
    ensure.assert_called_once_with(dry_run=False)
    mocks["auth"].assert_called_once()


def test_dry_run_is_forwarded_to_the_label_creator(mocker):
    ensure = mocker.patch.object(LabelCreator, "ensure_labels", return_value=[])
    _mock_pipeline_stages(mocker)

    main(["--repo", REPO, "--dry-run"])

    ensure.assert_called_once_with(dry_run=True)


# main - pipeline success


@pytest.mark.parametrize(("legacy_id", "dry_run"), [
    (None, False),
    ("abc12345-e89b-12d3-a456-426614174000", False),
    ("not-a-uuid", True),
])
def test_pipeline_success_returns_0(mocker, monkeypatch, legacy_id, dry_run):
    if legacy_id is None:
        monkeypatch.delenv("AQUA_REPOSITORY_ID", raising=False)
    else:
        monkeypatch.setenv("AQUA_REPOSITORY_ID", legacy_id)
    mocks = _mock_pipeline(mocker)
    args = ["--repo", REPO] + (["--dry-run"] if dry_run else [])
    assert 0 == main(args)
    mocks["auth"].assert_called_once_with("test-key", "test-secret")
    mocks["repository_fetcher"].assert_called_once_with("token")
    mocks["repository_fetcher"].return_value.fetch_repository_id.assert_called_once_with(REPO)
    mocks["fetcher"].assert_called_once_with("token", REPOSITORY_ID)


def test_pipeline_calls_notify(mocker):
    mocks = _mock_pipeline(mocker)
    main(["--repo", REPO])
    mocks["notifier"].assert_called_once()


def test_failed_notification_does_not_fail_the_run(mocker, monkeypatch):
    """Issues are already synced by then, so a failed card must not redden the run."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    mocks = _mock_pipeline(mocker)
    mocks["notifier"].return_value = False
    warn = mocker.patch("security.main.emit_workflow_warning")

    assert main(["--repo", REPO]) == 0
    warn.assert_called_once()


def test_failed_notification_skips_annotation_outside_actions(mocker, monkeypatch):
    """A local run must not print stray workflow commands."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    mocks = _mock_pipeline(mocker)
    mocks["notifier"].return_value = False
    warn = mocker.patch("security.main.emit_workflow_warning")

    assert main(["--repo", REPO]) == 0
    warn.assert_not_called()


# main - scan output


def test_scan_output_writes_scan_data(mocker):
    mocks = _mock_pipeline(mocker)
    mocks["fetcher"].return_value.fetch_findings.return_value = {"total": 1, "data": [{"a": 1}]}
    mock_write = mocker.patch("security.main.write_json")

    main(["--repo", REPO, "--scan-output", "aquasec_scan.json"])

    mock_write.assert_called_once_with("aquasec_scan.json", {"total": 1, "data": [{"a": 1}]})


def test_scan_output_skipped_when_not_provided(mocker):
    _mock_pipeline(mocker)
    mock_write = mocker.patch("security.main.write_json")

    main(["--repo", REPO])

    mock_write.assert_not_called()


def test_pipeline_call_order(mocker):
    call_order: list[str] = []
    mocker.patch.object(LabelCreator, "ensure_labels", side_effect=lambda **_: (call_order.append("ensure"), [])[-1])
    mock_auth = mocker.patch("security.main.AquaSecAuthenticator")
    mock_auth.return_value.authenticate.side_effect = lambda: (call_order.append("auth"), "token")[-1]
    mock_repository_fetcher = mocker.patch("security.main.RepositoryFetcher")
    mock_repository_fetcher.return_value.fetch_repository_id.side_effect = lambda _: (
        call_order.append("repository"), REPOSITORY_ID
    )[-1]
    mock_fetcher = mocker.patch("security.main.ScanFetcher")
    mock_fetcher.return_value.fetch_findings.side_effect = lambda: (call_order.append("fetch"), {"total": 0, "data": []})[-1]
    mock_parser = mocker.patch("security.main.AquaSecParser")
    mock_parser.return_value.parse.side_effect = lambda *a: (call_order.append("parse"), mocker.Mock(open_by_number={}))[-1]
    mock_syncer = mocker.patch("security.main.IssueSyncer")
    mock_syncer.return_value.sync.side_effect = lambda *a, **kw: (call_order.append("sync"), mocker.Mock())[-1]
    mocker.patch.object(NotificationSender, "notify", side_effect=lambda *a, **kw: call_order.append("notify"))

    main(["--repo", REPO])

    assert ["ensure", "auth", "repository", "fetch", "parse", "sync", "notify"] == call_order


# main - error propagation


@pytest.mark.parametrize(("stage", "method", "downstream"), [
    ("auth", "authenticate", ["repository_fetcher", "fetcher", "parser", "syncer", "notifier"]),
    ("repository_fetcher", "fetch_repository_id", ["fetcher", "parser", "syncer", "notifier"]),
    ("fetcher", "fetch_findings", ["parser", "syncer", "notifier"]),
])
def test_pipeline_error_propagates_without_running_downstream_stages(mocker, stage, method, downstream):
    mocks = _mock_pipeline(mocker)
    getattr(mocks[stage].return_value, method).side_effect = SystemExit(f"{stage} failed")

    with pytest.raises(SystemExit, match=f"{stage} failed"):
        main(["--repo", REPO])
    for next_stage in downstream:
        mocks[next_stage].assert_not_called()


# main - verbose via RUNNER_DEBUG


def test_verbose_via_runner_debug(mocker, monkeypatch):
    monkeypatch.setenv("RUNNER_DEBUG", "1")
    _mock_pipeline(mocker)
    assert main(["--repo", REPO]) == 0
