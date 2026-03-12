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

"""Unit tests for ``promote_alerts.py`` – CLI entry-point wiring."""

from types import SimpleNamespace

import pytest
from pytest_mock import MockerFixture

from utils.models import LoadedAlerts, NotifiedIssue, SeverityChange, SyncResult

# Default empty sync result reused across tests.
_SYNC_RESULT_EMPTY = SyncResult(notifications=[], severity_changes=[])


# =====================================================================
# parse_args
# =====================================================================


def test_parse_args_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Defaults are applied when no CLI args are given."""
    monkeypatch.setattr("sys.argv", ["promote_alerts.py"])
    monkeypatch.delenv("SEVERITY_PRIORITY_MAP", raising=False)
    monkeypatch.delenv("PROJECT_NUMBER", raising=False)
    monkeypatch.delenv("PROJECT_ORG", raising=False)
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    from promote_alerts import parse_args

    args = parse_args()
    assert args.file == "alerts.json"
    assert args.dry_run is False
    assert args.verbose is False


def test_parse_args_all_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    """All CLI flags and options are parsed correctly."""
    monkeypatch.setattr("sys.argv", [
        "promote_alerts.py",
        "--file", "custom.json",
        "--dry-run",
        "--verbose",
        "--issue-label", "my-label",
        "--severity-priority-map", "High=Urgent",
        "--project-number", "42",
        "--project-org", "my-org",
        "--teams-webhook-url", "https://hook.example.com",
    ])
    from promote_alerts import parse_args

    args = parse_args()
    assert args.file == "custom.json"
    assert args.dry_run is True
    assert args.verbose is True
    assert args.issue_label == "my-label"
    assert args.severity_priority_map == "High=Urgent"
    assert args.project_number == 42
    assert args.project_org == "my-org"
    assert args.teams_webhook_url == "https://hook.example.com"


# =====================================================================
# main() – gh CLI guard
# =====================================================================


def test_missing_gh_cli_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """main() raises SystemExit when gh CLI is not found."""
    monkeypatch.setattr("sys.argv", ["promote_alerts.py"])
    monkeypatch.setattr("shutil.which", lambda _cmd: None)
    from promote_alerts import main

    with pytest.raises(SystemExit, match="gh CLI"):
        main()


# =====================================================================
# Fixture: mock all external deps used by main()
# =====================================================================


@pytest.fixture()
def main_mocks(mocker: MockerFixture) -> SimpleNamespace:
    """Provide mocked dependencies for ``main()`` with sensible defaults."""
    return SimpleNamespace(
        which=mocker.patch("promote_alerts.shutil.which", return_value="/usr/bin/gh"),
        load=mocker.patch(
            "promote_alerts.load_open_alerts_from_file",
            return_value=LoadedAlerts(repo_full="org/repo", open_by_number={}),
        ),
        list_issues=mocker.patch(
            "promote_alerts.gh_issue_list_by_label",
            return_value={},
        ),
        sync=mocker.patch(
            "promote_alerts.sync_alerts_and_issues",
            return_value=_SYNC_RESULT_EMPTY,
        ),
        notify=mocker.patch("promote_alerts.notify_teams"),
        notify_sev=mocker.patch("promote_alerts.notify_teams_severity_changes"),
    )


# =====================================================================
# main() – wiring tests
# =====================================================================


def test_main_dry_run(
    main_mocks: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run mode passes dry_run=True to sync_alerts_and_issues."""
    monkeypatch.setattr("sys.argv", ["promote_alerts.py", "--dry-run"])
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SEVERITY_PRIORITY_MAP", raising=False)
    monkeypatch.delenv("PROJECT_NUMBER", raising=False)
    monkeypatch.delenv("PROJECT_ORG", raising=False)
    from promote_alerts import main

    main()
    _, kwargs = main_mocks.sync.call_args
    assert kwargs["dry_run"] is True


def test_main_passes_file_arg(
    main_mocks: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--file value is forwarded to load_open_alerts_from_file."""
    monkeypatch.setattr("sys.argv", ["promote_alerts.py", "--file", "custom.json"])
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SEVERITY_PRIORITY_MAP", raising=False)
    monkeypatch.delenv("PROJECT_NUMBER", raising=False)
    monkeypatch.delenv("PROJECT_ORG", raising=False)
    from promote_alerts import main

    main()
    main_mocks.load.assert_called_once_with("custom.json")


def test_main_no_webhook_skips_notification(
    main_mocks: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without TEAMS_WEBHOOK_URL, notify_teams is still called (with empty url)."""
    monkeypatch.setattr("sys.argv", ["promote_alerts.py"])
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SEVERITY_PRIORITY_MAP", raising=False)
    monkeypatch.delenv("PROJECT_NUMBER", raising=False)
    monkeypatch.delenv("PROJECT_ORG", raising=False)

    # sync returns notifications to trigger the notification branch
    main_mocks.sync.return_value = SyncResult(
        notifications=[
            NotifiedIssue(
                repo="org/repo", issue_number=1, severity="high",
                category="sast", state="new", tool="AquaSec",
            ),
        ],
        severity_changes=[],
    )
    from promote_alerts import main

    main()
    # Without webhook URL, logging.debug is hit and notify_teams is not called
    main_mocks.notify.assert_not_called()


def test_main_with_webhook_sends_notifications(
    main_mocks: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When TEAMS_WEBHOOK_URL is set and there are notifications, notify_teams is called."""
    monkeypatch.setattr("sys.argv", [
        "promote_alerts.py", "--teams-webhook-url", "https://hook.example.com",
    ])
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SEVERITY_PRIORITY_MAP", raising=False)
    monkeypatch.delenv("PROJECT_NUMBER", raising=False)
    monkeypatch.delenv("PROJECT_ORG", raising=False)

    main_mocks.sync.return_value = SyncResult(
        notifications=[
            NotifiedIssue(
                repo="org/repo", issue_number=1, severity="high",
                category="sast", state="new", tool="AquaSec",
            ),
        ],
        severity_changes=[],
    )
    from promote_alerts import main

    main()
    main_mocks.notify.assert_called_once()
    call_args = main_mocks.notify.call_args
    assert call_args[0][0] == "https://hook.example.com"


def test_main_severity_priority_map_forwarded(
    main_mocks: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--severity-priority-map value is parsed and forwarded to sync."""
    monkeypatch.setattr("sys.argv", [
        "promote_alerts.py", "--severity-priority-map", "High=Urgent,Low=Minor",
    ])
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SEVERITY_PRIORITY_MAP", raising=False)
    monkeypatch.delenv("PROJECT_NUMBER", raising=False)
    monkeypatch.delenv("PROJECT_ORG", raising=False)
    from promote_alerts import main

    main()
    _, kwargs = main_mocks.sync.call_args
    assert kwargs["severity_priority_map"] == {"high": "Urgent", "low": "Minor"}


def test_main_project_number_forwarded(
    main_mocks: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--project-number and --project-org are forwarded to sync."""
    monkeypatch.setattr("sys.argv", [
        "promote_alerts.py", "--project-number", "42", "--project-org", "my-org",
    ])
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SEVERITY_PRIORITY_MAP", raising=False)
    monkeypatch.delenv("PROJECT_NUMBER", raising=False)
    monkeypatch.delenv("PROJECT_ORG", raising=False)
    from promote_alerts import main

    main()
    _, kwargs = main_mocks.sync.call_args
    assert kwargs["project_number"] == 42
    assert kwargs["project_org"] == "my-org"
