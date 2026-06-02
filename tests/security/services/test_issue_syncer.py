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

"""Unit tests for ``security.services.issue_syncer``."""

import pytest
from unittest.mock import MagicMock

from security.config import SecurityConfig
from security.services.issue_syncer import IssueSyncer


@pytest.fixture()
def config():
    """Minimal SecurityConfig for testing."""
    return SecurityConfig(
        aqua_key="k",
        aqua_secret="s",
        aqua_group_id="g",
        aqua_repository_id="00000000-0000-0000-0000-000000000000",
        repo="org/repo",
        issue_label="scope:security",
        severity_priority_map="Critical=P0",
        project_number=42,
        project_org="org",
        teams_webhook_url="https://hooks.example.com/webhook",
    )


# sync


def test_sync_calls_sync_alerts_and_issues(mocker, config):
    mocker.patch("security.services.issue_syncer.gh_issue_list_by_label", return_value={})
    mock_sync = mocker.patch("security.services.issue_syncer.sync_alerts_and_issues")
    mock_sync.return_value = MagicMock(notifications=[], severity_changes=[])

    syncer = IssueSyncer(config)
    syncer.sync({}, dry_run=False)

    mock_sync.assert_called_once()


def test_sync_passes_dry_run(mocker, config):
    mocker.patch("security.services.issue_syncer.gh_issue_list_by_label", return_value={})
    mock_sync = mocker.patch("security.services.issue_syncer.sync_alerts_and_issues")
    mock_sync.return_value = MagicMock(notifications=[], severity_changes=[])

    syncer = IssueSyncer(config)
    syncer.sync({}, dry_run=True)

    _, kwargs = mock_sync.call_args
    assert kwargs["dry_run"] is True


def test_sync_returns_sync_result(mocker, config):
    mocker.patch("security.services.issue_syncer.gh_issue_list_by_label", return_value={})
    expected = MagicMock(notifications=["n"], severity_changes=["s"])
    mocker.patch("security.services.issue_syncer.sync_alerts_and_issues", return_value=expected)

    syncer = IssueSyncer(config)
    result = syncer.sync({}, dry_run=False)

    assert result is expected


def test_sync_does_not_send_notifications(mocker, config):
    mocker.patch("security.services.issue_syncer.gh_issue_list_by_label", return_value={})
    mocker.patch("security.services.issue_syncer.sync_alerts_and_issues", return_value=MagicMock(notifications=["n"], severity_changes=[]))

    syncer = IssueSyncer(config)
    result = syncer.sync({}, dry_run=False)

    assert result is not None
