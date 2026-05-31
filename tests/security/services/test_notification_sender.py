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

"""Tests for security.services.notification_sender module."""

import pytest
import requests
from unittest.mock import MagicMock

from security.issues.models import NotifiedIssue, SeverityChange
from security.services.notification_sender import NotificationSender


@pytest.fixture
def sample_notifications() -> list[NotifiedIssue]:
    return [
        NotifiedIssue(repo="org/repo-a", issue_number=10, severity="high", category="sast", state="new", tool="AquaSec"),
        NotifiedIssue(repo="org/repo-b", issue_number=20, severity="medium", category="sca", state="reopen", tool="AquaSec"),
    ]


@pytest.fixture
def sample_changes() -> list[SeverityChange]:
    return [
        SeverityChange(repo="org/repo-a", issue_number=5, rule_id="CVE-2026-1234", old_severity="medium", new_severity="critical"),
    ]


# _build_payload


def test_build_payload_without_title():
    payload = NotificationSender._build_payload("Hello **world**")

    assert "message" == payload["type"]
    card = payload["attachments"][0]["content"]
    assert "AdaptiveCard" == card["type"]
    assert 1 == len(card["body"])
    assert "Hello **world**" == card["body"][0]["items"][0]["text"]


def test_build_payload_with_title_and_subtitle():
    payload = NotificationSender._build_payload("Body text", title="My Title", subtitle="Sub")

    card = payload["attachments"][0]["content"]
    assert 2 == len(card["body"])
    header = card["body"][0]
    assert "accent" == header["style"]
    assert "My Title" == header["items"][0]["text"]
    assert "Sub" == header["items"][1]["text"]


# _build_issues_body


def test_build_issues_body_counts(sample_notifications):
    body = NotificationSender._build_issues_body(sample_notifications)
    assert "**1** new" in body
    assert "**1** reopened" in body


def test_build_issues_body_contains_links(sample_notifications):
    body = NotificationSender._build_issues_body(sample_notifications)
    assert "https://github.com/org/repo-a/issues/10" in body
    assert "https://github.com/org/repo-b/issues/20" in body


def test_build_issues_body_state_tags(sample_notifications):
    body = NotificationSender._build_issues_body(sample_notifications)
    assert "[new]" in body
    assert "[reopen]" in body


def test_build_issues_body_pending_issue_number_zero():
    n = NotifiedIssue(repo="org/repo", issue_number=0, severity="high", category="sast", state="new", tool="AquaSec")
    body = NotificationSender._build_issues_body([n])
    assert "(pending)" in body
    assert "issues/0" not in body


# _build_severity_body


def test_build_severity_body_counts(sample_changes):
    body = NotificationSender._build_severity_body(sample_changes)
    assert "**1** parent issue(s)" in body


def test_build_severity_body_contains_link(sample_changes):
    body = NotificationSender._build_severity_body(sample_changes)
    assert "https://github.com/org/repo-a/issues/5" in body


def test_build_severity_body_direction(sample_changes):
    body = NotificationSender._build_severity_body(sample_changes)
    assert "escalated" in body


def test_build_severity_body_severities(sample_changes):
    body = NotificationSender._build_severity_body(sample_changes)
    assert "**medium**" in body
    assert "**critical**" in body


def test_build_severity_body_rule_id(sample_changes):
    body = NotificationSender._build_severity_body(sample_changes)
    assert "CVE-2026-1234" in body


# notify


def test_notify_calls_both_dispatchers(mocker, sample_notifications, sample_changes):
    result = MagicMock(notifications=sample_notifications, severity_changes=sample_changes)
    mock_issues = mocker.patch.object(NotificationSender, "_notify_issues")
    mock_sev = mocker.patch.object(NotificationSender, "_notify_severity_changes")

    NotificationSender("https://hook").notify(result, dry_run=False)

    mock_issues.assert_called_once_with(sample_notifications, dry_run=False)
    mock_sev.assert_called_once_with(sample_changes, dry_run=False)


def test_notify_skips_when_no_webhook(mocker):
    result = MagicMock(notifications=["n"], severity_changes=[])
    mock_issues = mocker.patch.object(NotificationSender, "_notify_issues")

    NotificationSender("").notify(result, dry_run=False)

    mock_issues.assert_not_called()


def test_notify_dry_run_passed_through(mocker, sample_notifications):
    result = MagicMock(notifications=sample_notifications, severity_changes=[])
    mock_issues = mocker.patch.object(NotificationSender, "_notify_issues")
    mocker.patch.object(NotificationSender, "_notify_severity_changes")

    NotificationSender("https://hook").notify(result, dry_run=True)

    _, kwargs = mock_issues.call_args
    assert kwargs["dry_run"] is True


# send


def test_send_posts_to_webhook(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.text = "1"
    mock_post = mocker.patch("security.services.notification_sender.requests.post", return_value=mock_response)

    NotificationSender("https://hook.example.com").send("Test body", title="Title")

    mock_post.assert_called_once()
    assert "https://hook.example.com" == mock_post.call_args[0][0]


def test_send_raises_system_exit_on_non_200(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 500
    mock_response.text = "Internal error"
    mocker.patch("security.services.notification_sender.requests.post", return_value=mock_response)

    with pytest.raises(SystemExit, match="webhook request failed"):
        NotificationSender("https://hook.example.com").send("Test body")


def test_send_raises_system_exit_on_request_exception(mocker):
    mocker.patch(
        "security.services.notification_sender.requests.post",
        side_effect=requests.RequestException("Connection failed"),
    )

    with pytest.raises(SystemExit, match="webhook request failed"):
        NotificationSender("https://hook.example.com").send("Test body")


# send_dry_run


def test_send_dry_run_does_not_post(mocker):
    mock_post = mocker.patch("security.services.notification_sender.requests.post")

    NotificationSender("https://hook.example.com").send_dry_run("Test body", title="Title")

    mock_post.assert_not_called()
