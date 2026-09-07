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

import json
import logging

import pytest
import requests
from pytest_mock import MockerFixture

from security.issues.models import IssueChange, SyncResult
from security.services.notification_sender import NotificationSender

REPO = "org/repo"
WEBHOOK = "https://hook.example.com"


@pytest.fixture
def config(mocker: MockerFixture) -> object:
    return mocker.MagicMock(
        repo=REPO,
        teams_webhook_url=WEBHOOK,
        security_label="scope:security",
        min_severity="medium",
        github_server_url="https://github.com",
        github_run_id="12345",
    )


@pytest.fixture
def result() -> SyncResult:
    return SyncResult(
        issue_changes=[
            IssueChange(repo=REPO, issue_number=10, severity="high", rule_id="AVD-001", state="new")
        ],
        open_child_issues_by_severity={"high": 2},
    )


@pytest.fixture
def post(mocker: MockerFixture) -> MockerFixture:
    mock = mocker.patch("security.services.notification_sender.requests.post")
    mock.return_value.ok = True
    mock.return_value.status_code = 200
    mock.return_value.text = "1"
    return mock


# notify


def test_notify_sends_a_single_card(config: object, result: SyncResult, post: MockerFixture) -> None:
    NotificationSender(config).notify(result, dry_run=False)

    payload = json.loads(post.call_args.kwargs["data"].decode("utf-8"))
    assert 1 == len(payload["attachments"])
    assert REPO in json.dumps(payload)


def test_notify_logs_summary_and_payload(
    config: object, result: SyncResult, post: MockerFixture, caplog: pytest.LogCaptureFixture
) -> None:
    """Operators get a one-line confirmation, with the full card only under debug."""
    caplog.set_level(logging.DEBUG)

    NotificationSender(config).notify(result, dry_run=False)

    info = [r.message for r in caplog.records if r.levelno == logging.INFO]
    assert any(f"Teams notification for {REPO}: 1 issue change(s)" in m for m in info)
    assert any("Notification sent to Teams successfully" in m for m in info)
    assert any("Teams notification payload:" in r.message for r in caplog.records if r.levelno == logging.DEBUG)


def test_notify_skips_when_no_webhook(
    config: object, result: SyncResult, post: MockerFixture, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    config.teams_webhook_url = ""

    NotificationSender(config).notify(result, dry_run=False)

    post.assert_not_called()
    assert "Teams webhook URL not configured" in caplog.text


def test_notify_skips_when_run_changed_nothing(
    config: object, post: MockerFixture, caplog: pytest.LogCaptureFixture
) -> None:
    """Quiet runs stay silent instead of posting an empty report."""
    caplog.set_level(logging.INFO)
    NotificationSender(config).notify(SyncResult(issue_changes=[]), dry_run=False)

    post.assert_not_called()
    assert "No issue activity" in caplog.text


def test_notify_dry_run_logs_without_posting(
    config: object, result: SyncResult, post: MockerFixture, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    NotificationSender(config).notify(result, dry_run=True)

    post.assert_not_called()
    assert "Would send Teams notification" in caplog.text


# _build_payload


def test_build_payload_degrades_when_oversized(
    config: object, result: SyncResult, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
) -> None:
    """An oversized card is silently dropped by Teams, so the issue list is trimmed locally."""
    caplog.set_level(logging.WARNING)
    mocker.patch("security.services.notification_sender.TEAMS_CARD_MAX_BYTES", 10)

    payload = NotificationSender(config)._build_payload(result)

    assert "exceeds" in caplog.text
    assert "...and 1 more" in json.dumps(payload)


# send


def test_send_posts_utf8_with_charset(config: object, result: SyncResult, post: MockerFixture) -> None:
    """Teams only renders emoji when the charset is declared and the body is UTF-8 encoded."""
    NotificationSender(config).notify(result, dry_run=False)

    assert WEBHOOK == post.call_args.args[0]
    assert "application/json; charset=utf-8" == post.call_args.kwargs["headers"]["Content-Type"]
    data = post.call_args.kwargs["data"]
    assert isinstance(data, bytes)
    assert "🟠" in data.decode("utf-8")


def test_send_reports_failure_on_error_response(
    config: object, result: SyncResult, post: MockerFixture, caplog: pytest.LogCaptureFixture
) -> None:
    """The sync already wrote to GitHub, so a rejected webhook is reported, not fatal."""
    post.return_value.ok = False
    post.return_value.status_code = 413
    post.return_value.text = "Request Entity too large"

    assert NotificationSender(config).notify(result, dry_run=False) is False
    assert "rejected the message" in caplog.text
    assert "413" in caplog.text


def test_send_reports_failure_on_request_exception(
    config: object, result: SyncResult, post: MockerFixture, caplog: pytest.LogCaptureFixture
) -> None:
    """A network error must not abort the run either."""
    post.side_effect = requests.RequestException("boom")

    assert NotificationSender(config).notify(result, dry_run=False) is False
    assert "boom" in caplog.text


@pytest.mark.parametrize(
    "body",
    [
        "Microsoft Teams endpoint returned HTTP error 429",
        "Request Entity too large",
        "Invalid webhook payload",
        "Summary or Text is required.",
    ],
)
def test_send_reports_failure_when_success_status_carries_an_error_body(
    config: object, result: SyncResult, post: MockerFixture, body: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Teams reports failures inside 200-level responses, so the body must be inspected."""
    post.return_value.text = body

    assert NotificationSender(config).notify(result, dry_run=False) is False
    assert "rejected the message" in caplog.text


@pytest.mark.parametrize("body", ["1", "", "   "])
def test_send_accepts_documented_success_bodies(
    config: object, result: SyncResult, post: MockerFixture, body: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A successful post returns either ``1`` or an empty body."""
    caplog.set_level(logging.INFO)
    post.return_value.text = body

    assert NotificationSender(config).notify(result, dry_run=False) is True
    assert "Notification sent to Teams successfully" in caplog.text


def test_send_reports_failure_when_body_is_unrecognized(
    config: object, result: SyncResult, post: MockerFixture, caplog: pytest.LogCaptureFixture
) -> None:
    """A body that isn't a documented success value is treated as a rejection, not a guess."""
    post.return_value.text = "something unexpected"

    assert NotificationSender(config).notify(result, dry_run=False) is False
    assert "rejected the message" in caplog.text
