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

"""Unit tests for ``shared.github_issues`` – all ``gh`` CLI calls are mocked
via ``run_gh``; ``time.sleep`` is always patched to keep tests instant.
"""

import subprocess
from typing import Any

import pytest
from pytest_mock import MockerFixture

from shared.github_issues import (
    _gh_with_retry,
    _is_not_found_error,
    _not_found_hint,
    gh_issue_add_labels,
    gh_issue_add_sub_issue,
    gh_issue_add_sub_issue_by_number,
    gh_issue_comment,
    gh_issue_create,
    gh_issue_edit_body,
    gh_issue_edit_state,
    gh_issue_edit_title,
    gh_issue_get_rest_id,
    gh_issue_get_sub_issue_numbers,
    gh_issue_list_by_label,
)


def _completed(*, returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    """Build a fake ``subprocess.CompletedProcess`` result."""
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _ok(**kwargs: Any) -> subprocess.CompletedProcess:
    return _completed(returncode=0, **kwargs)


def _err(stderr: str = "some error", **kwargs: Any) -> subprocess.CompletedProcess:
    return _completed(returncode=1, stderr=stderr, **kwargs)


def _not_found(via: str = "stderr") -> subprocess.CompletedProcess:
    """Return a 404-style failure (both REST and GraphQL flavours are covered by separate tests)."""
    if via == "stdout":
        return _completed(returncode=1, stdout="Not Found", stderr="")
    return _completed(returncode=1, stderr="gh: Not Found (HTTP 404)")


def test_is_not_found_http404_in_stderr() -> None:
    assert _is_not_found_error(_completed(returncode=1, stderr="gh: Not Found (HTTP 404)")) is True

def test_is_not_found_not_found_in_stdout() -> None:
    assert _is_not_found_error(_completed(returncode=1, stdout="Not Found", stderr="")) is True

def test_is_not_found_graphql_message() -> None:
    assert _is_not_found_error(
        _completed(returncode=1, stderr="GraphQL: Could not resolve to an issue or pull request with the number of 42. (repository.issue)")
    ) is True

def test_is_not_found_unrelated_error() -> None:
    assert _is_not_found_error(_completed(returncode=1, stderr="gh: timeout")) is False

def test_is_not_found_success_response() -> None:
    assert _is_not_found_error(_ok(stdout="12345")) is False


def test_not_found_hint_returns_hint_on_404() -> None:
    hint = _not_found_hint(_not_found())
    assert "deleted or transferred" in hint
    assert hint.startswith(" (")

def test_not_found_hint_empty_on_other_error() -> None:
    assert _not_found_hint(_err("rate limit exceeded")) == ""

def test_not_found_hint_empty_on_success() -> None:
    assert _not_found_hint(_ok()) == ""


def test_retry_succeeds_first_attempt(mocker: MockerFixture) -> None:
    """No retries when the first call succeeds."""
    mock_run = mocker.patch("shared.github_issues.run_gh", return_value=_ok(stdout="ok"))
    mock_sleep = mocker.patch("shared.github_issues.time.sleep")
    result = _gh_with_retry(["some", "cmd"])
    assert result.returncode == 0
    mock_run.assert_called_once()
    mock_sleep.assert_not_called()

def test_retry_succeeds_on_second_attempt(mocker: MockerFixture) -> None:
    """Retries once on 404 then succeeds."""
    mock_run = mocker.patch(
        "shared.github_issues.run_gh",
        side_effect=[_not_found(), _ok(stdout="42")],
    )
    mocker.patch("shared.github_issues.time.sleep")
    result = _gh_with_retry(["some", "cmd"], retries=3)
    assert result.returncode == 0
    assert mock_run.call_count == 2

def test_retry_exhausts_all_attempts(mocker: MockerFixture) -> None:
    """Returns the last failure after all retries are consumed."""
    mock_run = mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    mocker.patch("shared.github_issues.time.sleep")
    result = _gh_with_retry(["some", "cmd"], retries=3)
    assert result.returncode != 0
    # 1 initial + 3 retries = 4 total
    assert mock_run.call_count == 4

def test_retry_does_not_retry_non_404_error(mocker: MockerFixture) -> None:
    """Non-404 errors are not retried."""
    mock_run = mocker.patch("shared.github_issues.run_gh", return_value=_err("server error"))
    mocker.patch("shared.github_issues.time.sleep")
    result = _gh_with_retry(["some", "cmd"], retries=3)
    assert result.returncode != 0
    mock_run.assert_called_once()  # no retries

def test_retry_sleeps_with_exponential_backoff(mocker: MockerFixture) -> None:
    """Sleep duration grows as backoff_base ** attempt."""
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    mock_sleep = mocker.patch("shared.github_issues.time.sleep")
    _gh_with_retry(["cmd"], retries=3, backoff_base=2.0)
    sleep_calls = [c.args[0] for c in mock_sleep.call_args_list]
    # attempts 1, 2, 3 → 2**1=2, 2**2=4, 2**3=8
    assert sleep_calls == [2.0, 4.0, 8.0]

def test_retry_zero_retries_no_sleep(mocker: MockerFixture) -> None:
    """retries=0 means a single attempt with no sleep."""
    mock_run = mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    mock_sleep = mocker.patch("shared.github_issues.time.sleep")
    _gh_with_retry(["cmd"], retries=0)
    mock_run.assert_called_once()
    mock_sleep.assert_not_called()


def test_get_rest_id_success(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok(stdout="987654\n"))
    mocker.patch("shared.github_issues.time.sleep")
    assert gh_issue_get_rest_id("org/repo", 42) == 987654

def test_get_rest_id_retries_on_404(mocker: MockerFixture) -> None:
    mock_run = mocker.patch(
        "shared.github_issues.run_gh",
        side_effect=[_not_found(), _ok(stdout="1111\n")],
    )
    mocker.patch("shared.github_issues.time.sleep")
    result = gh_issue_get_rest_id("org/repo", 5)
    assert result == 1111
    assert mock_run.call_count == 2

def test_get_rest_id_returns_none_after_all_retries(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    mocker.patch("shared.github_issues.time.sleep")
    assert gh_issue_get_rest_id("org/repo", 5) is None

def test_get_rest_id_parse_failure(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok(stdout="not-a-number"))
    mocker.patch("shared.github_issues.time.sleep")
    assert gh_issue_get_rest_id("org/repo", 1) is None

def test_get_rest_id_not_found_hint_in_log(mocker: MockerFixture, caplog) -> None:
    """Log message includes the not-found hint for 404 errors."""
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    mocker.patch("shared.github_issues.time.sleep")
    import logging
    with caplog.at_level(logging.WARNING, logger="root"):
        gh_issue_get_rest_id("org/repo", 99)
    assert any("deleted or transferred" in r.message for r in caplog.records)


def test_add_sub_issue_success(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok())
    assert gh_issue_add_sub_issue("org/repo", 10, 9999) is True

def test_add_sub_issue_failure_logs_hint(mocker: MockerFixture, caplog) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        result = gh_issue_add_sub_issue("org/repo", 10, 9999)
    assert result is False
    assert any("deleted or transferred" in r.message for r in caplog.records)

def test_add_sub_issue_failure_plain_error(mocker: MockerFixture, caplog) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_err("rate limited"))
    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        result = gh_issue_add_sub_issue("org/repo", 10, 9999)
    assert result is False
    assert not any("deleted or transferred" in r.message for r in caplog.records)


def test_add_sub_issue_by_number_success(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", side_effect=[_ok(stdout="5555\n"), _ok()])
    mocker.patch("shared.github_issues.time.sleep")
    assert gh_issue_add_sub_issue_by_number("org/repo", 10, 42) is True

def test_add_sub_issue_by_number_rest_id_fails(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    mocker.patch("shared.github_issues.time.sleep")
    assert gh_issue_add_sub_issue_by_number("org/repo", 10, 42) is False


def test_get_sub_issue_numbers_success(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok(stdout="[1, 2, 3]\n"))
    assert gh_issue_get_sub_issue_numbers("org/repo", 10) == {1, 2, 3}

def test_get_sub_issue_numbers_empty(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok(stdout="[]\n"))
    assert gh_issue_get_sub_issue_numbers("org/repo", 10) == set()

def test_get_sub_issue_numbers_not_found_warning(mocker: MockerFixture, caplog) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    import logging
    with caplog.at_level(logging.WARNING, logger="root"):
        result = gh_issue_get_sub_issue_numbers("org/repo", 10)
    assert result == set()
    assert any("deleted or transferred" in r.message for r in caplog.records)

def test_get_sub_issue_numbers_parse_error(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok(stdout="not-json"))
    assert gh_issue_get_sub_issue_numbers("org/repo", 10) == set()


def test_issue_comment_success(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok())
    mocker.patch("shared.github_issues.time.sleep")
    assert gh_issue_comment("org/repo", 1, "hello") is True

def test_issue_comment_retries_on_404(mocker: MockerFixture) -> None:
    mock_run = mocker.patch(
        "shared.github_issues.run_gh",
        side_effect=[_not_found(), _ok()],
    )
    mocker.patch("shared.github_issues.time.sleep")
    assert gh_issue_comment("org/repo", 1, "hello") is True
    assert mock_run.call_count == 2

def test_issue_comment_fails_after_all_retries(mocker: MockerFixture, caplog) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    mocker.patch("shared.github_issues.time.sleep")
    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        result = gh_issue_comment("org/repo", 1, "hello")
    assert result is False
    assert any("deleted or transferred" in r.message for r in caplog.records)

def test_issue_comment_graphql_not_found_hint(mocker: MockerFixture, caplog) -> None:
    """GraphQL-style 404 also triggers the not-found hint."""
    graphql_err = _completed(
        returncode=1,
        stderr="GraphQL: Could not resolve to an issue or pull request with the number of 42. (repository.issue)",
    )
    mocker.patch("shared.github_issues.run_gh", return_value=graphql_err)
    mocker.patch("shared.github_issues.time.sleep")
    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        gh_issue_comment("org/repo", 42, "body")
    assert any("deleted or transferred" in r.message for r in caplog.records)


def test_edit_state_success(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok())
    assert gh_issue_edit_state("org/repo", 1, "open") is True

def test_edit_state_not_found_hint(mocker: MockerFixture, caplog) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        result = gh_issue_edit_state("org/repo", 1, "open")
    assert result is False
    assert any("deleted or transferred" in r.message for r in caplog.records)

def test_edit_state_invalid_state_raises() -> None:
    with pytest.raises(ValueError, match="Unsupported issue state"):
        gh_issue_edit_state("org/repo", 1, "unknown")


def test_edit_title_success(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok())
    assert gh_issue_edit_title("org/repo", 1, "New title") is True

def test_edit_title_not_found_hint(mocker: MockerFixture, caplog) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        result = gh_issue_edit_title("org/repo", 1, "New title")
    assert result is False
    assert any("deleted or transferred" in r.message for r in caplog.records)


def test_edit_body_success(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok())
    assert gh_issue_edit_body("org/repo", 1, "new body") is True

def test_edit_body_not_found_hint(mocker: MockerFixture, caplog) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        result = gh_issue_edit_body("org/repo", 1, "new body")
    assert result is False
    assert any("deleted or transferred" in r.message for r in caplog.records)


def test_add_labels_success(mocker: MockerFixture) -> None:
    mock_run = mocker.patch("shared.github_issues.run_gh", return_value=_ok())
    gh_issue_add_labels("org/repo", 1, ["bug", "security"])
    mock_run.assert_called_once()

def test_add_labels_no_labels_skips_call(mocker: MockerFixture) -> None:
    mock_run = mocker.patch("shared.github_issues.run_gh")
    gh_issue_add_labels("org/repo", 1, [])
    mock_run.assert_not_called()

def test_add_labels_not_found_hint(mocker: MockerFixture, caplog) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_not_found())
    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        gh_issue_add_labels("org/repo", 1, ["bug"])
    assert any("deleted or transferred" in r.message for r in caplog.records)


def test_create_issue_success_url(mocker: MockerFixture) -> None:
    mocker.patch(
        "shared.github_issues.run_gh",
        return_value=_ok(stdout="https://github.com/org/repo/issues/123\n"),
    )
    num = gh_issue_create("org/repo", "title", "body", ["label"])
    assert num == 123

def test_create_issue_success_bare_number(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_ok(stdout="issues/456"))
    assert gh_issue_create("org/repo", "t", "b", []) == 456

def test_create_issue_failure_returns_none(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_err("permission denied"))
    assert gh_issue_create("org/repo", "t", "b", []) is None


def test_list_by_label_success(mocker: MockerFixture) -> None:
    payload = [
        {"number": 1, "state": "open", "title": "T1", "body": "b1", "labels": [{"name": "bug"}]},
        {"number": 2, "state": "closed", "title": "T2", "body": "b2", "labels": []},
    ]
    import json
    mocker.patch("shared.github_issues.run_gh", return_value=_ok(stdout=json.dumps(payload)))
    issues = gh_issue_list_by_label("org/repo", "bug")
    assert len(issues) == 2
    assert issues[1].title == "T1"
    assert issues[1].labels == ["bug"]
    assert issues[2].labels == []

def test_list_by_label_empty_label_returns_empty(mocker: MockerFixture) -> None:
    mock_run = mocker.patch("shared.github_issues.run_gh")
    assert gh_issue_list_by_label("org/repo", "") == {}
    mock_run.assert_not_called()

def test_list_by_label_gh_failure_returns_empty(mocker: MockerFixture) -> None:
    mocker.patch("shared.github_issues.run_gh", return_value=_err("network error"))
    assert gh_issue_list_by_label("org/repo", "bug") == {}
