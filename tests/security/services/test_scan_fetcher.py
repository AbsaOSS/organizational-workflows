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

"""Tests for security.services.scan_fetcher module."""

import json

import pytest

from security.services.scan_fetcher import ScanFetcher


# fetch_findings


def test_fetch_findings_returns_single_page_results(mocker):
    fetcher = ScanFetcher("test_token", "abc12345-e89b-12d3-a456-426614174000")
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"total": 2, "data": [{"id": 1}, {"id": 2}]}
    mocker.patch("security.services.scan_fetcher.requests.get", return_value=mock_response)

    actual = fetcher.fetch_findings()

    assert 2 == actual["total"]
    assert 2 == len(actual["data"])
    assert {"id": 1} == actual["data"][0]


def test_fetch_findings_returns_multi_page_results(mocker):
    fetcher = ScanFetcher("test_token", "abc12345-e89b-12d3-a456-426614174000")

    mock_response_page1 = mocker.Mock()
    mock_response_page1.status_code = 200
    mock_response_page1.json.return_value = {"total": 3, "data": [{"id": 1}, {"id": 2}]}

    mock_response_page2 = mocker.Mock()
    mock_response_page2.status_code = 200
    mock_response_page2.json.return_value = {"total": 3, "data": [{"id": 3}]}

    mocker.patch("security.services.scan_fetcher.requests.get", side_effect=[mock_response_page1, mock_response_page2])
    mocker.patch("security.services.scan_fetcher.time.sleep")

    actual = fetcher.fetch_findings()

    assert 3 == actual["total"]
    assert 3 == len(actual["data"])


def test_fetch_findings_returns_empty_results(mocker):
    fetcher = ScanFetcher("test_token", "abc12345-e89b-12d3-a456-426614174000")
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"total": 0, "data": []}
    mocker.patch("security.services.scan_fetcher.requests.get", return_value=mock_response)

    actual = fetcher.fetch_findings()

    assert 0 == actual["total"]
    assert 0 == len(actual["data"])


def test_fetch_findings_raises_system_exit_on_non_200_status(mocker):
    fetcher = ScanFetcher("test_token", "abc12345-e89b-12d3-a456-426614174000")
    mock_response = mocker.Mock()
    mock_response.status_code = 403
    mock_response.text = "Access denied"
    mocker.patch("security.services.scan_fetcher.requests.get", return_value=mock_response)

    with pytest.raises(SystemExit, match="Status 403"):
        fetcher.fetch_findings()


def test_fetch_findings_raises_system_exit_on_invalid_json(mocker):
    fetcher = ScanFetcher("test_token", "abc12345-e89b-12d3-a456-426614174000")
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "doc", 0)
    mocker.patch("security.services.scan_fetcher.requests.get", return_value=mock_response)

    with pytest.raises(SystemExit, match="Invalid JSON"):
        fetcher.fetch_findings()


def test_fetch_findings_uses_correct_request_structure(mocker):
    fetcher = ScanFetcher("test_token_123", "abc12345-e89b-12d3-a456-426614174000")
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"total": 0, "data": []}
    mock_get = mocker.patch("security.services.scan_fetcher.requests.get", return_value=mock_response)

    fetcher.fetch_findings()

    call_args = mock_get.call_args
    assert "Bearer test_token_123" == call_args[1]["headers"]["Authorization"]
    assert "abc12345-e89b-12d3-a456-426614174000" in call_args[0][0]
    assert "size=100" in call_args[0][0]
    assert "page=1" in call_args[0][0]


def test_fetch_findings_raises_system_exit_on_request_exception(mocker):
    import requests

    fetcher = ScanFetcher("test_token", "abc12345-e89b-12d3-a456-426614174000")
    mocker.patch(
        "security.services.scan_fetcher.requests.get",
        side_effect=requests.RequestException("Connection failed"),
    )

    with pytest.raises(SystemExit, match="request failed"):
        fetcher.fetch_findings()
