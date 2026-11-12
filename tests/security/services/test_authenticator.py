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

"""Tests for security.services.authenticator module."""

import hashlib
import hmac
import json

import pytest
import requests

from security.services.authenticator import AquaSecAuthenticator


# _generate_signature


def test_generate_signature_returns_hex_string():
    authenticator = AquaSecAuthenticator("key", "test_secret")

    actual = authenticator._generate_signature("test_string")

    assert isinstance(actual, str)
    assert 64 == len(actual)


# authenticate


def test_authenticate_returns_bearer_token(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "bearer_token_123"}
    mocker.patch("security.services.authenticator.requests.post", return_value=mock_response)

    actual = AquaSecAuthenticator("test_key", "test_secret").authenticate()

    assert "bearer_token_123" == actual


def test_authenticate_raises_system_exit_on_non_200_status(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 403
    mock_response.text = "Access denied"
    mocker.patch("security.services.authenticator.requests.post", return_value=mock_response)

    with pytest.raises(SystemExit, match="Status 403"):
        AquaSecAuthenticator("test_key", "test_secret").authenticate()


def test_authenticate_raises_system_exit_when_token_missing(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": ""}
    mocker.patch("security.services.authenticator.requests.post", return_value=mock_response)

    with pytest.raises(SystemExit, match="missing bearer token"):
        AquaSecAuthenticator("test_key", "test_secret").authenticate()


def test_authenticate_signs_request_without_group_id(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "bearer_token_123"}
    mock_post = mocker.patch("security.services.authenticator.requests.post", return_value=mock_response)
    mocker.patch("security.services.authenticator.time.time", return_value=1700000000)

    AquaSecAuthenticator("test_key", "test_secret").authenticate()

    post_body = mock_post.call_args[1]["data"]
    headers = mock_post.call_args[1]["headers"]
    assert {"allowed_endpoints": ["ANY:*"], "validity": 240} == json.loads(post_body)
    expected_signature = hmac.new(
        b"test_secret",
        f"1700000000POST/v2/tokens{post_body}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert "1700000000" == headers["X-Timestamp"]
    assert expected_signature == headers["X-Signature"]


def test_authenticate_raises_system_exit_on_request_exception(mocker):
    mocker.patch(
        "security.services.authenticator.requests.post",
        side_effect=requests.RequestException("Connection failed"),
    )

    with pytest.raises(SystemExit, match="request failed"):
        AquaSecAuthenticator("test_key", "test_secret").authenticate()
