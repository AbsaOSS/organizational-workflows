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

import pytest

from security.services.authenticator import AquaSecAuthenticator


# _generate_signature


def test_generate_signature_returns_hex_string():
    authenticator = AquaSecAuthenticator("key", "test_secret", "1234")

    actual = authenticator._generate_signature("test_string")

    assert isinstance(actual, str)
    assert 64 == len(actual)


# authenticate


def test_authenticate_returns_bearer_token(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "bearer_token_123"}
    mocker.patch("security.services.authenticator.requests.post", return_value=mock_response)

    actual = AquaSecAuthenticator("test_key", "test_secret", "1234").authenticate()

    assert "bearer_token_123" == actual


def test_authenticate_raises_system_exit_on_non_200_status(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 403
    mock_response.text = "Access denied"
    mocker.patch("security.services.authenticator.requests.post", return_value=mock_response)

    with pytest.raises(SystemExit, match="Status 403"):
        AquaSecAuthenticator("test_key", "test_secret", "1234").authenticate()


def test_authenticate_raises_system_exit_when_token_missing(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": ""}
    mocker.patch("security.services.authenticator.requests.post", return_value=mock_response)

    with pytest.raises(SystemExit, match="missing bearer token"):
        AquaSecAuthenticator("test_key", "test_secret", "1234").authenticate()


def test_authenticate_uses_any_wildcard_endpoint(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "bearer_token_123"}
    mock_post = mocker.patch("security.services.authenticator.requests.post", return_value=mock_response)

    AquaSecAuthenticator("test_key", "test_secret", "1234").authenticate()

    post_body = mock_post.call_args[1]["data"]
    assert '"ANY:*"' in post_body


def test_authenticate_raises_system_exit_on_request_exception(mocker):
    import requests

    mocker.patch(
        "security.services.authenticator.requests.post",
        side_effect=requests.RequestException("Connection failed"),
    )

    with pytest.raises(SystemExit, match="request failed"):
        AquaSecAuthenticator("test_key", "test_secret", "1234").authenticate()
