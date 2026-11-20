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

import json

import pytest
import requests

from security.constants import HTTP_TIMEOUT
from security.services.repository_fetcher import RepositoryFetcher


REPO = "my-org/my-repo"
REPOSITORY_ID = "abc12345-e89b-12d3-a456-426614174000"
MATCH = {"full_name": REPO, "source": "github", "repository_id": REPOSITORY_ID}


# fetch_repository_id


def test_fetch_repository_id_matches_exact_github_identity(repository_lookup, repository_response):
    repository_lookup.return_value = repository_response([
        {"full_name": "other-org/my-repo", "source": "github"},
        {"full_name": "my-org/my-repo-extra", "source": "github"},
        MATCH,
    ])

    assert REPOSITORY_ID == RepositoryFetcher("token").fetch_repository_id(REPO)

    repository_lookup.assert_called_once_with(
        "https://api.eu-1.supply-chain.cloud.aquasec.com/v2/build/repositories",
        headers={"Authorization": "Bearer token", "Accept": "application/json"},
        params={"name": "my-repo", "page": 1, "page_size": 25},
        timeout=HTTP_TIMEOUT,
    )


def test_fetch_repository_id_paginates_filtered_results_and_deduplicates_uuid(repository_lookup, repository_response):
    repository_lookup.side_effect = [
        repository_response([{"full_name": "other-org/my-repo", "source": "github"}], total=3),
        repository_response([MATCH], page=2, total=3),
        repository_response([{**MATCH, "repository_id": REPOSITORY_ID.upper()}], page=3, total=3),
    ]

    assert REPOSITORY_ID == RepositoryFetcher("token").fetch_repository_id(REPO)
    assert [1, 2, 3] == [call.kwargs["params"]["page"] for call in repository_lookup.call_args_list]


def test_fetch_repository_id_rejects_ambiguity_on_a_later_page(repository_lookup, repository_response):
    repository_lookup.side_effect = [
        repository_response([MATCH], total=2),
        repository_response(
            [{**MATCH, "repository_id": "00000000-0000-0000-0000-000000000001"}], page=2, total=2
        ),
    ]

    with pytest.raises(SystemExit, match=f"Multiple AquaSec repository UUIDs.*{REPO}"):
        RepositoryFetcher("token").fetch_repository_id(REPO)


@pytest.mark.parametrize(("data", "error"), [
    ([], "not found"),
    ([{"full_name": REPO, "source": "github"}], "invalid UUID"),
    ([{**MATCH, "repository_id": "not-a-uuid"}], "invalid UUID"),
])
def test_fetch_repository_id_rejects_missing_or_invalid_match(repository_lookup, repository_response, data, error):
    repository_lookup.return_value = repository_response(data)

    with pytest.raises(SystemExit, match=f"{error}.*{REPO}"):
        RepositoryFetcher("token").fetch_repository_id(REPO)


@pytest.mark.parametrize(("failure", "error"), [
    ("request", "request failed"),
    ("status", "Status 403"),
    ("json", "Invalid JSON"),
])
def test_fetch_repository_id_propagates_api_failures(repository_lookup, repository_response, failure, error):
    response = repository_response([])
    repository_lookup.return_value = response
    if failure == "request":
        repository_lookup.side_effect = requests.RequestException("Connection failed")
    elif failure == "status":
        response.status_code = 403
    else:
        response.json.side_effect = json.JSONDecodeError("Invalid JSON", "doc", 0)

    with pytest.raises(SystemExit, match=f"{error}.*{REPO}|{REPO}.*{error}"):
        RepositoryFetcher("token").fetch_repository_id(REPO)


@pytest.mark.parametrize("payload", [
    [],
    {},
    {"data": None},
    {"data": [None], "current_page": 1, "returned_count": 1, "total_count": 1},
    {"data": [], "current_page": 1, "returned_count": 1, "total_count": 1},
    {"data": [], "current_page": 1, "returned_count": 0, "total_count": -1},
    {"data": [], "current_page": 1, "returned_count": 0, "total_count": "1"},
])
def test_fetch_repository_id_rejects_malformed_response(repository_lookup, repository_response, payload):
    response = repository_response([])
    response.json.return_value = payload
    repository_lookup.return_value = response

    with pytest.raises(SystemExit, match=f"Invalid AquaSec repository discovery.*{REPO}"):
        RepositoryFetcher("token").fetch_repository_id(REPO)


@pytest.mark.parametrize(("page", "total", "data"), [
    (1, 2, [MATCH]),
    (2, 3, [MATCH]),
    (2, 2, []),
    (2, 2, [MATCH, MATCH]),
])
def test_fetch_repository_id_rejects_incomplete_or_inconsistent_pagination(
    repository_lookup, repository_response, page, total, data
):
    repository_lookup.side_effect = [
        repository_response([MATCH], total=2),
        repository_response(data, page=page, total=total),
    ]

    with pytest.raises(SystemExit, match=f"pagination.*{REPO}"):
        RepositoryFetcher("token").fetch_repository_id(REPO)
