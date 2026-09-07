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

"""Unit tests for ``security.notifications.links``."""

from security.constants import AQUA_PLATFORM_URL
from security.notifications.links import NotificationLinks

REPO = "org/repo"
SERVER = "https://github.com"


def _build(**overrides: str) -> NotificationLinks:
    params = {"repo": REPO, "security_label": "scope:security", "server_url": SERVER, "run_id": "12345"}
    params.update(overrides)
    return NotificationLinks.build(**params)


# build


def test_build_creates_run_and_repo_links() -> None:
    links = _build()

    assert REPO == links.repo
    assert f"{SERVER}/{REPO}/actions/runs/12345" == links.run_url
    assert AQUA_PLATFORM_URL == links.aqua_url


def test_build_encodes_the_issue_search_query() -> None:
    """The label filter contains spaces and colons, which must survive as a query value."""
    links = _build()

    assert links.repo_url.startswith(f"{SERVER}/{REPO}/issues?q=")
    assert " " not in links.repo_url
    assert "is%3Aissue%20is%3Aopen%20label%3Ascope%3Asecurity" in links.repo_url


def test_build_omits_run_link_without_run_id() -> None:
    """Outside GitHub Actions there is no run id, so the link is dropped, not left broken."""
    assert "" == _build(run_id="").run_url


def test_build_falls_back_to_public_github() -> None:
    assert _build(server_url="").run_url.startswith("https://github.com/")


def test_build_honours_enterprise_server_url() -> None:
    links = _build(server_url="https://github.absa.co.za")

    assert links.run_url.startswith("https://github.absa.co.za/")
    assert links.repo_url.startswith("https://github.absa.co.za/")


def test_build_without_repo_yields_no_links() -> None:
    links = _build(repo="")

    assert "" == links.run_url
    assert "" == links.repo_url
