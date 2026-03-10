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

"""Unit tests for ``check_labels.py``."""

import json
import subprocess

import pytest
from pytest_mock import MockerFixture

from check_labels import REQUIRED_LABELS, check_labels, fetch_repo_labels, main


REPO = "my-org/my-repo"


def _gh_result(labels: list[str]) -> subprocess.CompletedProcess:
    """Build a fake ``run_gh`` return value."""
    payload = json.dumps([{"name": n} for n in labels])
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr="")


def test_fetch_repo_labels_returns_names(mocker: MockerFixture) -> None:
    mock_gh = mocker.patch("check_labels.run_gh", return_value=_gh_result(["scope:security", "epic"]))
    assert fetch_repo_labels(REPO) == ["scope:security", "epic"]
    mock_gh.assert_called_once_with(
        ["label", "list", "--repo", REPO, "--json", "name", "--limit", "500"],
    )


def test_fetch_repo_labels_skips_empty_names(mocker: MockerFixture) -> None:
    payload = json.dumps([{"name": "good"}, {"name": ""}, {}])
    mocker.patch(
        "check_labels.run_gh",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr=""),
    )
    assert fetch_repo_labels(REPO) == ["good"]


def test_check_labels_all_present(mocker: MockerFixture) -> None:
    mocker.patch("check_labels.fetch_repo_labels", return_value=list(REQUIRED_LABELS) + ["extra-label"])
    assert check_labels(REPO) == []


def test_check_labels_some_missing(mocker: MockerFixture) -> None:
    mocker.patch("check_labels.fetch_repo_labels", return_value=["scope:security", "epic"])
    missing = check_labels(REPO)
    assert "type:tech-debt" in missing
    assert "sec:adept-to-close" in missing
    assert len(missing) == 2


def test_check_labels_all_missing(mocker: MockerFixture) -> None:
    mocker.patch("check_labels.fetch_repo_labels", return_value=[])
    assert check_labels(REPO) == list(REQUIRED_LABELS)


def test_check_labels_custom_required(mocker: MockerFixture) -> None:
    mocker.patch("check_labels.fetch_repo_labels", return_value=["a"])
    assert check_labels(REPO, required=["a", "b"]) == ["b"]


def test_main_success(mocker: MockerFixture) -> None:
    mock_check = mocker.patch("check_labels.check_labels", return_value=[])
    assert main(["--repo", REPO]) == 0
    mock_check.assert_called_once_with(REPO)


def test_main_failure(mocker: MockerFixture) -> None:
    mocker.patch("check_labels.check_labels", return_value=["epic"])
    assert main(["--repo", REPO]) == 1


def test_main_missing_repo() -> None:
    with pytest.raises(SystemExit):
        main([])
