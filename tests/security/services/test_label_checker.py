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

"""Unit tests for ``security.services.label_checker``."""

import json
import subprocess

import pytest
from pytest_mock import MockerFixture

from security.constants import REQUIRED_LABELS
from security.services.label_checker import LabelChecker


REPO = "my-org/my-repo"


def _gh_result(labels: list[str]) -> subprocess.CompletedProcess:
    payload = json.dumps([{"name": n} for n in labels])
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr="")


# _fetch_labels


def test_fetch_labels_returns_names(mocker: MockerFixture) -> None:
    mock_gh = mocker.patch("security.services.label_checker.run_gh", return_value=_gh_result(["scope:security", "epic"]))
    checker = LabelChecker(REPO)
    assert checker._fetch_labels() == ["scope:security", "epic"]
    mock_gh.assert_called_once_with(
        ["label", "list", "--repo", REPO, "--json", "name", "--limit", "500"],
    )


def test_fetch_labels_skips_empty_names(mocker: MockerFixture) -> None:
    payload = json.dumps([{"name": "good"}, {"name": ""}, {}])
    mocker.patch(
        "security.services.label_checker.run_gh",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr=""),
    )
    assert LabelChecker(REPO)._fetch_labels() == ["good"]


def test_fetch_labels_raises_on_gh_failure(mocker: MockerFixture) -> None:
    mocker.patch(
        "security.services.label_checker.run_gh",
        return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error"),
    )
    with pytest.raises(SystemExit):
        LabelChecker(REPO)._fetch_labels()


# check_labels


def test_check_labels_all_present(mocker: MockerFixture) -> None:
    mocker.patch.object(LabelChecker, "_fetch_labels", return_value=list(REQUIRED_LABELS) + ["extra"])
    assert LabelChecker(REPO).check_labels() == []


def test_check_labels_some_missing(mocker: MockerFixture) -> None:
    mocker.patch.object(LabelChecker, "_fetch_labels", return_value=["scope:security", "epic"])
    missing = LabelChecker(REPO).check_labels()
    assert "type:tech-debt" in missing
    assert len(missing) == 1


def test_check_labels_all_missing(mocker: MockerFixture) -> None:
    mocker.patch.object(LabelChecker, "_fetch_labels", return_value=[])
    assert LabelChecker(REPO).check_labels() == list(REQUIRED_LABELS)


def test_check_labels_custom_required(mocker: MockerFixture) -> None:
    mocker.patch.object(LabelChecker, "_fetch_labels", return_value=["a"])
    assert LabelChecker(REPO, required=["a", "b"]).check_labels() == ["b"]
