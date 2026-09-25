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

"""Unit tests for ``security.services.label_creator``.

Each method is tested against its own collaborators: ``_fetch_labels`` against the
``gh`` CLI, and ``ensure_labels`` against ``_fetch_labels`` and ``gh_label_create``.
Anything left unmocked is caught by the global guard in ``tests/conftest.py``.
"""

import logging
import subprocess

import pytest
from pytest_mock import MockerFixture

from security.constants import REQUIRED_LABEL_SPECS
from security.services.label_creator import LabelCreator


REPO = "my-org/my-repo"


def _all_label_names() -> list[str]:
    """Every label the pipeline requires, as ``gh api .../labels`` would report them."""
    return [spec.name for spec in REQUIRED_LABEL_SPECS]


def _completed(*, returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    """Build a fake ``subprocess.CompletedProcess`` result."""
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _label_list(*names: str) -> subprocess.CompletedProcess:
    """A successful ``gh api --paginate .../labels --jq '.[].name'`` response for *names*.

    Mirrors ``gh``'s real output: one name per line, with one line per page rather than
    a single JSON document, which is why ``_fetch_labels`` parses lines instead of JSON.
    """
    stdout = "".join(f"{name}\n" for name in names)
    return _completed(stdout=stdout)


# _fetch_labels


def test_fetch_labels_returns_names(mocker: MockerFixture) -> None:
    mock_gh = mocker.patch(
        "security.services.label_creator.run_gh",
        return_value=_label_list("scope:security", "epic"),
    )

    assert LabelCreator(REPO)._fetch_labels() == ["scope:security", "epic"]
    mock_gh.assert_called_once_with(
        ["api", "--paginate", f"repos/{REPO}/labels", "--jq", ".[].name"],
    )


def test_fetch_labels_skips_empty_names(mocker: MockerFixture) -> None:
    stdout = "good\n\n"
    mocker.patch("security.services.label_creator.run_gh", return_value=_completed(stdout=stdout))

    assert LabelCreator(REPO)._fetch_labels() == ["good"]


def test_fetch_labels_raises_on_gh_failure(mocker: MockerFixture) -> None:
    mocker.patch(
        "security.services.label_creator.run_gh",
        return_value=_completed(returncode=1, stderr="boom"),
    )

    with pytest.raises(SystemExit):
        LabelCreator(REPO)._fetch_labels()


# ensure_labels


def test_ensure_labels_all_present_creates_nothing(mocker: MockerFixture, caplog) -> None:
    mocker.patch.object(LabelCreator, "_fetch_labels", return_value=_all_label_names())
    create = mocker.patch("security.services.label_creator.gh_label_create")

    with caplog.at_level(logging.INFO, logger="root"):
        still_missing = LabelCreator(REPO).ensure_labels()

    assert still_missing == []
    create.assert_not_called()
    assert any("All required labels are present" in record.message for record in caplog.records)


def test_ensure_labels_creates_only_the_missing_ones(mocker: MockerFixture, caplog) -> None:
    mocker.patch.object(
        LabelCreator, "_fetch_labels", return_value=["scope:security", "type:aquasec", "sec:suppression"]
    )
    create = mocker.patch("security.services.label_creator.gh_label_create", return_value=True)

    with caplog.at_level(logging.INFO, logger="root"):
        still_missing = LabelCreator(REPO).ensure_labels()

    assert still_missing == []
    assert [call.args[1] for call in create.call_args_list] == ["epic", "sec:false-positive"]
    assert any("Created label 'epic' (missing)" in record.message for record in caplog.records)


def test_ensure_labels_creates_with_approved_colour_and_description(mocker: MockerFixture) -> None:
    mocker.patch.object(LabelCreator, "_fetch_labels", return_value=[])
    create = mocker.patch("security.services.label_creator.gh_label_create", return_value=True)

    LabelCreator(REPO).ensure_labels()

    epic = next(call for call in create.call_args_list if call.args[1] == "epic")
    assert epic.args[0] == REPO
    assert epic.kwargs["color"] == "3e4b9e"
    assert epic.kwargs["description"] == "A bigger feature that needs more deliverable subtasks to finish"


def test_ensure_labels_reports_the_ones_it_could_not_create(mocker: MockerFixture) -> None:
    mocker.patch.object(LabelCreator, "_fetch_labels", return_value=["scope:security", "type:aquasec"])
    create = mocker.patch("security.services.label_creator.gh_label_create", return_value=False)

    still_missing = LabelCreator(REPO).ensure_labels()

    assert still_missing == ["epic", "sec:suppression", "sec:false-positive"]
    assert [call.args[1] for call in create.call_args_list] == ["epic", "sec:suppression", "sec:false-positive"]


# ensure_labels - dry run


def test_ensure_labels_dry_run_creates_nothing_but_reports_missing(mocker: MockerFixture, caplog) -> None:
    mocker.patch.object(
        LabelCreator, "_fetch_labels", return_value=["scope:security", "type:aquasec", "sec:suppression"]
    )
    create = mocker.patch("security.services.label_creator.gh_label_create")

    with caplog.at_level(logging.INFO, logger="root"):
        still_missing = LabelCreator(REPO).ensure_labels(dry_run=True)

    assert still_missing == []
    create.assert_not_called()
    assert any("Would create label 'epic' (missing)" in record.message for record in caplog.records)


def test_ensure_labels_dry_run_all_present(mocker: MockerFixture, caplog) -> None:
    mocker.patch.object(LabelCreator, "_fetch_labels", return_value=_all_label_names())
    create = mocker.patch("security.services.label_creator.gh_label_create")

    with caplog.at_level(logging.INFO, logger="root"):
        still_missing = LabelCreator(REPO).ensure_labels(dry_run=True)

    assert still_missing == []
    create.assert_not_called()
    assert any(
        "Would check all required labels are present" in record.message for record in caplog.records
    )
