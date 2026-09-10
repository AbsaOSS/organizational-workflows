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

import pytest

from core.config import emit_workflow_warning


# emit_workflow_warning


def test_emit_workflow_warning_prints_an_actions_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Actions only recognises the command when ``::warning`` starts the line."""
    emit_workflow_warning("Card not delivered", title="Teams notification")

    out = capsys.readouterr().out
    assert out.startswith("::warning title=")
    assert "::warning title=Teams notification::Card not delivered\n" == out


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("100% failed", "100%25 failed"),
        ("line one\nline two", "line one%0Aline two"),
        ("carriage\rreturn", "carriage%0Dreturn"),
    ],
)
def test_emit_workflow_warning_escapes_the_message(
    message: str, expected: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unescaped newlines would truncate the annotation at the first line break."""
    emit_workflow_warning(message, title="t")

    assert f"::warning title=t::{expected}\n" == capsys.readouterr().out


def test_emit_workflow_warning_escapes_reserved_property_characters(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Colons and commas delimit properties, so a title carrying them must be escaped."""
    emit_workflow_warning("body", title="Teams: failed, retry")

    assert "::warning title=Teams%3A failed%2C retry::body\n" == capsys.readouterr().out
