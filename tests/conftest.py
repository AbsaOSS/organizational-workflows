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

"""Global test guard preventing any real ``gh`` CLI invocation."""

import pytest

import core.github.client as gh_client


class RealGhCallError(RuntimeError):
    """Raised when a test reaches the real ``gh`` subprocess boundary."""


def _guard(cmd: list[str], *args: object, **kwargs: object) -> None:
    raise RealGhCallError(
        f"Real gh/subprocess call blocked in tests: {cmd!r}. "
        "Mock run_gh (or the gh_* wrapper) in this test."
    )


@pytest.fixture(autouse=True)
def _block_real_gh(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test that reaches the real ``gh`` subprocess boundary."""
    monkeypatch.setattr(gh_client, "run_cmd", _guard)
