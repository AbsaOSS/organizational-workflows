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

"""Subprocess wrappers for the ``gh`` CLI."""

import logging
import subprocess


def run_cmd(
    cmd: list[str],
    *,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """Run *cmd* as a subprocess and return the completed process."""
    return subprocess.run(cmd, check=False, capture_output=capture_output, text=True)


def run_gh(
    args: list[str],
    *,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """Run a ``gh`` CLI command and return the completed process."""
    cmd = ["gh"] + args
    try:
        return run_cmd(cmd, capture_output=capture_output)
    except FileNotFoundError as exc:
        logging.error("gh CLI not found. Install and authenticate gh.")
        raise SystemExit(1) from exc
