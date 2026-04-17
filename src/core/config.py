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

"""Runtime configuration – GitHub Actions environment detection and logging setup."""

import logging
import os
import sys


def parse_runner_debug() -> bool:
    """Return ``True`` when the GitHub Actions ``RUNNER_DEBUG`` env var is ``'1'``."""
    raw = os.getenv("RUNNER_DEBUG")
    if raw is None or raw == "":
        return False
    if raw not in {"0", "1"}:
        raise SystemExit("ERROR: RUNNER_DEBUG must be '0' or '1' when set")
    return raw == "1"


def setup_logging(verbose: bool = False) -> None:
    """Configure the root logger (DEBUG when *verbose*, else INFO)."""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if verbose:
        logging.debug("Verbose logging enabled")
