#!/usr/bin/env python3
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

"""Check that required labels exist in a GitHub repository using ``gh`` CLI."""

import argparse
import json
import logging
import os
import sys

_repo_root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.common import run_gh
from shared.logging_config import setup_logging
from utils.constants import (
    LABEL_EPIC,
    LABEL_SCOPE_SECURITY,
    LABEL_SEC_ADEPT_TO_CLOSE,
    LABEL_TYPE_TECH_DEBT,
)

logger = logging.getLogger(__name__)

REQUIRED_LABELS: list[str] = [
    LABEL_SCOPE_SECURITY,
    LABEL_TYPE_TECH_DEBT,
    LABEL_EPIC,
    LABEL_SEC_ADEPT_TO_CLOSE,
]


def fetch_repo_labels(repo: str) -> list[str]:
    """Return all label names in *repo* via ``gh label list``."""
    result = run_gh(["label", "list", "--repo", repo, "--json", "name", "--limit", "500"])
    if result.returncode != 0:
        logger.error("gh label list failed for %s:\n%s", repo, result.stderr)
        raise SystemExit(1)
    labels = json.loads(result.stdout)
    return [entry["name"] for entry in labels if entry.get("name")]


def check_labels(repo: str, required: list[str] | None = None) -> list[str]:
    """Return a list of missing labels.  Empty list means all labels exist."""
    if required is None:
        required = REQUIRED_LABELS
    existing = set(fetch_repo_labels(repo))
    return [label for label in required if label not in existing]


def main(argv: list[str] | None = None) -> int:
    """Check labels exist in the repository and report any that are missing."""
    parser = argparse.ArgumentParser(description="Check that required labels exist in a GitHub repo.")
    parser.add_argument("--repo", required=True, help="GitHub repository (owner/repo)")
    args = parser.parse_args(argv)

    setup_logging()

    missing = check_labels(args.repo)

    if not missing:
        logger.info("All %d required labels exist in %s", len(REQUIRED_LABELS), args.repo)
        return 0

    logger.error(
        "%d required label(s) missing in %s\n  Missing: %s\n  Required: %s",
        len(missing),
        args.repo,
        ", ".join(missing),
        ", ".join(REQUIRED_LABELS),
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
