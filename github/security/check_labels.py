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

"""Check that all labels required by the security automation exist in the repository.

Required labels (referenced by promote_alerts.py and the remove-adept-to-close workflow):

  epic
  scope:security
  type:tech-debt
  sec:adept-to-close

Usage:
  python3 check_labels.py --repo owner/repo
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


REQUIRED_LABELS: list[str] = [
    "scope:security",
    "type:tech-debt",
    "epic",
    "sec:adept-to-close",
]


def fetch_repo_labels(repo: str) -> set[str]:
    """Return the set of label names defined in *repo*."""
    result = subprocess.run(
        ["gh", "label", "list", "--repo", repo, "--json", "name", "--limit", "500"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: failed to list labels for {repo}: {result.stderr}", file=sys.stderr)
        raise SystemExit(1)

    try:
        labels = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        print(f"ERROR: failed to parse label JSON: {exc}", file=sys.stderr)
        raise SystemExit(1)

    return {str(item.get("name", "")) for item in labels}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify that all labels required by security automation exist in the repository",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="GitHub repository in owner/repo format",
    )
    args = parser.parse_args()

    existing = fetch_repo_labels(args.repo)
    missing = [label for label in REQUIRED_LABELS if label not in existing]

    if not missing:
        print(f"All {len(REQUIRED_LABELS)} required labels exist in {args.repo}")
        raise SystemExit(0)

    print(f"ERROR: {len(missing)} required label(s) missing in {args.repo}\n", file=sys.stderr)
    print("Missing labels:", file=sys.stderr)
    for label in missing:
        print(f"  - {label}", file=sys.stderr)
    print(f"\nAll required labels:\n  {', '.join(REQUIRED_LABELS)}", file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
