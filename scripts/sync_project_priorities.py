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

"""
Sync GitHub Project Priority fields from security issue severity.

Reads all open 'scope:security' issues from a repository, extracts their
severity from the embedded secmeta block, maps it through a user-supplied
severity→priority table, and sets the Priority single-select field on the
target GitHub ProjectV2 board.

Run this script manually when the automated priority sync in the AquaSec
pipeline cannot reach the project board (e.g. cross-org token restrictions).

Requirements
------------
- GitHub CLI (gh) installed and available on PATH.
- GH_TOKEN environment variable set to a personal access token (or fine-grained
  token) with the following scopes:
    • repo   (read issues)
    • project:write (read and update ProjectV2 items)

Usage
-----
    export GH_TOKEN=ghp_...
    python3 scripts/sync_project_priorities.py \
        --repo AbsaOSS/my-repo \
        --project-number 203 \
        --severity-priority-map "Critical=P1,High=P2,Medium=P3,Low=P4,Unknown=P4" \
        [--project-org org123] \
        [--dry-run]

Options
-------
  --repo                  GitHub repository whose issues are synced (owner/repo).
  --project-number        Number of the GitHub ProjectV2 board (the integer in the
                          board URL, e.g. https://github.com/orgs/org123/projects/203).
  --severity-priority-map Comma-separated severity=priority pairs.  Severities are
                          case-insensitive; priority values must match option names on
                          the board exactly (check under Settings → Fields → Priority).
  --project-org           Organisation that owns the ProjectV2 board.  Defaults to the
                          org extracted from --repo.  Set this when the board lives in a
                          different org than the scanned repository.
  --dry-run               Print what would be changed without writing anything to GitHub.
"""

import argparse
import logging
import os
import sys

# Allow the script to be run directly from the repo root without setting PYTHONPATH.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.github.issues import gh_issue_list_by_label  # noqa: E402
from core.github.projects import ProjectPrioritySync, gh_project_get_priority_field  # noqa: E402
from core.priority import parse_severity_priority_map  # noqa: E402
from security.issues.secmeta import load_secmeta  # noqa: E402


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sync_project_priorities.py",
        description=(
            "Sync GitHub Project Priority fields from security issue severity.\n\n"
            "Reads open scope:security issues from --repo, maps their severity to a\n"
            "priority value via --severity-priority-map, and updates the Priority\n"
            "single-select field on the target ProjectV2 board."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  # Preview changes without writing anything\n"
            "  python3 scripts/sync_project_priorities.py ... --dry-run\n"
        ),
    )
    p.add_argument(
        "--repo",
        required=True,
        metavar="OWNER/REPO",
        help="GitHub repository whose scope:security issues are synced.",
    )
    p.add_argument(
        "--project-number",
        required=True,
        type=int,
        metavar="N",
        help=(
            "GitHub ProjectV2 board number.  Find it in the board URL: "
            "https://github.com/orgs/<org>/projects/<N>"
        ),
    )
    p.add_argument(
        "--severity-priority-map",
        required=True,
        metavar="MAP",
        help=(
            'Comma-separated severity=priority pairs, e.g. "Critical=P1,High=P2,Medium=P3". '
            "Severity values are case-insensitive.  Priority values must match the option "
            "names on the board exactly."
        ),
    )
    p.add_argument(
        "--project-org",
        default="",
        metavar="ORG",
        help=(
            "Organisation that owns the ProjectV2 board.  "
            "Defaults to the org derived from --repo.  "
            "Required when the board lives in a different org than the repository."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Log intended changes without writing anything to GitHub.",
    )
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_env() -> None:
    if not os.environ.get("GH_TOKEN"):
        raise SystemExit(
            "ERROR: GH_TOKEN is not set.\n"
            "Export a GitHub token with 'repo' and 'project:write' scopes:\n"
            "    export GH_TOKEN=ghp_..."
        )


def _validate_repo(repo: str) -> None:
    if not repo or "/" not in repo or repo.startswith("/") or repo.endswith("/"):
        raise SystemExit(
            f"ERROR: --repo must be in 'owner/repo' format, got: {repo!r}"
        )


def _validate_severity_priority_map(spm: dict[str, str], raw: str) -> None:
    if not spm:
        raise SystemExit(
            f"ERROR: --severity-priority-map produced no valid pairs from: {raw!r}\n"
            'Expected format: "Critical=P1,High=P2,Medium=P3"'
        )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _setup_logging(dry_run: bool) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    if dry_run:
        logging.info("DRY-RUN mode – no changes will be written to GitHub.")


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    _setup_logging(args.dry_run)

    _validate_env()
    _validate_repo(args.repo)

    repo: str = args.repo
    project_number: int = args.project_number
    raw_map: str = args.severity_priority_map
    dry_run: bool = args.dry_run

    org: str = args.project_org or repo.split("/", 1)[0]

    spm = parse_severity_priority_map(raw_map)
    _validate_severity_priority_map(spm, raw_map)

    logging.info("Repository  : %s", repo)
    logging.info("Project     : #%d  (org: %s)", project_number, org)
    logging.info("Priority map: %s", spm)

    # ------------------------------------------------------------------
    # 1. Fetch issues
    # ------------------------------------------------------------------
    logging.info("Fetching open scope:security issues from %s …", repo)
    all_issues = gh_issue_list_by_label(repo, "scope:security")
    open_issues = {n: i for n, i in all_issues.items() if i.state.lower() == "open"}

    if not open_issues:
        logging.info("No open scope:security issues found – nothing to sync.")
        return 0

    logging.info("Found %d open issue(s).", len(open_issues))

    # ------------------------------------------------------------------
    # 2. Load ProjectV2 metadata
    # ------------------------------------------------------------------
    logging.info("Loading ProjectV2 #%d in org %r …", project_number, org)
    pf = gh_project_get_priority_field(org, project_number)
    if pf is None:
        raise SystemExit(
            f"ERROR: Could not load project #{project_number} in org {org!r}.\n"
            "Check that:\n"
            "  • the project number is correct (integer from the board URL)\n"
            f"  • the org is correct (use --project-org if the board is not in {org!r})\n"
            "  • your GH_TOKEN has 'project:read' access to that org's projects"
        )

    logging.info(
        "Project loaded. Priority options available: %s",
        ", ".join(sorted(pf.options.keys())),
    )

    # ------------------------------------------------------------------
    # 3. Enqueue priority updates
    # ------------------------------------------------------------------
    priority_sync = ProjectPrioritySync(org, project_number, pf, dry_run=dry_run)

    enqueued = 0
    skipped_no_severity = 0
    skipped_no_map = 0

    for issue in open_issues.values():
        secmeta = load_secmeta(issue.body or "")
        severity = (secmeta.get("severity") or "").strip().lower()

        if not severity:
            logging.debug("Issue #%d: no severity in secmeta – skipped.", issue.number)
            skipped_no_severity += 1
            continue

        if severity not in spm:
            logging.debug(
                "Issue #%d: severity %r has no mapping in --severity-priority-map – skipped.",
                issue.number,
                severity,
            )
            skipped_no_map += 1
            continue

        priority_sync.enqueue(repo, issue.number, severity, spm)
        enqueued += 1

    logging.info(
        "Enqueue summary: %d to sync, %d skipped (no severity), %d skipped (no mapping).",
        enqueued,
        skipped_no_severity,
        skipped_no_map,
    )

    if enqueued == 0:
        logging.info("Nothing to sync – all issues were skipped.")
        return 0

    # ------------------------------------------------------------------
    # 4. Flush (resolve node-ids, add to project, batch-update)
    # ------------------------------------------------------------------
    priority_sync.flush()

    logging.info("Priority sync complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
