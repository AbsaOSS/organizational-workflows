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
severity-priority table, and sets the Priority single-select field on the
target GitHub ProjectV2 board.

Run this script manually when the automated priority sync in the AquaSec
pipeline cannot reach the project board (e.g. cross-org token restrictions).

'unknown' severity is never assigned a priority and is silently skipped.

Requirements
------------
- GitHub CLI (gh) installed and available on PATH.
- Authentication via one of:
    export GH_TOKEN=ghp_...          (classic PAT)
    export GITHUB_TOKEN=ghp_...      (alternative name)
    gh auth login                    (stored credentials)
  The token must have 'repo' (read issues) and 'project:write' scopes.

Usage
-----
    python3 scripts/security/sync_project_priorities.py \
        --repo AbsaOSS/repo123 \
        --project-number 203 \
        --severity-priority-map "Critical=P0,High=P1,Medium=P2,Low=P3" \
        --project-org org123 \
        [--dry-run]

Options
-------
  --repo                  GitHub repository whose issues are synced (owner/repo).
  --project-number        Number of the GitHub ProjectV2 board (integer from the
                          board URL, e.g. https://github.com/orgs/absa-group/projects/203).
  --severity-priority-map Comma-separated severity=priority pairs. Severities are
                          case-insensitive; priority values must match option names on
                          the board exactly (check under Settings - Fields - Priority).
                          'unknown' severity is always skipped regardless of mapping.
  --project-org           Organisation that owns the ProjectV2 board. Defaults to the
                          org extracted from --repo. Set this when the board lives in a
                          different org than the scanned repository.
  --dry-run               Print what would be changed without writing anything to GitHub.
"""

import argparse
import logging
import os
import sys

# Allow the script to be run directly from the repo root without setting PYTHONPATH.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from core.github.issues import gh_issue_list_by_label  # noqa: E402
from core.github.projects import ProjectPrioritySync, gh_project_get_priority_field  # noqa: E402
from core.priority import parse_severity_priority_map  # noqa: E402
from security.constants import DRY_RUN_PREFIX, LOGGING_PREFIX  # noqa: E402
from security.issues.secmeta import load_secmeta  # noqa: E402


# CLI

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sync_project_priorities.py",
        description="Sync GitHub Project Priority fields from security issue severity.",
    )
    p.add_argument("--repo", required=True, metavar="OWNER/REPO", help="Repository to sync.")
    p.add_argument("--project-number", required=True, type=int, metavar="N", help="ProjectV2 board number.")
    p.add_argument(
        "--severity-priority-map",
        required=True,
        metavar="MAP",
        help='Severity-to-priority pairs, e.g. "Critical=P0,High=P1".',
    )
    p.add_argument("--project-org", default="", metavar="ORG", help="Org owning the board (defaults to repo org).")
    p.add_argument("--dry-run", action="store_true", help="Log intended changes without writing to GitHub.")
    return p.parse_args(argv)


# Validation

def _validate_repo(repo: str) -> None:
    if not repo or "/" not in repo or repo.startswith("/") or repo.endswith("/"):
        raise SystemExit(f"ERROR: --repo must be in 'owner/repo' format, got: {repo!r}")


def _validate_severity_priority_map(spm: dict[str, str], raw: str) -> None:
    if not spm:
        raise SystemExit(
            f"ERROR: --severity-priority-map produced no valid pairs from: {raw!r}\n"
            'Expected format: "Critical=P0,High=P1,Medium=P2,Low=P3"'
        )


# Logging

def _setup_logging(dry_run: bool) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    if dry_run:
        logging.info("%sDRY-RUN mode - no changes will be written to GitHub.", DRY_RUN_PREFIX)


# Main logic

def main(argv: list[str] | None = None) -> int:
    """Run the priority sync script.

    Args:
        argv: Argument list for the CLI parser. Defaults to sys.argv when None.

    Returns:
        Exit code: 0 on success, raises SystemExit on fatal errors.
    """
    args = _parse_args(argv)
    _setup_logging(args.dry_run)

    _validate_repo(args.repo)

    repo: str = args.repo
    project_number: int = args.project_number
    raw_map: str = args.severity_priority_map
    dry_run: bool = args.dry_run
    log_prefix = DRY_RUN_PREFIX if dry_run else LOGGING_PREFIX

    org: str = args.project_org or repo.split("/", 1)[0]

    spm = parse_severity_priority_map(raw_map)
    _validate_severity_priority_map(spm, raw_map)

    if not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"):
        logging.warning(
            "%sGH_TOKEN / GITHUB_TOKEN not set - falling back to gh CLI stored credentials.",
            log_prefix,
        )

    logging.info("%sRepository  : %s", log_prefix, repo)
    logging.info("%sProject     : #%d  (org: %s)", log_prefix, project_number, org)
    logging.info("%sPriority map: %s", log_prefix, spm)

    # 1. Fetch issues
    logging.info("%sFetching open scope:security issues from %s ...", log_prefix, repo)
    all_issues = gh_issue_list_by_label(repo, "scope:security")
    open_issues = {n: i for n, i in all_issues.items() if i.state.lower() == "open"}

    if not open_issues:
        logging.info("%sNo open scope:security issues found - nothing to sync.", log_prefix)
        return 0

    logging.info("%sFound %d open issue(s).", log_prefix, len(open_issues))

    # 2. Load ProjectV2 metadata
    logging.info("%sLoading ProjectV2 #%d in org %r ...", log_prefix, project_number, org)
    pf = gh_project_get_priority_field(org, project_number)
    if pf is None:
        raise SystemExit(
            f"ERROR: Could not load project #{project_number} in org {org!r}.\n"
            "Check that:\n"
            "  - the project number is correct (integer from the board URL)\n"
            f"  - the org is correct (use --project-org if the board is not in {org!r})\n"
            "  - your token has 'project:read' access to that org's projects"
        )

    logging.info(
        "%sProject loaded. Priority options available: %s",
        log_prefix,
        ", ".join(sorted(pf.options.keys())),
    )

    # 3. Enqueue priority updates
    priority_sync = ProjectPrioritySync(org, project_number, pf, dry_run=dry_run)

    enqueued = 0
    skipped_unknown = 0
    skipped_no_severity = 0
    skipped_no_map = 0

    for issue in open_issues.values():
        secmeta = load_secmeta(issue.body or "")
        severity = (secmeta.get("severity") or "").strip().lower()

        if not severity:
            logging.debug("Issue #%d: no severity in secmeta - skipped.", issue.number)
            skipped_no_severity += 1
            continue

        if severity == "unknown":
            logging.debug("Issue #%d: severity 'unknown' - skipped.", issue.number)
            skipped_unknown += 1
            continue

        if severity not in spm:
            logging.debug(
                "Issue #%d: severity %r has no mapping in --severity-priority-map - skipped.",
                issue.number,
                severity,
            )
            skipped_no_map += 1
            continue

        priority_sync.enqueue(repo, issue.number, severity, spm)
        enqueued += 1

    logging.info(
        "%sEnqueue summary: %d to sync, %d skipped (unknown), %d skipped (no severity), %d skipped (no mapping).",
        log_prefix,
        enqueued,
        skipped_unknown,
        skipped_no_severity,
        skipped_no_map,
    )

    if enqueued == 0:
        logging.info("%sNothing to sync - all issues were skipped.", log_prefix)
        return 0

    # 4. Flush (resolve node-ids, add to project, batch-update)
    priority_sync.flush()

    logging.info("%sPriority sync complete.", log_prefix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
