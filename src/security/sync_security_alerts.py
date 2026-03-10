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

"""Orchestrator that runs the full security-alert sync pipeline.

Steps
-----
1. **check_labels** – verify required labels exist in the repository.
2. **collect_alert** – fetch code-scanning alerts and write a normalised JSON file.
3. **promote_alerts** – create / update GitHub Issues from the collected alerts.
"""

import argparse
import logging
import os
import sys

_repo_root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.common import parse_runner_debug
from shared.logging_config import setup_logging

from check_labels import check_labels
from collect_alert import main as collect_alert_main
from promote_alerts import main as promote_alerts_main

logger = logging.getLogger(__name__)

VALID_STATES = {"open", "dismissed", "fixed", "all"}


def _resolve_repo(cli_repo: str) -> str:
    """Return *cli_repo* if given, else fall back to ``GITHUB_REPOSITORY``."""
    repo = cli_repo or os.environ.get("GITHUB_REPOSITORY", "")
    if not repo or "/" not in repo:
        raise SystemExit(
            "ERROR: repo not specified or invalid. "
            "Use --repo owner/repo or set GITHUB_REPOSITORY=owner/repo."
        )
    return repo


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    p = argparse.ArgumentParser(
        description=(
            "Thin orchestrator that runs:\n"
            "  1) check_labels   -> verify required labels exist\n"
            "  2) collect_alert  -> writes alerts.json\n"
            "  3) promote_alerts -> creates/updates Issues from alerts.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--repo", default="", help="GitHub repository (owner/repo)")
    p.add_argument(
        "--state",
        default="open",
        choices=sorted(VALID_STATES),
        help="Alert state filter (default: open)",
    )
    p.add_argument(
        "--out",
        default="alerts.json",
        dest="out_file",
        help="Output file for alerts JSON (default: alerts.json)",
    )
    p.add_argument(
        "--issue-label",
        default="scope:security",
        help="Mine existing issues with this label (default: scope:security)",
    )
    p.add_argument(
        "--severity-priority-map",
        default=os.environ.get("SEVERITY_PRIORITY_MAP", ""),
        help=(
            "Comma-separated severity=priority pairs, e.g. "
            "'Critical=Blocker,High=Urgent,Medium=Normal,Low=Minor,Unknown=Normal'. "
            "Only listed severities get a priority; unlisted ones are left empty. "
            "When not set at all, priority is skipped for every severity. "
            "Default: $SEVERITY_PRIORITY_MAP"
        ),
    )
    p.add_argument(
        "--project-number",
        default=os.environ.get("PROJECT_NUMBER", ""),
        help=(
            "GitHub Projects V2 number (org-level) where a Priority "
            "single-select field will be set for each promoted issue. "
            "Required together with --severity-priority-map. "
            "When omitted, project-level priority is skipped. "
            "Default: $PROJECT_NUMBER"
        ),
    )
    p.add_argument(
        "--project-org",
        default=os.environ.get("PROJECT_ORG", ""),
        help=(
            "GitHub organisation that owns the Projects V2 board. "
            "Use when the project lives in a different org than the scanned repo. "
            "When omitted, derived from the repo name. "
            "Default: $PROJECT_ORG"
        ),
    )
    p.add_argument(
        "--teams-webhook-url",
        default=os.environ.get("TEAMS_WEBHOOK_URL", ""),
        help="Teams Incoming Webhook URL (default: $TEAMS_WEBHOOK_URL)",
    )
    p.add_argument("--skip-label-check", action="store_true", help="Skip the label existence check")
    p.add_argument("--dry-run", action="store_true", help="Do not write issues; only print intended actions")
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose logs (also enabled by RUNNER_DEBUG=1)",
    )
    p.add_argument("--force", action="store_true", help="Overwrite --out file if it exists")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the full sync pipeline and return an exit code."""
    args = parse_args(argv)

    verbose = bool(args.verbose) or parse_runner_debug()
    setup_logging(verbose)

    repo = _resolve_repo(args.repo)
    out_file: str = args.out_file

    # ── Step 1: label check ──────────────────────────────────────────
    if not args.skip_label_check:
        missing = check_labels(repo)
        if missing:
            logger.error(
                "Required labels missing in %s: %s",
                repo,
                ", ".join(missing),
            )
            return 1
        logger.info("All required labels present in %s", repo)

    # ── Step 2: handle --force / existing output file ────────────────
    if os.path.exists(out_file):
        if args.force:
            os.remove(out_file)
        else:
            logger.error(
                "Output file '%s' exists. Delete it, choose a different --out, or pass --force.",
                out_file,
            )
            return 1

    # ── Step 3: collect alerts ───────────────────────────────────────
    collect_argv = ["--repo", repo, "--state", args.state, "--out", out_file]
    if verbose:
        collect_argv.append("--verbose")
    collect_alert_main(collect_argv)

    # ── Step 4: promote alerts ───────────────────────────────────────
    promote_argv = ["--file", out_file, "--issue-label", args.issue_label]
    if args.dry_run:
        promote_argv.append("--dry-run")
    if verbose:
        promote_argv.append("--verbose")
    if args.teams_webhook_url:
        promote_argv.extend(["--teams-webhook-url", args.teams_webhook_url])
    if args.severity_priority_map:
        promote_argv.extend(["--severity-priority-map", args.severity_priority_map])
    if args.project_number:
        promote_argv.extend(["--project-number", str(args.project_number)])
    if args.project_org:
        promote_argv.extend(["--project-org", args.project_org])

    promote_alerts_main(promote_argv)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
