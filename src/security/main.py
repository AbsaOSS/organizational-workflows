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

"""Orchestrator that runs the full Security pipeline.
Pipeline: validate config -> check labels -> authenticate -> fetch -> parse -> sync -> notify.
"""

import argparse
import logging
import shutil

from core.config import parse_runner_debug, setup_logging

from security.alerts.aquasec_parser import AquaSecParser
from security.constants import LOGGING_PREFIX
from security.config import SecurityConfig
from security.services.authenticator import AquaSecAuthenticator
from security.services.issue_syncer import IssueSyncer
from security.services.label_checker import LabelChecker
from security.services.notification_sender import NotificationSender
from security.services.scan_fetcher import ScanFetcher

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    p = argparse.ArgumentParser(
        description=(
            "Security pipeline orchestrator:\n"
            "  1) Validate configuration\n"
            "  2) Check required labels exist\n"
            "  3) Authenticate with AquaSec API\n"
            "  4) Fetch repository scan findings\n"
            "  5) Parse findings\n"
            "  6) Sync findings to GitHub Issues\n"
            "  7) Send Teams notifications"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "--repo", default="", help="GitHub repository (owner/repo). Falls back to $GITHUB_REPOSITORY env var"
    )
    p.add_argument(
        "--issue-label",
        default="scope:security",
        help="Mine existing issues with this label (default: scope:security)",
    )
    p.add_argument(
        "--severity-priority-map",
        default="",
        help=(
            "Comma-separated severity=priority pairs, e.g. "
            "'Critical=Blocker,High=Urgent,Medium=Normal,Low=Minor,Unknown=Normal'. "
            "Falls back to $SEVERITY_PRIORITY_MAP env var"
        ),
    )
    p.add_argument(
        "--project-number",
        default="",
        help="GitHub Projects V2 number (org-level) for priority sync. Falls back to $PROJECT_NUMBER env var",
    )
    p.add_argument(
        "--project-org",
        default="",
        help="GitHub organisation that owns the Projects V2 board. Falls back to $PROJECT_ORG env var",
    )
    p.add_argument(
        "--teams-webhook-url",
        default="",
        help="Teams Incoming Webhook URL. Falls back to $TEAMS_WEBHOOK_URL env var",
    )
    p.add_argument("--dry-run", action="store_true", help="Do not write issues; only print intended actions")
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose logs (also enabled by RUNNER_DEBUG=1)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the full Security pipeline."""
    args = parse_args(argv)

    setup_logging(bool(args.verbose) or parse_runner_debug())

    # Load and validate configuration
    config = SecurityConfig.load(args)
    config.validate()

    repo = config.repo

    if dry_run := config.dry_run:
        logger.info("%sStarting the DRY-RUN process for %s", LOGGING_PREFIX, repo)
    else:
        logger.info("%sStarting process for %s", LOGGING_PREFIX, repo)

    # Check gh CLI availability
    if shutil.which("gh") is None:
        raise SystemExit("ERROR: gh CLI is required. Install and authenticate (gh auth login).")

    # Check required labels
    if missing := LabelChecker(repo).check_labels():
        logger.error("%sRequired labels missing in %s: %s", LOGGING_PREFIX, repo, ", ".join(missing))
        return 1
    logger.info("%sAll required labels present", LOGGING_PREFIX)

    # Authenticate with AquaSec
    authenticator = AquaSecAuthenticator(config.aqua_key, config.aqua_secret, config.aqua_group_id)
    bearer_token = authenticator.authenticate()

    # Fetch scan findings
    fetcher = ScanFetcher(bearer_token, config.aqua_repository_id)
    scan_data = fetcher.fetch_findings()

    # Parse findings
    parser = AquaSecParser(repo)
    loaded_alerts = parser.parse(scan_data)
    open_alerts = loaded_alerts.open_by_number

    # Sync alerts to GitHub Issues
    syncer = IssueSyncer(config)
    result = syncer.sync(open_alerts, dry_run=dry_run)

    # Send Teams notifications
    NotificationSender(config.teams_webhook_url).notify(result, dry_run=dry_run)

    logger.info("%sProcess finished", LOGGING_PREFIX)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
