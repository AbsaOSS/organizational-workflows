#!/usr/bin/env python3
"""
React to label changes on Issues.

This script is triggered ONLY by issue label events.
No cron. No polling.

Rules:
- Ignore non-security issues
- Emit structured events instead of silent changes
"""

import json
import os
from github import Github

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
REPO_FULL = os.environ["GITHUB_REPOSITORY"]
EVENT_PATH = os.environ["GITHUB_EVENT_PATH"]

SEC_PREFIX = "sec:"


def main():
    with open(EVENT_PATH) as f:
        event = json.load(f)

    issue_number = event["issue"]["number"]
    labels = [l["name"] for l in event["issue"]["labels"]]

    if not any(l.startswith(SEC_PREFIX) for l in labels):
        return

    gh = Github(GITHUB_TOKEN)
    repo = gh.get_repo(REPO_FULL)
    issue = repo.get_issue(issue_number)

    if "sec:state/postponed" in labels:
        issue.create_comment(
            """
[sec-event]
action=postpone
trigger=label-change
[/sec-event]
""".strip()
        )


if __name__ == "__main__":
    main()
