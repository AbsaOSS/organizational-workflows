#!/usr/bin/env python3
"""
Process structured [sec-event] comments on Issues.

Issue comments are the SOURCE OF TRUTH.
This script mirrors decisions to GitHub Security Alerts when applicable.
"""

import json
import os
import re
from github import Github

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
REPO_FULL = os.environ["GITHUB_REPOSITORY"]
EVENT_PATH = os.environ["GITHUB_EVENT_PATH"]

EVENT_RE = re.compile(r"\[sec-event\](.*?)\[/sec-event\]", re.S)


def parse_kv(block: str) -> dict:
    data = {}
    for line in block.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def main():
    with open(EVENT_PATH) as f:
        event = json.load(f)

    issue_number = event["issue"]["number"]

    gh = Github(GITHUB_TOKEN)
    repo = gh.get_repo(REPO_FULL)
    issue = repo.get_issue(issue_number)

    comment_body = event["comment"]["body"]
    matches = EVENT_RE.findall(comment_body or "")

    for raw in matches:
        data = parse_kv(raw)
        action = data.get("action")

        if action == "close":
            issue.add_to_labels("sec:state/closed")

        if action == "revisit":
            issue.add_to_labels("sec:state/needs-review")


if __name__ == "__main__":
    main()
