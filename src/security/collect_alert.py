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

"""Collect GitHub code-scanning alerts for a repository and write a normalised JSON file."""

import argparse
import json
import logging
import os
import re
import shutil
import sys
from datetime import datetime, timezone

_repo_root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.common import parse_runner_debug, run_gh
from shared.logging_config import setup_logging

VALID_STATES = {"open", "dismissed", "fixed", "all"}


def _help_value(rule_help: str, name: str) -> str | None:
    """Extract a value from ``**Name:** value`` markup in the rule help text."""
    m = re.search(rf"\*\*{re.escape(name)}:\*\*\s*([^\n\r]+)", rule_help, re.IGNORECASE)
    return m.group(1) if m else None


def _msg_value(message_text: str, name: str) -> str | None:
    """Extract a value from ``Name: value`` lines in the alert message."""
    for line in message_text.split("\n"):
        if re.match(rf"^{re.escape(name)}\s*:", line, re.IGNORECASE):
            value = re.sub(rf"^{re.escape(name)}\s*:\s*", "", line, flags=re.IGNORECASE)
            return value.rstrip("\r")
    return None


def _gh_api_json(endpoint: str) -> dict | list:
    """Call ``gh api`` and return parsed JSON."""
    res = run_gh(["api", "-H", "Accept: application/vnd.github+json", endpoint])
    if res.returncode != 0:
        logging.error("gh api %s failed:\n%s", endpoint, res.stderr)
        raise SystemExit(1)
    return json.loads(res.stdout)


def _gh_api_paginate(endpoint: str) -> list[dict]:
    """Call ``gh api --paginate`` and return the concatenated list of results."""
    res = run_gh(["api", "-H", "Accept: application/vnd.github+json", "--paginate", endpoint])
    if res.returncode != 0:
        logging.error("gh api %s failed:\n%s", endpoint, res.stderr)
        raise SystemExit(1)
    # --paginate may emit multiple JSON arrays back-to-back; decode all of them.
    decoder = json.JSONDecoder()
    results: list[dict] = []
    text = res.stdout.lstrip()
    while text:
        obj, idx = decoder.raw_decode(text)
        if isinstance(obj, list):
            results.extend(obj)
        else:
            results.append(obj)
        text = text[idx:].lstrip()
    return results


def _normalise_alert(alert: dict) -> dict:
    """Transform a raw GitHub code-scanning alert into the canonical schema."""
    rule = alert.get("rule") or {}
    tool = alert.get("tool") or {}
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}
    message_text = (instance.get("message") or {}).get("text", "")
    rule_help = rule.get("help") or ""

    return {
        "alert_number": alert.get("number"),
        "state": alert.get("state"),
        "created_at": alert.get("created_at"),
        "updated_at": alert.get("updated_at"),
        "url": alert.get("url"),
        "alert_url": alert.get("html_url"),
        "rule_id": rule.get("id"),
        "rule_name": rule.get("name"),
        "severity": rule.get("security_severity_level"),
        "confidence": rule.get("severity"),
        "impact": _help_value(rule_help, "Impact"),
        "likelihood": _help_value(rule_help, "Likelihood"),
        "reachable": _msg_value(message_text, "Reachable"),
        "tags": rule.get("tags") or [],
        "help_uri": rule.get("help_uri"),
        "tool": tool.get("name"),
        "tool_version": tool.get("version"),
        "ref": instance.get("ref"),
        "commit_sha": instance.get("commit_sha"),
        "message": message_text,
        "instance_url": instance.get("html_url"),
        "classifications": instance.get("classifications") or [],
        "file": location.get("path"),
        "start_line": location.get("start_line"),
        "end_line": location.get("end_line"),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect GitHub code-scanning alerts and write a normalised JSON file.",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="GitHub repository in owner/repo format (e.g. my-org/my-repo)",
    )
    parser.add_argument(
        "--state",
        default="open",
        choices=sorted(VALID_STATES),
        help="Alert state filter (default: open)",
    )
    parser.add_argument(
        "--out",
        default="alerts.json",
        dest="out_file",
        help="Output file path (default: alerts.json)",
    )
    parser.add_argument("--verbose", action="store_true", default=False)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    verbose = bool(args.verbose) or parse_runner_debug()
    setup_logging(verbose)

    repo: str = args.repo
    state: str = args.state
    out_file: str = args.out_file

    # Validate repo format
    if "/" not in repo:
        logging.error("--repo must be in owner/repo format")
        raise SystemExit(1)

    # Ensure gh CLI is available
    if not shutil.which("gh"):
        logging.error("gh CLI is required")
        raise SystemExit(1)

    # Ensure gh is authenticated
    auth = run_gh(["auth", "status"])
    if auth.returncode != 0:
        logging.error("gh is not authenticated")
        raise SystemExit(1)

    # Refuse to overwrite
    if os.path.exists(out_file):
        print(f"Output file {out_file} exists. Exiting")
        raise SystemExit(1)

    # Fetch repository metadata
    print(f"Fetching repository metadata for {repo}...")
    repo_data = _gh_api_json(f"/repos/{repo}")

    # Fetch alerts
    print(f"Fetching code scanning alerts (state={state})...")
    endpoint = f"/repos/{repo}/code-scanning/alerts?per_page=100"
    if state != "all":
        endpoint += f"&state={state}"
    raw_alerts = _gh_api_paginate(endpoint)

    # Assemble output
    owner = repo_data.get("owner") or {}
    output = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": {
            "id": repo_data.get("id"),
            "name": repo_data.get("name"),
            "full_name": repo_data.get("full_name"),
            "private": repo_data.get("private"),
            "html_url": repo_data.get("html_url"),
            "default_branch": repo_data.get("default_branch"),
            "owner": {
                "login": owner.get("login"),
                "id": owner.get("id"),
                "html_url": owner.get("html_url"),
            },
        },
        "query": {"state": state},
        "alerts": [_normalise_alert(a) for a in raw_alerts],
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
        f.write("\n")

    count = len(output["alerts"])
    print("Done.")
    print(f"Repository : {repo}")
    print(f"State      : {state}")
    print(f"Alerts     : {count}")
    print(f"Output     : {out_file}")


if __name__ == "__main__":
    main()
