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
Extract security statistics per GitHub team.

Model:
- Source of truth: GitHub Issues
- Scope: repositories owned by a given GitHub team
- Unit: one Issue = one logical vulnerability (fingerprint)

Outputs:
- data/issues_snapshot.json
- data/events_flat.csv
- reports/summary.md
"""

import csv
import json
import os
import re
from datetime import datetime
from github import Github

# --------------------
# Configuration
# --------------------
def require_env(key: str) -> str:
    try:
        return os.environ[key]
    except KeyError as exc:
        raise SystemExit(f"Missing required environment variable: {key}") from exc


GITHUB_TOKEN = require_env('GITHUB_TOKEN')
ORG = require_env('GITHUB_ORG')
TEAM_SLUG = require_env('GITHUB_TEAM_SLUG')

OUT_DATA = 'data'
OUT_REPORTS = 'reports'

SEC_LABEL_PREFIX = 'sec:'

SEC_EVENT_RE = re.compile(r'\[sec-event\](.*?)\[/sec-event\]', re.S)
SECMETA_RE = re.compile(r'```secmeta(.*?)```', re.S)

# --------------------
# Helpers
# --------------------

def ensure_dirs():
    os.makedirs(OUT_DATA, exist_ok=True)
    os.makedirs(OUT_REPORTS, exist_ok=True)


def parse_kv_block(block: str) -> dict:
    data = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        k, v = line.split('=', 1)
        data[k.strip()] = v.strip()
    return data


def parse_secmeta(body: str) -> dict:
    match = SECMETA_RE.search(body or '')
    if not match:
        return {}
    return parse_kv_block(match.group(1))


def parse_events(comments):
    events = []
    for c in comments:
        for raw in SEC_EVENT_RE.findall(c.body or ''):
            evt = parse_kv_block(raw)
            evt['timestamp'] = c.created_at.isoformat()
            events.append(evt)
    return events


def issue_has_sec_label(issue):
    return any(l.name.startswith(SEC_LABEL_PREFIX) for l in issue.labels)


# --------------------
# Main extraction
# --------------------

def main():
    ensure_dirs()

    gh = Github(GITHUB_TOKEN)
    org = gh.get_organization(ORG)
    team = org.get_team_by_slug(TEAM_SLUG)

    repos = list(team.get_repos())

    snapshot = []
    flat_events = []

    for repo in repos:
        issues = repo.get_issues(state='all')
        for issue in issues:
            # Skip PRs that may be returned by the issues API
            if getattr(issue, 'pull_request', None):
                continue

            if not issue_has_sec_label(issue):
                continue

            secmeta = parse_secmeta(issue.body or '')
            events = parse_events(issue.get_comments())

            snapshot.append({
                'repo': repo.full_name,
                'issue_number': issue.number,
                'title': issue.title,
                'state': issue.state,
                'labels': [l.name for l in issue.labels],
                'secmeta': secmeta,
                'created_at': issue.created_at.isoformat(),
                'updated_at': issue.updated_at.isoformat(),
                'event_count': len(events),
            })

            for e in events:
                fp = secmeta.get('fingerprint') if secmeta else None
                if not fp:
                    continue  # ignore events without a fingerprint
                flat_events.append({
                    'repo': repo.full_name,
                    'issue_number': issue.number,
                    'fingerprint': fp,
                    'action': e.get('action'),
                    'reason': e.get('reason'),
                    'timestamp': e.get('timestamp'),
                })

    # Write snapshot
    with open(os.path.join(OUT_DATA, 'issues_snapshot.json'), 'w') as f:
        json.dump(snapshot, f, indent=2)

    # Write flat events
    with open(os.path.join(OUT_DATA, 'events_flat.csv'), 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['repo', 'issue_number', 'fingerprint', 'action', 'reason', 'timestamp']
        )
        writer.writeheader()
        writer.writerows(flat_events)

    # Summary report
    total = len(snapshot)
    by_sev = {}

    for item in snapshot:
        sev = next((l for l in item['labels'] if l.startswith('sec:sev/')), 'sec:sev/unknown')
        by_sev[sev] = by_sev.get(sev, 0) + 1

    with open(os.path.join(OUT_REPORTS, 'summary.md'), 'w') as f:
        f.write(f"# Security summary for team `{TEAM_SLUG}`\n\n")
        f.write(f"Generated at: {datetime.utcnow().isoformat()} UTC\n\n")
        f.write(f"## Total security issues: {total}\n\n")
        f.write("## By severity\n\n")
        for sev, cnt in sorted(by_sev.items()):
            f.write(f"- {sev}: {cnt}\n")


if __name__ == '__main__':
    main()
