# Security automation (Code Scanning → Issues)

This folder contains the scripts and conventions to turn GitHub **Code Scanning alerts** (SARIF-based, e.g. AquaSec) into a managed **GitHub Issues** backlog.

In one sentence: SARIF uploads create alerts; these scripts sync alerts into Issues; labels + structured comments drive lifecycle; reporting is derived from Issues.

## What this is (and what it isn’t)

- This is an **organizational toolkit**: copy the scripts (or vendor them) into an application repository and wire them into Actions.
- SARIF is **write-only input**. Automation reads from GitHub’s Code Scanning alerts API and from GitHub Issues.
- Issues are the **system of record** for operational work (ownership, postponement, closure reasons, reporting).

## Contents

| Script | Purpose | Requires |
|---|---|---|
| `collect_alert.sh` | Fetch and normalize code scanning alerts into `alerts.json` | `gh`, `jq` |
| `promote_alerts.py` | Create/reopen Issues from `alerts.json` | `gh` |
| `sync_issue_labels.py` | React to `sec:*` label changes and emit `[sec-event]` comments | `PyGithub`, `GITHUB_TOKEN` |
| `process_sec_events.py` | Parse `[sec-event]` comments and apply state/side-effects | `PyGithub`, `GITHUB_TOKEN` |
| `extract_team_security_stats.py` | Snapshot security Issues for a team across repos | `PyGithub`, `GITHUB_TOKEN` |
| `derive_team_security_metrics.py` | Compute metrics/deltas from snapshots | stdlib |

## Quick start (local)

Prereqs:
- Install and authenticate GitHub CLI: `gh auth login`
- Install `jq`
- Python 3.11+ recommended

1) Collect open alerts:

```bash
./collect_alert.sh --owner <org> --repo <repo> --state open --out alerts.json
```

2) Promote alerts to Issues:

```bash
python3 promote_alerts.py --file alerts.json
```

## Run in GitHub Actions (minimal example)

This is the simplest “after SARIF upload, sync issues” job.

```yaml
name: Promote code scanning alerts to issues

on:
  workflow_run:
    workflows: ["Upload SARIF"]
    types: [completed]

permissions:
  security-events: read
  issues: write
  contents: read

jobs:
  promote:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Collect open alerts
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          OWNER="${GITHUB_REPOSITORY%/*}"
          REPO="${GITHUB_REPOSITORY#*/}"
          ./github/security/collect_alert.sh --owner "$OWNER" --repo "$REPO" --state open --out alerts.json

      - name: Promote alerts to issues
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python3 github/security/promote_alerts.py --file alerts.json
```

## Labels (contract)

Automation only reacts to Issues that contain at least one `sec:*` label.

### Source
- `sec:src/aquasec-sarif`

### State
- `sec:state/postponed`
- `sec:state/needs-review`

### Severity
- `sec:sev/critical`
- `sec:sev/high`
- `sec:sev/medium`
- `sec:sev/low`

### Closure reasons
- `sec:close/fixed`
- `sec:close/false-positive`
- `sec:close/accepted-risk`
- `sec:close/not-applicable`

### Postpone reasons
- `sec:postpone/vendor`
- `sec:postpone/platform`
- `sec:postpone/roadmap`
- `sec:postpone/other`

## Issue metadata (secmeta)

Each security Issue contains exactly one fenced `secmeta` block.

Minimum recommended keys:

```secmeta
schema=1
fingerprint=<finding_fingerprint>
repo=org/repo
source=code_scanning
tool=AquaSec
severity=high
rule_id=...
first_seen=YYYY-MM-DD
last_seen=YYYY-MM-DD
postponed_until=
gh_alert_numbers=["123"]
occurrence_count=1
```

The `secmeta` block is automation-owned (humans express intent via labels and `[sec-event]` comments).

## Issue structure

### Title

Recommended example (fingerprint-first):

```text
[SEC][FP=ab12cd34] Stored XSS in HTML rendering
```

Rules:
- `FP=` is a short prefix of the canonical `finding_fingerprint` (8 chars is enough)
- `POSTPONE=` exists only if postponed
- Severity is expressed via labels, not the title

### Structured comments (events)

All lifecycle changes are logged via structured comments.

Example close event:

```
[sec-event]
action=close
reason=fixed
detail=Escaped user input in renderer
evidence=PR#123
[/sec-event]
```

Example postpone event:

```
[sec-event]
action=postpone
postponed_until=2026-03-15
reason=vendor
[/sec-event]
```
## How you “say duplicate / grouped / dismissed / reopened”

Use Issue comments to express intent, and have automation translate that intent into labels / state changes / (optionally) GitHub alert actions.

Recommended commands (example format):

- `/sec duplicate-of #123` — mark as duplicate and point to canonical Issue
- `/sec group-into #456` — group related findings under a parent Issue
- `/sec dismiss reason=false_positive|accepted_risk|wont_fix comment="..."` — close with an auditable reason
- `/sec reopen` — reopen a previously closed Issue

Implementation note: the command parsing/side-effects depend on how [github/security/process_sec_events.py](process_sec_events.py) evolves. The format above is the intended contract.


## Design: fingerprints and matching

### Why you need your own fingerprint

GitHub Code Scanning uses fingerprints internally to deduplicate alerts, but those fingerprints are not exposed as a stable field in the alert API response.

Therefore you maintain your own Issue identity.

### Identifiers you maintain

You need three identifiers, each with a different purpose:

1) `gh_alert_key` (operational pointer)
   - Store `gh_alert_number` + `tool` + `rule_id` (+ optional config/category fields)
2) `finding_fingerprint` (stable identity → one Issue per finding)
   - Compute from rule + code context (not from alert numbers)
3) `occurrence_fingerprint` (history)
   - Compute from commit + (path/start/end)

### Practical fingerprint algorithm

Two levels, with a clear fallback:

```text
fast_fp = sha256(tool_name + "|" + rule_id + "|" + normalize(path) + "|" + start_line)
```

Preferred (more stable): snippet-based logical fingerprint:

```text
snippet_hash = sha256(normalize_snippet(file_at(commit_sha, path, start_line-3, end_line+3)))
logical_fp   = sha256(tool_name + "|" + rule_id + "|" + snippet_hash)
```

Rule:
- Prefer `logical_fp` when you can compute the snippet.
- Otherwise fall back to `fast_fp`.

### SARIF normalization to reduce duplicate GitHub alerts

Even with your own Issue fingerprint, you want GitHub alerts to remain stable:

- normalize SARIF paths to repo-relative `artifactLocation.uri`
- keep `ruleId` stable
- avoid unnecessary result reordering

## Current implementation status

As of 2026-02, [github/security/promote_alerts.py](promote_alerts.py) implements the fingerprint-based sync loop described above:

- Computes `fast_fp` for every alert and attempts `logical_fp` using `git show <commit_sha>:<path>` (falls back cleanly when snippet lookup fails)
- Matches issues in order: `logical_fp` → `fast_fp` → legacy alert token in title (migration fallback)
- Writes/updates `secmeta` with `fingerprint` (canonical), `logical_fp`, `fast_fp`, `gh_alert_numbers`, and lifecycle fields (`first_seen`, `last_seen`, `last_seen_commit`)
- Reopens a closed matching Issue when an alert is open again
- Adds `[sec-event]` comments only for meaningful events (reopen, new occurrence)

## Troubleshooting

- `gh: command not found`: install GitHub CLI and ensure it’s on `PATH`.
- `gh auth status` fails: run `gh auth login` locally, or set `GH_TOKEN` in Actions.
- Permission errors in Actions: ensure the workflow has `security-events: read` and `issues: write` permissions.

## References

- [REST API endpoints for code scanning - GitHub Docs](https://docs.github.com/en/rest/code-scanning/code-scanning)
- [SARIF support for code scanning - GitHub Docs](https://docs.github.com/en/code-security/reference/code-scanning/sarif-support-for-code-scanning)
- [upload-sarif: Adding fingerprints discussion](https://github.com/github/codeql-action/issues/2386)

