# Security automation (Code Scanning → Issues)

This folder contains the scripts and conventions to turn GitHub **Code Scanning alerts** (SARIF-based, e.g. AquaSec) into a managed **GitHub Issues** backlog.

In one sentence: SARIF uploads create alerts; these scripts sync alerts into Issues; labels + structured comments drive lifecycle; reporting is derived from Issues.

## Table of contents

- [What this is (and what it isn’t)](#what-this-is-and-what-it-isnt)
- [Contents](#contents)
- [Quick start (local)](#quick-start-local)
  - [Recommended (expected): `sync_security_alerts.sh`](#recommended-expected-sync_security_alertssh)
  - [Advanced (expert): individual steps](#advanced-expert-individual-steps)
- [Run in GitHub Actions (minimal example)](#run-in-github-actions-minimal-example)
- [Shared workflows](#shared-workflows)
  - [Available reusable workflows](#available-reusable-workflows)
  - [How to adopt a shared workflow](#how-to-adopt-a-shared-workflow)
    - [Aquasec Night Scan](#aquasec-night-scan)
    - [Remove sec:adept-to-close on close](#remove-secadept-to-close-on-close)
- [Labels (contract)](#labels-contract)
- [Issue metadata (secmeta)](#issue-metadata-secmeta)
- [Issue structure](#issue-structure)
- [How you “say duplicate / grouped / dismissed / reopened”](#how-you-say-duplicate--grouped--dismissed--reopened)
- [Design: fingerprints and matching](#design-fingerprints-and-matching)
- [Current implementation status](#current-implementation-status)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## What this is (and what it isn’t)

- This is an **organizational toolkit**: copy the scripts (or vendor them) into an application repository and wire them into Actions.
- SARIF is **write-only input**. Automation reads from GitHub’s Code Scanning alerts API and from GitHub Issues.
- Issues are the **system of record** for operational work (ownership, postponement, closure reasons, reporting).

## Contents

| Script | Purpose | Requires |
| --- | --- | --- |
| `sync_security_alerts.sh` | Main entrypoint: check labels, collect alerts, promote to Issues (local or Actions) | `gh`, `jq`, `python3` |
| `check_labels.sh` | Verify that all labels required by the automation exist in the repository | `gh` |
| `collect_alert.sh` | Fetch and normalize code scanning alerts into `alerts.json` | `gh`, `jq` |
| `promote_alerts.py` | Create/update parent+child Issues from `alerts.json` and link children under parents | `gh` |
| `send_to_teams.py` | Send a Markdown message to a Microsoft Teams channel via Incoming Webhook | `requests` |
| `sync_issue_labels.py` | React to `sec:*` label changes and emit `[sec-event]` comments | `PyGithub`, `GITHUB_TOKEN` |
| `process_sec_events.py` | Parse `[sec-event]` comments and apply state/side-effects | `PyGithub`, `GITHUB_TOKEN` |
| `extract_team_security_stats.py` | Snapshot security Issues for a team across repos | `PyGithub`, `GITHUB_TOKEN` |
| `derive_team_security_metrics.py` | Compute metrics/deltas from snapshots | stdlib |

## Quick start (local)

Prereqs:

- Install and authenticate GitHub CLI: `gh auth login`
- Install `jq`
- Python 3.14+ recommended

### Recommended (expected): `sync_security_alerts.sh`

This is the normal entrypoint for day-to-day use. It runs `check_labels.sh`, `collect_alert.sh`, and then `promote_alerts.py`.

1. Collect + promote in one command:

```bash
./sync_security_alerts.sh --repo <owner/repo>
```

To do a safe preview (no issue writes):

```bash
./sync_security_alerts.sh --repo <owner/repo> --dry-run
```

To see full body previews in dry-run, use `--verbose` (or set `RUNNER_DEBUG=1`).

### Advanced (expert): individual steps

You can run the individual steps when you need finer control or want to debug the pipeline:

1. Collect open alerts:

```bash
./collect_alert.sh --repo <owner/repo> --state open --out alerts.json
```

1. Promote alerts to Issues:

```bash
python3 promote_alerts.py --file alerts.json
```

## Run in GitHub Actions (minimal example)

This is the simplest “after SARIF upload, sync issues” job.

The expected entrypoint is `sync_security_alerts.sh` (the individual scripts are still available when you need finer control).

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
          python-version: '3.14'

      - name: Collect + promote
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          ./github/security/sync_security_alerts.sh --state open --out alerts.json
```

## Shared workflows

This repository provides **reusable GitHub Actions workflows** in `.github/workflows/`.
Application repositories call them with a short caller workflow instead of duplicating the logic.

The `worklows/` directory contains ready-to-copy **example caller workflows** that you drop into your application repository's `.github/workflows/` directory.

### Available reusable workflows

| Workflow | Trigger (caller) | Purpose |
| --- | --- | --- |
| `aquasec-night-scan.yml` | `schedule` / `workflow_dispatch` | Runs AquaSec scan, uploads SARIF, then syncs alerts to Issues via `sync_security_alerts.sh` |
| `remove-adept-to-close-on-issue-close.yml` | `issues: [closed]` | Removes the `sec:adept-to-close` label from security issues when they are closed |

### How to adopt a shared workflow

1. Pick a workflow from the table above.
2. Copy the matching example caller from `worklows/` into your application repository at `.github/workflows/`.

#### Aquasec Night Scan

The caller needs the following **repository secrets** configured:

| Secret | Required | Purpose |
| --- | --- | --- |
| `AQUA_KEY` | yes | AquaSec API key |
| `AQUA_SECRET` | yes | AquaSec API secret |
| `AQUA_GROUP_ID` | yes | AquaSec group identifier |
| `AQUA_REPOSITORY_ID` | yes | AquaSec repository identifier |
| `TEAMS_WEBHOOK_URL` | no | Teams Incoming Webhook URL for new/reopened issue alerts |

Example caller (already available in `worklows/aquasec-night-scan.yml`):

```yaml
name: Aquasec Night Scan

on:
  schedule:
    - cron: '23 2 * * *'
  workflow_dispatch:

concurrency:
  group: aquasec-night-scan-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  actions: read
  issues: write
  security-events: write

jobs:
  scan:
    uses: AbsaOSS/organizational-workflows/.github/workflows/aquasec-night-scan.yml@master
    secrets:
      AQUA_KEY: ${{ secrets.AQUA_KEY }}
      AQUA_SECRET: ${{ secrets.AQUA_SECRET }}
      AQUA_GROUP_ID: ${{ secrets.AQUA_GROUP_ID }}
      AQUA_REPOSITORY_ID: ${{ secrets.AQUA_REPOSITORY_ID }}
      TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
```

#### Remove sec:adept-to-close on close

Example caller (already available in `worklows/remove-adept-to-close-on-issue-close.yml`):

```yaml
name: Remove sec:adept-to-close on close

on:
  issues:
    types: [closed]

permissions:
  issues: write

jobs:
  remove-label:
    uses: AbsaOSS/organizational-workflows/.github/workflows/remove-adept-to-close-on-issue-close.yml@master
```

> **Note:** The calling repository must grant the permissions the reusable workflow needs (listed in each workflow file). For cross-organization calls the reusable workflow repository must be set to "Accessible from repositories in the organization" under **Settings → Actions → General**.

## Labels (contract)

This repository contains multiple scripts with different “label contracts”:

- `promote_alerts.py` mines existing issues by `--issue-label` (default: `scope:security`) and ensures baseline labels `scope:security` and `type:tech-debt` on child/parent issues it creates/updates.
- `sync_issue_labels.py` and `process_sec_events.py` are intended to react to `sec:*` label changes and `[sec-event]` comments.

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

Minimum recommended keys (child issue):

```secmeta
schema=1
type=child
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

Minimum recommended keys (parent issue):

```secmeta
schema=1
type=parent
repo=org/repo
source=code_scanning
tool=AquaSec
severity=high
rule_id=...
first_seen=YYYY-MM-DD
last_seen=YYYY-MM-DD
postponed_until=
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

```text
[sec-event]
action=close
reason=fixed
detail=Escaped user input in renderer
evidence=PR#123
[/sec-event]
```

Example postpone event:

```text
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

### Current fingerprint source

The current `promote_alerts.py` implementation expects the scanner to embed a stable fingerprint in the alert instance message text as a line in the form:

```text
Alert hash: <value>
```

That `Alert hash` value is treated as the canonical `fingerprint` and is used to match Issues.

### Identifiers stored in secmeta

`promote_alerts.py` stores:

- `fingerprint`: canonical finding identity (from `Alert hash`)
- `gh_alert_numbers`: list of GitHub alert numbers observed for this finding
- `occurrence_count` and `last_occurrence_fp`: best-effort occurrence tracking over time

### Occurrence fingerprint

For tracking repeat sightings, `promote_alerts.py` computes an occurrence fingerprint from:

```text
commit_sha + path + start_line + end_line
```

### SARIF normalization to reduce duplicate GitHub alerts

Even with your own Issue fingerprint, you want GitHub alerts to remain stable:

- normalize SARIF paths to repo-relative `artifactLocation.uri`
- keep `ruleId` stable
- avoid unnecessary result reordering

## Current implementation status

As of 2026-02, [github/security/promote_alerts.py](promote_alerts.py) implements the fingerprint-based sync loop described above:

- Matches issues strictly by `secmeta.fingerprint` (from the alert message `Alert hash: ...`)
- Ensures a parent issue per `rule_id` (`secmeta.type=parent`) and links child issues under the parent using GitHub sub-issues
- Writes/updates `secmeta` on child issues, including `gh_alert_numbers`, `first_seen`, `last_seen`, `last_seen_commit`, and occurrence tracking
- Reopens a closed matching Issue when an alert is open again
- Adds `[sec-event]` comments only for meaningful events (reopen, new occurrence)

## Troubleshooting

- `gh: command not found`: install GitHub CLI and ensure it’s on `PATH`.
- `gh auth status` fails: run `gh auth login` locally, or set `GH_TOKEN` in Actions.
- Permission errors in Actions: ensure the workflow has `security-events: read` and `issues: write` permissions.
- `Output file alerts.json exists`: `collect_alert.sh` refuses to overwrite output; delete the file or pass a different `--out` path.
- `missing 'alert hash' in alert message`: the scanner/collector needs to include an `Alert hash: ...` line in the alert instance message text.

## References

- [REST API endpoints for code scanning - GitHub Docs](https://docs.github.com/en/rest/code-scanning/code-scanning)
- [SARIF support for code scanning - GitHub Docs](https://docs.github.com/en/code-security/reference/code-scanning/sarif-support-for-code-scanning)
- [upload-sarif: Adding fingerprints discussion](https://github.com/github/codeql-action/issues/2386)




