# Security Automation

- [Overview](#overview)
- [Onboarding](#onboarding)
- [Running Locally](#running-locally)
- [Features](#features)
- [Developer & Contribution Guide](#developer--contribution-guide)
- [License & Support](#license--support)

## Overview

This solution automates the management of security findings by authenticating directly with the AquaSec API, fetching scan results, and converting them into a structured GitHub Issues backlog.

Solution supports:

- **Automated Issue creation**: Each unique finding becomes a GitHub Issue with severity, affected file, and remediation context.
- **Parent/child structure**: Findings are grouped under epic (parent) issues by rule, with individual occurrences as child sub-issues.
- **Lifecycle sync**: Issues are reopened when findings reappear, automatically closed when findings disappear, and parent issues auto-close when all children are resolved.
- **Teams notifications**: A single Microsoft Teams Adaptive Card summarizing opened, reopened and closed child issues plus the repository's current open-finding posture.

> For a business-level overview of what this solution does and why, see the [Security Automation docs](/docs/security/security.md).

---

## Onboarding

Prerequisites, AquaSec credentials, workflow inputs, secrets and the caller workflow are described step by step in the [How to Onboard guide](/docs/security/how-to-onboard.md).
A ready-to-copy example is available at [docs/security/aquasec-night-scan-example.yml](/docs/security/aquasec-night-scan-example.yml).

---

## Running Locally

The entry point is `src/security/main.py`. It runs the full pipeline: authenticate with AquaSec, fetch findings, sync to Issues, and notify if set.

### Prerequisites

- Python 3.14 (current required runtime)
- Install and authenticate GitHub CLI: `gh auth login`
- Required labels are created automatically if missing; the token needs `issues: write`
- AquaSec credentials available as environment variables: `AQUA_KEY`, `AQUA_SECRET`, `AQUA_GROUP_ID`, `AQUA_REPOSITORY_ID`

### Commands

**Set Up Python Environment**

```shell
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Dry-run** (no changes are made, actions are logged):

```bash
AQUA_KEY=... AQUA_SECRET=... AQUA_GROUP_ID=... AQUA_REPOSITORY_ID=... \
PYTHONPATH=src python3 src/security/main.py --repo <owner/repo> --dry-run
```

**Live run** (creates/updates real GitHub Issues):

```bash
AQUA_KEY=... AQUA_SECRET=... AQUA_GROUP_ID=... AQUA_REPOSITORY_ID=... \
PYTHONPATH=src python3 src/security/main.py --repo <owner/repo>
```

**With verbose logging:**

```bash
AQUA_KEY=... AQUA_SECRET=... AQUA_GROUP_ID=... AQUA_REPOSITORY_ID=... \
PYTHONPATH=src python3 src/security/main.py --repo <owner/repo> --dry-run --verbose
```

### CLI Flags

| Flag                      | Description                                                                                |
|---------------------------|--------------------------------------------------------------------------------------------|
| `--repo`                  | Target repository (owner/repo).                                                            |
| `--dry-run`               | Simulate without writing issues. All intended actions are logged.                          |
| `--verbose`               | Enable verbose logging.                                                                    |
| `--teams-webhook-url`     | Teams webhook URL (default: `$TEAMS_WEBHOOK_URL`).                                         |
| `--min-severity`          | Minimum severity for issue creation: `low`, `medium`, `high`, `critical` (default: `low`). |

---

## Features

- **Dry-run mode**: Safe preview of all actions without making changes.
- **Verbose logging**: Detailed output for debugging and audit.
- **Severity filtering**: Configurable minimum severity threshold to limit issue creation to findings at or above the chosen level.
- **Teams notifications**: One card, sent only when a child issue is opened, reopened or closed.
- **Parent/child issue structure**: Findings grouped by rule with automatic lifecycle management.
- **Fingerprint-based matching**: Stable identification of findings across runs.

---

## Developer & Contribution Guide

We welcome community contributions!

- [Developer Guide](/DEVELOPERS.md)
- [Contributing Guide](/CONTRIBUTING.md)

---

## License & Support

This project is licensed under the **Apache License 2.0**. See the [LICENSE](/LICENSE) file for full terms.

- [Issues](https://github.com/AbsaOSS/organizational-workflows/issues)
- [Discussions](https://github.com/AbsaOSS/organizational-workflows/discussions)
