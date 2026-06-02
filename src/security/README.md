# Security Automation

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Adding the Workflow to Your Repository](#adding-the-workflow-to-your-repository)
- [Workflow Configuration](#workflow-configuration)
  - [Input Parameters](#input-parameters)
  - [Secrets](#secrets)
  - [Credentials Configuration](#credentials-configuration)
  - [How to Obtain AquaSec Group ID](#how-to-obtain-aquasec-group-id)
  - [How to Obtain AquaSec Repository ID](#how-to-obtain-aquasec-repository-id)
- [Running Locally](#running-locally)
- [Features](#features)
- [Developer & Contribution Guide](#developer--contribution-guide)
- [License & Support](#license--support)

## Overview

This solution automates the management of security findings by authenticating directly with the AquaSec API, fetching scan results, and converting them into a structured GitHub Issues backlog.

Solution supports:

- **Automated Issue creation**: Each unique finding becomes a GitHub Issue with severity, affected file, and remediation context.
- **Parent/child structure**: Findings are grouped under epic (parent) issues by rule, with individual occurrences as child sub-issues.
- **Lifecycle sync**: Issues are reopened when findings reappear, marked as ready-to-close when findings disappear, and parent issues auto-close when all children are resolved.
- **Teams notifications**: New and reopened findings trigger a Microsoft Teams Adaptive Card notification.
- **Priority sync**: Severity is mapped to priority on a GitHub ProjectV2 board.

> For a business-level overview of what this solution does and why, see the [Security Automation docs](/docs/security/security.md).

---

## Prerequisites

To use this solution, make sure your environment meets the following requirements:

- Python 3.14
- AquaSec API credentials (Key and Secret)
- AquaSec Group ID for authentication
- AquaSec Repository ID (UUID format) for the target scan results
- Required labels in the target repository: `scope:security`, `type:tech-debt`, `sec:adept-to-close`, `epic`

---

## Adding the Workflow to Your Repository

Create a workflow file (e.g. `.github/workflows/aquasec-night-scan.yml`) in your repository. A ready-to-copy example is available at [docs/security/aquasec-night-scan-example.yml](/docs/security/aquasec-night-scan-example.yml).

The caller workflow delegates to the shared reusable workflow in this repository:

```yaml
jobs:
  scan:
    uses: AbsaOSS/organizational-workflows/.github/workflows/aquasec-scan.yml@master
    with:
      dry-run: false
      severity-priority-map: 'Critical=P0,High=P1,Medium=P2,Low=P3'
      project-number: 42
      project-org: 'my-org'
    secrets:
      AQUA_KEY: ${{ secrets.AQUA_KEY }}
      AQUA_SECRET: ${{ secrets.AQUA_SECRET }}
      AQUA_GROUP_ID: ${{ secrets.AQUA_GROUP_ID }}
      AQUA_REPOSITORY_ID: ${{ secrets.AQUA_REPOSITORY_ID }}
      TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
```

---

## Workflow Configuration

### Input Parameters

| Name                    | Description                                                                                                        | Required | Default |
|-------------------------|--------------------------------------------------------------------------------------------------------------------|----------|---------|
| `dry-run`               | Simulate issue management without making changes.                                                                  | No       | false   |
| `verbose-logging`       | Enable verbose logging for the AquaSec scan step.                                                                  | No       | false   |
| `severity-priority-map` | Comma-separated severity=priority pairs. Only listed severities get a priority. When not set, priority is skipped. | No       | ''      |
| `project-number`        | GitHub ProjectV2 number (org-level) for priority sync. Required together with `severity-priority-map`.             | No       | 0       |
| `project-org`           | GitHub organisation that owns the ProjectV2 board.                                                                 | No       | ''      |

### Secrets

| Name                 | Required | Description                                            |
|----------------------|----------|--------------------------------------------------------|
| `AQUA_KEY`           | Yes      | AquaSec API Key credential                             |
| `AQUA_SECRET`        | Yes      | AquaSec API Secret credential                          |
| `AQUA_GROUP_ID`      | Yes      | AquaSec Group ID for authentication                    |
| `AQUA_REPOSITORY_ID` | Yes      | AquaSec Repository ID (UUID format)                    |
| `TEAMS_WEBHOOK_URL`  | No       | Microsoft Teams Incoming Webhook URL for notifications |

### Credentials Configuration

**For AbsaOSS / absa-group Organisation:**

- `AQUA_KEY` and `AQUA_SECRET` are stored as **organisation secrets** and automatically available to all repositories.
- You only need to configure `AQUA_GROUP_ID` and `AQUA_REPOSITORY_ID` as **repository secrets**.

**For Other Organisations:**

- Store all four credentials (`AQUA_KEY`, `AQUA_SECRET`, `AQUA_GROUP_ID`, `AQUA_REPOSITORY_ID`) as [GitHub repository secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets).
- Contact your AquaSec administrator if you don't have API credentials.

### How to Obtain AquaSec Group ID

**Option 1: Via User Management (requires User Management access)**

1. Navigate to **User Management** → **Groups** in the AquaSec platform.
2. Search for and select your specific group.
3. Click on the group to view its details.
4. The **Group ID** is displayed at the end of the URL after `/groups/`.

**Option 2: Via JWT Token Inspection**

1. Open your browser's Developer Tools and navigate to the **Network** tab.
2. Reload the AquaSec platform and locate any API request in the **Request Headers** section.
3. Copy your **Authorization Bearer token** from the headers.
4. Decode the token using for example [jwt.io](https://jwt.io/).
5. In the decoded payload, look for the **user_groups_user** field containing your accessible Group IDs.

### How to Obtain AquaSec Repository ID

1. Navigate to **Code Repositories** in the AquaSec platform.
2. Use the search bar to filter and locate your repository.
3. Click on the repository name to open its overview page.
4. The **Repository ID** (UUID format) is displayed in the URL after `/repositories/`.

**Example:** `https://aquasec.com/repositories/9d93jajb-6c6e-438d-8bef-afb5a12396e5/overview`  
→ Repository ID: `9d93jajb-6c6e-438d-8bef-afb5a12396e5`

---

## Running Locally

The entry point is `src/security/main.py`. It runs the full pipeline: authenticate with AquaSec, fetch findings, sync to Issues, and notify if set.

### Prerequisites

- Python 3.14 (current required runtime)
- Install and authenticate GitHub CLI: `gh auth login`
- Required labels must exist in the target repository: `scope:security`, `type:tech-debt`, `sec:adept-to-close`, `epic`
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

| Flag                      | Description                                                                  |
|---------------------------|------------------------------------------------------------------------------|
| `--repo`                  | Target repository (owner/repo).                                              |
| `--dry-run`               | Simulate without writing issues. All intended actions are logged.            |
| `--verbose`               | Enable verbose logging.                                                      |
| `--issue-label`           | Label used to discover existing security issues (default: `scope:security`). |
| `--severity-priority-map` | Severity-to-priority mapping (default: `$SEVERITY_PRIORITY_MAP`).            |
| `--project-number`        | ProjectV2 number for priority sync (default: `$PROJECT_NUMBER`).             |
| `--project-org`           | Org that owns the ProjectV2 board (default: `$PROJECT_ORG`).                 |
| `--teams-webhook-url`     | Teams webhook URL (default: `$TEAMS_WEBHOOK_URL`).                           |

---

## Features

- **Dry-run mode**: Safe preview of all actions without making changes.
- **Verbose logging**: Detailed output for debugging and audit.
- **Priority mapping**: Configurable severity-to-priority mapping for ProjectV2 boards.
- **Teams notifications**: Real-time alerts for new and reopened findings.
- **Parent/child issue structure**: Findings grouped by rule with automatic lifecycle management.
- **Fingerprint-based matching**: Stable identification of findings across runs.

---

## Developer & Contribution Guide

We welcome community contributions!

- [Developer Guide](/DEVELOPERS.md)
- [Contributing Guide](/CONTRIBUTING.md)

## License & Support

This project is licensed under the **Apache License 2.0**. See the [LICENSE](/LICENSE) file for full terms.

- [Issues](https://github.com/AbsaOSS/organizational-workflows/issues)
- [Discussions](https://github.com/AbsaOSS/organizational-workflows/discussions)
