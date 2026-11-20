# How Onboard to Security Automation

## Overview

This guide walks you through onboarding your repository to **Security Automation** step by step. When you are done, a nightly workflow will fetch AquaSec scan findings for your repository and turn them into a managed GitHub Issues backlog.

> For a business-level overview of what the solution does and why, see the [Security Automation docs](../security-automation).

- **Step 0:** Check the prerequisites.
- **Step 1:** Store the credentials as GitHub secrets.
- **Step 2:** Add the caller workflow to your repository.
- **Step 3:** Run it in dry-run mode, then switch to live mode.

---

## Step 0: Prerequisites

Make sure you have the following before you start:

- Admin (or equivalent) access to the GitHub repository you are onboarding, so you can add secrets and workflow files.
- Access to the AquaSec platform, and your repository already onboarded there as a **Code Repository**.
- *(Optional)* A Microsoft Teams Incoming Webhook URL, if you want to run notifications.

> **No label setup required.** The pipeline creates any missing labels on its first run: `scope:security`, `type:aquasec`, `epic`, `sec:suppression`, `sec:false-positive`.

---

## Step 1: Store the Credentials as GitHub Secrets

The workflow reads its credentials from GitHub secrets.

| Secret               | Required | Description                          |
|----------------------|----------|--------------------------------------|
| `AQUA_KEY`           | Yes      | AquaSec API Key credential           |
| `AQUA_SECRET`        | Yes      | AquaSec API Secret credential        |
| `TEAMS_WEBHOOK_URL`  | No       | Microsoft Teams Incoming Webhook URL |

**For the AbsaOSS / absa-group organizations:**

- `AQUA_KEY` and `AQUA_SECRET` are stored as **organization secrets** and are automatically available to all repositories.

To add a repository secret, open your repository on GitHub and go to **Settings** → **Secrets and variables** → **Actions** → **New repository secret**.

---

## Step 2: Add the Caller Workflow

Create a workflow file in your repository, for example `.github/workflows/aquasec-night-scan.yml`. A ready-to-copy example is available at <a href="https://github.com/AbsaOSS/organizational-workflows/blob/master/docs/security/aquasec-night-scan-example.yml" target="_blank" rel="noopener noreferrer">aquasec-night-scan-example.yml</a>.

The caller workflow delegates to the shared reusable workflow in this repository:

```yaml
jobs:
  scan:
    uses: AbsaOSS/organizational-workflows/.github/workflows/aquasec-scan.yml@<commit-sha> # Should be changed to the newest release SHA
    with:
      dry-run: true
      min-severity: 'high' # Only high and critical severity alerts will be promoted to issues
      project-number: 42
      project-org: 'my-org'
    secrets:
      AQUA_KEY: ${{ secrets.AQUA_KEY }}
      AQUA_SECRET: ${{ secrets.AQUA_SECRET }}
      TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
```

> **Start with `dry-run: true`.** The first run then only logs what it would do and creates no issues.

### Input Parameters

| Name                    | Description                                                                                                         | Required | Default |
|-------------------------|---------------------------------------------------------------------------------------------------------------------|----------|---------|
| `dry-run`               | Simulate issue management without making changes.                                                                   | No       | false   |
| `verbose-logging`       | Enable verbose logging for the AquaSec scan step.                                                                   | No       | false   |
| `project-number`        | GitHub ProjectV2 number (org-level) for priority sync. Required together with `severity-priority-map`.              | No       | 0       |
| `project-org`           | GitHub organization that owns the ProjectV2 board.                                                                  | No       | ''      |
| `min-severity`          | Minimum severity level for issue creation. Accepted values: `low`, `medium`, `high`, `critical` (case-insensitive). | No       | 'low'   |

Optional features:

- **Teams notifications:** pass the `TEAMS_WEBHOOK_URL` secret. A card is sent only when a child issue is opened, reopened or closed.
- **Severity filtering:** set `min-severity` to limit issue creation to findings at or above a level.

---

## Step 3: Run in Dry-Run Mode and Go Live

1. Open the **Actions** tab of your repository and run the workflow manually (or wait for the schedule).
2. Open the run log and check that AquaSec authentication and repository ID lookup succeed and the planned actions look right.
3. Set `dry-run: false` in your caller workflow and run it again.
4. Open the **Issues** tab and filter by the `type:aquasec` label. You should see one parent (rule) issue per rule, with the individual findings as child sub-issues.

From now on, the workflow keeps the backlog in sync on every run: issues are reopened when findings reappear and closed when findings disappear.

---

## Troubleshooting

| Symptom                                             | What to check                                                                                                                 |
|-----------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Authentication with AquaSec fails                   | Verify `AQUA_KEY` and `AQUA_SECRET`, and make sure the secrets are available to the repository.                              |
| No findings are fetched                             | Confirm repository ID lookup succeeded and that the repository has a scan in AquaSec.                                    |
| No issues are created                               | Check whether `dry-run` is still `true`, and whether `min-severity` is higher than your findings.                             |
| Priority is not set on the project board            | `project-number` and `project-org` must all be set, and the token needs access to the project.                                |
| No Teams card arrives                               | `TEAMS_WEBHOOK_URL` secret must be set. A card is sent only when a child issue was opened, reopened or closed during the run. |

> Still stuck? Open an <a href="https://github.com/AbsaOSS/organizational-workflows/issues" target="_blank" rel="noopener noreferrer">Issue</a> or start a <a href="https://github.com/AbsaOSS/organizational-workflows/discussions" target="_blank" rel="noopener noreferrer">Discussion</a>. Happy to help.

---

## See Also

- [Security Automation docs](../security-automation): what the solution does and why
- [Security README](https://github.com/AbsaOSS/organizational-workflows/blob/master/src/security/README.md): running the pipeline locally, CLI flags and contributor details
- [Example Caller Workflow](https://github.com/AbsaOSS/organizational-workflows/blob/master/docs/security/aquasec-night-scan-example.yml): ready-to-copy workflow file for your repository
