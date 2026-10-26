# Security Automation

A reusable GitHub Actions pipeline that authenticates directly with AquaSec, fetches scan results, and manages them as GitHub Issues with full lifecycle management.

This file defines the domain language and rules. Code style and testing conventions live in `.github/copilot-instructions.md`; setup steps live in `docs/security/how-to-onboard.md`.

## Language

**Finding**:
A vulnerability or code-security result returned by AquaSec for a specific repository. The raw unit of input to the pipeline.
_Avoid_: result, scan result, vulnerability

**Alert**:
The internal representation of a Finding after parsing (`security.alerts.models.Alert`). The in-memory domain object that flows from parse to sync.
_Avoid_: Finding (once parsed), scan item

**Fingerprint**:
The identity used to match an Alert to an existing Child Issue across runs. Currently, taken directly from AquaSec's `result_hash` (stored as `alert_hash`), which embeds the line number. Therefore, the Fingerprint changes when an edit shifts the finding's line, and the pipeline then treats it as a resolved finding plus a new one.
_Avoid_: hash, result_hash (outside the parser)

**Rule**:
The AquaSec check that produced a Finding, identified by `rule_id`. Many Findings can share one Rule.
_Avoid_: check, policy

**Severity**:
The AquaSec level of a Finding: `critical`, `high`, `medium`, `low`, or `unknown`. Stored lowercase in Secmeta and ordered by `SEVERITY_ORDER`. `unknown` ranks lowest and is dropped by any `min-severity` above `low`.

**Child Issue**:
A GitHub Issue representing a single Alert occurrence. Identified by the `fingerprint` in its Secmeta block.
_Avoid_: alert issue

**Parent Issue (Epic)**:
A GitHub Issue that groups all Child Issues of one Rule, carrying the `epic` label. Auto-closes when all its Children are closed, and is reopened when a Child is reopened.
_Avoid_: rule issue, parent

**Sub-issue**:
GitHub's own parent/child link feature. It is the mechanism that attaches a Child Issue to its Parent Issue; a GitHub issue can have only one parent.
_Avoid_: using it as a synonym of Child Issue

**Secmeta**:
A hidden HTML-comment block at the top of every Issue body, holding machine-readable metadata. Parent keys: `type`, `repo`, `rule_id`, `severity`. Child keys: those plus `fingerprint`. This is how the pipeline recognizes its own issues.
_Avoid_: metadata block, frontmatter

**Issue Index**:
The in-memory lookup built from existing issues at the start of a sync: Child Issue by Fingerprint and Parent Issue by Rule ID. When duplicates share a key, the lowest issue number wins.

**Resolved Alert**:
An Alert that no longer appears in the current scan results. Its Child Issue is closed automatically (there is no intermediate "ready to close" state).
_Avoid_: fixed alert, gone finding

**Waiver**:
A human-owned decision to accept a Finding rather than fix it. Two kinds, each recorded on the Child Issue by a label plus a comment linking the Jira ticket. The pipeline never adds, removes, or reads these labels; they exist for traceability and filtering.
_Avoid_: exception, exemption, override

**Suppression**:
A Waiver where a real Finding is knowingly accepted for a period (`sec:suppression`).
_Avoid_: mute, ignore

**False Positive**:
A Waiver where a Finding is confirmed not to be a real issue (`sec:false-positive`).
_Avoid_: FP (in prose), invalid finding

**Dry-run**:
A run that logs every intended action and writes nothing to GitHub. Log lines use the `Security [DRY-RUN] -` prefix instead of `Security -`.

**Notification**:
A single Teams Adaptive Card per run, sent only when at least one Child Issue was opened, reopened, or closed. It also reports the repository's open Child Issues per Severity.

**Caller workflow / Reusable workflow**:
The Caller workflow lives in a consumer repository and invokes the Reusable workflow `.github/workflows/aquasec-scan.yml` in this repository via `workflow_call`.

## Relationships

- One **Rule** has one **Parent Issue** and many **Child Issues**.
- One **Alert** maps to at most one **Child Issue**, matched by **Fingerprint**.
- A **Child Issue** is attached to its **Parent Issue** as a **Sub-issue**.
- A **Waiver** attaches to a **Child Issue** and is never touched by the pipeline.

## Pipeline

`security/main.py` runs: validate config → ensure labels → authenticate → fetch → parse → sync → notify.

| Step | Owner |
|------|-------|
| Config | `security/config.py` |
| Labels (`scope:security`, `type:aquasec`, `epic`, waiver labels) | `services/label_creator.py` |
| Auth and fetch | `services/authenticator.py`, `services/scan_fetcher.py` |
| Parse | `alerts/aquasec_parser.py` |
| Sync | `services/issue_syncer.py`, `issues/sync.py` |
| Notify | `services/notification_sender.py`, `notifications/` |
| GitHub access (via `gh`) | `core/github/` |

## Lifecycle rules

- **Create**: an Alert with no matching Child Issue, at or above `min-severity`, creates one and links it to the Parent Issue (created if missing).
- **Update**: a matching open Child Issue has its body, title, and labels refreshed.
- **Reopen**: a matching closed Child Issue is reopened, and so is its Parent Issue.
- **Close**: an open Child Issue whose Fingerprint is absent from the scan is closed; a Parent Issue whose known Children are all closed is closed.
- **Counting**: the Notification counts open Child Issues per Fingerprint, not per GitHub issue, and never counts Parent Issues. It cannot be expected to equal the AquaSec platform figure.

## Invariants

- The pipeline only manages issues that carry Secmeta; everything else is left alone.
- Only the pipeline's own labels are managed; Waiver labels are human-owned.
- Every run must be safe to repeat: re-running with the same scan produces no changes.
- Existing issues are fetched by the `type:aquasec` label alone, then narrowed by Secmeta. `scope:security` is a human-facing classification, not part of the machine identity.
- Labels are applied when an Issue is created and never re-stamped afterward.

## Example dialogue

> **Dev:** "A finding came in with `result_hash=abc123`. Do we already have an issue for it?"
> **Domain expert:** "Check the Issue Index — if `abc123` matches a Child Issue's Secmeta fingerprint, update it. Otherwise, create a new Child Issue and link it to the Parent Issue for that Rule."

## Flagged ambiguities

- "Alert" was used for both the raw and parsed form; now **Finding** = raw, **Alert** = parsed.
- "Parent" and "Epic" name the same issue; prefer **Parent Issue**.
- "Sub-issue" is GitHub's link mechanism, not a synonym for **Child Issue**.
