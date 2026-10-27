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

**Finding Identity**:
The value used to decide whether a Finding in the current scan is the same Finding as one already tracked by a Child Issue. Taken from the AquaSec Fingerprint when AquaSec populates it, and from the Result Hash otherwise.
_Avoid_: fingerprint (bare), unique key, hash

> Both source values are unique per Finding. They differ in **stability**, not uniqueness.

**AquaSec Fingerprint**:
AquaSec's line-independent identifier for a Finding, carried in the `fingerprint` field. Populated for the `sast` Finding Category only. Shaped `<base>_<ordinal>`, where the ordinal is the occurrence's position among findings of the same Rule in the same file, so removing an earlier occurrence renumbers the later ones.
_Avoid_: fingerprint (bare), stable hash

**Result Hash**:
AquaSec's per-Finding hash, carried in the `result_hash` field and stored as `alert_hash`. Populated for every Finding Category. For line-based Categories the line number is an input, so it changes whenever an unrelated edit shifts the Finding. For `vulnerabilities` it is equivalent to _(rule, file, package, installed version)_ and is therefore stable.
_Avoid_: fingerprint, alert_hash (outside the parser)

**Finding Category**:
The AquaSec result group a Finding belongs to: `vulnerabilities`, `sast`, `pipelineMisconfigurations`, `iacMisconfigurations`, or `secrets`.
_Avoid_: type, kind, scan type

**Rule**:
The AquaSec check that produced a Finding, identified by `rule_id`. Many Findings can share one Rule.
_Avoid_: check, policy

**Severity**:
The AquaSec level of a Finding: `critical`, `high`, `medium`, `low`, or `unknown`. Stored lowercase in Secmeta and ordered by `SEVERITY_ORDER`. `unknown` ranks lowest and is dropped by any `min-severity` above `low`.

**Child Issue**:
A GitHub Issue representing a single Alert occurrence. Identified by its Finding Identity.
_Avoid_: alert issue

**Parent Issue (Epic)**:
A GitHub Issue that groups all Child Issues of one Rule, carrying the `epic` label. Auto-closes when all its Children are closed, and is reopened when a Child is reopened.
_Avoid_: rule issue, parent

**Sub-issue**:
GitHub's own parent/child link feature. It is the mechanism that attaches a Child Issue to its Parent Issue; a GitHub issue can have only one parent.
_Avoid_: using it as a synonym of Child Issue

**Secmeta**:
A hidden HTML-comment block at the top of every Issue body, holding machine-readable metadata. Parent keys: `type`, `repo`, `rule_id`, `severity`. Child keys: those plus `fingerprint`, which holds the Finding Identity, and `alert_hash`, which holds the Result Hash. This is how the pipeline recognizes its own issues.
_Avoid_: metadata block, frontmatter

**Issue Index**:
The in-memory lookup built from existing issues at the start of a sync. Child Issue by Finding Identity is the primary map, used for enumeration, counting and closure; Child Issue by Result Hash is a lookup-only fallback for Issues written before the Finding Identity change. Parent Issue is looked up by Rule ID. When duplicates share a key, the lowest issue number wins, so each Issue appears exactly once in the primary map.

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
- One **Alert** maps to at most one **Child Issue**, matched by **Finding Identity**.
- A **Child Issue** is attached to its **Parent Issue** as a **Sub-issue**.
- A **Waiver** attaches to a **Child Issue** and is never touched by the pipeline.
- A **Finding Category** determines whether an **AquaSec Fingerprint** exists, and therefore whether the **Finding Identity** survives a line shift.

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
- **Close**: an open Child Issue whose Finding Identity is absent from the scan is closed; a Parent Issue whose known Children are all closed is closed.
- **Counting**: the Notification counts open Child Issues per Finding Identity, not per AquaSec result row, and never counts Parent Issues. It cannot be expected to equal the AquaSec platform figure.

## Invariants

- The pipeline only manages issues that carry Secmeta; everything else is left alone.
- Only the pipeline's own labels are managed; Waiver labels are human-owned.
- Every run must be safe to repeat: re-running with the same scan produces no changes.
- Existing issues are fetched by the `type:aquasec` label alone, then narrowed by Secmeta. `scope:security` is a human-facing classification, not part of the machine identity.
- Labels are applied when an Issue is created and never re-stamped afterward.

## Example dialogue

> **Dev:** "A finding came in with `result_hash=abc123`. Do we already have an issue for it?"
> **Domain expert:** "Resolve its Finding Identity first — for `sast` that's the AquaSec Fingerprint, otherwise the Result Hash. Look that up in the Issue Index; if it matches a Child Issue, update it. If not, try the Result Hash against the fallback map. Only if both miss do you create a new Child Issue and link it to the Parent Issue for that Rule."

## Flagged ambiguities

- "Alert" was used for both the raw and parsed form; now **Finding** = raw, **Alert** = parsed.
- "Parent" and "Epic" name the same issue; prefer **Parent Issue**.
- "Sub-issue" is GitHub's link mechanism, not a synonym for **Child Issue**.
- "Fingerprint" named two different things — AquaSec's `fingerprint` field and the Secmeta key holding a Finding Identity. Now **AquaSec Fingerprint** and **Result Hash** are the two sources, and **Finding Identity** is the value chosen from them. Never use "fingerprint" bare.
- "Unique key" is not a synonym for **AquaSec Fingerprint** or **Result Hash**. Every source value is unique; they differ in stability.

## Current gaps

Finding Identity stability differs per Finding Category:

| Finding Category | Finding Identity source | survives a line shift |
|---|---|---|
| `vulnerabilities` | Result Hash | yes — the line is not an input |
| `sast` | AquaSec Fingerprint | yes |
| `pipelineMisconfigurations` | Result Hash | **no** |
| `iacMisconfigurations` | Result Hash | **no** |
| `secrets` | Result Hash | **no** |

- **`pipelineMisconfigurations`, `iacMisconfigurations` and `secrets` stay line-fragile.** They carry line numbers that feed the Result Hash and receive no AquaSec Fingerprint, so an unrelated edit that shifts a Finding still closes its Child Issue and opens a new one. AquaSec exposes no other discriminator — within one Rule and file, the line number is the only field that differs, and `message` and `scm_link` merely embed it. Any invented line-independent key would collapse genuinely distinct Findings into one Issue, which is worse. Closing that gap requires an upstream change.
- **The AquaSec Fingerprint carries an ordinal.** It is shaped `<base>_<ordinal>`, so deleting an earlier occurrence of the same Rule in the same file renumbers the later ones. When the surviving Finding keeps its line, its Result Hash is unchanged, and an exact Result Hash match on another Child Issue outranks the reused ordinal, so the Issue is preserved and its Finding Identity migrated. Only when the Result Hash changed in the same scan — the Finding both renumbered and shifted lines — is there no discriminator left, and the Child Issue churns once. Accepted, not worked around.
