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

"""Core sync orchestration – builds the issue_index, matches alerts to
existing issues, creates / updates / reopens parent and child issues,
and labels orphaned issues for closure.

This is the main business-logic module that ties together all other
``issues.*`` modules.
"""

import logging
import re

from core.helpers import normalize_path
from core.github.issues import (
    gh_issue_add_sub_issue_by_number,
    gh_issue_create,
    gh_issue_edit_body,
    gh_issue_edit_state,
    gh_issue_edit_title,
    gh_issue_get_sub_issue_numbers,
)
from core.github.projects import ProjectPrioritySync, gh_project_get_priority_field
from core.models import Issue
from core.rendering import render_markdown_template, strip_na_sections

from security.alerts.models import Alert
from security.constants import (
    DRY_RUN_PREFIX,
    LABEL_EPIC,
    LABEL_SCOPE_SECURITY,
    LABEL_TYPE_AQUASEC,
    LOGGING_PREFIX,
    SECMETA_TYPE_CHILD,
    SECMETA_TYPE_PARENT,
    SECMETA_KEYS_PARENT,
    SECMETA_KEYS_CHILD,
    MIN_SEVERITY_DEFAULT,
)
from .builder import (
    build_child_issue_body,
    build_issue_title,
    build_parent_issue_body,
    build_parent_issue_title,
    build_parent_template_values,
)
from .models import (
    AlertContext,
    IssueIndex,
    IssueChange,
    ParentOriginalBodies,
    SEVERITY_ORDER,
    SyncContext,
    SyncResult,
    SyncStats,
    bump_severity,
)
from .secmeta import load_secmeta, render_secmeta, replace_secmeta
from .summary import render_sync_summary
from .templates import PARENT_BODY_TEMPLATE

_FINGERPRINT_ORDINAL_RE = re.compile(r"^(.+)_(\d+)$")


def _fingerprint_base(identity_key: str) -> str | None:
    """Return the ``<base>`` of an AquaSec Fingerprint shaped ``<base>_<ordinal>``, or ``None``."""
    found = _FINGERPRINT_ORDINAL_RE.match(identity_key)
    return found.group(1) if found else None


def _is_preferred_child(candidate: Issue, current: Issue | None) -> bool:
    """Return True if *candidate* should replace *current* under a shared lookup key.

    An open issue beats a closed one, so an issue whose Finding Identity was migrated onto a reused
    AquaSec Fingerprint ordinal is not shadowed by the closed issue of the removed occurrence. Among
    equally open issues the oldest (lowest-numbered) wins.
    """
    if current is None:
        return True
    candidate_closed = candidate.state.lower() == "closed"
    current_closed = current.state.lower() == "closed"
    if candidate_closed != current_closed:
        return not candidate_closed
    return candidate.number < current.number


def _index_child_issue(issue_index: IssueIndex, issue: Issue, *, identity_key: str, alert_hash: str) -> None:
    """Register a child issue for enumeration and under each of its lookup keys."""
    issue_index.children.append(issue)
    if identity_key and _is_preferred_child(issue, issue_index.child_by_identity_key.get(identity_key)):
        issue_index.child_by_identity_key[identity_key] = issue
    if alert_hash and _is_preferred_child(issue, issue_index.child_by_alert_hash.get(alert_hash)):
        issue_index.child_by_alert_hash[alert_hash] = issue


def build_issue_index(issues: dict[int, Issue]) -> IssueIndex:
    """Build the child and parent lookup maps from existing issues.

    Every child issue is listed once in ``children`` and keyed in two lookup-only maps: by its stored
    Finding Identity and by its stored Result Hash. The Result Hash is the Finding Identity itself for
    every Finding Category except ``sast`` — there it also catches issues created before the AquaSec
    Fingerprint was adopted.

    A child issue that stores no Finding Identity is keyed in the identity map by its Result Hash.

    When several child issues share a key, an open issue wins over a closed one, then the oldest
    (lowest-numbered). For parent issues the oldest wins.
    """
    issue_index = IssueIndex(parent_by_rule_id={}, child_by_identity_key={})
    parent_by_rule_id = issue_index.parent_by_rule_id

    for issue in issues.values():
        secmeta = load_secmeta(issue.body)
        secmeta_type = secmeta.get("type", "").strip().lower()
        if secmeta_type == SECMETA_TYPE_PARENT:
            rule_id = secmeta.get("rule_id", "").strip()
            if rule_id:
                existing_parent = parent_by_rule_id.get(rule_id)
                if existing_parent is None or issue.number < existing_parent.number:
                    parent_by_rule_id[rule_id] = issue
            continue

        alert_hash = secmeta.get("alert_hash", "").strip()
        # Fall back to the Result Hash so a child issue written without a Finding Identity is still
        # reachable through the identity map.
        identity_key = secmeta.get("fingerprint", "").strip() or alert_hash
        if not identity_key:
            continue
        _index_child_issue(issue_index, issue, identity_key=identity_key, alert_hash=alert_hash)

    return issue_index


def _is_open(issue: Issue) -> bool:
    """Return True if *issue* is open."""
    return issue.state.lower() == "open"


def _alert_fingerprint_base(alert: Alert) -> str | None:
    """Return the AquaSec Fingerprint base of a ``sast`` alert, or ``None`` for every other Category."""
    details = alert.alert_details
    if details.identity_key == details.alert_hash:
        return None
    return _fingerprint_base(details.identity_key)


def _stable_fingerprint_bases(
    alerts: dict[int, Alert],
    issue_index: IssueIndex,
    unmatched_keys: list[int],
    claimed: set[int],
) -> set[str]:
    """Return the AquaSec Fingerprint bases whose occurrence set is unchanged since the last run.

    A base is stable when the Finding Identities of its still-unmatched alerts equal those of its
    still-unclaimed open child issues, with no conflicting open owners of an identity. Otherwise,
    an ordinal may have been reused and the Finding Identity no longer tells the occurrences apart.
    """
    alert_ids: dict[str, set[str]] = {}
    for alert_key in unmatched_keys:
        alert = alerts[alert_key]
        base = _alert_fingerprint_base(alert)
        if base is not None:
            alert_ids.setdefault(base, set()).add(alert.alert_details.identity_key)

    if not alert_ids:
        return set()

    owners_by_identity: dict[tuple[str, str], list[Issue]] = {}
    for issue in issue_index.children:
        if not _is_open(issue):
            continue
        secmeta = load_secmeta(issue.body)
        identity_key = secmeta.get("fingerprint", "").strip() or secmeta.get("alert_hash", "").strip()
        base = _fingerprint_base(identity_key)
        if base is not None and base in alert_ids:
            owners_by_identity.setdefault((base, identity_key), []).append(issue)

    issue_ids: dict[str, set[str]] = {}
    conflicting_bases: set[str] = set()
    for (base, identity_key), owners in owners_by_identity.items():
        if len({load_secmeta(owner.body).get("alert_hash", "").strip() for owner in owners}) > 1:
            conflicting_bases.add(base)
        # A duplicate of a claimed finding is not another available occurrence.
        if not any(id(owner) in claimed for owner in owners):
            issue_ids.setdefault(base, set()).add(identity_key)

    return {base for base, ids in alert_ids.items() if ids == issue_ids.get(base, set())} - conflicting_bases


def resolve_child_matches(alerts: dict[int, Alert], issue_index: IssueIndex) -> dict[int, Issue]:
    """Match every alert of the scan to at most one existing child issue, each issue claimed once.

    Returns the matched issue per key of *alerts*; an alert without an entry needs a new issue.

    Matching runs over the whole scan in three passes, so the strongest evidence wins regardless of
    alert order:

    1. **Exact Result Hash on an open issue** — the same finding on the same line. Tried against the
       identity map first, where issues created before the Finding Identity was adopted store it,
       then against the Result Hash map.
    2. **Finding Identity** — for alerts still unmatched, e.g. a ``sast`` finding whose line shifted.
       For ``sast`` it applies only while the alert's AquaSec Fingerprint base kept the same set of
       occurrences; see ``_stable_fingerprint_bases``.
    3. **Exact Result Hash on a closed issue** — a resolved finding that reappeared on its old line.

    An AquaSec Fingerprint ordinal is reused when an earlier occurrence of the same Rule in the same
    file is removed or a new one is inserted ahead of it. Exact Result Hashes first, single claims,
    and the stable-base guard keep a reused ordinal from handing one finding's issue — with its
    history and Waivers — to another finding. When the guard refuses, the finding gets a new issue
    and the unclaimed one closes.
    """
    matches: dict[int, Issue] = {}
    claimed: set[int] = set()  # id() of claimed issues - dry-run placeholders all share number 0

    def _claim(alert_key: int, candidate: Issue | None, *, want_open: bool | None = None) -> bool:
        if candidate is None or id(candidate) in claimed:
            return False
        if want_open is not None and _is_open(candidate) != want_open:
            return False
        matches[alert_key] = candidate
        claimed.add(id(candidate))
        return True

    def _claim_by_result_hash(*, want_open: bool) -> None:
        for alert_key, alert in alerts.items():
            alert_hash = alert.alert_details.alert_hash
            if alert_key in matches or not alert_hash:
                continue
            if not _claim(alert_key, issue_index.child_by_identity_key.get(alert_hash), want_open=want_open):
                _claim(alert_key, issue_index.child_by_alert_hash.get(alert_hash), want_open=want_open)

    _claim_by_result_hash(want_open=True)

    unmatched_keys = [alert_key for alert_key in alerts if alert_key not in matches]
    stable_bases = _stable_fingerprint_bases(alerts, issue_index, unmatched_keys, claimed)
    for alert_key in unmatched_keys:
        alert = alerts[alert_key]
        identity_key = alert.alert_details.identity_key
        base = _alert_fingerprint_base(alert)
        if identity_key and (base is None or base in stable_bases):
            _claim(alert_key, issue_index.child_by_identity_key.get(identity_key))

    _claim_by_result_hash(want_open=False)

    return matches


def find_parent_issue(issue_index: IssueIndex, *, rule_id: str) -> Issue | None:
    """Return the parent issue for *rule_id*, or ``None``."""
    return issue_index.parent_by_rule_id.get(rule_id)


def maybe_reopen_parent_issue(
    repo: str,
    parent_issue: Issue | None,
    *,
    rule_id: str,
    dry_run: bool,
    stats: SyncStats,
    severity: str | None = None,
) -> None:
    """Reopen *parent_issue* (if closed)."""
    if parent_issue is None:
        return

    if parent_issue.state.lower() != "closed":
        return

    parent_severity = severity or load_secmeta(parent_issue.body).get("severity")

    if dry_run:
        logging.info(
            "%sWould reopen parent issue #%d %s",
            DRY_RUN_PREFIX,
            parent_issue.number,
            rule_id,
        )
        parent_issue.state = "open"
        stats.parents_reopened += 1
        bump_severity(stats.parents_reopened_by_severity, parent_severity)
        return

    if gh_issue_edit_state(repo, parent_issue.number, "open"):
        parent_issue.state = "open"
        logging.info("%sReopened parent issue #%d %s", LOGGING_PREFIX, parent_issue.number, rule_id)
        stats.parents_reopened += 1
        bump_severity(stats.parents_reopened_by_severity, parent_severity)


def _close_resolved_parent_issues(
    parent_issues: dict[int, Issue],
    issue_index: IssueIndex,
    *,
    dry_run: bool,
    stats: SyncStats,
) -> None:
    """Close open parent issues whose known child issues are all closed."""
    child_issues_by_rule_id: dict[str, list[Issue]] = {}

    for parent_issue in parent_issues.values():
        secmeta = load_secmeta(parent_issue.body)
        if secmeta.get("type", "").strip().lower() != SECMETA_TYPE_CHILD:
            continue

        rule_id = secmeta.get("rule_id", "").strip()
        if not rule_id:
            continue

        child_issues_by_rule_id.setdefault(rule_id, []).append(parent_issue)

    for rule_id, parent_issue in issue_index.parent_by_rule_id.items():
        if parent_issue.state.lower() == "closed":
            continue

        child_issues = child_issues_by_rule_id.get(rule_id, [])
        if not child_issues:
            continue

        if any(child_issue.state.lower() != "closed" for child_issue in child_issues):
            continue

        parent_secmeta = load_secmeta(parent_issue.body)
        repo = parent_secmeta.get("repo", "").strip()
        if not repo and child_issues:
            repo = load_secmeta(child_issues[0].body).get("repo", "").strip()
        if not repo:
            logging.debug("Skip closing parent issue #%d: no repo in secmeta", parent_issue.number)
            continue

        parent_severity = parent_secmeta.get("severity")

        if dry_run:
            logging.info(
                "%sWould close parent issue #%d (all children resolved)",
                DRY_RUN_PREFIX,
                parent_issue.number,
            )
            stats.parents_closed += 1
            bump_severity(stats.parents_closed_by_severity, parent_severity)
            continue

        if gh_issue_edit_state(repo, parent_issue.number, "closed"):
            logging.info(
                "%sClosed parent issue #%d (all children resolved)",
                LOGGING_PREFIX,
                parent_issue.number,
            )
            parent_issue.state = "closed"
            stats.parents_closed += 1
            bump_severity(stats.parents_closed_by_severity, parent_severity)


def ensure_parent_issue(
    alert: Alert,
    issues: dict[int, Issue],
    issue_index: IssueIndex,
    *,
    dry_run: bool,
    severity_priority_map: dict[str, str] | None = None,
    priority_sync: ProjectPrioritySync | None = None,
    parent_original_bodies: ParentOriginalBodies,
    stats: SyncStats,
) -> Issue | None:
    """Find or create the parent issue for the alert's ``rule_id``."""
    rule_id = alert.metadata.rule_id
    if not rule_id:
        return None

    repo_full = alert.repo
    existing = find_parent_issue(issue_index, rule_id=rule_id)
    if existing is not None:
        # Keep parent issues aligned to the template as alerts evolve.
        existing_secmeta = load_secmeta(existing.body) or {}

        existing_severity = str(existing_secmeta.get("severity") or "unknown")
        severity_stored = alert.metadata.severity or existing_severity

        existing_secmeta.update(
            {
                "type": SECMETA_TYPE_PARENT,
                "repo": repo_full,
                "severity": severity_stored,
                "rule_id": rule_id,
            }
        )
        existing_secmeta = {k: v for k, v in existing_secmeta.items() if k in SECMETA_KEYS_PARENT}

        rebuilt = (
            render_secmeta(existing_secmeta)
            + "\n\n"
            + strip_na_sections(
                render_markdown_template(
                    PARENT_BODY_TEMPLATE,
                    build_parent_template_values(alert, rule_id=rule_id, severity=severity_stored),
                )
            ).strip()
            + "\n"
        )

        # Snapshot the original body on first encounter so we can
        # defer the API call until all alerts have been processed.
        if existing.number not in parent_original_bodies:
            parent_original_bodies[existing.number] = (repo_full, existing.body or "")
        existing.body = rebuilt

        # Detect parent title drift and update when needed.
        expected_title = build_parent_issue_title(rule_id)
        if expected_title != (existing.title or ""):
            if dry_run:
                existing.title = expected_title
                logging.info("%sWould update parent issue #%d title", DRY_RUN_PREFIX, existing.number)
                logging.debug(
                    "%sWould update title for parent issue #%d to %s", DRY_RUN_PREFIX, existing.number, expected_title
                )
                stats.parents_title_updated += 1
                bump_severity(stats.parents_title_updated_by_severity, severity_stored)
            else:
                if gh_issue_edit_title(repo_full, existing.number, expected_title):
                    existing.title = expected_title
                    logging.info("%sUpdated parent issue #%d title", LOGGING_PREFIX, existing.number)
                    logging.debug("New updated title for parent issue #%d: %s", existing.number, expected_title)
                    stats.parents_title_updated += 1
                    bump_severity(stats.parents_title_updated_by_severity, severity_stored)

        if priority_sync is not None:
            priority_sync.enqueue(repo_full, existing.number, severity_stored, severity_priority_map or {})

        return existing

    title = build_parent_issue_title(rule_id)
    body = build_parent_issue_body(alert)
    labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_AQUASEC, LABEL_EPIC]
    if dry_run:
        logging.info(
            "%sWould create parent issue for rule %s (severity: %s)",
            DRY_RUN_PREFIX,
            rule_id,
            alert.metadata.severity,
        )
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug("%sWould create parent issue for rule %s with body:\n%s", DRY_RUN_PREFIX, rule_id, body)
        stats.parents_created += 1
        bump_severity(stats.parents_created_by_severity, alert.metadata.severity)
        placeholder = Issue(number=0, state="open", title=title, body=body)
        issue_index.parent_by_rule_id[rule_id] = placeholder
        return placeholder

    num = gh_issue_create(repo_full, title, body, labels)
    if num is None:
        return None

    created = Issue(number=num, state="open", title=title, body=body)
    issues[num] = created
    issue_index.parent_by_rule_id[rule_id] = created
    logging.info("%sCreated parent issue #%d for rule %s", LOGGING_PREFIX, num, rule_id)
    stats.parents_created += 1
    bump_severity(stats.parents_created_by_severity, alert.metadata.severity)

    if priority_sync is not None:
        priority_sync.enqueue(
            repo_full,
            num,
            alert.metadata.severity,
            severity_priority_map or {},
        )

    return created


def _record_for_notification(
    issue_changes: list[IssueChange] | None,
    *,
    repo: str,
    issue_number: int,
    severity: str,
    rule_id: str,
    state: str,
) -> None:
    """Record a child issue change if the *issue_changes* list is active."""
    if issue_changes is not None:
        issue_changes.append(
            IssueChange(
                repo=repo,
                issue_number=issue_number,
                severity=severity,
                rule_id=rule_id,
                state=state,
            )
        )


def _handle_new_child_issue(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    parent_issue: Issue | None,
) -> None:
    """Create a new child issue for an alert that has no matching issue yet."""
    secmeta: dict[str, str] = {
        "type": SECMETA_TYPE_CHILD,
        "fingerprint": ctx.identity_key,
        "alert_hash": ctx.alert_hash,
        "repo": ctx.repo,
        "rule_id": ctx.rule_id,
        "severity": ctx.severity,
    }

    human_body = build_child_issue_body(ctx.alert)
    body = render_secmeta(secmeta) + "\n\n" + human_body
    title = build_issue_title(ctx.rule_description, ctx.identity_key, ctx.severity)

    if sync.dry_run:
        logging.info(
            "%sWould create child issue for alert FP=%s (rule: %s, severity: %s)",
            DRY_RUN_PREFIX,
            ctx.identity_key[:8],
            ctx.rule_id,
            ctx.severity,
        )
        if parent_issue is None and ctx.rule_id:
            logging.debug("No parent issue yet for rule_id=%s. Link will happen on next sync", ctx.rule_id)
        sync.stats.children_created += 1
        bump_severity(sync.stats.children_created_by_severity, ctx.severity)
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug(
                "%sWould create child issue for alert FP=%s with body:\n%s", DRY_RUN_PREFIX, ctx.identity_key[:8], body
            )

        _record_for_notification(
            sync.issue_changes,
            repo=ctx.repo,
            issue_number=0,
            severity=ctx.severity,
            rule_id=ctx.rule_id,
            state="new",
        )
        # Mirror the real path so the run's posture count includes this issue.
        mirrored = Issue(number=0, state="open", title=title, body=body)
        _index_child_issue(sync.issue_index, mirrored, identity_key=ctx.identity_key, alert_hash=ctx.alert_hash)
        if sync.priority_sync is not None:
            sync.priority_sync.enqueue(ctx.repo, 0, ctx.severity, sync.severity_priority_map)
        return

    num = gh_issue_create(ctx.repo, title, body, [LABEL_SCOPE_SECURITY, LABEL_TYPE_AQUASEC])
    if num is None:
        return

    logging.info("%sCreated child issue #%d for alert FP=%s", LOGGING_PREFIX, num, ctx.identity_key[:8])
    sync.stats.children_created += 1
    bump_severity(sync.stats.children_created_by_severity, ctx.severity)
    created = Issue(number=num, state="open", title=title, body=body)
    sync.issues[num] = created
    _index_child_issue(sync.issue_index, created, identity_key=ctx.identity_key, alert_hash=ctx.alert_hash)

    _record_for_notification(
        sync.issue_changes,
        repo=ctx.repo,
        issue_number=num,
        severity=ctx.severity,
        rule_id=ctx.rule_id,
        state="new",
    )

    if parent_issue is not None:
        maybe_reopen_parent_issue(
            ctx.repo,
            parent_issue,
            rule_id=ctx.rule_id,
            dry_run=sync.dry_run,
            stats=sync.stats,
            severity=ctx.severity,
        )
        if gh_issue_add_sub_issue_by_number(ctx.repo, parent_issue.number, num):
            logging.debug(
                "Added link child issue #%d to parent #%d (alert FP=%s)", num, parent_issue.number, ctx.identity_key[:8]
            )
        else:
            logging.warning(
                "Failed to link child issue #%d to parent #%d (alert FP=%s)",
                num,
                parent_issue.number,
                ctx.identity_key[:8],
            )

    if sync.priority_sync is not None:
        sync.priority_sync.enqueue(ctx.repo, num, ctx.severity, sync.severity_priority_map)


def _maybe_reopen_child(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    child_issue: Issue,
    parent_issue: Issue | None,
) -> bool:
    """Reopen a closed child issue and cascade to its parent.

    Returns ``True`` if the issue was reopened.
    """
    if child_issue.state.lower() != "closed":
        return False

    reopened = False
    if sync.dry_run:
        reopened = True
        child_issue.state = "open"
        logging.info("%sWould reopen child issue #%d", DRY_RUN_PREFIX, child_issue.number)
    elif gh_issue_edit_state(ctx.repo, child_issue.number, "open"):
        reopened = True
        child_issue.state = "open"
        logging.info("%sReopened child issue #%d", LOGGING_PREFIX, child_issue.number)

    if reopened:
        sync.stats.children_reopened += 1
        bump_severity(sync.stats.children_reopened_by_severity, ctx.severity)
        maybe_reopen_parent_issue(
            ctx.repo,
            parent_issue,
            rule_id=ctx.rule_id,
            dry_run=sync.dry_run,
            stats=sync.stats,
            severity=ctx.severity,
        )
        existing_secmeta = load_secmeta(child_issue.body)
        reopen_rule_id = (existing_secmeta.get("rule_id") or "").strip() or ctx.rule_id
        _record_for_notification(
            sync.issue_changes,
            repo=ctx.repo,
            issue_number=child_issue.number,
            severity=ctx.severity,
            rule_id=reopen_rule_id,
            state="reopen",
        )
        if sync.priority_sync is not None:
            sync.priority_sync.enqueue(ctx.repo, child_issue.number, ctx.severity, sync.severity_priority_map)

    return reopened


def _merge_child_secmeta(
    *,
    ctx: AlertContext,
    child_issue: Issue,
) -> dict[str, str]:
    """Merge incoming alert data into the child issue's secmeta."""
    secmeta = load_secmeta(child_issue.body) or {}

    secmeta.update(
        {
            "type": SECMETA_TYPE_CHILD,
            "fingerprint": ctx.identity_key,
            "alert_hash": ctx.alert_hash,
            "repo": ctx.repo,
            "rule_id": ctx.rule_id or secmeta.get("rule_id", ""),
            "severity": ctx.severity,
        }
    )
    secmeta = {k: v for k, v in secmeta.items() if k in SECMETA_KEYS_CHILD}

    return secmeta


def _rebuild_and_apply_child_body(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    child_issue: Issue,
    secmeta: dict[str, str],
) -> None:
    """Render a fresh child body from *secmeta* + template and apply if changed."""
    human_body = build_child_issue_body(ctx.alert)
    new_body = render_secmeta(secmeta) + "\n\n" + human_body

    if new_body != child_issue.body:
        if sync.dry_run:
            logging.info("%sWould update child issue #%d body", DRY_RUN_PREFIX, child_issue.number)
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.debug(
                    "%sWould update child issue #%d body to:\n%s", DRY_RUN_PREFIX, child_issue.number, new_body
                )
            sync.stats.children_body_updated += 1
            bump_severity(sync.stats.children_body_updated_by_severity, ctx.severity)
        else:
            if gh_issue_edit_body(ctx.repo, child_issue.number, new_body):
                child_issue.body = new_body
                logging.info("%sUpdated child issue #%d body", LOGGING_PREFIX, child_issue.number)
                sync.stats.children_body_updated += 1
                bump_severity(sync.stats.children_body_updated_by_severity, ctx.severity)


def _sync_child_title(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    child_issue: Issue,
) -> None:
    """Fix title drift and ensure the priority on the child issue."""
    expected_title = build_issue_title(ctx.rule_description, ctx.identity_key, ctx.severity)
    if expected_title != (child_issue.title or ""):
        if sync.dry_run:
            logging.info("%sWould update child issue #%d title", DRY_RUN_PREFIX, child_issue.number)
            logging.debug(
                "%sWould update title for child issue #%d to %s", DRY_RUN_PREFIX, child_issue.number, expected_title
            )
            sync.stats.children_title_updated += 1
            bump_severity(sync.stats.children_title_updated_by_severity, ctx.severity)
        else:
            if gh_issue_edit_title(ctx.repo, child_issue.number, expected_title):
                child_issue.title = expected_title
                logging.info("%sUpdated child issue #%d title", LOGGING_PREFIX, child_issue.number)
                logging.debug("New updated title for child issue #%d: %s", child_issue.number, expected_title)
                sync.stats.children_title_updated += 1
                bump_severity(sync.stats.children_title_updated_by_severity, ctx.severity)

    if sync.priority_sync is not None:
        sync.priority_sync.enqueue(ctx.repo, child_issue.number, ctx.severity, sync.severity_priority_map)


def _ensure_child_linked_to_parent(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    child_issue: Issue,
    parent_issue: Issue,
) -> None:
    """Detect and repair a missing parent-to-child sub-issue link."""
    cache = sync.parent_sub_issues_cache
    if parent_issue.number not in cache:
        cache[parent_issue.number] = gh_issue_get_sub_issue_numbers(ctx.repo, parent_issue.number)

    if child_issue.number in cache[parent_issue.number]:
        return

    if sync.dry_run:
        logging.info(
            "%sWould relink child issue #%d to parent #%d (alert FP=%s)",
            DRY_RUN_PREFIX,
            child_issue.number,
            parent_issue.number,
            ctx.identity_key[:8],
        )
        cache[parent_issue.number].add(child_issue.number)
        sync.stats.children_relinked += 1
        return

    if gh_issue_add_sub_issue_by_number(ctx.repo, parent_issue.number, child_issue.number):
        logging.info(
            "%sRelinked child issue #%d to parent #%d (alert FP=%s)",
            LOGGING_PREFIX,
            child_issue.number,
            parent_issue.number,
            ctx.identity_key[:8],
        )
        cache[parent_issue.number].add(child_issue.number)
        sync.stats.children_relinked += 1
    else:
        logging.warning(
            "Failed to relink child issue #%d to parent #%d (alert FP=%s)",
            child_issue.number,
            parent_issue.number,
            ctx.identity_key[:8],
        )


def _handle_existing_child_issue(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    child_issue: Issue,
    parent_issue: Issue | None,
) -> None:
    """Update an existing child issue with refreshed alert data."""
    if parent_issue is None and ctx.rule_id:
        parent_issue = find_parent_issue(sync.issue_index, rule_id=ctx.rule_id)

    _maybe_reopen_child(ctx=ctx, sync=sync, child_issue=child_issue, parent_issue=parent_issue)
    secmeta = _merge_child_secmeta(ctx=ctx, child_issue=child_issue)
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, child_issue=child_issue, secmeta=secmeta)
    _sync_child_title(ctx=ctx, sync=sync, child_issue=child_issue)

    if parent_issue is not None:
        _ensure_child_linked_to_parent(ctx=ctx, sync=sync, child_issue=child_issue, parent_issue=parent_issue)


def ensure_issue(
    alert: Alert,
    sync: SyncContext,
    *,
    matched_issue: Issue | None,
) -> None:
    """Process a single alert: create or update its child issue and parent.

    *matched_issue* is the alert's existing child issue as resolved by ``resolve_child_matches``
    over the whole scan, or ``None`` when a new child issue is needed.
    """
    alert_number = alert.metadata.alert_number
    rule_id = alert.metadata.rule_id

    path = normalize_path(alert.metadata.file)
    start_line = alert.metadata.start_line
    end_line = alert.metadata.end_line
    commit_sha = alert.metadata.commit_sha

    identity_key = alert.alert_details.identity_key
    alert_hash = alert.alert_details.alert_hash

    if not identity_key:
        raise SystemExit(
            f"ERROR: missing Finding Identity in alert_details for alert_number={alert_number}. "
            "Ensure the scan result carries an AquaSec 'fingerprint' or a 'result_hash'."
        )

    repo_full = alert.repo

    parent_issue = ensure_parent_issue(
        alert,
        sync.issues,
        sync.issue_index,
        dry_run=sync.dry_run,
        severity_priority_map=sync.severity_priority_map,
        priority_sync=sync.priority_sync,
        parent_original_bodies=sync.parent_original_bodies,
        stats=sync.stats,
    )

    ctx = AlertContext(
        alert=alert,
        alert_number=alert_number,
        identity_key=identity_key,
        alert_hash=alert_hash,
        repo=repo_full,
        tool=alert.metadata.tool,
        rule_id=rule_id,
        rule_name=alert.metadata.rule_name,
        rule_description=alert.metadata.rule_description,
        severity=alert.metadata.severity,
        path=path,
        start_line=start_line,
        end_line=end_line,
        commit_sha=commit_sha,
    )

    if matched_issue is None:
        _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=parent_issue)
        return

    _handle_existing_child_issue(ctx=ctx, sync=sync, child_issue=matched_issue, parent_issue=parent_issue)


def _init_priority_sync(
    alerts: dict[int, Alert],
    *,
    severity_priority_map: dict[str, str],
    project_number: int | None,
    project_org: str,
    dry_run: bool,
) -> ProjectPrioritySync | None:
    """Create and return a ``ProjectPrioritySync`` instance, or ``None``."""
    if not severity_priority_map or not project_number:
        return None

    org = project_org or ""
    if not org:
        first_alert = next(iter(alerts.values()), None)
        if first_alert:
            repo_full = first_alert.repo
            org = repo_full.split("/", 1)[0] if "/" in repo_full else ""

    if not org:
        logging.warning("Cannot determine org for project priority – priority sync disabled")
        return None

    pf = gh_project_get_priority_field(org, project_number)
    if pf is None:
        logging.warning("Could not load project #%d metadata – priority sync disabled", project_number)
        return None

    return ProjectPrioritySync(org, project_number, pf, dry_run=dry_run)


def _flush_parent_body_updates(
    parent_original_bodies: ParentOriginalBodies,
    issues: dict[int, Issue],
    *,
    dry_run: bool,
    stats: SyncStats,
) -> None:
    """Write deferred parent-issue body updates to GitHub.

    Args:
        parent_original_bodies: Pre-sync body snapshots, keyed by parent issue number.
        issues: All repository issues, used to look up each parent by number.
        dry_run: If True, log the intended updates without calling GitHub.
        stats: Counters updated for each parent body written.
    """
    for num, (repo, original_body) in parent_original_bodies.items():
        parent_issue = issues.get(num)
        if parent_issue is None:
            continue
        if parent_issue.body != original_body:
            severity = load_secmeta(parent_issue.body).get("severity")
            if dry_run:
                logging.info("%sWould update parent issue #%d body", DRY_RUN_PREFIX, num)
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.debug(
                        "%sWould update parent issue #%d body to:\n%s", DRY_RUN_PREFIX, num, parent_issue.body
                    )
                stats.parents_body_updated += 1
                bump_severity(stats.parents_body_updated_by_severity, severity)
            else:
                if gh_issue_edit_body(repo, num, parent_issue.body):
                    logging.info("%sUpdated parent issue #%d body", LOGGING_PREFIX, num)
                    stats.parents_body_updated += 1
                    bump_severity(stats.parents_body_updated_by_severity, severity)


def _close_resolved_child_issues(
    child_issues: list[Issue],
    matched_issues: list[Issue],
    *,
    dry_run: bool,
    stats: SyncStats,
    issue_changes: list[IssueChange] | None = None,
) -> None:
    """Close open child issues that no alert in the scan results matched.

    *child_issues* are the child issues that existed before the run and *matched_issues* those
    claimed by ``resolve_child_matches``. Every alert is matched, including those below
    min-severity, so their issues stay open.
    """
    matched_ids = {id(issue) for issue in matched_issues}
    to_close = [
        child_issue
        for child_issue in child_issues
        if child_issue.state.lower() == "open" and id(child_issue) not in matched_ids
    ]

    if not to_close:
        logging.debug("No unmatched child issues – skipping resolved-alert closure")
        return

    logging.info("%sDetected %d child issue/s with no matching alert", LOGGING_PREFIX, len(to_close))

    for child_issue in to_close:
        secmeta = load_secmeta(child_issue.body)
        repo = secmeta.get("repo", "")
        if not repo:
            logging.debug("Skipping closure for issue #%d: no repo in secmeta", child_issue.number)
            continue
        severity = secmeta.get("severity")
        if dry_run:
            logging.info(
                "%sWould close issue #%d (finding no longer detected in scan)",
                DRY_RUN_PREFIX,
                child_issue.number,
            )
            child_issue.state = "closed"
            stats.children_closed += 1
            bump_severity(stats.children_closed_by_severity, severity)
            _record_closed_for_notification(issue_changes, child_issue.number, repo=repo, secmeta=secmeta)
        elif gh_issue_edit_state(repo, child_issue.number, "closed"):
            logging.info(
                "%sClosed issue #%d (finding no longer detected in scan)",
                LOGGING_PREFIX,
                child_issue.number,
            )
            child_issue.state = "closed"
            stats.children_closed += 1
            bump_severity(stats.children_closed_by_severity, severity)
            _record_closed_for_notification(issue_changes, child_issue.number, repo=repo, secmeta=secmeta)


def _record_closed_for_notification(
    issue_changes: list[IssueChange] | None,
    issue_number: int,
    *,
    repo: str,
    secmeta: dict[str, str],
) -> None:
    """Record a closed child issue for notification"""
    if issue_changes is None:
        return

    issue_changes.append(
        IssueChange(
            repo=repo,
            issue_number=issue_number,
            severity=secmeta.get("severity", "") or "unknown",
            rule_id=secmeta.get("rule_id", ""),
            state="closed",
        )
    )


def _count_open_child_issues_by_severity(issue_index: IssueIndex) -> dict[str, int]:
    """Count still-open child issues per severity, describing the repository's posture.

    Runs after the sync so closures made during this run are already reflected.
    """
    counts: dict[str, int] = {}
    for child_issue in issue_index.children:
        if child_issue.state.lower() != "open":
            continue
        bump_severity(counts, load_secmeta(child_issue.body).get("severity"))
    return counts


def _meets_min_severity(severity: str, min_severity: str) -> bool:
    """Return True if *severity* is at or above *min_severity*.

    When min_severity is 'low' (the default) every finding passes, including
    those with 'unknown' severity. For any higher threshold, 'unknown' (rank 0)
    is always filtered out because it cannot be confirmed to meet the bar.
    """
    if min_severity == "low":
        return True
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER[min_severity]


def _refresh_child_identity(alert: Alert, child_issue: Issue | None, sync: SyncContext) -> None:
    """Persist only identity bookkeeping on a matched open child below min-severity."""
    if child_issue is None or not _is_open(child_issue):
        return

    secmeta = load_secmeta(child_issue.body)
    identity_values = {
        "fingerprint": alert.alert_details.identity_key,
        "alert_hash": alert.alert_details.alert_hash,
    }
    if all(secmeta.get(key) == value for key, value in identity_values.items()):
        return

    secmeta.update(identity_values)
    new_body = replace_secmeta(child_issue.body, secmeta)
    if sync.dry_run:
        logging.info("%sWould update child issue #%d identity bookkeeping", DRY_RUN_PREFIX, child_issue.number)
    elif not gh_issue_edit_body(alert.repo, child_issue.number, new_body):
        raise RuntimeError(
            f"Security - Failed to update Finding Identity for issue #{child_issue.number} in {alert.repo}; "
            "aborting before issue closure"
        )
    else:
        logging.info("%sUpdated child issue #%d identity bookkeeping", LOGGING_PREFIX, child_issue.number)

    child_issue.body = new_body
    sync.stats.children_body_updated += 1
    bump_severity(sync.stats.children_body_updated_by_severity, secmeta.get("severity"))


def sync_alerts_and_issues(
    alerts: dict[int, Alert],
    issues: dict[int, Issue],
    *,
    dry_run: bool = False,
    severity_priority_map: dict[str, str] | None = None,
    project_number: int | None = None,
    project_org: str = "",
    min_severity: str = MIN_SEVERITY_DEFAULT,
) -> SyncResult:
    """Sync open alerts into issues."""

    issue_changes: list[IssueChange] = []
    issue_index = build_issue_index(issues)
    spm = severity_priority_map or {}

    priority_sync = _init_priority_sync(
        alerts,
        severity_priority_map=spm,
        project_number=project_number,
        project_org=project_org,
        dry_run=dry_run,
    )

    sync = SyncContext(
        issues=issues,
        issue_index=issue_index,
        dry_run=dry_run,
        issue_changes=issue_changes,
        severity_priority_map=spm,
        priority_sync=priority_sync,
    )

    # Resolve the whole scan before any write, so each existing issue is claimed by one alert at most.
    child_matches = resolve_child_matches(alerts, issue_index)
    existing_children = list(issue_index.children)

    for alert_key, alert in alerts.items():
        if not _meets_min_severity(alert.metadata.severity, min_severity):
            # Keep frozen issues matchable without promoting or refreshing their content.
            _refresh_child_identity(alert, child_matches.get(alert_key), sync)
            continue
        ensure_issue(alert, sync, matched_issue=child_matches.get(alert_key))

    _flush_parent_body_updates(sync.parent_original_bodies, issues, dry_run=dry_run, stats=sync.stats)

    if priority_sync is not None:
        priority_sync.flush()

    _close_resolved_child_issues(
        existing_children,
        list(child_matches.values()),
        dry_run=dry_run,
        stats=sync.stats,
        issue_changes=issue_changes,
    )
    _close_resolved_parent_issues(issues, issue_index, dry_run=dry_run, stats=sync.stats)

    _log_sync_summary(sync.stats, dry_run=dry_run)

    return SyncResult(
        issue_changes=issue_changes,
        open_child_issues_by_severity=_count_open_child_issues_by_severity(issue_index),
    )


def _log_sync_summary(stats: SyncStats, *, dry_run: bool) -> None:
    """Log the completed sync run's summary, reusing the shared pure renderer."""
    prefix = DRY_RUN_PREFIX if dry_run else LOGGING_PREFIX
    lines = render_sync_summary(stats)
    logging.info("\n".join(prefix + line for line in lines))
