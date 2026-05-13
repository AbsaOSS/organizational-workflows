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

"""Core sync orchestration – builds the issue index, matches alerts to
existing issues, creates / updates / reopens parent and child issues,
and labels orphaned issues for closure.

This is the main business-logic module that ties together all other
``issues.*`` modules.
"""

import logging

from core.helpers import normalize_path
from core.github.issues import (
    gh_issue_add_labels,
    gh_issue_add_sub_issue_by_number,
    gh_issue_create,
    gh_issue_edit_body,
    gh_issue_edit_state,
    gh_issue_edit_title,
    gh_issue_get_sub_issue_numbers,
    gh_issue_remove_labels,
)
from core.github.projects import ProjectPrioritySync, gh_project_get_priority_field
from core.models import Issue
from core.rendering import render_markdown_template, strip_na_sections

from security.alerts.models import Alert
from security.constants import (
    DRY_RUN_PREFIX,
    LABEL_EPIC,
    LABEL_SCOPE_SECURITY,
    LABEL_SEC_ADEPT_TO_CLOSE,
    LABEL_TYPE_TECH_DEBT,
    LOGGING_PREFIX,
    SECMETA_TYPE_CHILD,
    SECMETA_TYPE_PARENT,
)
from .builder import (
    build_child_issue_body,
    build_issue_title,
    build_parent_issue_body,
    build_parent_issue_title,
    build_parent_template_values,
    classify_category,
)
from .models import (
    AlertContext,
    IssueIndex,
    NotifiedIssue,
    ParentOriginalBodies,
    SeverityChange,
    SyncContext,
    SyncResult,
    SyncStats,
)
from .secmeta import json_list, load_secmeta, parse_json_list, render_secmeta
from .templates import PARENT_BODY_TEMPLATE


def build_issue_index(issues: dict[int, Issue]) -> IssueIndex:
    """Build lookup indexes (by fingerprint and by rule_id) from existing issues."""
    by_fingerprint: dict[str, Issue] = {}
    parent_by_rule_id: dict[str, Issue] = {}

    for issue in issues.values():
        secmeta = load_secmeta(issue.body)
        secmeta_type = secmeta.get("type", "").strip().lower()
        if secmeta_type == SECMETA_TYPE_PARENT:
            rule_id = secmeta.get("rule_id", "").strip()
            if rule_id:
                parent_by_rule_id.setdefault(rule_id, issue)

        fp = secmeta.get("fingerprint", "").strip() or secmeta.get("alert_hash", "").strip()
        if fp and secmeta_type != SECMETA_TYPE_PARENT:
            by_fingerprint.setdefault(fp, issue)

    return IssueIndex(
        by_fingerprint=by_fingerprint,
        parent_by_rule_id=parent_by_rule_id,
    )


def find_issue_in_index(
    index: IssueIndex,
    *,
    fingerprint: str,
) -> Issue | None:
    """Return the child issue matching *fingerprint*, or ``None``."""
    return index.by_fingerprint.get(fingerprint)


def find_parent_issue(index: IssueIndex, *, rule_id: str) -> Issue | None:
    """Return the parent issue for *rule_id*, or ``None``."""
    return index.parent_by_rule_id.get(rule_id)


def maybe_reopen_parent_issue(
    repo: str,
    parent_issue: Issue | None,
    *,
    rule_id: str,
    dry_run: bool,
    stats: SyncStats,
) -> None:
    """Reopen *parent_issue* (if closed)."""
    if parent_issue is None:
        return

    if parent_issue.state.lower() != "closed":
        return

    if dry_run:
        logging.info(
            DRY_RUN_PREFIX + "Would reopen parent issue #%d %s",
            parent_issue.number,
            rule_id,
        )
        parent_issue.state = "open"
        stats.parents_reopened += 1
        return

    if gh_issue_edit_state(repo, parent_issue.number, "open"):
        parent_issue.state = "open"
        stats.parents_reopened += 1


def _close_resolved_parent_issues(
    issues: dict[int, Issue],
    index: IssueIndex,
    *,
    dry_run: bool,
    stats: SyncStats,
) -> None:
    """Close open parent issues whose known child issues are all closed."""
    child_issues_by_rule_id: dict[str, list[Issue]] = {}

    for issue in issues.values():
        secmeta = load_secmeta(issue.body)
        if secmeta.get("type", "").strip().lower() != SECMETA_TYPE_CHILD:
            continue

        rule_id = secmeta.get("rule_id", "").strip()
        if not rule_id:
            continue

        child_issues_by_rule_id.setdefault(rule_id, []).append(issue)

    for rule_id, parent_issue in index.parent_by_rule_id.items():
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

        if dry_run:
            logging.info(
                DRY_RUN_PREFIX + "Would close parent issue #%d (all children resolved)",
                parent_issue.number,
            )
            stats.parents_closed += 1
            continue

        if gh_issue_edit_state(repo, parent_issue.number, "closed"):
            logging.info(
                LOGGING_PREFIX + "Closed parent issue #%d (all children resolved)",
                parent_issue.number,
            )
            parent_issue.state = "closed"
            stats.parents_closed += 1


def ensure_parent_issue(
    alert: Alert,
    issues: dict[int, Issue],
    index: IssueIndex,
    *,
    dry_run: bool,
    severity_priority_map: dict[str, str] | None = None,
    priority_sync: ProjectPrioritySync | None = None,
    severity_changes: list[SeverityChange],
    parent_original_bodies: ParentOriginalBodies,
    stats: SyncStats,
) -> Issue | None:
    """Find or create the parent issue for the alert's ``rule_id``."""
    rule_id = alert.metadata.rule_id
    if not rule_id:
        return None

    repo_full = alert.repo
    existing = find_parent_issue(index, rule_id=rule_id)
    if existing is not None:
        # Keep parent issues aligned to the template as alerts evolve.
        existing_secmeta = load_secmeta(existing.body) or {}

        existing_severity = str(existing_secmeta.get("severity") or "unknown")
        existing_severity_cmp = existing_severity.lower()
        incoming_severity = alert.metadata.severity
        incoming_severity_cmp = incoming_severity.lower()

        if incoming_severity_cmp and existing_severity_cmp != incoming_severity_cmp:
            change = SeverityChange(
                repo=repo_full,
                issue_number=existing.number,
                rule_id=rule_id,
                old_severity=existing_severity_cmp,
                new_severity=incoming_severity_cmp,
            )
            if dry_run:
                logging.info(
                    DRY_RUN_PREFIX + "Severity changed on parent #%d: %s → %s",
                    existing.number,
                    existing_severity_cmp,
                    incoming_severity_cmp,
                )
            severity_changes.append(change)

        severity_stored = incoming_severity or existing_severity

        existing_secmeta.update(
            {
                "type": SECMETA_TYPE_PARENT,
                "repo": repo_full,
                "severity": severity_stored,
                "rule_id": rule_id,
            }
        )

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
                logging.info(DRY_RUN_PREFIX + "Would update parent issue #%d title", existing.number)
                logging.debug("DRY-RUN: Would update title for parent issue #%d to %s", existing.number, expected_title)
                stats.parents_title_updated += 1
            else:
                if gh_issue_edit_title(repo_full, existing.number, expected_title):
                    existing.title = expected_title
                    logging.info(LOGGING_PREFIX + "Updated parent issue #%d title", existing.number)
                    logging.debug("New updated title for parent issue #%d: %s", existing.number, expected_title)
                    stats.parents_title_updated += 1

        if priority_sync is not None:
            priority_sync.enqueue(repo_full, existing.number, severity_stored, severity_priority_map or {})

        return existing

    title = build_parent_issue_title(rule_id)
    body = build_parent_issue_body(alert)
    labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT, LABEL_EPIC]
    if dry_run:
        logging.info(
            DRY_RUN_PREFIX + "Would create parent issue for rule %s (severity: %s)",
            rule_id,
            alert.metadata.severity,
        )
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug("DRY-RUN: body_preview_begin")
            logging.debug(body)
            logging.debug("DRY-RUN: body_preview_end")
        stats.parents_created += 1
        placeholder = Issue(number=0, state="open", title=title, body=body)
        index.parent_by_rule_id[rule_id] = placeholder
        return placeholder

    num = gh_issue_create(repo_full, title, body, labels)
    if num is None:
        return None

    created = Issue(number=num, state="open", title=title, body=body)
    issues[num] = created
    index.parent_by_rule_id[rule_id] = created
    logging.info(LOGGING_PREFIX + "Created parent issue #%d for rule %s", num, rule_id)
    stats.parents_created += 1

    if priority_sync is not None:
        priority_sync.enqueue(
            repo_full,
            num,
            alert.metadata.severity,
            severity_priority_map or {},
        )

    return created


def _append_notification(
    notifications: list[NotifiedIssue] | None,
    *,
    repo: str,
    issue_number: int,
    severity: str,
    category: str,
    state: str,
    tool: str,
) -> None:
    """Append a notification entry if the *notifications* list is active."""
    if notifications is not None:
        notifications.append(
            NotifiedIssue(
                repo=repo,
                issue_number=issue_number,
                severity=severity,
                category=category,
                state=state,
                tool=tool,
            )
        )


def _handle_new_child_issue(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    parent_issue: Issue | None,
) -> None:
    """Create a new child issue for an alert that has no matching issue yet."""
    category = classify_category(ctx.alert)
    secmeta: dict[str, str] = {
        "type": SECMETA_TYPE_CHILD,
        "fingerprint": ctx.fingerprint,
        "repo": ctx.repo,
        "rule_id": ctx.rule_id,
        "severity": ctx.severity,
        "gh_alert_numbers": json_list([str(ctx.alert_number)]),
    }

    human_body = build_child_issue_body(ctx.alert)
    body = render_secmeta(secmeta) + "\n\n" + human_body
    title = build_issue_title(ctx.rule_description, ctx.fingerprint, ctx.severity)

    if sync.dry_run:
        if parent_issue is not None:
            logging.info(
                DRY_RUN_PREFIX + "Would create child issue for alert %d (rule: %s, severity: %s) linked to parent #%d",
                ctx.alert_number,
                ctx.rule_id,
                ctx.severity,
                parent_issue.number,
            )
            sync.stats.children_linked += 1
        else:
            logging.info(
                DRY_RUN_PREFIX + "Would create child issue for alert %d (rule: %s, severity: %s)",
                ctx.alert_number,
                ctx.rule_id,
                ctx.severity,
            )
            if ctx.rule_id:
                logging.debug("No parent issue yet for rule_id=%s – link will happen on next sync", ctx.rule_id)
        sync.stats.children_created += 1
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug("DRY-RUN: body_preview_begin")
            logging.debug(body)
            logging.debug("DRY-RUN: body_preview_end")

        _append_notification(
            sync.notifications,
            repo=ctx.repo,
            issue_number=0,
            severity=ctx.severity,
            category=category,
            state="new",
            tool=ctx.tool,
        )
        if sync.priority_sync is not None:
            sync.priority_sync.enqueue(ctx.repo, 0, ctx.severity, sync.severity_priority_map)
        return

    num = gh_issue_create(ctx.repo, title, body, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])
    if num is None:
        return

    logging.info(LOGGING_PREFIX + "Created child issue #%d for alert %d", num, ctx.alert_number)
    sync.stats.children_created += 1
    created = Issue(number=num, state="open", title=title, body=body)
    sync.issues[num] = created
    sync.index.by_fingerprint[ctx.fingerprint] = created

    _append_notification(
        sync.notifications,
        repo=ctx.repo,
        issue_number=num,
        severity=ctx.severity,
        category=category,
        state="new",
        tool=ctx.tool,
    )

    if parent_issue is not None:
        maybe_reopen_parent_issue(
            ctx.repo,
            parent_issue,
            rule_id=ctx.rule_id,
            dry_run=sync.dry_run,
            stats=sync.stats,
        )
        logging.debug("Add sub-issue link parent=#%d child=#%d (alert %d)", parent_issue.number, num, ctx.alert_number)
        gh_issue_add_sub_issue_by_number(ctx.repo, parent_issue.number, num)

    if sync.priority_sync is not None:
        sync.priority_sync.enqueue(ctx.repo, num, ctx.severity, sync.severity_priority_map)


def _remove_adept_to_close_label(repo: str, issue: Issue, *, dry_run: bool) -> None:
    """Remove the ``sec:adept-to-close`` label from *issue* if present."""
    if not issue.labels or LABEL_SEC_ADEPT_TO_CLOSE not in issue.labels:
        return

    if dry_run:
        logging.info(
            DRY_RUN_PREFIX + "Would remove label %r from issue #%d",
            LABEL_SEC_ADEPT_TO_CLOSE,
            issue.number,
        )
    else:
        logging.info(
            LOGGING_PREFIX + "Removed label %r from reopened issue #%d",
            LABEL_SEC_ADEPT_TO_CLOSE,
            issue.number,
        )
        gh_issue_remove_labels(repo, issue.number, [LABEL_SEC_ADEPT_TO_CLOSE])

    issue.labels.remove(LABEL_SEC_ADEPT_TO_CLOSE)


def _maybe_reopen_child(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    issue: Issue,
    parent_issue: Issue | None,
) -> bool:
    """Reopen a closed child issue and cascade to its parent.

    Returns ``True`` if the issue was reopened.
    """
    if issue.state.lower() != "closed":
        return False

    reopened = False
    if sync.dry_run:
        reopened = True
        issue.state = "open"
        logging.info(DRY_RUN_PREFIX + "Would reopen issue #%d", issue.number)
    elif gh_issue_edit_state(ctx.repo, issue.number, "open"):
        reopened = True
        issue.state = "open"
        logging.info(LOGGING_PREFIX + "Reopened issue #%d", issue.number)

    if reopened:
        sync.stats.children_reopened += 1
        _remove_adept_to_close_label(ctx.repo, issue, dry_run=sync.dry_run)
        maybe_reopen_parent_issue(
            ctx.repo,
            parent_issue,
            rule_id=ctx.rule_id,
            dry_run=sync.dry_run,
            stats=sync.stats,
        )
        existing_secmeta = load_secmeta(issue.body)
        reopen_category = (existing_secmeta.get("category") or "").strip() or classify_category(ctx.alert)
        _append_notification(
            sync.notifications,
            repo=ctx.repo,
            issue_number=issue.number,
            severity=ctx.severity,
            category=reopen_category,
            state="reopen",
            tool=ctx.tool,
        )
        if sync.priority_sync is not None:
            sync.priority_sync.enqueue(ctx.repo, issue.number, ctx.severity, sync.severity_priority_map)

    return reopened


def _merge_child_secmeta(
    *,
    ctx: AlertContext,
    issue: Issue,
) -> dict[str, str]:
    """Merge incoming alert data into the child issue's secmeta."""
    secmeta = load_secmeta(issue.body) or {}
    secmeta.pop("alert_hash", None)

    existing_alerts = parse_json_list(secmeta.get("gh_alert_numbers"))
    if not existing_alerts and secmeta.get("related_alert_ids"):
        existing_alerts = parse_json_list(secmeta.get("related_alert_ids"))
    if str(ctx.alert_number) not in existing_alerts:
        existing_alerts.append(str(ctx.alert_number))

    secmeta.update(
        {
            "type": SECMETA_TYPE_CHILD,
            "fingerprint": ctx.fingerprint,
            "repo": ctx.repo,
            "rule_id": ctx.rule_id or secmeta.get("rule_id", ""),
            "severity": ctx.severity,
            "gh_alert_numbers": json_list(existing_alerts),
        }
    )

    return secmeta


def _rebuild_and_apply_child_body(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    issue: Issue,
    secmeta: dict[str, str],
) -> None:
    """Render a fresh child body from *secmeta* + template and apply if changed."""
    human_body = build_child_issue_body(ctx.alert)
    new_body = render_secmeta(secmeta) + "\n\n" + human_body

    if new_body != issue.body:
        if sync.dry_run:
            logging.info(DRY_RUN_PREFIX + "Would update child issue #%d body", issue.number)
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.debug("DRY-RUN: Body preview begin child issue #%d", issue.number)
                logging.debug(new_body)
                logging.debug("DRY-RUN: Body preview end child issue #%d", issue.number)
            sync.stats.children_body_updated += 1
        else:
            if gh_issue_edit_body(ctx.repo, issue.number, new_body):
                issue.body = new_body
                logging.info(LOGGING_PREFIX + "Updated child issue #%d body", issue.number)
                sync.stats.children_body_updated += 1


def _sync_child_title_and_labels(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    issue: Issue,
) -> None:
    """Fix title drift and ensure required labels and priority on the child issue."""
    expected_title = build_issue_title(ctx.rule_description, ctx.fingerprint, ctx.severity)
    if expected_title != (issue.title or ""):
        if sync.dry_run:
            logging.info(DRY_RUN_PREFIX + "Would update child issue #%d title", issue.number)
            logging.debug("DRY-RUN: Would update title for child issue #%d to %s", issue.number, expected_title)
            sync.stats.children_title_updated += 1
        else:
            if gh_issue_edit_title(ctx.repo, issue.number, expected_title):
                issue.title = expected_title
                logging.info(LOGGING_PREFIX + "Updated child issue #%d title", issue.number)
                logging.debug("New updated title for child issue #%d: %s", issue.number, expected_title)
                sync.stats.children_title_updated += 1

    if not sync.dry_run:
        gh_issue_add_labels(ctx.repo, issue.number, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])

    if sync.priority_sync is not None:
        sync.priority_sync.enqueue(ctx.repo, issue.number, ctx.severity, sync.severity_priority_map)


def _ensure_child_linked_to_parent(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    issue: Issue,
    parent_issue: Issue,
) -> None:
    """Detect and repair a missing parent-to-child sub-issue link."""
    cache = sync.parent_sub_issues_cache
    if parent_issue.number not in cache:
        cache[parent_issue.number] = gh_issue_get_sub_issue_numbers(ctx.repo, parent_issue.number)

    if issue.number in cache[parent_issue.number]:
        return

    if sync.dry_run:
        logging.info(
            DRY_RUN_PREFIX + "Would link child issue #%d to parent #%d",
            issue.number,
            parent_issue.number,
        )
        cache[parent_issue.number].add(issue.number)
        sync.stats.children_linked += 1
        return

    logging.info(
        LOGGING_PREFIX + "Linked child issue #%d to parent #%d",
        issue.number,
        parent_issue.number,
    )
    if gh_issue_add_sub_issue_by_number(ctx.repo, parent_issue.number, issue.number):
        cache[parent_issue.number].add(issue.number)
        sync.stats.children_linked += 1


def _handle_existing_child_issue(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    issue: Issue,
    parent_issue: Issue | None,
) -> None:
    """Update an existing child issue with refreshed alert data."""
    if parent_issue is None and ctx.rule_id:
        parent_issue = find_parent_issue(sync.index, rule_id=ctx.rule_id)

    _maybe_reopen_child(ctx=ctx, sync=sync, issue=issue, parent_issue=parent_issue)
    secmeta = _merge_child_secmeta(ctx=ctx, issue=issue)
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, issue=issue, secmeta=secmeta)
    _sync_child_title_and_labels(ctx=ctx, sync=sync, issue=issue)

    if parent_issue is not None:
        _ensure_child_linked_to_parent(ctx=ctx, sync=sync, issue=issue, parent_issue=parent_issue)


def ensure_issue(
    alert: Alert,
    sync: SyncContext,
) -> None:
    """Process a single alert: create or update its child issue and parent."""
    alert_number = alert.metadata.alert_number

    alert_state = alert.metadata.state
    if alert_state and alert_state != "open":
        # This script is designed to process open alerts only!
        # Input is typically produced by collect_alert.py with --state open (default).
        logging.debug("Skip alert %d: state=%r (only 'open' processed)", alert_number, alert_state)
        return

    rule_id = alert.metadata.rule_id

    path = normalize_path(alert.metadata.file)
    start_line = alert.metadata.start_line
    end_line = alert.metadata.end_line
    commit_sha = alert.metadata.commit_sha

    fingerprint = alert.alert_details.alert_hash

    if not fingerprint:
        raise SystemExit(
            f"ERROR: missing 'alert_hash' in alert_details for alert_number={alert_number}. "
            "Ensure the collector/scanner includes an 'Alert hash: ...' line."
        )

    repo_full = alert.repo

    parent_issue = ensure_parent_issue(
        alert,
        sync.issues,
        sync.index,
        dry_run=sync.dry_run,
        severity_priority_map=sync.severity_priority_map,
        priority_sync=sync.priority_sync,
        severity_changes=sync.severity_changes,
        parent_original_bodies=sync.parent_original_bodies,
        stats=sync.stats,
    )
    matched = find_issue_in_index(
        sync.index,
        fingerprint=fingerprint,
    )

    ctx = AlertContext(
        alert=alert,
        alert_number=alert_number,
        fingerprint=fingerprint,
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

    if matched is None:
        _handle_new_child_issue(ctx=ctx, sync=sync, parent_issue=parent_issue)
        return

    _handle_existing_child_issue(ctx=ctx, sync=sync, issue=matched, parent_issue=parent_issue)


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
    """Write deferred parent-issue body updates to GitHub."""
    for num, (repo, original_body) in parent_original_bodies.items():
        issue = issues.get(num)
        if issue is None:
            continue
        if issue.body != original_body:
            if dry_run:
                logging.info(DRY_RUN_PREFIX + "Would update parent issue #%d body", num)
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.debug("DRY-RUN: Body preview begin parent issue #%d", num)
                    logging.debug(issue.body)
                    logging.debug("DRY-RUN: Body preview end parent issue #%d", num)
                stats.parents_body_updated += 1
            else:
                if gh_issue_edit_body(repo, num, issue.body):
                    logging.info(LOGGING_PREFIX + "Updated parent issue #%d body", num)
                    stats.parents_body_updated += 1


def _label_adept_to_close_issues(
    alerts: dict[int, Alert],
    index: IssueIndex,
    *,
    dry_run: bool,
    stats: SyncStats,
) -> None:
    """Detect open child issues with no matching alert and add the adept-to-close label."""
    alert_fingerprints: set[str] = set()
    for alert in alerts.values():
        fp = alert.alert_details.alert_hash
        if fp:
            alert_fingerprints.add(fp)

    open_issue_fps = {fp for fp, issue in index.by_fingerprint.items() if issue.state.lower() == "open"}
    unmatched_fps = open_issue_fps - alert_fingerprints

    if not unmatched_fps:
        logging.debug("No unmatched child issues – skipping adept-to-close labelling")
        return

    logging.info(LOGGING_PREFIX + "Detected %d child issue/s with no matching alert", len(unmatched_fps))

    for fp in unmatched_fps:
        issue = index.by_fingerprint[fp]
        repo = load_secmeta(issue.body).get("repo", "")
        if not repo:
            logging.debug("Skipping adept-to-close labelling for issue #%d: no repo in secmeta", issue.number)
            continue
        if issue.labels and LABEL_SEC_ADEPT_TO_CLOSE in issue.labels:
            logging.debug(
                "Label %r already on issue #%d (fingerprint=%s…) – skipping",
                LABEL_SEC_ADEPT_TO_CLOSE,
                issue.number,
                fp[:12],
            )
            continue
        if dry_run:
            logging.info(
                DRY_RUN_PREFIX + "Would mark issue #%d for closure (no matching alert)",
                issue.number,
            )
        else:
            logging.info(
                LOGGING_PREFIX + "Marked issue #%d for closure (no matching alert)",
                issue.number,
            )
            gh_issue_add_labels(repo, issue.number, [LABEL_SEC_ADEPT_TO_CLOSE])
        stats.children_marked_for_closure += 1


def sync_alerts_and_issues(
    alerts: dict[int, Alert],
    issues: dict[int, Issue],
    *,
    dry_run: bool = False,
    severity_priority_map: dict[str, str] | None = None,
    project_number: int | None = None,
    project_org: str = "",
) -> SyncResult:
    """Sync open alerts into issues."""

    notifications: list[NotifiedIssue] = []
    index = build_issue_index(issues)
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
        index=index,
        dry_run=dry_run,
        notifications=notifications,
        severity_priority_map=spm,
        priority_sync=priority_sync,
    )

    for alert in alerts.values():
        ensure_issue(alert, sync)

    _flush_parent_body_updates(sync.parent_original_bodies, issues, dry_run=dry_run, stats=sync.stats)

    if priority_sync is not None:
        priority_sync.flush()

    _label_adept_to_close_issues(alerts, index, dry_run=dry_run, stats=sync.stats)
    _close_resolved_parent_issues(issues, index, dry_run=dry_run, stats=sync.stats)

    _log_sync_summary(sync.stats, dry_run=dry_run)

    return SyncResult(notifications=notifications, severity_changes=sync.severity_changes)


def _log_sync_summary(stats: SyncStats, *, dry_run: bool) -> None:
    """Log a compact multi-line summary of the completed sync run."""
    prefix = DRY_RUN_PREFIX if dry_run else LOGGING_PREFIX

    parent_parts: list[str] = []
    if stats.parents_created:
        parent_parts.append(f"created: {stats.parents_created}")
    if stats.parents_title_updated:
        parent_parts.append(f"title updated: {stats.parents_title_updated}")
    if stats.parents_body_updated:
        parent_parts.append(f"body updated: {stats.parents_body_updated}")
    if stats.parents_reopened:
        parent_parts.append(f"reopened: {stats.parents_reopened}")
    if stats.parents_closed:
        parent_parts.append(f"closed: {stats.parents_closed}")

    child_parts: list[str] = []
    if stats.children_created:
        child_parts.append(f"created: {stats.children_created}")
    if stats.children_reopened:
        child_parts.append(f"reopened: {stats.children_reopened}")
    if stats.children_title_updated:
        child_parts.append(f"title updated: {stats.children_title_updated}")
    if stats.children_body_updated:
        child_parts.append(f"body updated: {stats.children_body_updated}")
    if stats.children_linked:
        child_parts.append(f"linked: {stats.children_linked}")
    if stats.children_marked_for_closure:
        child_parts.append(f"marked for closure: {stats.children_marked_for_closure}")

    if not parent_parts and not child_parts:
        logging.info(prefix + "Sync complete: no changes")
        return

    lines = [prefix + "Sync complete:"]
    if parent_parts:
        lines.append("  " + prefix + "Parent issues - " + ", ".join(parent_parts))
    if child_parts:
        lines.append("  " + prefix + "Child issues  - " + ", ".join(child_parts))
    logging.info("\n".join(lines))
