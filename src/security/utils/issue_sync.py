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
``utils.*`` modules.
"""

import logging

from shared.common import iso_date, normalize_path, utc_today
from shared.github_issues import (
    gh_issue_add_labels,
    gh_issue_add_sub_issue_by_number,
    gh_issue_comment,
    gh_issue_create,
    gh_issue_edit_body,
    gh_issue_edit_state,
    gh_issue_edit_title,
)
from shared.github_projects import ProjectPrioritySync, gh_project_get_priority_field
from shared.models import Issue
from shared.templates import render_markdown_template

from .alert_parser import compute_occurrence_fp
from .constants import (
    LABEL_EPIC,
    LABEL_SCOPE_SECURITY,
    LABEL_SEC_ADEPT_TO_CLOSE,
    LABEL_TYPE_TECH_DEBT,
    NOT_AVAILABLE,
    SEC_EVENT_OPEN,
    SEC_EVENT_REOPEN,
    SECMETA_TYPE_CHILD,
    SECMETA_TYPE_PARENT,
)
from .issue_builder import (
    build_child_issue_body,
    build_issue_title,
    build_parent_issue_body,
    build_parent_issue_title,
    build_parent_template_values,
    classify_category,
)
from .models import Alert, AlertContext, IssueIndex, NotifiedIssue, SeverityChange, SyncContext, SyncResult
from .sec_events import render_sec_event, strip_sec_events_from_body
from .secmeta import json_list, load_secmeta, parse_json_list, render_secmeta
from .templates import PARENT_BODY_TEMPLATE


def build_issue_index(issues: dict[int, Issue]) -> IssueIndex:
    """Build lookup indexes (by fingerprint and by rule_id) from existing issues."""
    by_fingerprint: dict[str, Issue] = {}
    parent_by_rule_id: dict[str, Issue] = {}

    for issue in issues.values():
        secmeta = load_secmeta(issue.body)
        secmeta_type = (secmeta.get("type") or "").strip().lower()
        if secmeta_type == SECMETA_TYPE_PARENT:
            rule_id = (secmeta.get("rule_id") or "").strip()
            if rule_id:
                parent_by_rule_id.setdefault(rule_id, issue)

        fp = (secmeta.get("fingerprint") or "").strip() or (secmeta.get("alert_hash") or "").strip()
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
    context: str,
    child_issue_number: int | None = None,
) -> None:
    """Reopen *parent_issue* (if closed) and record a sec-event comment."""
    if parent_issue is None:
        return

    if parent_issue.state.lower() != "closed":
        return

    if dry_run:
        logging.info(
            f"DRY-RUN: would reopen parent issue #{parent_issue.number} (rule_id={rule_id}) "
            f"due_to={context} child={child_issue_number or ''}".rstrip()
        )
        logging.info(
            f"DRY-RUN: would comment parent reopen sec-event on issue #{parent_issue.number} (rule_id={rule_id})"
        )
        parent_issue.state = "open"
        return

    if gh_issue_edit_state(repo, parent_issue.number, "open"):
        parent_issue.state = "open"
        gh_issue_comment(
            repo,
            parent_issue.number,
            render_sec_event(
                {
                    "action": SEC_EVENT_REOPEN,
                    "seen_at": utc_today(),
                    "source": "code_scanning",
                    "rule_id": rule_id,
                    "context": context,
                    "child_issue": str(child_issue_number) if child_issue_number else "",
                }
            ),
        )


def ensure_parent_issue(
    alert: Alert,
    issues: dict[int, Issue],
    index: IssueIndex,
    *,
    dry_run: bool,
    severity_priority_map: dict[str, str] | None = None,
    priority_sync: ProjectPrioritySync | None = None,
    severity_changes: list[SeverityChange] | None = None,
    parent_original_bodies: dict[int, tuple[str, str]] | None = None,
) -> Issue | None:
    """Find or create the parent issue for the alert's ``rule_id``."""
    rule_id = alert.metadata.rule_id
    if not rule_id:
        return None

    repo_full = alert.repo
    existing = find_parent_issue(index, rule_id=rule_id)
    if existing is not None:
        # Keep parent issues aligned to the template as alerts evolve.
        existing_secmeta = load_secmeta(existing.body) or {"schema": "1"}
        existing_first = existing_secmeta.get("first_seen") or iso_date(alert.metadata.created_at)
        existing_last = existing_secmeta.get("last_seen") or iso_date(alert.metadata.updated_at)
        first_seen_final = min(existing_first, iso_date(alert.metadata.created_at))
        last_seen_final = max(existing_last, iso_date(alert.metadata.updated_at))

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
                    f"DRY-RUN: severity change on parent #{existing.number} "
                    f"(rule_id={rule_id}): {existing_severity_cmp} \u2192 {incoming_severity_cmp}"
                )
            if severity_changes is not None:
                severity_changes.append(change)

        severity_stored = incoming_severity or existing_severity

        existing_secmeta.update(
            {
                "schema": existing_secmeta.get("schema") or "1",
                "type": SECMETA_TYPE_PARENT,
                "repo": repo_full,
                "source": existing_secmeta.get("source") or "code_scanning",
                "tool": alert.metadata.tool or existing_secmeta.get("tool") or "",
                "severity": severity_stored,
                "rule_id": rule_id,
                "first_seen": first_seen_final,
                "last_seen": last_seen_final,
                "postponed_until": existing_secmeta.get("postponed_until", ""),
            }
        )

        rebuilt = (
            render_secmeta(existing_secmeta)
            + "\n\n"
            + render_markdown_template(
                PARENT_BODY_TEMPLATE,
                build_parent_template_values(alert, rule_id=rule_id, severity=severity_stored),
            ).strip()
            + "\n"
        )
        rebuilt = strip_sec_events_from_body(rebuilt)

        # Snapshot the original body on first encounter so we can
        # defer the API call until all alerts have been processed.
        if parent_original_bodies is not None and existing.number not in parent_original_bodies:
            parent_original_bodies[existing.number] = (repo_full, existing.body or "")
        existing.body = rebuilt

        # Detect parent title drift and update when needed.
        expected_title = build_parent_issue_title(rule_id, severity_stored)
        if expected_title != (existing.title or ""):
            if dry_run:
                logging.info(
                    f"DRY-RUN: would update parent issue #{existing.number} title "
                    f"from {existing.title!r} to {expected_title!r}"
                )
            else:
                if gh_issue_edit_title(repo_full, existing.number, expected_title):
                    existing.title = expected_title

        if priority_sync is not None:
            priority_sync.enqueue(repo_full, existing.number, severity_stored, severity_priority_map or {})

        return existing

    title = build_parent_issue_title(rule_id, alert.metadata.severity)
    body = build_parent_issue_body(alert)
    labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT, LABEL_EPIC]
    if dry_run:
        logging.info(f"DRY-RUN: create parent rule_id={rule_id} title={title!r} labels={labels}")
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug("DRY-RUN: body_preview_begin")
            logging.debug(body)
            logging.debug("DRY-RUN: body_preview_end")
        return None

    num = gh_issue_create(repo_full, title, body, labels)
    if num is None:
        return None

    # Parent lifecycle event (human visible): opened/created.
    if dry_run:
        logging.info(f"DRY-RUN: would comment parent open sec-event on issue #{num} (rule_id={rule_id})")
    else:
        gh_issue_comment(
            repo_full,
            num,
            render_sec_event(
                {
                    "action": SEC_EVENT_OPEN,
                    "seen_at": iso_date(alert.metadata.created_at),
                    "source": "code_scanning",
                    "rule_id": rule_id,
                    "severity": alert.metadata.severity,
                }
            ),
        )

    created = Issue(number=num, state="open", title=title, body=body)
    issues[num] = created
    index.parent_by_rule_id[rule_id] = created
    logging.info(f"Created parent issue #{num} for rule_id={rule_id}")

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
        "schema": "1",
        "type": SECMETA_TYPE_CHILD,
        "fingerprint": ctx.fingerprint,
        "repo": ctx.repo,
        "source": "code_scanning",
        "tool": ctx.tool,
        "severity": ctx.severity,
        "category": category,
        "rule_id": ctx.rule_id,
        "first_seen": ctx.first_seen,
        "last_seen": ctx.last_seen,
        "last_seen_commit": ctx.commit_sha,
        "postponed_until": "",
        "gh_alert_numbers": json_list([str(ctx.alert_number)]),
        "occurrence_count": "1",
        "last_occurrence_fp": ctx.occurrence_fp,
    }
    if ctx.cve:
        secmeta["cve"] = ctx.cve

    human_body = build_child_issue_body(ctx.alert)
    body = render_secmeta(secmeta) + "\n\n" + human_body
    title = build_issue_title(ctx.rule_name, ctx.rule_id, ctx.fingerprint)

    if sync.dry_run:
        labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT]

        loc = f"{ctx.path}:{ctx.start_line or ''}".rstrip(":")
        commit_short = ctx.commit_sha[:8] if ctx.commit_sha else ""
        logging.info(
            "DRY-RUN: create child "
            f"alert={ctx.alert_number} rule_id={ctx.rule_id} sev={ctx.severity}"
            f" fp={ctx.fingerprint[:8]} tool={ctx.tool} commit={commit_short}"
            f" loc={loc} title={title!r} labels=[{','.join(labels)}]"
            f" | secmeta:first_seen={ctx.first_seen} last_seen={ctx.last_seen}"
            f" occurrence_count=1 gh_alert_numbers=[{ctx.alert_number}]"
        )
        if parent_issue is None and ctx.rule_id:
            logging.info(
                f"DRY-RUN: add sub-issue link parent_rule_id={ctx.rule_id} child=(new) alert={ctx.alert_number}"
            )
        elif parent_issue is not None:
            logging.info(
                f"DRY-RUN: add sub-issue link parent=#{parent_issue.number} child=(new) alert={ctx.alert_number}"
            )
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

    logging.info(f"Created issue #{num} for alert {ctx.alert_number} (fp={ctx.fingerprint[:8]})")
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
            context="new_child",
            child_issue_number=num,
        )
        logging.info(f"Add sub-issue link parent=#{parent_issue.number} child=#{num} (alert {ctx.alert_number})")
        gh_issue_add_sub_issue_by_number(ctx.repo, parent_issue.number, num)

    gh_issue_comment(
        ctx.repo,
        num,
        render_sec_event(
            {
                "action": SEC_EVENT_OPEN,
                "seen_at": ctx.first_seen,
                "source": "code_scanning",
                "gh_alert_number": str(ctx.alert_number),
                "occurrence_fp": str(ctx.occurrence_fp),
                "commit_sha": str(ctx.commit_sha),
                "path": str(ctx.path),
                "start_line": str(ctx.start_line or ""),
                "end_line": str(ctx.end_line or ""),
            }
        ),
    )

    if sync.priority_sync is not None:
        sync.priority_sync.enqueue(ctx.repo, num, ctx.severity, sync.severity_priority_map)


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
        logging.info(f"DRY-RUN: would reopen issue #{issue.number} (alert {ctx.alert_number})")
    elif gh_issue_edit_state(ctx.repo, issue.number, "open"):
        reopened = True
        logging.info(f"Reopened issue #{issue.number} (alert {ctx.alert_number})")

    if reopened:
        maybe_reopen_parent_issue(
            ctx.repo,
            parent_issue,
            rule_id=ctx.rule_id,
            dry_run=sync.dry_run,
            context="reopen_child",
            child_issue_number=issue.number,
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
) -> tuple[dict[str, str], bool]:
    """Merge incoming alert data into the child issue's secmeta.

    Returns ``(updated_secmeta, new_occurrence)``.
    """
    secmeta = load_secmeta(issue.body) or {"schema": "1"}
    secmeta.pop("alert_hash", None)

    existing_alerts = parse_json_list(secmeta.get("gh_alert_numbers"))
    if not existing_alerts and secmeta.get("related_alert_ids"):
        existing_alerts = parse_json_list(secmeta.get("related_alert_ids"))
    if str(ctx.alert_number) not in existing_alerts:
        existing_alerts.append(str(ctx.alert_number))

    last_occ_fp = secmeta.get("last_occurrence_fp") or ""
    occurrence_count = int(secmeta.get("occurrence_count") or "0" or 0)
    new_occurrence = bool(ctx.occurrence_fp and ctx.occurrence_fp != last_occ_fp)
    if occurrence_count <= 0:
        occurrence_count = 1
    if new_occurrence:
        occurrence_count += 1

    existing_first = secmeta.get("first_seen") or ctx.first_seen
    existing_last = secmeta.get("last_seen") or ctx.last_seen
    first_seen_final = min(existing_first, ctx.first_seen)
    last_seen_final = max(existing_last, ctx.last_seen)

    secmeta.update(
        {
            "fingerprint": ctx.fingerprint,
            "repo": ctx.repo,
            "source": secmeta.get("source") or "code_scanning",
            "tool": ctx.tool or secmeta.get("tool", ""),
            "severity": ctx.severity,
            "category": classify_category(ctx.alert) or secmeta.get("category", ""),
            "rule_id": ctx.rule_id or secmeta.get("rule_id", ""),
            "first_seen": first_seen_final,
            "last_seen": last_seen_final,
            "last_seen_commit": ctx.commit_sha or secmeta.get("last_seen_commit", ""),
            "gh_alert_numbers": json_list(existing_alerts),
            "occurrence_count": str(occurrence_count),
            "last_occurrence_fp": ctx.occurrence_fp or last_occ_fp,
        }
    )
    if ctx.cve:
        secmeta["cve"] = ctx.cve

    return secmeta, new_occurrence


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
    new_body = strip_sec_events_from_body(new_body)

    if new_body != issue.body:
        if sync.dry_run:
            logging.info(f"DRY-RUN: would update issue #{issue.number} body to template (alert {ctx.alert_number})")
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.debug("DRY-RUN: body_preview_begin")
                logging.debug(new_body)
                logging.debug("DRY-RUN: body_preview_end")
        else:
            gh_issue_edit_body(ctx.repo, issue.number, new_body)
            issue.body = new_body


def _comment_child_event(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    issue: Issue,
    reopened: bool,
) -> None:
    """Post a reopen sec-event comment on the child issue."""
    if reopened:
        if sync.dry_run:
            logging.info(f"DRY-RUN: would comment reopen event on issue #{issue.number} (alert {ctx.alert_number})")
        else:
            gh_issue_comment(
                ctx.repo,
                issue.number,
                render_sec_event(
                    {
                        "action": SEC_EVENT_REOPEN,
                        "seen_at": utc_today(),
                        "source": "code_scanning",
                        "gh_alert_number": str(ctx.alert_number),
                    }
                ),
            )


def _sync_child_title_and_labels(
    *,
    ctx: AlertContext,
    sync: SyncContext,
    issue: Issue,
) -> None:
    """Fix title drift and ensure required labels and priority on the child issue."""
    expected_title = build_issue_title(ctx.rule_name, ctx.rule_id, ctx.fingerprint)
    if expected_title != (issue.title or ""):
        if sync.dry_run:
            logging.info(
                f"DRY-RUN: would update issue #{issue.number} title " f"from {issue.title!r} to {expected_title!r}"
            )
        else:
            if gh_issue_edit_title(ctx.repo, issue.number, expected_title):
                issue.title = expected_title

    if sync.dry_run:
        logging.info(
            f"DRY-RUN: would ensure labels on issue #{issue.number}: "
            f"[{LABEL_SCOPE_SECURITY}, {LABEL_TYPE_TECH_DEBT}]"
        )
    else:
        gh_issue_add_labels(ctx.repo, issue.number, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])

    if sync.priority_sync is not None:
        sync.priority_sync.enqueue(ctx.repo, issue.number, ctx.severity, sync.severity_priority_map)


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

    reopened = _maybe_reopen_child(ctx=ctx, sync=sync, issue=issue, parent_issue=parent_issue)
    secmeta, _ = _merge_child_secmeta(ctx=ctx, issue=issue)
    _rebuild_and_apply_child_body(ctx=ctx, sync=sync, issue=issue, secmeta=secmeta)
    _comment_child_event(ctx=ctx, sync=sync, issue=issue, reopened=reopened)
    _sync_child_title_and_labels(ctx=ctx, sync=sync, issue=issue)


def ensure_issue(
    alert: Alert,
    issues: dict[int, Issue],
    index: IssueIndex,
    *,
    dry_run: bool = False,
    notifications: list[NotifiedIssue] | None = None,
    severity_priority_map: dict[str, str] | None = None,
    priority_sync: ProjectPrioritySync | None = None,
    severity_changes: list[SeverityChange] | None = None,
    parent_original_bodies: dict[int, tuple[str, str]] | None = None,
) -> None:
    """Process a single alert: create or update its child issue and parent."""
    alert_number = alert.metadata.alert_number

    alert_state = alert.metadata.state
    if alert_state and alert_state != "open":
        # This script is designed to process open alerts only!
        # Input is typically produced by collect_alert.py with --state open (default).
        logging.debug(f"Skip alert {alert_number}: state={alert_state!r} (only 'open' processed)")
        return

    rule_id = alert.metadata.rule_id
    cve = rule_id if rule_id.upper().startswith("CVE-") else NOT_AVAILABLE

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

    occurrence_fp = compute_occurrence_fp(commit_sha, path, start_line, end_line)

    repo_full = alert.repo
    first_seen = iso_date(alert.metadata.created_at)
    last_seen = iso_date(alert.metadata.updated_at)

    _spm = severity_priority_map or {}

    parent_issue = ensure_parent_issue(
        alert,
        issues,
        index,
        dry_run=dry_run,
        severity_priority_map=_spm,
        priority_sync=priority_sync,
        severity_changes=severity_changes,
        parent_original_bodies=parent_original_bodies,
    )
    matched = find_issue_in_index(
        index,
        fingerprint=fingerprint,
    )

    ctx = AlertContext(
        alert=alert,
        alert_number=alert_number,
        fingerprint=fingerprint,
        occurrence_fp=occurrence_fp,
        repo=repo_full,
        first_seen=first_seen,
        last_seen=last_seen,
        tool=alert.metadata.tool,
        rule_id=rule_id,
        rule_name=alert.metadata.rule_name,
        severity=alert.metadata.severity,
        cve=cve,
        path=path,
        start_line=start_line,
        end_line=end_line,
        commit_sha=commit_sha,
    )
    sync_ctx = SyncContext(
        issues=issues,
        index=index,
        dry_run=dry_run,
        notifications=notifications,
        severity_priority_map=_spm,
        priority_sync=priority_sync,
    )

    if matched is None:
        _handle_new_child_issue(ctx=ctx, sync=sync_ctx, parent_issue=parent_issue)
        return

    _handle_existing_child_issue(ctx=ctx, sync=sync_ctx, issue=matched, parent_issue=parent_issue)


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
        logging.warning(f"Could not load project #{project_number} metadata – priority sync disabled")
        return None

    return ProjectPrioritySync(org, project_number, pf, dry_run=dry_run)


def _flush_parent_body_updates(
    parent_original_bodies: dict[int, tuple[str, str]],
    issues: dict[int, Issue],
    *,
    dry_run: bool,
) -> None:
    """Write deferred parent-issue body updates to GitHub."""
    for num, (repo, original_body) in parent_original_bodies.items():
        issue = issues.get(num)
        if issue is None:
            continue
        if issue.body != original_body:
            if dry_run:
                logging.info(f"DRY-RUN: would update parent issue #{num} body to template")
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.debug("DRY-RUN: body_preview_begin")
                    logging.debug(issue.body)
                    logging.debug("DRY-RUN: body_preview_end")
            else:
                gh_issue_edit_body(repo, num, issue.body)


def _label_orphan_issues(
    alerts: dict[int, Alert],
    index: IssueIndex,
    *,
    dry_run: bool,
) -> None:
    """Detect open child issues with no matching alert and add the adept-to-close label."""
    alert_fingerprints: set[str] = set()
    for alert in alerts.values():
        fp = alert.alert_details.alert_hash
        if fp:
            alert_fingerprints.add(fp)

    open_issue_fps = {fp for fp, issue in index.by_fingerprint.items() if issue.state.lower() == "open"}
    orphan_fps = open_issue_fps - alert_fingerprints

    if not orphan_fps:
        logging.debug("No orphan child issues detected \u2013 skipping sec:adept-to-close labelling")
        return

    logging.info(f"Detected {len(orphan_fps)} orphan child issue(s) (open issue without matching alert)")

    for fp in orphan_fps:
        issue = index.by_fingerprint[fp]
        repo = load_secmeta(issue.body).get("repo", "")
        if not repo:
            logging.debug(f"Skip orphan labelling for issue #{issue.number}: no repo in secmeta")
            continue
        if issue.labels and LABEL_SEC_ADEPT_TO_CLOSE in issue.labels:
            logging.debug(
                f"Label {LABEL_SEC_ADEPT_TO_CLOSE!r} already on issue #{issue.number} "
                f"(fingerprint={fp[:12]}…) – skipping"
            )
            continue
        if dry_run:
            logging.info(
                f"DRY-RUN: would add label {LABEL_SEC_ADEPT_TO_CLOSE!r} "
                f"to issue #{issue.number} (fingerprint={fp[:12]}\u2026) \u2013 no matching open alert"
            )
        else:
            logging.info(
                f"Adding label {LABEL_SEC_ADEPT_TO_CLOSE!r} to issue #{issue.number} "
                f"(fingerprint={fp[:12]}…) – no matching open alert"
            )
            gh_issue_add_labels(repo, issue.number, [LABEL_SEC_ADEPT_TO_CLOSE])


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
    severity_changes: list[SeverityChange] = []
    index = build_issue_index(issues)
    spm = severity_priority_map or {}
    parent_original_bodies: dict[int, tuple[str, str]] = {}

    priority_sync = _init_priority_sync(
        alerts,
        severity_priority_map=spm,
        project_number=project_number,
        project_org=project_org,
        dry_run=dry_run,
    )

    for alert in alerts.values():
        ensure_issue(
            alert,
            issues,
            index,
            dry_run=dry_run,
            notifications=notifications,
            severity_priority_map=severity_priority_map,
            priority_sync=priority_sync,
            severity_changes=severity_changes,
            parent_original_bodies=parent_original_bodies,
        )

    _flush_parent_body_updates(parent_original_bodies, issues, dry_run=dry_run)

    if priority_sync is not None:
        priority_sync.flush()

    _label_orphan_issues(alerts, index, dry_run=dry_run)

    return SyncResult(notifications=notifications, severity_changes=severity_changes)
