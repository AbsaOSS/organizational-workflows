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

from __future__ import annotations

from typing import Any

from .alert_parser import AlertMessageKey, compute_occurrence_fp, extract_cwe
from .common import is_verbose, iso_date, normalize_path, utc_today, vprint
from .constants import (
    LABEL_EPIC,
    LABEL_SCOPE_SECURITY,
    LABEL_SEC_ADEPT_TO_CLOSE,
    LABEL_TYPE_TECH_DEBT,
    SEC_EVENT_OCCURRENCE,
    SEC_EVENT_OPEN,
    SEC_EVENT_REOPEN,
    SECMETA_TYPE_CHILD,
    SECMETA_TYPE_PARENT,
)
from .github_issues import (
    gh_issue_add_labels,
    gh_issue_add_sub_issue_by_number,
    gh_issue_comment,
    gh_issue_create,
    gh_issue_edit_body,
    gh_issue_edit_state,
)
from .github_projects import (
    ProjectPrioritySync,
    gh_project_get_priority_field,
)
from .issue_builder import (
    build_child_issue_body,
    build_issue_title,
    build_parent_issue_body,
    build_parent_issue_title,
    build_parent_template_values,
    classify_category,
)
from .models import Issue, IssueIndex, NotifiedIssue
from .sec_events import render_sec_event, strip_sec_events_from_body
from .secmeta import json_list, load_secmeta, parse_json_list, render_secmeta
from .templates import PARENT_BODY_TEMPLATE, render_markdown_template


def build_issue_index(issues: dict[int, Issue]) -> IssueIndex:
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
    return index.by_fingerprint.get(fingerprint)


def find_parent_issue(index: IssueIndex, *, rule_id: str) -> Issue | None:
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
    if parent_issue is None:
        return

    if parent_issue.state.lower() != "closed":
        return

    if dry_run:
        print(
            f"DRY-RUN: would reopen parent issue #{parent_issue.number} (rule_id={rule_id}) "
            f"due_to={context} child={child_issue_number or ''}".rstrip()
        )
        print(
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
    alert: dict[str, Any],
    issues: dict[int, Issue],
    index: IssueIndex,
    *,
    dry_run: bool,
    severity_priority_map: dict[str, str] | None = None,
    priority_sync: ProjectPrioritySync | None = None,
) -> Issue | None:
    rule_id = str(alert.get("rule_id") or "").strip()
    if not rule_id:
        return None

    repo_full = str(alert.get("_repo") or "")
    existing = find_parent_issue(index, rule_id=rule_id)
    if existing is not None:
        # Keep parent issues aligned to the template as alerts evolve.
        existing_secmeta = load_secmeta(existing.body) or {"schema": "1"}
        existing_first = existing_secmeta.get("first_seen") or iso_date(alert.get("created_at"))
        existing_last = existing_secmeta.get("last_seen") or iso_date(alert.get("updated_at"))
        first_seen_final = min(existing_first, iso_date(alert.get("created_at")))
        last_seen_final = max(existing_last, iso_date(alert.get("updated_at")))

        _severity = str((alert.get("severity") or existing_secmeta.get("severity") or "unknown")).lower()

        existing_secmeta.update(
            {
                "schema": existing_secmeta.get("schema") or "1",
                "type": SECMETA_TYPE_PARENT,
                "repo": repo_full,
                "source": existing_secmeta.get("source") or "code_scanning",
                "tool": str(alert.get("tool") or existing_secmeta.get("tool") or ""),
                "severity": _severity,
                "rule_id": rule_id,
                "first_seen": first_seen_final,
                "last_seen": last_seen_final,
                "postponed_until": existing_secmeta.get("postponed_until", ""),
            }
        )

        rebuilt = render_secmeta(existing_secmeta) + "\n\n" + render_markdown_template(
            PARENT_BODY_TEMPLATE,
            build_parent_template_values(alert, rule_id=rule_id, severity=_severity),
        ).strip() + "\n"
        rebuilt = strip_sec_events_from_body(rebuilt)

        if rebuilt != (existing.body or ""):
            if dry_run:
                print(f"DRY-RUN: would update parent issue #{existing.number} body to template (rule_id={rule_id})")
                if is_verbose():
                    print("DRY-RUN: body_preview_begin")
                    print(rebuilt)
                    print("DRY-RUN: body_preview_end")
            else:
                gh_issue_edit_body(repo_full, existing.number, rebuilt)
                existing.body = rebuilt

        # Enqueue priority sync (bulk – resolved + flushed later).
        if priority_sync is not None:
            priority_sync.enqueue(repo_full, existing.number, _severity, severity_priority_map or {})

        return existing

    title = build_parent_issue_title(rule_id)
    body = build_parent_issue_body(alert)
    labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT, LABEL_EPIC]
    if dry_run:
        print(f"DRY-RUN: create parent rule_id={rule_id} title={title!r} labels={labels}")
        if is_verbose():
            print("DRY-RUN: body_preview_begin")
            print(body)
            print("DRY-RUN: body_preview_end")
        return None

    num = gh_issue_create(repo_full, title, body, labels)
    if num is None:
        return None

    # Parent lifecycle event (human visible): opened/created.
    if dry_run:
        print(f"DRY-RUN: would comment parent open sec-event on issue #{num} (rule_id={rule_id})")
    else:
        gh_issue_comment(
            repo_full,
            num,
            render_sec_event(
                {
                    "action": SEC_EVENT_OPEN,
                    "seen_at": iso_date(alert.get("created_at")),
                    "source": "code_scanning",
                    "rule_id": rule_id,
                    "severity": str((alert.get("severity") or "unknown")).lower(),
                }
            ),
        )

    created = Issue(number=num, state="open", title=title, body=body)
    issues[num] = created
    index.parent_by_rule_id[rule_id] = created
    print(f"Created parent issue #{num} for rule_id={rule_id}")

    # Enqueue priority sync (bulk – resolved + flushed later).
    if priority_sync is not None:
        priority_sync.enqueue(
            repo_full, num, str((alert.get("severity") or "unknown")).lower(),
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
    alert: dict[str, Any],
    alert_number: int,
    issues: dict[int, Issue],
    index: IssueIndex,
    parent_issue: Issue | None,
    fingerprint: str,
    occurrence_fp: str,
    repo_full: str,
    first_seen: str,
    last_seen: str,
    dry_run: bool,
    notifications: list[NotifiedIssue] | None,
    severity_priority_map: dict[str, str],
    priority_sync: ProjectPrioritySync | None,
    tool: str,
    rule_id: str,
    rule_name: str,
    severity: str,
    cwe: str,
    path: str,
    start_line: Any,
    end_line: Any,
    commit_sha: str,
) -> None:
    category = classify_category(alert)
    secmeta: dict[str, str] = {
        "schema": "1",
        "type": SECMETA_TYPE_CHILD,
        "fingerprint": fingerprint,
        "repo": repo_full,
        "source": "code_scanning",
        "tool": tool,
        "severity": severity,
        "category": category,
        "rule_id": rule_id,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "last_seen_commit": commit_sha,
        "postponed_until": "",
        "gh_alert_numbers": json_list([str(alert_number)]),
        "occurrence_count": "1",
        "last_occurrence_fp": occurrence_fp,
    }
    if cwe:
        secmeta["cwe"] = cwe

    human_body = build_child_issue_body(alert)
    body = render_secmeta(secmeta) + "\n\n" + human_body
    title = build_issue_title(rule_name, rule_id, fingerprint)

    if dry_run:
        labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT]
        loc = f"{path}:{start_line or ''}".rstrip(":")
        commit_short = commit_sha[:8] if commit_sha else ""
        print(
            "DRY-RUN: create child "
            f"alert={alert_number} rule_id={rule_id} sev={severity} fp={fingerprint[:8]} tool={tool} "
            f"commit={commit_short} loc={loc} title={title!r} labels=[{','.join(labels)}] "
            f"| secmeta:first_seen={first_seen} last_seen={last_seen} occurrence_count=1 gh_alert_numbers=[{alert_number}]"
        )
        if parent_issue is None and rule_id:
            print(f"DRY-RUN: add sub-issue link parent_rule_id={rule_id} child=(new) alert={alert_number}")
        elif parent_issue is not None:
            print(f"DRY-RUN: add sub-issue link parent=#{parent_issue.number} child=(new) alert={alert_number}")
        if is_verbose():
            print("DRY-RUN: body_preview_begin")
            print(body)
            print("DRY-RUN: body_preview_end")

        _append_notification(
            notifications,
            repo=repo_full,
            issue_number=0,
            severity=severity,
            category=category,
            state="new",
            tool=tool,
        )
        if priority_sync is not None:
            priority_sync.enqueue(repo_full, 0, severity, severity_priority_map)
        return

    num = gh_issue_create(repo_full, title, body, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])
    if num is None:
        return

    print(f"Created issue #{num} for alert {alert_number} (fp={fingerprint[:8]})")
    created = Issue(number=num, state="open", title=title, body=body)
    issues[num] = created
    index.by_fingerprint[fingerprint] = created

    _append_notification(
        notifications,
        repo=repo_full,
        issue_number=num,
        severity=severity,
        category=category,
        state="new",
        tool=tool,
    )

    if parent_issue is not None:
        maybe_reopen_parent_issue(
            repo_full,
            parent_issue,
            rule_id=rule_id,
            dry_run=dry_run,
            context="new_child",
            child_issue_number=num,
        )
        print(f"Add sub-issue link parent=#{parent_issue.number} child=#{num} (alert {alert_number})")
        gh_issue_add_sub_issue_by_number(repo_full, parent_issue.number, num)

    gh_issue_comment(
        repo_full,
        num,
        render_sec_event(
            {
                "action": SEC_EVENT_OPEN,
                "seen_at": first_seen,
                "source": "code_scanning",
                "gh_alert_number": str(alert_number),
                "occurrence_fp": str(occurrence_fp),
                "commit_sha": str(commit_sha),
                "path": str(path),
                "start_line": str(start_line or ""),
                "end_line": str(end_line or ""),
            }
        ),
    )

    if priority_sync is not None:
        priority_sync.enqueue(repo_full, num, severity, severity_priority_map)


def _handle_existing_child_issue(
    *,
    alert: dict[str, Any],
    alert_number: int,
    issue: Issue,
    index: IssueIndex,
    parent_issue: Issue | None,
    dry_run: bool,
    notifications: list[NotifiedIssue] | None,
    severity_priority_map: dict[str, str],
    priority_sync: ProjectPrioritySync | None,
    fingerprint: str,
    occurrence_fp: str,
    repo_full: str,
    first_seen: str,
    last_seen: str,
    tool: str,
    rule_id: str,
    severity: str,
    cwe: str,
    path: str,
    start_line: Any,
    end_line: Any,
    commit_sha: str,
) -> None:
    if parent_issue is None and rule_id:
        parent_issue = find_parent_issue(index, rule_id=rule_id)

    reopened = False
    if issue.state.lower() == "closed":
        if dry_run:
            reopened = True
            print(f"DRY-RUN: would reopen issue #{issue.number} (alert {alert_number})")
        elif gh_issue_edit_state(repo_full, issue.number, "open"):
            reopened = True
            print(f"Reopened issue #{issue.number} (alert {alert_number})")

    if reopened:
        maybe_reopen_parent_issue(
            repo_full,
            parent_issue,
            rule_id=rule_id,
            dry_run=dry_run,
            context="reopen_child",
            child_issue_number=issue.number,
        )
        existing_secmeta = load_secmeta(issue.body)
        reopen_category = (existing_secmeta.get("category") or "").strip() or classify_category(alert)
        _append_notification(
            notifications,
            repo=repo_full,
            issue_number=issue.number,
            severity=severity,
            category=reopen_category,
            state="reopen",
            tool=tool,
        )
        if priority_sync is not None:
            priority_sync.enqueue(repo_full, issue.number, severity, severity_priority_map)

    secmeta = load_secmeta(issue.body) or {"schema": "1"}
    secmeta.pop("alert_hash", None)

    existing_alerts = parse_json_list(secmeta.get("gh_alert_numbers"))
    if not existing_alerts and secmeta.get("related_alert_ids"):
        existing_alerts = parse_json_list(secmeta.get("related_alert_ids"))
    if str(alert_number) not in existing_alerts:
        existing_alerts.append(str(alert_number))

    last_occ_fp = secmeta.get("last_occurrence_fp") or ""
    occurrence_count = int(secmeta.get("occurrence_count") or "0" or 0)
    new_occurrence = bool(occurrence_fp and occurrence_fp != last_occ_fp)
    if occurrence_count <= 0:
        occurrence_count = 1
    if new_occurrence:
        occurrence_count += 1

    existing_first = secmeta.get("first_seen") or first_seen
    existing_last = secmeta.get("last_seen") or last_seen
    first_seen_final = min(existing_first, first_seen)
    last_seen_final = max(existing_last, last_seen)

    secmeta.update(
        {
            "fingerprint": fingerprint,
            "repo": repo_full,
            "source": secmeta.get("source") or "code_scanning",
            "tool": tool or secmeta.get("tool", ""),
            "severity": severity,
            "category": classify_category(alert) or secmeta.get("category", ""),
            "rule_id": rule_id or secmeta.get("rule_id", ""),
            "first_seen": first_seen_final,
            "last_seen": last_seen_final,
            "last_seen_commit": commit_sha or secmeta.get("last_seen_commit", ""),
            "gh_alert_numbers": json_list(existing_alerts),
            "occurrence_count": str(occurrence_count),
            "last_occurrence_fp": occurrence_fp or last_occ_fp,
        }
    )
    if cwe:
        secmeta["cwe"] = cwe

    human_body = build_child_issue_body(alert)
    new_body = render_secmeta(secmeta) + "\n\n" + human_body
    new_body = strip_sec_events_from_body(new_body)

    if reopened:
        if dry_run:
            print(f"DRY-RUN: would comment reopen event on issue #{issue.number} (alert {alert_number})")
        else:
            gh_issue_comment(
                repo_full,
                issue.number,
                render_sec_event(
                    {
                        "action": SEC_EVENT_REOPEN,
                        "seen_at": utc_today(),
                        "source": "code_scanning",
                        "gh_alert_number": str(alert_number),
                    }
                ),
            )
    elif new_occurrence:
        if dry_run:
            print(f"DRY-RUN: would comment occurrence event on issue #{issue.number} (alert {alert_number})")
        else:
            gh_issue_comment(
                repo_full,
                issue.number,
                render_sec_event(
                    {
                        "action": SEC_EVENT_OCCURRENCE,
                        "seen_at": utc_today(),
                        "source": "code_scanning",
                        "gh_alert_number": str(alert_number),
                        "occurrence_fp": str(occurrence_fp),
                        "commit_sha": str(commit_sha),
                        "path": str(path),
                        "start_line": str(start_line or ""),
                        "end_line": str(end_line or ""),
                    }
                ),
            )

    if new_body != issue.body:
        if dry_run:
            print(f"DRY-RUN: would update issue #{issue.number} body to template (alert {alert_number})")
            if is_verbose():
                print("DRY-RUN: body_preview_begin")
                print(new_body)
                print("DRY-RUN: body_preview_end")
        else:
            gh_issue_edit_body(repo_full, issue.number, new_body)
            issue.body = new_body

    if dry_run:
        print(
            f"DRY-RUN: would ensure labels on issue #{issue.number}: "
            f"[{LABEL_SCOPE_SECURITY}, {LABEL_TYPE_TECH_DEBT}]"
        )
    else:
        gh_issue_add_labels(repo_full, issue.number, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])

    if priority_sync is not None:
        priority_sync.enqueue(repo_full, issue.number, severity, severity_priority_map)


def ensure_issue(
    alert: dict[str, Any],
    issues: dict[int, Issue],
    index: IssueIndex,
    *,
    dry_run: bool = False,
    notifications: list[NotifiedIssue] | None = None,
    severity_priority_map: dict[str, str] | None = None,
    priority_sync: ProjectPrioritySync | None = None,
) -> None:
    alert_number = int(alert.get("alert_number"))

    alert_state = str(alert.get("state") or "").lower().strip()
    if alert_state and alert_state != "open":
        # This script is designed to process open alerts only.
        # Input is typically produced by collect_alert.sh with --state open (default).
        vprint(f"Skip alert {alert_number}: state={alert_state!r} (only 'open' processed)")
        return

    tool = str(alert.get("tool") or "")
    rule_id = str(alert.get("rule_id") or "")
    rule_name = alert.get("rule_name")
    severity = str((alert.get("severity") or "unknown")).lower()
    cwe = extract_cwe(alert)

    path = normalize_path(alert.get("file"))
    start_line = alert.get("start_line")
    end_line = alert.get("end_line")
    commit_sha = str(alert.get("commit_sha") or "")

    msg_params = alert.get("_message_params")
    if not isinstance(msg_params, dict):
        raise SystemExit(
            "ERROR: missing parsed message params on alert. "
            "Expected alert['_message_params'] to be set by load_open_alerts_from_file()."
        )

    fingerprint = str(msg_params.get(AlertMessageKey.ALERT_HASH.value) or "").strip()

    if not fingerprint:
        raise SystemExit(
            f"ERROR: missing {AlertMessageKey.ALERT_HASH.value!r} in alert message parameters for alert_number={alert_number}. "
            "Ensure the collector/scanner includes an 'Alert hash: ...' line."
        )

    occurrence_fp = compute_occurrence_fp(commit_sha, path, start_line, end_line)

    repo_full = alert["_repo"]
    first_seen = iso_date(alert.get("created_at"))
    last_seen = iso_date(alert.get("updated_at"))

    _spm = severity_priority_map or {}

    parent_issue = ensure_parent_issue(
        alert, issues, index, dry_run=dry_run,
        severity_priority_map=_spm, priority_sync=priority_sync,
    )
    matched = find_issue_in_index(
        index,
        fingerprint=fingerprint,
    )

    if matched is None:
        _handle_new_child_issue(
            alert=alert,
            alert_number=alert_number,
            issues=issues,
            index=index,
            parent_issue=parent_issue,
            fingerprint=fingerprint,
            occurrence_fp=occurrence_fp,
            repo_full=repo_full,
            first_seen=first_seen,
            last_seen=last_seen,
            dry_run=dry_run,
            notifications=notifications,
            severity_priority_map=_spm,
            priority_sync=priority_sync,
            tool=tool,
            rule_id=rule_id,
            rule_name=str(rule_name or ""),
            severity=severity,
            cwe=cwe,
            path=path,
            start_line=start_line,
            end_line=end_line,
            commit_sha=commit_sha,
        )
        return

    _handle_existing_child_issue(
        alert=alert,
        alert_number=alert_number,
        issue=matched,
        index=index,
        parent_issue=parent_issue,
        dry_run=dry_run,
        notifications=notifications,
        severity_priority_map=_spm,
        priority_sync=priority_sync,
        fingerprint=fingerprint,
        occurrence_fp=occurrence_fp,
        repo_full=repo_full,
        first_seen=first_seen,
        last_seen=last_seen,
        tool=tool,
        rule_id=rule_id,
        severity=severity,
        cwe=cwe,
        path=path,
        start_line=start_line,
        end_line=end_line,
        commit_sha=commit_sha,
    )


def sync_alerts_and_issues(
    alerts: dict[int, dict[str, Any]],
    issues: dict[int, Issue],
    *,
    dry_run: bool = False,
    severity_priority_map: dict[str, str] | None = None,
    project_number: int | None = None,
    project_org: str = "",
) -> list[NotifiedIssue]:
    """Sync open alerts into issues.

    Creates/updates child issues (keyed by fingerprint) and ensures a parent issue
    per rule_id, then links children under the parent via GitHub sub-issues.

    Returns a list of NotifiedIssue entries for new or reopened child issues.
    """

    notifications: list[NotifiedIssue] = []
    index = build_issue_index(issues)

    # Initialise bulk priority sync (one-time prefetch of project items).
    priority_sync: ProjectPrioritySync | None = None
    spm = severity_priority_map or {}
    if spm and project_number:
        org = project_org or ""
        if not org:
            # Derive from the first alert's repo.
            first_alert = next(iter(alerts.values()), None)
            if first_alert:
                repo_full = str(first_alert.get("_repo") or "")
                org = repo_full.split("/", 1)[0] if "/" in repo_full else ""
        if org:
            pf = gh_project_get_priority_field(org, project_number)
            if pf is not None:
                priority_sync = ProjectPrioritySync(org, project_number, pf, dry_run=dry_run)
            else:
                vprint(f"WARN: Could not load project #{project_number} metadata – priority sync disabled")
        else:
            vprint("WARN: Cannot determine org for project priority – priority sync disabled")

    for alert in alerts.values():
        ensure_issue(
            alert, issues, index,
            dry_run=dry_run, notifications=notifications,
            severity_priority_map=severity_priority_map,
            priority_sync=priority_sync,
        )

    # Flush all pending priority mutations in bulk.
    if priority_sync is not None:
        priority_sync.flush()

    # Detect child issues that have no matching open alert and label for closure.
    alert_fingerprints: set[str] = set()
    for alert in alerts.values():
        msg_params = alert.get("_message_params")
        if isinstance(msg_params, dict):
            fp = str(msg_params.get(AlertMessageKey.ALERT_HASH.value) or "").strip()
            if fp:
                alert_fingerprints.add(fp)

    open_issue_fps = {fp for fp, issue in index.by_fingerprint.items() if issue.state.lower() == "open"}
    orphan_fps = open_issue_fps - alert_fingerprints

    if not orphan_fps:
        vprint("No orphan child issues detected – skipping sec:adept-to-close labelling")
        return notifications

    print(f"Detected {len(orphan_fps)} orphan child issue(s) (open issue without matching alert)")

    for fp in orphan_fps:
        issue = index.by_fingerprint[fp]
        repo = load_secmeta(issue.body).get("repo", "")
        if not repo:
            vprint(f"Skip orphan labelling for issue #{issue.number}: no repo in secmeta")
            continue
        # Skip if the issue already carries the label.
        if issue.labels and LABEL_SEC_ADEPT_TO_CLOSE in issue.labels:
            vprint(
                f"Label {LABEL_SEC_ADEPT_TO_CLOSE!r} already on issue #{issue.number} "
                f"(fingerprint={fp[:12]}…) – skipping"
            )
            continue
        if dry_run:
            print(
                f"DRY-RUN: would add label {LABEL_SEC_ADEPT_TO_CLOSE!r} "
                f"to issue #{issue.number} (fingerprint={fp[:12]}…) – no matching open alert"
            )
        else:
            print(
                f"Adding label {LABEL_SEC_ADEPT_TO_CLOSE!r} to issue #{issue.number} "
                f"(fingerprint={fp[:12]}…) – no matching open alert"
            )
            gh_issue_add_labels(repo, issue.number, [LABEL_SEC_ADEPT_TO_CLOSE])

    return notifications
