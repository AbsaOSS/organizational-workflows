#!/usr/bin/env python3
"""Promote collected Code Scanning alerts JSON into GitHub Issues.

Input:
- JSON produced by `collect_alert.sh` (default: alerts.json)

Design intent:
- One Issue per *finding* (stable identity), not per GitHub alert.
- Match Issues strictly by fingerprint (scanner-provided "Alert hash").
- Store identifiers + lifecycle metadata in a single `secmeta` block in the Issue body.
- Add structured `[sec-event]` comments only for meaningful lifecycle changes (reopen, new occurrence).

Requirements:
- `gh` CLI (authenticated; uses GH_TOKEN in CI)


Draft / debug (no writes):
- Run in dry-run mode to use alert hash, build secmeta, and show intended actions without creating/editing Issues:
    `python3 promote_alerts.py --file alerts.json --issue-label scope:Security --dry-run`
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Any


LABEL_SCOPE_SECURITY = "scope:Security"
LABEL_TYPE_TECH_DEBT = "type:Tech-debt"
SEC_EVENT_OPEN = "open"
SEC_EVENT_REOPEN = "reopen"
SEC_EVENT_OCCURRENCE = "occurrence"

SECMETA_RE = re.compile(r"```secmeta\n(.*?)\n```", re.S)


# Alert message parsing
#
# Some scanners embed structured fields into the alert "message" string, one per line:
#   "Artifact: ...\nType: ...\n...\nAlert hash: abc123"
#
# We parse these into a dict so callers can access values by parameter name,
# e.g. params[ALERT_MSG_ALERT_HASH].

# Keys are stored in lowercase by default (e.g. "alert hash").

try:
    # Python 3.11+
    from enum import StrEnum
except ImportError:
    class StrEnum(str, Enum):
        pass


class AlertMessageKey(StrEnum):
    ARTIFACT = "artifact"
    TYPE = "type"
    VULNERABILITY = "vulnerability"
    SEVERITY = "severity"
    MESSAGE = "message"
    ALERT_HASH = "alert hash"


def parse_alert_message_params(message: str | None) -> dict[str, str]:
    """Parse key/value parameters from a multi-line alert message.

    Lines are expected in the form:
      <Key>: <Value>

    Keys are normalized to lowercase (and internal whitespace collapsed).
    Unknown keys are still included (in lowercase) for debugging.
    """

    params: dict[str, str] = {}
    for raw_line in (message or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key_raw, value_raw = line.split(":", 1)
        key = key_raw.strip()
        if not key:
            continue
        value = value_raw.strip()
        key_norm = " ".join(key.lower().split())
        params[key_norm] = value
        
    return params


def utc_today() -> str:
    return datetime.utcnow().date().isoformat()


def iso_date(iso_dt: str | None) -> str:
    if not iso_dt:
        return utc_today()
    if "T" in iso_dt:
        return iso_dt.split("T", 1)[0]
    return iso_dt


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def normalize_path(path: str | None) -> str:
    if not path:
        return ""
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    p = re.sub(r"/+", "/", p)
    return p


def run_cmd(cmd: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=capture_output, text=True)


def run_gh(args: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess:
    cmd = ["gh"] + args
    try:
        return run_cmd(cmd, capture_output=capture_output)
    except FileNotFoundError:
        print("ERROR: gh CLI not found. Install and authenticate gh.", file=sys.stderr)
        raise SystemExit(1)

@dataclass
class Issue:
    number: int
    state: str
    title: str
    body: str


@dataclass
class IssueIndex:
    by_fingerprint: dict[str, Issue]
def gh_issue_list_by_label(repo: str, label: str) -> dict[int, Issue]:
    """Load issues with a given label.

    This is used to pre-mine issue data so matching can happen locally without
    repeatedly calling `gh issue list` for every alert.
    """

    if not label:
        return {}

    res = run_gh(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--label",
            label,
            "--state",
            "all",
            "--json",
            "number,state,title,body",
            "--limit",
            "5000",
        ]
    )

    if res.returncode != 0:
        print(f"gh issue list by label failed: {res.stderr}", file=sys.stderr)
        return {}
    
    try:
        items = json.loads(res.stdout or "[]")
    except Exception:
        return {}

    issues: dict[int, Issue] = {}
    for obj in items or []:
        try:
            number = int(obj.get("number"))
        except Exception:
            continue
        issues[number] = Issue(
            number=number,
            state=str(obj.get("state") or ""),
            title=str(obj.get("title") or ""),
            body=str(obj.get("body") or ""),
        )

    print(f"Loaded {len(issues)} issues with label {label!r} from repository {repo}")
    return issues


def gh_issue_edit_state(repo: str, number: int, state: str) -> bool:
    res = run_gh(["issue", "edit", str(number), "--repo", repo, "--state", state])
    if res.returncode != 0:
        print(f"Failed to edit state for #{number}: {res.stderr}", file=sys.stderr)
        return False
    return True


def gh_issue_edit_body(repo: str, number: int, body: str) -> bool:
    res = run_gh(["issue", "edit", str(number), "--repo", repo, "--body", body])
    if res.returncode != 0:
        print(f"Failed to edit body for #{number}: {res.stderr}", file=sys.stderr)
        return False
    return True


def gh_issue_add_labels(repo: str, number: int, labels: list[str]) -> None:
    if not labels:
        return
    args: list[str] = ["issue", "edit", str(number), "--repo", repo]
    for label in labels:
        args += ["--add-label", label]
    res = run_gh(args)
    if res.returncode != 0:
        # Labels may not exist; don't fail the whole run.
        print(f"WARN: Failed to add labels to #{number}: {res.stderr}", file=sys.stderr)


def gh_issue_comment(repo: str, number: int, body: str) -> bool:
    res = run_gh(["issue", "comment", str(number), "--repo", repo, "--body", body])
    if res.returncode != 0:
        print(f"Failed to comment on #{number}: {res.stderr}", file=sys.stderr)
        return False
    return True


def gh_issue_create(repo: str, title: str, body: str, labels: list[str]) -> int | None:
    args: list[str] = ["issue", "create", "--repo", repo, "--title", title, "--body", body]
    for label in labels:
        args += ["--label", label]
    res = run_gh(args)
    if res.returncode != 0:
        print(f"Failed to create issue: {res.stderr}", file=sys.stderr)
        return None

    out = (res.stdout or "").strip()
    match = re.search(r"/issues/(?P<num>\d+)(?:\s*)$", out)
    if match:
        return int(match.group("num"))
    match = re.search(r"issues/(?P<num>\d+)", out)
    if match:
        return int(match.group("num"))
    return None


def parse_kv_block(block: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in (block or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()
    return data


def load_secmeta(issue_body: str) -> dict[str, str]:
    match = SECMETA_RE.search(issue_body or "")
    if not match:
        return {}
    return parse_kv_block(match.group(1))


def render_secmeta(secmeta: dict[str, str]) -> str:
    preferred_order = [
        "schema",
        "fingerprint",
        "repo",
        "source",
        "tool",
        "severity",
        "cwe",
        "rule_id",
        "first_seen",
        "last_seen",
        "last_seen_commit",
        "postponed_until",
        "gh_alert_numbers",
        "occurrence_count",
        "last_occurrence_fp",
    ]
    lines: list[str] = []
    for key in preferred_order:
        if key in secmeta:
            lines.append(f"{key}={secmeta.get(key, '')}")
    # include any additional keys deterministically
    for key in sorted(k for k in secmeta.keys() if k not in set(preferred_order)):
        lines.append(f"{key}={secmeta.get(key, '')}")
    return "```secmeta\n" + "\n".join(lines) + "\n```"


def upsert_secmeta(issue_body: str, secmeta: dict[str, str]) -> str:
    new_block = render_secmeta(secmeta)
    if SECMETA_RE.search(issue_body or ""):
        return SECMETA_RE.sub(new_block, issue_body, count=1)
    # Prepend if absent.
    if issue_body.strip():
        return new_block + "\n\n" + issue_body.strip() + "\n"
    return new_block + "\n"


def parse_json_list(value: str | None) -> list[str]:
    if not value:
        return []
    s = value.strip()
    try:
        parsed = json.loads(s)
        if isinstance(parsed, list):
            return [str(x) for x in parsed]
    except Exception:
        pass
    # very small fallback: treat comma-separated as list
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    parts = [p.strip().strip('"').strip("'") for p in s.split(",")]
    return [p for p in parts if p]


def json_list(value: list[str]) -> str:
    return json.dumps([str(x) for x in value])


def extract_cwe(alert: dict[str, Any]) -> str | None:
    """Best-effort CWE extraction.

    Not all code scanning alerts include CWE mapping.
    - If `alert["cwe"]` is present, use it.
    - Otherwise try to parse a CWE token from tags like "CWE-79".
    """

    raw = alert.get("cwe")
    if raw:
        s = str(raw).strip()
        return s or None

    tags = alert.get("tags")
    if isinstance(tags, list):
        for t in tags:
            m = re.search(r"\bCWE-(\d+)\b", str(t), flags=re.IGNORECASE)
            if m:
                return f"CWE-{m.group(1)}"
    return None


def compute_occurrence_fp(commit_sha: str, path: str, start_line: int | None, end_line: int | None) -> str:
    # Works without git; used to record distinct sightings over time.
    return sha256_hex(f"{commit_sha}|{path}|{start_line or ''}|{end_line or ''}")


def build_issue_index(issues: dict[int, Issue]) -> IssueIndex:
    by_fingerprint: dict[str, Issue] = {}

    for issue in issues.values():
        secmeta = load_secmeta(issue.body)
        fp = (secmeta.get("fingerprint") or "").strip() or (secmeta.get("alert_hash") or "").strip()
        if fp:
            by_fingerprint.setdefault(fp, issue)

    return IssueIndex(
        by_fingerprint=by_fingerprint,
    )


def find_issue_in_index(
    index: IssueIndex,
    *,
    fingerprint: str,
) -> Issue | None:
    return index.by_fingerprint.get(fingerprint)


def build_issue_title(rule_name: str | None, rule_id: str, canonical_fp: str) -> str:
    prefix = canonical_fp[:8] if canonical_fp else "unknown"
    summary = (rule_name or rule_id or "Security finding").strip() or "Security finding"
    return f"[SEC][FP={prefix}] {summary}"


def build_body_context(alert: dict[str, Any]) -> str:
    alert_number = alert.get("alert_number")
    alert_url = alert.get("alert_url") or alert.get("url") or ""
    rule_id = alert.get("rule_id") or ""
    help_uri = alert.get("help_uri") or ""
    message = alert.get("message") or ""
    file_path = alert.get("file") or ""
    start_line = alert.get("start_line") or ""
    commit_sha = alert.get("commit_sha") or ""
    tool = alert.get("tool") or ""

    parts: list[str] = []
    if alert_url:
        parts.append(f"Alert: {alert_url}")
    parts.append(f"Alert number: {alert_number}")
    if tool:
        parts.append(f"Tool: {tool}")
    if rule_id:
        parts.append(f"Rule: {rule_id}")
    if help_uri:
        parts.append(f"Help: {help_uri}")
    if file_path:
        parts.append(f"Location: {file_path}:{start_line}")
    if commit_sha:
        parts.append(f"Commit: {commit_sha}")
    if message:
        parts.append("")
        parts.append("Message:")
        parts.append(message)
    return "\n".join(parts).strip() + "\n"


def ensure_issue(
    alert: dict[str, Any],
    issues: dict[int, Issue],
    *,
    dry_run: bool = False,
    dry_run_details: bool = False,
) -> None:
    alert_number = int(alert.get("alert_number"))

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

    canonical_fp = fingerprint

    occurrence_fp = compute_occurrence_fp(commit_sha, path, start_line, end_line)

    repo_full = alert["_repo"]
    first_seen = iso_date(alert.get("created_at"))
    last_seen = iso_date(alert.get("updated_at"))

    index = build_issue_index(issues)
    matched = find_issue_in_index(
        index,
        fingerprint=fingerprint,
    )
    if matched is None:
        secmeta: dict[str, str] = {
            "schema": "1",
            "fingerprint": canonical_fp,
            "repo": repo_full,
            "source": "code_scanning",
            "tool": tool,
            "severity": severity,
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

        body = render_secmeta(secmeta) + "\n\n" + build_body_context(alert)
        body += (
            "\n[sec-event]\n"
            f"action={SEC_EVENT_OPEN}\n"
            "source=code_scanning\n"
            f"gh_alert_number={alert_number}\n"
            f"occurrence_fp={occurrence_fp}\n"
            "[/sec-event]\n"
        )

        title = build_issue_title(rule_name, rule_id, canonical_fp)
        if dry_run:
            labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT]
            print(f"DRY-RUN: would create issue for alert {alert_number} (fp={canonical_fp[:8]})")
            print(f"DRY-RUN: title={title!r}")
            print(f"DRY-RUN: labels={labels}")
            if dry_run_details:
                print("DRY-RUN: --- full alert payload ---")
                print(json.dumps(alert, indent=2, sort_keys=True))
                print("DRY-RUN: --- full issue body ---")
                print(body)
                print("DRY-RUN: --- end details ---")
            return

        num = gh_issue_create(repo_full, title, body, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])
        if num is not None:
            print(f"Created issue #{num} for alert {alert_number} (fp={canonical_fp[:8]})")
        return

    issue = matched

    # Reopen if needed.
    reopened = False
    needs_reopen = issue.state.lower() == "closed"
    if needs_reopen:
        if dry_run:
            reopened = True
            print(f"DRY-RUN: would reopen issue #{issue.number} (alert {alert_number})")
        else:
            if gh_issue_edit_state(repo_full, issue.number, "open"):
                reopened = True
                print(f"Reopened issue #{issue.number} (alert {alert_number})")

    secmeta = load_secmeta(issue.body)
    if not secmeta:
        # If missing, seed it; keep existing content below.
        secmeta = {"schema": "1"}

    # Keep `fingerprint` as the single canonical identifier.
    # Drop legacy `alert_hash` if present to avoid duplication.
    secmeta.pop("alert_hash", None)

    # Merge/migrate legacy keys.
    existing_alerts = parse_json_list(secmeta.get("gh_alert_numbers"))
    if not existing_alerts and secmeta.get("related_alert_ids"):
        existing_alerts = parse_json_list(secmeta.get("related_alert_ids"))
    if str(alert_number) not in existing_alerts:
        existing_alerts.append(str(alert_number))

    # Occurrence tracking (best-effort, low-noise): only increment when the last_occurrence changes.
    last_occ_fp = secmeta.get("last_occurrence_fp") or ""
    occurrence_count = int(secmeta.get("occurrence_count") or "0" or 0)
    new_occurrence = bool(occurrence_fp and occurrence_fp != last_occ_fp)
    if occurrence_count <= 0:
        occurrence_count = 1
    if new_occurrence:
        occurrence_count += 1

    # first/last seen (best effort)
    existing_first = secmeta.get("first_seen") or first_seen
    existing_last = secmeta.get("last_seen") or last_seen
    first_seen_final = min(existing_first, first_seen)
    last_seen_final = max(existing_last, last_seen)

    secmeta.update(
        {
            "fingerprint": canonical_fp,
            "repo": repo_full,
            "source": secmeta.get("source") or "code_scanning",
            "tool": tool or secmeta.get("tool", ""),
            "severity": severity,
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

    new_body = upsert_secmeta(issue.body, secmeta)
    if new_body != issue.body:
        if dry_run:
            print(f"DRY-RUN: would update secmeta/body for issue #{issue.number} (alert {alert_number})")
            if dry_run_details:
                print("DRY-RUN: --- full updated issue body ---")
                print(new_body)
                print("DRY-RUN: --- end details ---")
        else:
            gh_issue_edit_body(repo_full, issue.number, new_body)

    # Ensure baseline labels.
    if dry_run:
        print(
            f"DRY-RUN: would ensure labels on issue #{issue.number}: "
            f"[{LABEL_SCOPE_SECURITY}, {LABEL_TYPE_TECH_DEBT}]"
        )
    else:
        gh_issue_add_labels(repo_full, issue.number, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])

    if reopened:
        if dry_run:
            print(f"DRY-RUN: would comment reopen event on issue #{issue.number} (alert {alert_number})")
            if dry_run_details:
                print("DRY-RUN: --- comment body ---")
                print(
                    "[sec-event]\n"
                    f"action={SEC_EVENT_REOPEN}\n"
                    "source=code_scanning\n"
                    f"gh_alert_number={alert_number}\n"
                    "[/sec-event]"
                )
                print("DRY-RUN: --- end details ---")
        else:
            gh_issue_comment(
                repo_full,
                issue.number,
                "[sec-event]\n"
                f"action={SEC_EVENT_REOPEN}\n"
                "source=code_scanning\n"
                f"gh_alert_number={alert_number}\n"
                "[/sec-event]",
            )
    elif new_occurrence:
        if dry_run:
            print(f"DRY-RUN: would comment occurrence event on issue #{issue.number} (alert {alert_number})")
            if dry_run_details:
                print("DRY-RUN: --- comment body ---")
                print(
                    "[sec-event]\n"
                    f"action={SEC_EVENT_OCCURRENCE}\n"
                    "source=code_scanning\n"
                    f"seen_at={utc_today()}\n"
                    f"gh_alert_number={alert_number}\n"
                    f"occurrence_fp={occurrence_fp}\n"
                    f"commit_sha={commit_sha}\n"
                    f"path={path}\n"
                    f"start_line={start_line or ''}\n"
                    f"end_line={end_line or ''}\n"
                    "[/sec-event]"
                )
                print("DRY-RUN: --- end details ---")
        else:
            gh_issue_comment(
                repo_full,
                issue.number,
                "[sec-event]\n"
                f"action={SEC_EVENT_OCCURRENCE}\n"
                "source=code_scanning\n"
                f"seen_at={utc_today()}\n"
                f"gh_alert_number={alert_number}\n"
                f"occurrence_fp={occurrence_fp}\n"
                f"commit_sha={commit_sha}\n"
                f"path={path}\n"
                f"start_line={start_line or ''}\n"
                f"end_line={end_line or ''}\n"
                "[/sec-event]",
            )


def load_open_alerts_from_file(path: str) -> tuple[str, dict[int, dict[str, Any]]]:
    """Read alerts JSON and return (repo_full, open_alerts_by_number)."""

    if not os.path.exists(path):
        raise SystemExit(f"ERROR: alerts file not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    repo_meta = data.get("repo") or {}

    repo_full = repo_meta.get("full_name")
    if not repo_full:
        raise SystemExit(f"ERROR: repo.full_name not found in {path}")

    alerts = data.get("alerts", [])
    print(f"Loaded {len(alerts)} alerts from {path} (repo={repo_full})")

    open_alerts = [a for a in alerts if str((a.get("state") or "")).lower() == "open"]
    print(f"Found {len(open_alerts)} open alerts")

    open_by_number: dict[int, dict[str, Any]] = {}
    for alert in open_alerts:
        alert_number = alert.get("alert_number")
        if alert_number is None:
            print(f"WARN: skipping alert with missing alert_number: {alert}")
            continue

        try:
            alert_number_int = int(alert_number)
        except Exception:
            print(f"WARN: skipping alert with invalid alert_number: {alert_number}")
            continue

        # stash repo on the alert for convenience
        alert["_repo"] = repo_full

        # Parse structured parameters embedded in the message string.
        alert["_message_params"] = parse_alert_message_params(alert.get("message"))
        open_by_number[alert_number_int] = alert

        if os.getenv("DEBUG_ALERTS") == "1":
            print(
                f"DEBUG: full alert payload for alert_number={alert_number_int}:\n"
                + json.dumps(alert, indent=2, sort_keys=True)
            )

    return str(repo_full), open_by_number


def sync_alerts_and_issues(
    alerts: dict[int, dict[str, Any]],
    issues: dict[int, Issue],
    *,
    dry_run: bool = False,
    dry_run_details: bool = False,
) -> None:
    """Sync open alerts into issues.

    For now this simply runs the per-alert ensure/update logic.
    """

    for alert in alerts.values():
        ensure_issue(alert, issues, dry_run=dry_run, dry_run_details=dry_run_details)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Promote alerts JSON to GitHub issues using gh CLI")
    p.add_argument(
        "--file",
        "-f",
        default="alerts.json",
        help="alerts JSON file produced by collect_alert.sh (default: alerts.json)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not create/edit/comment/label issues; only read and print intended actions",
    )
    p.add_argument(
        "--dry-run-details",
        action="store_true",
        help="In dry-run mode, print full alert payload and issue payload details",
    )
    p.add_argument(
        "--issue-label",
        default=LABEL_SCOPE_SECURITY,
        help=f"Only mine issues with this label (default: {LABEL_SCOPE_SECURITY})",
    )
    return p.parse_args()


def main() -> None:
    if shutil.which("gh") is None:
        raise SystemExit("ERROR: gh CLI is required. Install and authenticate (gh auth login).")
    args = parse_args()

    repo_full, open_alerts = load_open_alerts_from_file(args.file)
    issues = gh_issue_list_by_label(repo_full, str(args.issue_label))
    sync_alerts_and_issues(
        open_alerts,
        issues,
        dry_run=bool(args.dry_run),
        dry_run_details=bool(args.dry_run_details),
    )


if __name__ == "__main__":
    main()
