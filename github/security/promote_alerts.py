#!/usr/bin/env python3
"""Promote collected Code Scanning alerts JSON into GitHub Issues.

Input:
- JSON produced by `collect_alert.sh` (default: alerts.json)

Design intent:
- One Issue per *finding* (stable identity), not per GitHub alert.
- Match Issues in this order: logical_fp → fast_fp → gh alert number (migration fallback).
- Store identifiers + lifecycle metadata in a single `secmeta` block in the Issue body.
- Add structured `[sec-event]` comments only for meaningful lifecycle changes (reopen, new occurrence).

Requirements:
- `gh` CLI (authenticated; uses GH_TOKEN in CI)
- `git` available + repository checkout if you want snippet-based fingerprints

Draft / debug (no writes):
- Run in dry-run mode to compute fingerprints and show intended actions without creating/editing Issues:
    `python3 promote_alerts.py --file alerts.json --dry-run`
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
from dataclasses import dataclass
from datetime import datetime
from typing import Any


LABEL_SOURCE = "sec:src/aquasec-sarif"
SEC_EVENT_OPEN = "open"
SEC_EVENT_REOPEN = "reopen"
SEC_EVENT_OCCURRENCE = "occurrence"

SECMETA_RE = re.compile(r"```secmeta\n(.*?)\n```", re.S)


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


def normalize_snippet(text: str) -> str:
    lines: list[str] = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s:
            continue
        s = re.sub(r"\s+", " ", s)
        lines.append(s)
    return "\n".join(lines)


def run_cmd(cmd: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=capture_output, text=True)


def run_gh(args: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess:
    cmd = ["gh"] + args
    try:
        return run_cmd(cmd, capture_output=capture_output)
    except FileNotFoundError:
        print("ERROR: gh CLI not found. Install and authenticate gh.", file=sys.stderr)
        raise SystemExit(1)


def run_git(args: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git"] + args
    try:
        return run_cmd(cmd, capture_output=capture_output)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", "git not found")


@dataclass
class IssueRef:
    number: int
    state: str


@dataclass
class Issue:
    number: int
    state: str
    title: str
    body: str


def gh_issue_list_first(repo: str, search: str) -> IssueRef | None:
    res = run_gh(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--search",
            search,
            "--state",
            "all",
            "--json",
            "number,state",
            "--limit",
            "1",
        ]
    )
    if res.returncode != 0:
        print(f"gh issue list failed: {res.stderr}", file=sys.stderr)
        return None
    try:
        items = json.loads(res.stdout or "[]")
    except Exception:
        return None
    if not items:
        return None
    num = items[0].get("number")
    state = items[0].get("state")
    if not isinstance(num, int):
        return None
    return IssueRef(number=num, state=state or "")


def gh_issue_view(repo: str, number: int) -> Issue | None:
    res = run_gh(
        [
            "issue",
            "view",
            str(number),
            "--repo",
            repo,
            "--json",
            "number,state,title,body",
        ]
    )
    if res.returncode != 0:
        print(f"gh issue view failed for #{number}: {res.stderr}", file=sys.stderr)
        return None
    try:
        obj = json.loads(res.stdout)
    except Exception:
        return None
    return Issue(
        number=int(obj.get("number")),
        state=str(obj.get("state") or ""),
        title=str(obj.get("title") or ""),
        body=str(obj.get("body") or ""),
    )


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
        "logical_fp",
        "fast_fp",
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


def compute_fast_fp(tool: str, rule_id: str, path: str, start_line: int | None) -> str:
    return sha256_hex(f"{tool}|{rule_id}|{path}|{start_line or ''}")


def git_file_at_commit(commit_sha: str, path: str) -> str | None:
    if not commit_sha or not path:
        return None
    if shutil.which("git") is None:
        return None
    in_repo = run_git(["rev-parse", "--is-inside-work-tree"])
    if in_repo.returncode != 0:
        return None

    res = run_git(["show", f"{commit_sha}:{path}"])
    if res.returncode == 0:
        return res.stdout
    res2 = run_git(["show", f"{commit_sha}:./{path}"])
    if res2.returncode == 0:
        return res2.stdout
    return None


def compute_logical_fp(tool: str, rule_id: str, commit_sha: str, path: str, start_line: int | None, end_line: int | None) -> str | None:
    file_text = git_file_at_commit(commit_sha, path)
    if file_text is None:
        return None

    lines = file_text.splitlines()
    if not lines:
        return None

    if not start_line:
        start_line = 1
    if not end_line:
        end_line = start_line

    start = max(1, start_line - 3)
    end = min(len(lines), end_line + 3)
    snippet = "\n".join(lines[start - 1 : end])
    snippet_norm = normalize_snippet(snippet)
    if not snippet_norm:
        return None

    snippet_hash = sha256_hex(snippet_norm)
    return sha256_hex(f"{tool}|{rule_id}|{snippet_hash}")


def compute_occurrence_fp(commit_sha: str, path: str, start_line: int | None, end_line: int | None) -> str:
    return sha256_hex(f"{commit_sha}|{path}|{start_line or ''}|{end_line or ''}")


def find_issue(repo: str, *, alert_number: int, logical_fp: str | None, fast_fp: str | None) -> IssueRef | None:
    if logical_fp:
        found = gh_issue_list_first(repo, f"logical_fp={logical_fp} in:body")
        if found:
            return found
    if fast_fp:
        found = gh_issue_list_first(repo, f"fast_fp={fast_fp} in:body")
        if found:
            return found
    # migration fallback: old issues used alert token in title
    return gh_issue_list_first(repo, f"[SEC][ALERT={alert_number}] in:title")


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


def ensure_issue(repo: str, alert: dict[str, Any], *, dry_run: bool = False) -> None:
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

    fast_fp = compute_fast_fp(tool, rule_id, path, start_line)
    logical_fp = compute_logical_fp(tool, rule_id, commit_sha, path, start_line, end_line)
    canonical_fp = logical_fp or fast_fp

    occurrence_fp = compute_occurrence_fp(commit_sha, path, start_line, end_line)

    repo_full = alert["_repo"]
    first_seen = iso_date(alert.get("created_at"))
    last_seen = iso_date(alert.get("updated_at"))

    ref = find_issue(repo_full, alert_number=alert_number, logical_fp=logical_fp, fast_fp=fast_fp)
    if ref is None:
        secmeta: dict[str, str] = {
            "schema": "1",
            "fingerprint": canonical_fp,
            "logical_fp": logical_fp or "",
            "fast_fp": fast_fp,
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
            print(
                "DRY-RUN: would create issue for alert "
                f"{alert_number} (fp={canonical_fp[:8]}) "
                f"labels=[{LABEL_SOURCE}, sec:sev/{severity}] title={title!r}"
            )
            return

        num = gh_issue_create(repo_full, title, body, [LABEL_SOURCE, f"sec:sev/{severity}"])
        if num is not None:
            print(f"Created issue #{num} for alert {alert_number} (fp={canonical_fp[:8]})")
        return

    issue = gh_issue_view(repo_full, ref.number)
    if issue is None:
        return

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
            "logical_fp": logical_fp or secmeta.get("logical_fp", "") or "",
            "fast_fp": fast_fp,
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
        else:
            gh_issue_edit_body(repo_full, issue.number, new_body)

    # Ensure baseline labels.
    if dry_run:
        print(f"DRY-RUN: would ensure labels on issue #{issue.number}: [{LABEL_SOURCE}, sec:sev/{severity}]")
    else:
        gh_issue_add_labels(repo_full, issue.number, [LABEL_SOURCE, f"sec:sev/{severity}"])

    if reopened:
        if dry_run:
            print(f"DRY-RUN: would comment reopen event on issue #{issue.number} (alert {alert_number})")
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


def promote_from_file(path: str, *, dry_run: bool = False) -> None:
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
    print(f"Promoting {len(open_alerts)} open alerts")

    for alert in open_alerts:
        alert_number = alert.get("alert_number")
        if alert_number is None:
            continue
        # stash repo on the alert for convenience
        alert["_repo"] = repo_full
        ensure_issue(repo_full, alert, dry_run=dry_run)


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
    return p.parse_args()


def main() -> None:
    if shutil.which("gh") is None:
        raise SystemExit("ERROR: gh CLI is required. Install and authenticate (gh auth login).")
    args = parse_args()
    promote_from_file(args.file, dry_run=bool(args.dry_run))


if __name__ == "__main__":
    main()
