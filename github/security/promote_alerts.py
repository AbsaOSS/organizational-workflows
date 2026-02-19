#!/usr/bin/env python3
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
    `python3 promote_alerts.py --file alerts.json --issue-label scope:security --dry-run`
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
import tempfile
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


LABEL_SCOPE_SECURITY = "scope:security"
LABEL_TYPE_TECH_DEBT = "type:tech-debt"
LABEL_EPIC = "epic"
LABEL_SEC_ADEPT_TO_CLOSE = "sec:adept-to-close"
SEC_EVENT_OPEN = "open"
SEC_EVENT_REOPEN = "reopen"
SEC_EVENT_OCCURRENCE = "occurrence"

VERBOSE_ENABLED = False

# ---------------------------------------------------------------------------
# Severity → Priority mapping
# ---------------------------------------------------------------------------
# Each severity coming from the scanner (Critical, High, Medium, Low, Unknown)
# can be mapped to a user-defined priority string via --severity-priority-map.
# When no mapping is supplied the priority field is left empty (skipped).


def parse_severity_priority_map(raw: str) -> dict[str, str]:
    """Parse a comma-separated ``severity=priority`` string into a dict.

    Keys are normalised to lowercase; values are kept as-is so the user
    controls the exact priority string that ends up on issues.

    Example input:  ``"Critical=P1,High=P2,Medium=P3,Low=P4,Unknown=P3"``
    """
    mapping: dict[str, str] = {}
    for pair in (raw or "").split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        sev, pri = pair.split("=", 1)
        sev = sev.strip().lower()
        pri = pri.strip()
        if sev and pri:
            mapping[sev] = pri
    return mapping


def resolve_priority(
    severity: str,
    severity_priority_map: dict[str, str],
) -> str:
    """Return the priority for *severity*.

    Looks up *severity* (case-insensitive) in *severity_priority_map*.
    Returns the mapped value, or an empty string when no mapping exists.
    """
    return severity_priority_map.get(severity.lower(), "")


# `secmeta` is automation-owned metadata. Store it in a hidden HTML comment block
# at the top of the issue body so humans don't see it by default.
SECMETA_RE = re.compile(r"<!--\s*secmeta\r?\n(.*?)\r?\n-->", re.S)
LEGACY_SECMETA_RE = re.compile(r"```secmeta\r?\n(.*?)\r?\n```", re.S)


PARENT_BODY_TEMPLATE = """# Security Alert – {{ avd_id }}

## General Information

- **Category:** {{ category }}
- **AVD ID:** {{ avd_id }}
- **Title:** {{ title }}
- **Severity:** {{ severity }}
- **Published date:** {{ published_date }}
- **Vendor scoring:** {{ vendor_scoring }}

## Affected Package

- **Package name:** {{ package_name }}
- **Fixed version:** {{ fixed_version }}

## Classification

- **CVE:** {{ extraData.cwe }}
- **OWASP:** {{ extraData.owasp }}
- **Category:** {{ extraData.category }}

## Risk Assessment

- **Impact:** {{ extraData.impact }}  
  *(Potential impact if the vulnerability is successfully exploited)*
- **Likelihood:** {{ extraData.likelihood }}  
  *(How easily the vulnerability can be exploited in practice)*
- **Confidence:** {{ extraData.confidence }}  
  *(How confident the finding is; likelihood of false positive)*

## Recommended Remediation

{{ extraData.remediation }}

## References

{{ extraData.references }}
"""


CHILD_BODY_TEMPLATE = """## General Information

- **AVD ID:** {{ avd_id }}
- **Alert hash:** {{ alert_hash }}
- **Title:** {{ title }}

## Vulnerability Description

{{ message }}

## Location

- **Repository:** {{ repository_full_name }}
- **File:** {{ scm_file }}
- **Line:** {{ target_line }}

## Dependency Details

- **Package name:** {{ package_name }}
- **Installed version:** {{ installed_version }}
- **Fixed version:** {{ fixed_version }}
- **Reachable:** {{ reachable }}

## Detection Timeline

- **Scan date:** {{ scan_date }}
- **First seen:** {{ first_seen }}
"""


PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_\.]+)\s*\}\}")


SEC_EVENT_BLOCK_RE = re.compile(r"\[sec-event\]\s*(.*?)\s*\[/sec-event\]", re.S)


def parse_sec_event_fields(raw: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in (raw or "").splitlines():
        s = line.strip()
        if not s or "=" not in s:
            continue
        k, v = s.split("=", 1)
        fields[k.strip()] = v.strip()
    return fields


def render_sec_event(fields: dict[str, str]) -> str:
    preferred_order = [
        "action",
        "seen_at",
        "source",
        "gh_alert_number",
        "occurrence_fp",
        "commit_sha",
        "path",
        "start_line",
        "end_line",
    ]
    lines: list[str] = ["[sec-event]"]
    for k in preferred_order:
        if k in fields and str(fields.get(k, "")).strip() != "":
            lines.append(f"{k}={fields.get(k, '')}")
    for k in sorted(k for k in fields.keys() if k not in set(preferred_order)):
        v = str(fields.get(k, ""))
        if v.strip() == "":
            continue
        lines.append(f"{k}={v}")
    lines.append("[/sec-event]")
    return "\n".join(lines) + "\n"


def strip_sec_events_from_body(body: str) -> str:
    """Remove any legacy sec-event content from an issue body.

    - Drops a dedicated '## Security Events' section if present (from previous versions).
    - Removes any inline [sec-event] blocks.
    """

    text = body or ""
    # Drop everything from the header onward (the section was intended to be last).
    m = re.search(r"\n##\s+Security\s+Events\s*\n", text, flags=re.IGNORECASE)
    if m:
        text = text[: m.start()].rstrip() + "\n"
    # Remove any inline blocks.
    text = SEC_EVENT_BLOCK_RE.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"
    return text


def _get_nested_value(data: dict[str, Any], dotted_key: str) -> Any:
    cur: Any = data
    for part in (dotted_key or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur.get(part)
        else:
            return ""
    if cur is None:
        return ""
    return cur


def render_markdown_template(template: str, values: dict[str, Any]) -> str:
    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        v = _get_nested_value(values, key)
        if isinstance(v, (dict, list)):
            return json.dumps(v)
        return str(v)

    return PLACEHOLDER_RE.sub(repl, template)


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


def _parse_runner_debug() -> bool:
    raw = os.getenv("RUNNER_DEBUG")
    if raw is None or raw == "":
        return False
    if raw not in {"0", "1"}:
        raise SystemExit("ERROR: RUNNER_DEBUG must be '0' or '1' when set")
    return raw == "1"


def _set_verbose_enabled(value: bool) -> None:
    global VERBOSE_ENABLED
    VERBOSE_ENABLED = bool(value)


def vprint(msg: str) -> None:
    if VERBOSE_ENABLED:
        print(msg)


def utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


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
    parent_by_rule_id: dict[str, Issue]


@dataclass
class NotifiedIssue:
    """Tracks a new or reopened child issue for Teams notification."""
    repo: str
    issue_number: int
    severity: str
    category: str
    state: str          # "new" or "reopen"
    tool: str


SECMETA_TYPE_PARENT = "parent"
SECMETA_TYPE_CHILD = "child"


def gh_issue_get_rest_id(repo: str, number: int) -> int | None:
    res = run_gh(["api", f"repos/{repo}/issues/{number}", "--jq", ".id"])
    if res.returncode != 0:
        print(f"WARN: Failed to fetch REST issue id for #{number}: {res.stderr}", file=sys.stderr)
        return None
    try:
        return int((res.stdout or "").strip())
    except Exception:
        print(f"WARN: Failed to parse REST issue id for #{number}: {res.stdout!r}", file=sys.stderr)
        return None


def gh_issue_add_sub_issue(repo: str, parent_number: int, sub_issue_id: int) -> bool:
    # NOTE: sub_issue_id must be an integer (REST issue id), not an issue number.
    res = run_gh(
        [
            "api",
            "--method",
            "POST",
            f"repos/{repo}/issues/{parent_number}/sub_issues",
            "-F",
            f"sub_issue_id={int(sub_issue_id)}",
        ]
    )
    if res.returncode != 0:
        print(
            f"WARN: Failed to add sub-issue link parent=#{parent_number} sub_issue_id={sub_issue_id}: {res.stderr}",
            file=sys.stderr,
        )
        return False
    return True


def gh_issue_add_sub_issue_by_number(repo: str, parent_number: int, child_number: int) -> bool:
    child_id = gh_issue_get_rest_id(repo, child_number)
    if child_id is None:
        return False
    return gh_issue_add_sub_issue(repo, parent_number, child_id)


# ---------------------------------------------------------------------------
# GitHub Projects V2 – set Priority field via GraphQL
# ---------------------------------------------------------------------------
# The "Priority" value is a single-select field on a GitHub Project (V2).
# To set it we need:
#   1. The project's GraphQL node-id           → gh_project_get_id()
#   2. The field id + option ids for "Priority" → gh_project_get_priority_field()
#   3. Add the issue to the project             → gh_project_add_item()
#   4. Set the field value                      → gh_project_set_priority()
#
# All calls go through `gh api graphql`.

@dataclass
class ProjectPriorityField:
    """Caches the IDs required to set a single-select "Priority" field."""
    project_id: str
    field_id: str
    options: dict[str, str]   # option name (lowercase) → option node-id


_project_priority_cache: dict[str, ProjectPriorityField | None] = {}


def _run_graphql(query: str, variables: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Execute a GraphQL query via ``gh api graphql`` and return parsed JSON."""
    args = ["api", "graphql", "-f", f"query={query}"]
    for k, v in (variables or {}).items():
        args += ["-F", f"{k}={v}"]
    res = run_gh(args)
    if res.returncode != 0:
        vprint(f"WARN: GraphQL call failed: {res.stderr}")
        return None
    try:
        return json.loads(res.stdout)
    except Exception:
        vprint(f"WARN: Could not parse GraphQL response: {res.stdout!r}")
        return None


def gh_project_get_priority_field(
    org: str,
    project_number: int,
    field_name: str = "Priority",
) -> ProjectPriorityField | None:
    """Fetch the project node-id and the Priority single-select field metadata.

    Results are cached per ``(org, project_number)`` so repeated calls are free.
    """
    cache_key = f"{org}/{project_number}"
    if cache_key in _project_priority_cache:
        return _project_priority_cache[cache_key]

    query = """
    query($org: String!, $num: Int!) {
      organization(login: $org) {
        projectV2(number: $num) {
          id
          fields(first: 50) {
            nodes {
              ... on ProjectV2SingleSelectField {
                id
                name
                options { id name }
              }
            }
          }
        }
      }
    }
    """
    data = _run_graphql(query, {"org": org, "num": project_number})
    if data is None:
        _project_priority_cache[cache_key] = None
        return None

    project = (data.get("data") or {}).get("organization", {}).get("projectV2")
    if project is None:
        vprint(f"WARN: Project #{project_number} not found in org {org}")
        _project_priority_cache[cache_key] = None
        return None

    project_id = project["id"]
    for node in project.get("fields", {}).get("nodes", []):
        if not isinstance(node, dict):
            continue
        if node.get("name") == field_name and "options" in node:
            options = {
                opt["name"].lower(): opt["id"]
                for opt in node["options"]
            }
            result = ProjectPriorityField(
                project_id=project_id,
                field_id=node["id"],
                options=options,
            )
            _project_priority_cache[cache_key] = result
            vprint(
                f"Project #{project_number}: field '{field_name}' id={node['id']} "
                f"options={list(options.keys())}"
            )
            return result

    vprint(f"WARN: No single-select field named '{field_name}' in project #{project_number}")
    _project_priority_cache[cache_key] = None
    return None


def gh_project_add_item(project_id: str, issue_node_id: str) -> str | None:
    """Add an issue/PR to a project. Returns the project-item node-id."""
    query = """
    mutation($projectId: ID!, $contentId: ID!) {
      addProjectV2ItemById(input: {projectId: $projectId, contentId: $contentId}) {
        item { id }
      }
    }
    """
    data = _run_graphql(query, {"projectId": project_id, "contentId": issue_node_id})
    if data is None:
        return None
    item = ((data.get("data") or {}).get("addProjectV2ItemById") or {}).get("item")
    return item["id"] if item else None


def gh_issue_get_node_id(repo: str, issue_number: int) -> str | None:
    """Get the GraphQL node-id for a repo issue (required by Projects V2 mutations)."""
    res = run_gh(["api", f"repos/{repo}/issues/{issue_number}", "--jq", ".node_id"])
    if res.returncode != 0:
        vprint(f"WARN: Failed to fetch node_id for #{issue_number}: {res.stderr}")
        return None
    node_id = (res.stdout or "").strip()
    return node_id if node_id else None


def gh_project_set_field_value(
    project_id: str,
    item_id: str,
    field_id: str,
    option_id: str,
) -> bool:
    """Set a single-select field value on a project item."""
    query = """
    mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
      updateProjectV2ItemFieldValue(input: {
        projectId: $projectId
        itemId: $itemId
        fieldId: $fieldId
        value: { singleSelectOptionId: $optionId }
      }) {
        projectV2Item { id }
      }
    }
    """
    data = _run_graphql(query, {
        "projectId": project_id,
        "itemId": item_id,
        "fieldId": field_id,
        "optionId": option_id,
    })
    return data is not None and "errors" not in data


def set_issue_priority_on_project(
    repo: str,
    issue_number: int,
    severity: str,
    severity_priority_map: dict[str, str],
    project_number: int,
    *,
    project_org: str = "",
    dry_run: bool = False,
) -> None:
    """Resolve severity → priority and set the value on the GitHub Project field.

    Does nothing when:
    - ``project_number`` is not provided (0 / None)
    - ``severity_priority_map`` has no entry for this severity
    - The project's Priority field has no matching option
    """
    if not project_number:
        return

    priority_value = resolve_priority(severity, severity_priority_map)
    if not priority_value:
        vprint(f"  No priority mapping for severity={severity!r} – skipping project field")
        return

    org = project_org or (repo.split("/", 1)[0] if "/" in repo else "")
    if not org:
        vprint("WARN: Cannot determine org from repo or --project-org – skipping project priority")
        return

    pf = gh_project_get_priority_field(org, project_number)
    if pf is None:
        vprint(f"WARN: Could not load project #{project_number} metadata – skipping project priority")
        return

    option_id = pf.options.get(priority_value.lower())
    if option_id is None:
        print(
            f"WARN: Priority value {priority_value!r} (from severity={severity!r}) "
            f"does not match any option in project #{project_number}. "
            f"Available options: {list(pf.options.keys())}",
            file=sys.stderr,
        )
        return

    if dry_run:
        print(
            f"DRY-RUN: would set Priority={priority_value!r} on issue #{issue_number} "
            f"in project #{project_number}"
        )
        return

    node_id = gh_issue_get_node_id(repo, issue_number)
    if node_id is None:
        vprint(f"WARN: Could not fetch node_id for issue #{issue_number} – skipping project priority")
        return

    item_id = gh_project_add_item(pf.project_id, node_id)
    if item_id is None:
        vprint(f"WARN: Could not add issue #{issue_number} to project #{project_number}")
        return

    ok = gh_project_set_field_value(pf.project_id, item_id, pf.field_id, option_id)
    if ok:
        print(f"Set Priority={priority_value!r} on issue #{issue_number} in project #{project_number}")
    else:
        print(
            f"WARN: Failed to set Priority={priority_value!r} on issue #{issue_number}",
            file=sys.stderr,
        )


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
    desired = (state or "").strip().lower()
    if desired not in {"open", "closed"}:
        raise ValueError(f"Unsupported issue state: {state!r}")

    # Preferred (newer gh): `gh issue edit --state open|closed`
    res = run_gh(["issue", "edit", str(number), "--repo", repo, "--state", desired])
    if res.returncode == 0:
        return True

    stderr = (res.stderr or "") + (res.stdout or "")
    if "unknown flag: --state" not in stderr:
        print(f"Failed to edit state for #{number}: {res.stderr}", file=sys.stderr)
        return False

    # Fallback for older gh versions that don't support `issue edit --state`.
    if desired == "open":
        res2 = run_gh(["issue", "reopen", str(number), "--repo", repo])
    else:
        res2 = run_gh(["issue", "close", str(number), "--repo", repo])
    if res2.returncode == 0:
        return True

    # Last resort: REST API.
    res3 = run_gh(["api", "--method", "PATCH", f"repos/{repo}/issues/{number}", "-f", f"state={desired}"])
    if res3.returncode != 0:
        print(
            f"Failed to edit state for #{number}: {res2.stderr or res2.stdout or res.stderr}",
            file=sys.stderr,
        )
        return False
    return True


def gh_issue_edit_body(repo: str, number: int, body: str) -> bool:
    res = run_gh(["issue", "edit", str(number), "--repo", repo, "--body", body])
    if res.returncode != 0:
        print(f"Failed to edit body for #{number}: {res.stderr}", file=sys.stderr)
        return False
    print(f"Updated issue #{number} body")
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
    body = issue_body or ""
    match = SECMETA_RE.search(body)
    if match:
        return parse_kv_block(match.group(1))
    # Back-compat for older issues created with a visible fenced block.
    legacy = LEGACY_SECMETA_RE.search(body)
    if legacy:
        return parse_kv_block(legacy.group(1))
    return {}


def render_secmeta(secmeta: dict[str, str]) -> str:
    preferred_order = [
        "schema",
        "fingerprint",
        "repo",
        "source",
        "tool",
        "severity",
        "cwe",
        "category",
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
    # Hidden metadata block for automation.
    return "<!--secmeta\n" + "\n".join(lines) + "\n-->"


def upsert_secmeta(issue_body: str, secmeta: dict[str, str]) -> str:
    new_block = render_secmeta(secmeta)
    body = issue_body or ""
    if SECMETA_RE.search(body):
        return SECMETA_RE.sub(new_block, body, count=1)
    # Migrate legacy fenced metadata into hidden block.
    if LEGACY_SECMETA_RE.search(body):
        return LEGACY_SECMETA_RE.sub(new_block, body, count=1)
    # Prepend if absent.
    if body.strip():
        return new_block + "\n\n" + body.strip() + "\n"
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


def build_parent_issue_title(rule_id: str) -> str:
    return f"Security Alert – {rule_id}".strip()


def _alert_extra_data(alert: dict[str, Any]) -> dict[str, Any]:
    extra = alert.get("extraData")
    if isinstance(extra, dict):
        return extra
    return {}


def _alert_value(alert: dict[str, Any], *keys: str) -> str:
    for k in keys:
        if not k:
            continue
        v = alert.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def build_parent_issue_body(
    alert: dict[str, Any],
) -> str:
    rule_id = str(alert.get("rule_id") or "").strip()
    tool = str(alert.get("tool") or "").strip()
    severity = str((alert.get("severity") or "unknown")).lower()
    repo_full = str(alert.get("_repo") or "").strip()

    avd_id = _alert_value(alert, "avd_id", "rule_id") or rule_id
    title = _alert_value(alert, "title", "rule_name", "rule_id") or rule_id
    category = _alert_value(alert, "category")
    published_date = _alert_value(alert, "published_date", "publishedDate", "created_at")
    vendor_scoring = _alert_value(alert, "vendor_scoring", "vendorScoring")
    package_name = _alert_value(alert, "package_name", "packageName")
    fixed_version = _alert_value(alert, "fixed_version", "fixedVersion")

    extra = _alert_extra_data(alert)

    secmeta: dict[str, str] = {
        "schema": "1",
        "type": SECMETA_TYPE_PARENT,
        "repo": repo_full,
        "source": "code_scanning",
        "tool": tool,
        "severity": severity,
        "rule_id": rule_id,
        "first_seen": iso_date(alert.get("created_at")),
        "last_seen": iso_date(alert.get("updated_at")),
        "postponed_until": "",
    }

    values: dict[str, Any] = {
        "category": category,
        "avd_id": avd_id,
        "title": title,
        "severity": severity,
        "published_date": iso_date(published_date),
        "vendor_scoring": vendor_scoring,
        "package_name": package_name,
        "fixed_version": fixed_version,
        "extraData": extra,
    }

    human_body = render_markdown_template(PARENT_BODY_TEMPLATE, values).strip() + "\n"
    return render_secmeta(secmeta) + "\n\n" + human_body


def ensure_parent_issue(
    alert: dict[str, Any],
    issues: dict[int, Issue],
    index: IssueIndex,
    *,
    dry_run: bool,
    severity_priority_map: dict[str, str] | None = None,
    project_number: int | None = None,
    project_org: str = "",
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
            {
                "category": _alert_value(alert, "category"),
                "avd_id": _alert_value(alert, "avd_id", "rule_id") or rule_id,
                "title": _alert_value(alert, "title", "rule_name", "rule_id") or rule_id,
                "severity": _severity,
                "published_date": iso_date(_alert_value(alert, "published_date", "publishedDate", "created_at")),
                "vendor_scoring": _alert_value(alert, "vendor_scoring", "vendorScoring"),
                "package_name": _alert_value(alert, "package_name", "packageName"),
                "fixed_version": _alert_value(alert, "fixed_version", "fixedVersion"),
                "extraData": _alert_extra_data(alert),
            },
        ).strip() + "\n"
        rebuilt = strip_sec_events_from_body(rebuilt)

        if rebuilt != (existing.body or ""):
            if dry_run:
                print(f"DRY-RUN: would update parent issue #{existing.number} body to template (rule_id={rule_id})")
                if VERBOSE_ENABLED:
                    print("DRY-RUN: body_preview_begin")
                    print(rebuilt)
                    print("DRY-RUN: body_preview_end")
            else:
                gh_issue_edit_body(repo_full, existing.number, rebuilt)
                existing.body = rebuilt

        return existing

    title = build_parent_issue_title(rule_id)
    body = build_parent_issue_body(alert)
    labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT, LABEL_EPIC]
    if dry_run:
        print(f"DRY-RUN: create parent rule_id={rule_id} title={title!r} labels={labels}")
        if VERBOSE_ENABLED:
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

    # Set Priority on the GitHub Project.
    set_issue_priority_on_project(
        repo_full, num, str((alert.get("severity") or "unknown")).lower(),
        severity_priority_map or {}, project_number or 0,
        project_org=project_org, dry_run=dry_run,
    )

    return created


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


def build_child_issue_body(
    alert: dict[str, Any],
) -> str:
    repo_full = str(alert.get("_repo") or "").strip()
    avd_id = _alert_value(alert, "avd_id", "rule_id")
    title = _alert_value(alert, "title", "rule_name", "rule_id")
    scm_file = _alert_value(alert, "file", "scm_file")
    target_line = _alert_value(alert, "target_line")
    if not target_line:
        target_line = _alert_value(alert, "start_line")

    package_name = _alert_value(alert, "package_name", "packageName")
    installed_version = _alert_value(alert, "installed_version", "installedVersion")
    fixed_version = _alert_value(alert, "fixed_version", "fixedVersion")
    reachable = _alert_value(alert, "reachable")

    scan_date = _alert_value(alert, "scan_date", "scanDate", "updated_at")
    first_seen = _alert_value(alert, "first_seen", "created_at")

    msg_params = alert.get("_message_params")
    alert_hash = ""
    if isinstance(msg_params, dict):
        alert_hash = str(msg_params.get(AlertMessageKey.ALERT_HASH.value) or "").strip()
    message = _alert_value(alert, "message")

    values: dict[str, Any] = {
        "avd_id": avd_id,
        "alert_hash": alert_hash,
        "title": title,
        "message": message,
        "repository_full_name": repo_full,
        "scm_file": scm_file,
        "target_line": target_line,
        "package_name": package_name,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "reachable": reachable,
        "scan_date": iso_date(scan_date),
        "first_seen": iso_date(first_seen),
    }
    return render_markdown_template(CHILD_BODY_TEMPLATE, values).strip() + "\n"


def _classify_category(alert: dict[str, Any]) -> str:
    """Derive a category from ``rule_name`` (left side of ``category/name``)."""
    return str(alert.get("rule_name") or "").strip()

def ensure_issue(
    alert: dict[str, Any],
    issues: dict[int, Issue],
    index: IssueIndex,
    *,
    dry_run: bool = False,
    notifications: list[NotifiedIssue] | None = None,
    severity_priority_map: dict[str, str] | None = None,
    project_number: int | None = None,
    project_org: str = "",
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

    canonical_fp = fingerprint

    occurrence_fp = compute_occurrence_fp(commit_sha, path, start_line, end_line)

    repo_full = alert["_repo"]
    first_seen = iso_date(alert.get("created_at"))
    last_seen = iso_date(alert.get("updated_at"))

    _spm = severity_priority_map or {}

    parent_issue = ensure_parent_issue(
        alert, issues, index, dry_run=dry_run,
        severity_priority_map=_spm, project_number=project_number,
        project_org=project_org,
    )
    matched = find_issue_in_index(
        index,
        fingerprint=fingerprint,
    )

    if matched is None:
        category = _classify_category(alert)
        secmeta: dict[str, str] = {
            "schema": "1",
            "type": SECMETA_TYPE_CHILD,
            "fingerprint": canonical_fp,
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

        title = build_issue_title(rule_name, rule_id, canonical_fp)
        if dry_run:
            labels = [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT]

            loc = f"{path}:{start_line or ''}".rstrip(":")
            commit_short = commit_sha[:8] if commit_sha else ""
            print(
                "DRY-RUN: create child "
                f"alert={alert_number} rule_id={rule_id} sev={severity} fp={canonical_fp[:8]} tool={tool} "
                f"commit={commit_short} loc={loc} title={title!r} labels=[{','.join(labels)}] "
                f"| secmeta:first_seen={first_seen} last_seen={last_seen} occurrence_count=1 gh_alert_numbers=[{alert_number}]"
            )
            if parent_issue is None and rule_id:
                print(f"DRY-RUN: add sub-issue link parent_rule_id={rule_id} child=(new) alert={alert_number}")
            elif parent_issue is not None:
                print(
                    f"DRY-RUN: add sub-issue link parent=#{parent_issue.number} child=(new) alert={alert_number}"
                )
            if VERBOSE_ENABLED:
                print("DRY-RUN: body_preview_begin")
                print(body)
                print("DRY-RUN: body_preview_end")
            if notifications is not None:
                notifications.append(NotifiedIssue(
                    repo=repo_full, issue_number=0,
                    severity=severity, category=category,
                    state="new", tool=tool,
                ))
            # show what project priority would be set.
            set_issue_priority_on_project(
                repo_full, 0, severity, _spm, project_number or 0,
                project_org=project_org, dry_run=True,
            )
            return

        num = gh_issue_create(repo_full, title, body, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])
        if num is not None:
            print(f"Created issue #{num} for alert {alert_number} (fp={canonical_fp[:8]})")

            created = Issue(number=num, state="open", title=title, body=body)
            issues[num] = created
            index.by_fingerprint[canonical_fp] = created

            if notifications is not None:
                notifications.append(NotifiedIssue(
                    repo=repo_full, issue_number=num,
                    severity=severity, category=category,
                    state="new", tool=tool,
                ))

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

            # Each security event is recorded as a new comment (human visible).
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

            # Set Priority on the GitHub Project.
            set_issue_priority_on_project(
                repo_full, num, severity, _spm, project_number or 0,
                project_org=project_org, dry_run=dry_run,
            )
        return

    issue = matched

    if parent_issue is None and rule_id:
        # Try to find a parent if it already exists (e.g., created earlier).
        parent_issue = find_parent_issue(index, rule_id=rule_id)

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

    if reopened:
        maybe_reopen_parent_issue(
            repo_full,
            parent_issue,
            rule_id=rule_id,
            dry_run=dry_run,
            context="reopen_child",
            child_issue_number=issue.number,
        )
        if notifications is not None:
            existing_secmeta = load_secmeta(issue.body)
            reopen_category = (existing_secmeta.get("category") or "").strip() or _classify_category(alert)
            notifications.append(NotifiedIssue(
                repo=repo_full, issue_number=issue.number,
                severity=severity, category=reopen_category,
                state="reopen", tool=tool,
            ))

        # Re-apply Priority on the GitHub Project after reopen.
        set_issue_priority_on_project(
            repo_full, issue.number, severity, _spm, project_number or 0,
            project_org=project_org, dry_run=dry_run,
        )

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
            "category": _classify_category(alert) or secmeta.get("category", ""),
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

    # Rewrite body to match templates (human-first) while keeping hidden secmeta and events.
    human_body = build_child_issue_body(alert)
    new_body = render_secmeta(secmeta) + "\n\n" + human_body
    new_body = strip_sec_events_from_body(new_body)

    # Each security event is recorded as a new comment (human visible).
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
            if VERBOSE_ENABLED:
                print("DRY-RUN: body_preview_begin")
                print(new_body)
                print("DRY-RUN: body_preview_end")
        else:
            gh_issue_edit_body(repo_full, issue.number, new_body)
            issue.body = new_body

    # Ensure baseline labels.
    if dry_run:
        print(
            f"DRY-RUN: would ensure labels on issue #{issue.number}: "
            f"[{LABEL_SCOPE_SECURITY}, {LABEL_TYPE_TECH_DEBT}]"
        )
    else:
        gh_issue_add_labels(repo_full, issue.number, [LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT])

    # Ensure Priority on the GitHub Project (idempotent – always sync).
    set_issue_priority_on_project(
        repo_full, issue.number, severity, _spm, project_number or 0,
        project_org=project_org, dry_run=dry_run,
    )

    # (dry-run logging handled above for comments)


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
    for alert in alerts.values():
        ensure_issue(
            alert, issues, index,
            dry_run=dry_run, notifications=notifications,
            severity_priority_map=severity_priority_map,
            project_number=project_number,
            project_org=project_org,
        )

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


# ---------------------------------------------------------------------------
# Teams notification
# ---------------------------------------------------------------------------

def build_teams_notification_body(notifications: list[NotifiedIssue]) -> str:
    """Build a Markdown body summarising new / reopened issues for Teams."""
    new_issues = [n for n in notifications if n.state == "new"]
    reopened_issues = [n for n in notifications if n.state == "reopen"]

    lines: list[str] = []
    lines.append(f"**{len(new_issues)}** new, **{len(reopened_issues)}** reopened\n")

    for n in notifications:
        state_tag = "new" if n.state == "new" else "reopen"
        link = f"https://github.com/{n.repo}/issues/{n.issue_number}"
        issue_ref = f"[Issue #{n.issue_number}]({link})" if n.issue_number else "(pending)"
        lines.append(f"- **[{state_tag}]** *{n.severity}* - {n.category} - {issue_ref} ({n.repo})\n")

    return "\n".join(lines)


def notify_teams(
    webhook_url: str,
    notifications: list[NotifiedIssue],
    *,
    dry_run: bool = False,
) -> None:
    """Send a Teams message about new / reopened issues via send_to_teams.py."""
    if not notifications:
        print("No new or reopened issues – skipping Teams notification")
        return

    if dry_run:
        if webhook_url:
            print("DRY-RUN: Teams webhook configured; no delivery will occur")
        else:
            print(
                "DRY-RUN: no Teams Incoming Webhook URL configured (TEAMS_WEBHOOK_URL/--teams-webhook-url). "
                "No post to Teams will be made."
            )

    body = build_teams_notification_body(notifications)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    send_script = os.path.join(script_dir, "send_to_teams.py")

    if not os.path.exists(send_script):
        print(
            f"WARN: send_to_teams.py not found at {send_script} – skipping Teams notification",
            file=sys.stderr,
        )
        return

    tmp: tempfile.NamedTemporaryFile[str] | None = None
    try:
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="teams_notification_",
            suffix=".md",
            delete=False,
        )
        tmp.write(body)
        tmp.flush()
        body_file = tmp.name

        cmd = [
            sys.executable, send_script,
            "--body-file", body_file,
            "--title", "Aquasec - New/Reopened Security Issues",
        ]
        if dry_run:
            cmd.append("--dry-run")
        else:
            cmd.extend(["--webhook-url", webhook_url])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"WARN: Teams notification failed: {result.stderr}", file=sys.stderr)
        else:
            if dry_run:
                print("DRY-RUN: send_to_teams.py output:")
                print(result.stdout)
            else:
                print("Teams notification sent successfully")
    finally:
        try:
            os.remove(body_file)
        except OSError:
            pass


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
        "--verbose",
        action="store_true",
        help="Enable verbose logs (also enabled when RUNNER_DEBUG=1)",
    )
    p.add_argument(
        "--issue-label",
        default=LABEL_SCOPE_SECURITY,
        help=f"Only mine issues with this label (default: {LABEL_SCOPE_SECURITY})",
    )
    p.add_argument(
        "--severity-priority-map",
        default=os.environ.get("SEVERITY_PRIORITY_MAP", ""),
        help="Comma-separated severity=priority pairs that define which priority string "
             "to assign for each alert severity. Severities: Critical, High, Medium, Low, Unknown. "
             "Example: 'Critical=Blocker,High=Urgent,Medium=Normal,Low=Minor,Unknown=Normal'. "
             "Only listed severities get a priority; unlisted ones are left empty. "
             "When not set at all, priority is skipped for every severity. "
             "Priority values must match the option names of the Priority single-select field "
             "in the target GitHub Project. "
             "Default: $SEVERITY_PRIORITY_MAP env var.",
    )
    p.add_argument(
        "--project-number",
        type=int,
        default=int(os.environ.get("PROJECT_NUMBER", "0")) or None,
        help="GitHub Projects V2 number (org-level) where a Priority single-select field "
             "will be set for each promoted issue.  Required together with --severity-priority-map. "
             "When omitted, project-level priority is skipped. "
             "Default: $PROJECT_NUMBER env var.",
    )
    p.add_argument(
        "--project-org",
        default=os.environ.get("PROJECT_ORG", ""),
        help="GitHub organisation that owns the Projects V2 board.  "
             "Use this when the project lives in a different org than the scanned repo. "
             "When omitted, the org is derived from the repo name. "
             "Default: $PROJECT_ORG env var.",
    )
    p.add_argument(
        "--teams-webhook-url",
        default=os.environ.get("TEAMS_WEBHOOK_URL"),
        help="Teams Incoming Webhook URL for new/reopened issue alerts (default: $TEAMS_WEBHOOK_URL). "
             "If not set, Teams notification is skipped.",
    )
    return p.parse_args()


def main() -> None:
    if shutil.which("gh") is None:
        raise SystemExit("ERROR: gh CLI is required. Install and authenticate (gh auth login).")
    args = parse_args()

    _set_verbose_enabled(bool(args.verbose) or _parse_runner_debug())

    repo_full, open_alerts = load_open_alerts_from_file(args.file)
    issues = gh_issue_list_by_label(repo_full, str(args.issue_label))

    # Build severity → priority map from user input; empty by default (priority skipped).
    spm = parse_severity_priority_map(str(args.severity_priority_map or ""))

    notifications = sync_alerts_and_issues(
        open_alerts,
        issues,
        dry_run=bool(args.dry_run),
        severity_priority_map=spm,
        project_number=args.project_number,
        project_org=str(args.project_org or ""),
    )

    webhook_url = args.teams_webhook_url
    if bool(args.dry_run):
        # Still generate the payload for visibility.
        notify_teams(webhook_url or "", notifications, dry_run=True)
    else:
        if webhook_url:
            notify_teams(webhook_url, notifications, dry_run=False)
        elif notifications:
            vprint("Teams webhook URL not configured – skipping notification")


if __name__ == "__main__":
    main()
