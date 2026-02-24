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

"""GitHub Issues REST / CLI operations – all CRUD operations on issues
via the ``gh`` CLI: create, edit state/body, comment, add labels,
sub-issue linking, list-by-label, and node-id lookup.
"""

import json
import re
import sys

from .common import run_gh
from .models import Issue


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


def gh_issue_list_by_label(repo: str, label: str) -> dict[int, Issue]:
    """Load issues with a given label.

    This is used to pre-mine issue data so matching can happen locally without
    repeatedly calling ``gh issue list`` for every alert.
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
            "number,state,title,body,labels",
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
        raw_labels = obj.get("labels") or []
        label_names = [
            str(lbl.get("name") or lbl) if isinstance(lbl, dict) else str(lbl)
            for lbl in raw_labels
        ]
        issues[number] = Issue(
            number=number,
            state=str(obj.get("state") or ""),
            title=str(obj.get("title") or ""),
            body=str(obj.get("body") or ""),
            labels=label_names,
        )

    print(f"Loaded {len(issues)} issues with label {label!r} from repository {repo}")
    return issues


def gh_issue_edit_state(repo: str, number: int, state: str) -> bool:
    desired = (state or "").strip().lower()
    if desired not in {"open", "closed"}:
        raise ValueError(f"Unsupported issue state: {state!r}")

    # Newer gh: `gh issue edit --state open|closed`
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


def gh_issue_edit_title(repo: str, number: int, title: str) -> bool:
    res = run_gh(["issue", "edit", str(number), "--repo", repo, "--title", title])

    if res.returncode != 0:
        print(f"Failed to edit title for #{number}: {res.stderr}", file=sys.stderr)
        return False

    print(f"Updated issue #{number} title")
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
