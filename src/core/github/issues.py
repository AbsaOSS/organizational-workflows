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
import logging
import re
import subprocess
import time

from .client import run_gh
from ..models import Issue

_NOT_FOUND_MARKERS = (
    "HTTP 404",
    "Not Found",
    "Could not resolve to an issue or pull request",
)


def _is_not_found_error(res: subprocess.CompletedProcess[str]) -> bool:
    """Return ``True`` when *res* contains a GitHub 404 / not-found indicator."""
    combined = (res.stderr or "") + (res.stdout or "")
    return any(marker in combined for marker in _NOT_FOUND_MARKERS)


def _not_found_hint(res: subprocess.CompletedProcess[str]) -> str:
    """Return a log context hint when the error looks like a missing/stale issue."""
    return " (issue may no longer exist – deleted or transferred)" if _is_not_found_error(res) else ""


def _gh_with_retry(args: list[str], *, retries: int = 3, backoff_base: float = 2.0) -> subprocess.CompletedProcess[str]:
    """Run a ``gh`` command, retrying up to *retries* times on 404 responses.

    Waits ``backoff_base ** attempt`` seconds between attempts (2 s, 4 s, 8 s by
    default) to tolerate GitHub API replication lag immediately after issue creation.
    """
    res = run_gh(args)
    for attempt in range(1, retries + 1):
        if res.returncode == 0 or not _is_not_found_error(res):
            break
        wait = backoff_base**attempt
        logging.debug(
            "gh 404 on attempt %d/%d, retrying in %.0fs (cmd=%s)",
            attempt,
            retries,
            wait,
            " ".join(str(a) for a in args[:3]),
        )
        time.sleep(wait)
        res = run_gh(args)
    return res


def gh_issue_get_rest_id(repo: str, number: int) -> int | None:
    """Fetch the REST API numeric ID for issue *number*.

    Retries on 404 to tolerate GitHub API replication lag after issue creation.
    """
    res = _gh_with_retry(["api", f"repos/{repo}/issues/{number}", "--jq", ".id"])
    if res.returncode != 0:
        logging.warning("Failed to fetch REST issue id for #%d%s: %s", number, _not_found_hint(res), res.stderr)
        return None
    try:
        return int((res.stdout or "").strip())
    except ValueError:
        logging.warning("Failed to parse REST issue id for #%d: %r", number, res.stdout)
        return None


def gh_issue_add_sub_issue(repo: str, parent_number: int, sub_issue_id: int) -> bool:
    """Link a sub-issue to *parent_number* using the REST issue *sub_issue_id*."""
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
        logging.error(
            "Failed to add sub-issue link parent=#%d sub_issue_id=%d%s: %s",
            parent_number,
            sub_issue_id,
            _not_found_hint(res),
            res.stderr,
        )
        return False

    return True


def gh_issue_add_sub_issue_by_number(repo: str, parent_number: int, child_number: int) -> bool:
    """Resolve *child_number* to a REST ID and link it as a sub-issue of *parent_number*."""
    child_id = gh_issue_get_rest_id(repo, child_number)

    if child_id is None:
        return False

    return gh_issue_add_sub_issue(repo, parent_number, child_id)


def gh_issue_get_sub_issue_numbers(repo: str, parent_number: int) -> set[int]:
    """Return the set of child issue numbers currently linked to *parent_number*.

    Retries on 404 to tolerate GitHub API replication lag after issue creation.
    Uses ``--paginate`` to handle parents with more than 30 sub-issues.
    """
    res = _gh_with_retry(
        [
            "api",
            "--paginate",
            f"repos/{repo}/issues/{parent_number}/sub_issues",
            "--jq",
            "[.[].number]",
        ]
    )
    if res.returncode != 0:
        logging.error("Failed to list sub-issues for parent #%d%s: %s", parent_number, _not_found_hint(res), res.stderr)
        return set()
    try:
        numbers = json.loads((res.stdout or "").strip() or "[]")
        return {int(n) for n in numbers}
    except json.JSONDecodeError, ValueError:
        logging.error("Failed to parse sub-issues for parent #%d: %r", parent_number, res.stdout)
        return set()


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
        logging.error("gh issue list by label failed: %s", res.stderr)
        return {}

    try:
        items = json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        return {}

    issues: dict[int, Issue] = {}
    for obj in items or []:
        try:
            number = int(obj.get("number"))
        except TypeError, ValueError:
            continue
        raw_labels = obj.get("labels") or []
        label_names = [str(lbl.get("name") or lbl) if isinstance(lbl, dict) else str(lbl) for lbl in raw_labels]
        issues[number] = Issue(
            number=number,
            state=str(obj.get("state", "")),
            title=str(obj.get("title", "")),
            body=str(obj.get("body", "")),
            labels=label_names,
        )

    logging.info("Loaded %d issues with label %r from repository %s", len(issues), label, repo)
    return issues


def gh_issue_edit_state(repo: str, number: int, state: str) -> bool:
    """Set the state of issue *number* to *state* (``open`` or ``closed``)."""
    desired = (state or "").strip().lower()
    if desired not in {"open", "closed"}:
        raise ValueError(f"Unsupported issue state: {state!r}")

    # Newer gh: `gh issue edit --state open|closed`
    res = run_gh(["issue", "edit", str(number), "--repo", repo, "--state", desired])
    if res.returncode == 0:
        return True

    stderr = (res.stderr or "") + (res.stdout or "")
    if "unknown flag: --state" not in stderr:
        logging.error("Failed to edit state for #%d%s: %s", number, _not_found_hint(res), res.stderr)
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
        logging.error(
            "Failed to edit state for #%d%s: %s",
            number,
            _not_found_hint(res3),
            res2.stderr or res2.stdout or res.stderr,
        )
        return False
    return True


def gh_issue_edit_title(repo: str, number: int, title: str) -> bool:
    """Update the title of issue *number*."""
    res = run_gh(["issue", "edit", str(number), "--repo", repo, "--title", title])

    if res.returncode != 0:
        logging.error("Failed to edit title for #%d%s: %s", number, _not_found_hint(res), res.stderr)
        return False

    logging.info("Updated issue #%d title", number)
    return True


def gh_issue_edit_body(repo: str, number: int, body: str) -> bool:
    """Replace the body of issue *number*."""
    res = run_gh(["issue", "edit", str(number), "--repo", repo, "--body", body])

    if res.returncode != 0:
        logging.error("Failed to edit body for #%d%s: %s", number, _not_found_hint(res), res.stderr)
        return False

    logging.info("Updated issue #%d body", number)
    return True


def gh_issue_add_labels(repo: str, number: int, labels: list[str]) -> None:
    """Add *labels* to issue *number* (idempotent)."""
    if not labels:
        return

    args: list[str] = ["issue", "edit", str(number), "--repo", repo]

    for label in labels:
        args += ["--add-label", label]

    res = run_gh(args)
    if res.returncode != 0:
        # Labels may not exist; don't fail the whole run.
        logging.warning("Failed to add labels to #%d%s: %s", number, _not_found_hint(res), res.stderr)


def gh_issue_comment(repo: str, number: int, body: str) -> bool:
    """Post a comment with *body* on issue *number*.

    Retries on 404 to tolerate GitHub API replication lag after issue creation.
    """
    res = _gh_with_retry(["issue", "comment", str(number), "--repo", repo, "--body", body])

    if res.returncode != 0:
        logging.error("Failed to comment on #%d%s: %s", number, _not_found_hint(res), res.stderr)
        return False

    return True


def gh_issue_create(repo: str, title: str, body: str, labels: list[str]) -> int | None:
    """Create a new issue and return its number, or ``None`` on failure."""
    args: list[str] = ["issue", "create", "--repo", repo, "--title", title, "--body", body]

    for label in labels:
        args += ["--label", label]

    res = run_gh(args)
    if res.returncode != 0:
        logging.error("Failed to create issue: %s", res.stderr)
        return None

    out = (res.stdout or "").strip()
    match = re.search(r"/issues/(?P<num>\d+)(?:\s*)$", out)
    if match:
        return int(match.group("num"))

    match = re.search(r"issues/(?P<num>\d+)", out)
    if match:
        return int(match.group("num"))

    return None
