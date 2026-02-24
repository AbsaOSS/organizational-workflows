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

"""GitHub Projects V2 GraphQL operations – project field metadata lookup,
add/update items, field value read/write, the legacy single-issue wrapper,
and the bulk :class:`ProjectPrioritySync` class (prefetch -> enqueue -> flush).
"""


import json
import sys
from dataclasses import dataclass
from typing import Any

from .common import run_gh, vprint
from .priority import resolve_priority


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ProjectPriorityField:
    """Caches the IDs required to set a single-select "Priority" field."""
    project_id: str
    field_id: str
    options: dict[str, str]   # option name (lowercase) -> option node-id


_project_priority_cache: dict[str, ProjectPriorityField | None] = {}


# ---------------------------------------------------------------------------
# GraphQL helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Bulk priority sync
# ---------------------------------------------------------------------------

_BULK_PAGE_SIZE = 50   # items per page when prefetching project items
_BULK_MUTATION_SIZE = 20  # mutations per batched GraphQL call


@dataclass
class _PriorityUpdate:
    """A single pending priority field mutation."""
    repo: str
    issue_number: int
    node_id: str | None       # issue GraphQL node-id (None = needs lookup)
    item_id: str | None       # project-item id (None = not yet on project)
    desired_option_id: str
    priority_label: str        # human-readable priority value for logging


class ProjectPrioritySync:
    """Bulk read -> diff -> bulk write for a GitHub Project Priority field."""

    def __init__(
        self,
        org: str,
        project_number: int,
        pf: ProjectPriorityField,
        *,
        dry_run: bool = False,
    ):
        """Initialise with project metadata and prefetch existing items."""
        self.org = org
        self.project_number = project_number
        self.pf = pf
        self.dry_run = dry_run

        # Maps populated by _prefetch_items()
        # content_node_id -> item_id
        self._content_to_item: dict[str, str] = {}
        # item_id -> current option-id for the Priority field (or "")
        self._item_current_option: dict[str, str] = {}

        # Pending updates  (populated by enqueue())
        self._pending: list[_PriorityUpdate] = []

        # Prefetch existing items
        self._prefetch_items()

    # ------------------------------------------------------------------
    # Prefetch
    # ------------------------------------------------------------------

    def _prefetch_items(self) -> None:
        """Paginate through all project items and cache their Priority values."""
        query = """
        query($projectId: ID!, $pageSize: Int!, $cursor: String) {
          node(id: $projectId) {
            ... on ProjectV2 {
              items(first: $pageSize, after: $cursor) {
                pageInfo { hasNextPage endCursor }
                nodes {
                  id
                  content {
                    ... on Issue { id }
                    ... on PullRequest { id }
                    ... on DraftIssue { id }
                  }
                  fieldValueByName(name: "Priority") {
                    ... on ProjectV2ItemFieldSingleSelectValue {
                      optionId
                    }
                  }
                }
              }
            }
          }
        }
        """
        cursor: str | None = None
        total = 0
        while True:
            variables: dict[str, Any] = {
                "projectId": self.pf.project_id,
                "pageSize": _BULK_PAGE_SIZE,
            }
            if cursor:
                variables["cursor"] = cursor
            data = _run_graphql(query, variables)
            if data is None:
                vprint("WARN: Failed to prefetch project items – falling back to per-issue calls")
                break

            items_data = ((data.get("data") or {}).get("node") or {}).get("items", {})
            nodes = items_data.get("nodes") or []
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                item_id = node.get("id")
                content = node.get("content") or {}
                content_id = content.get("id") if isinstance(content, dict) else None
                if item_id and content_id:
                    self._content_to_item[content_id] = item_id
                fv = node.get("fieldValueByName") or {}
                current_opt = fv.get("optionId") or ""
                if item_id:
                    self._item_current_option[item_id] = current_opt
            total += len(nodes)

            page_info = items_data.get("pageInfo") or {}
            if page_info.get("hasNextPage") and page_info.get("endCursor"):
                cursor = page_info["endCursor"]
            else:
                break

        vprint(f"Prefetched {total} project items from project #{self.project_number}")

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------

    def enqueue(
        self,
        repo: str,
        issue_number: int,
        severity: str,
        severity_priority_map: dict[str, str],
    ) -> None:
        """Resolve severity -> priority and queue an update if needed."""
        priority_value = resolve_priority(severity, severity_priority_map)        
        if not priority_value:
            vprint(f"No priority mapping for severity={severity!r} – skipping project field")
            return

        option_id = self.pf.options.get(priority_value.lower())
        if option_id is None:
            print(
                f"WARN: Priority value {priority_value!r} (from severity={severity!r}) "
                f"does not match any option in project #{self.project_number}. "
                f"Available options: {list(self.pf.options.keys())}",
                file=sys.stderr,
            )
            return

        if self.dry_run:
            print(
                f"DRY-RUN: would set Priority={priority_value!r} on issue #{issue_number} "
                f"in project #{self.project_number}"
            )
            return

        # Deduplicate: if we already have a pending entry for this issue,
        # update it (last-write-wins) instead of appending a duplicate.
        for existing in self._pending:
            if existing.repo == repo and existing.issue_number == issue_number:
                existing.desired_option_id = option_id
                existing.priority_label = priority_value
                return

        self._pending.append(_PriorityUpdate(
            repo=repo,
            issue_number=issue_number,
            node_id=None,
            item_id=None,
            desired_option_id=option_id,
            priority_label=priority_value,
        ))

    # ------------------------------------------------------------------
    # Flush – resolve node-ids, add to project, diff, batch-update
    # ------------------------------------------------------------------

    def flush(self) -> None:
        """Execute all pending priority changes in bulk."""
        if not self._pending:
            return

        # 1. Resolve issue node-ids in bulk (batch REST calls).
        self._resolve_node_ids()

        # 2. Ensure all issues are on the project (batch add mutations).
        self._ensure_on_project()

        # 3. Diff against prefetched state and batch-update changed values.
        self._batch_update()

    def _resolve_node_ids(self) -> None:
        """Fetch GraphQL node-ids for issues that we haven't seen yet."""
        # Batch in groups to avoid extremely long GraphQL queries.
        need_resolve = [p for p in self._pending if p.node_id is None]
        for i in range(0, len(need_resolve), _BULK_MUTATION_SIZE):
            batch = need_resolve[i:i + _BULK_MUTATION_SIZE]
            aliases: list[str] = []
            parts: list[str] = []
            for idx, p in enumerate(batch):
                owner, name = p.repo.split("/", 1) if "/" in p.repo else (p.repo, "")
                alias = f"r{idx}"
                aliases.append(alias)
                parts.append(
                    f'{alias}: repository(owner: "{owner}", name: "{name}") '
                    f'{{ issue(number: {p.issue_number}) {{ id }} }}'
                )
            query = "query {\n" + "\n".join(parts) + "\n}"
            data = _run_graphql(query)
            if data is None:
                continue
            d = data.get("data") or {}
            for idx, p in enumerate(batch):
                alias = f"r{idx}"
                issue_data = (d.get(alias) or {}).get("issue") or {}
                nid = issue_data.get("id")
                if nid:
                    p.node_id = nid

    def _ensure_on_project(self) -> None:
        """Add issues not yet on the project in batched mutations."""
        to_add = [
            p for p in self._pending
            if p.node_id and p.node_id not in self._content_to_item
        ]
        for i in range(0, len(to_add), _BULK_MUTATION_SIZE):
            batch = to_add[i:i + _BULK_MUTATION_SIZE]
            parts: list[str] = []
            var_defs: list[str] = []
            variables: dict[str, str] = {}
            for idx, p in enumerate(batch):
                cvar = f"$c{idx}"
                var_defs.append(f"{cvar}: ID!")
                variables[f"c{idx}"] = p.node_id  # type: ignore[assignment]
                parts.append(
                    f'a{idx}: addProjectV2ItemById(input: {{projectId: "{self.pf.project_id}", '
                    f"contentId: {cvar}}}) {{ item {{ id }} }}"
                )
            query = f"mutation({', '.join(var_defs)}) {{\n" + "\n".join(parts) + "\n}"
            data = _run_graphql(query, variables)
            if data is None:
                continue
            d = data.get("data") or {}
            for idx, p in enumerate(batch):
                item = (d.get(f"a{idx}") or {}).get("item")
                if item and item.get("id"):
                    item_id = item["id"]
                    p.item_id = item_id
                    self._content_to_item[p.node_id] = item_id  # type: ignore[index]
                    # New items have no priority value yet.
                    self._item_current_option[item_id] = ""

        # Map already-existing items.
        for p in self._pending:
            if p.node_id and p.item_id is None:
                p.item_id = self._content_to_item.get(p.node_id)

    def _batch_update(self) -> None:
        """Batch set-field-value mutations for items whose priority differs."""
        to_update: list[_PriorityUpdate] = []
        for p in self._pending:
            if not p.item_id:
                vprint(f"WARN: Could not resolve project item for issue #{p.issue_number} – skipping priority")
                continue
            current = self._item_current_option.get(p.item_id, "")
            if current == p.desired_option_id:
                vprint(
                    f"Priority already {p.priority_label!r} on issue #{p.issue_number} "
                    f"in project #{self.project_number} – skipping update"
                )
                continue
            to_update.append(p)

        if not to_update:
            vprint("No priority updates needed – all values are current")
            return

        vprint(f"Updating priority on {len(to_update)} issue(s) in project #{self.project_number}")

        for i in range(0, len(to_update), _BULK_MUTATION_SIZE):
            batch = to_update[i:i + _BULK_MUTATION_SIZE]
            parts: list[str] = []
            var_defs: list[str] = []
            variables: dict[str, str] = {}
            for idx, p in enumerate(batch):
                ivar = f"$i{idx}"
                ovar = f"$o{idx}"
                var_defs += [f"{ivar}: ID!", f"{ovar}: String!"]
                variables[f"i{idx}"] = p.item_id  # type: ignore[assignment]
                variables[f"o{idx}"] = p.desired_option_id
                parts.append(
                    f'u{idx}: updateProjectV2ItemFieldValue(input: {{'
                    f'projectId: "{self.pf.project_id}", '
                    f"itemId: {ivar}, "
                    f'fieldId: "{self.pf.field_id}", '
                    f"value: {{singleSelectOptionId: {ovar}}}"
                    f"}}) {{ projectV2Item {{ id }} }}"
                )
            query = f"mutation({', '.join(var_defs)}) {{\n" + "\n".join(parts) + "\n}"
            data = _run_graphql(query, variables)
            if data is None:
                print(
                    f"WARN: Batch priority update failed for issues "
                    f"{[p.issue_number for p in batch]}",
                    file=sys.stderr,
                )
                continue
            for idx, p in enumerate(batch):
                result = (data.get("data") or {}).get(f"u{idx}")
                if result:
                    print(
                        f"Set Priority={p.priority_label!r} on issue #{p.issue_number} "
                        f"in project #{self.project_number}"
                    )
                else:
                    print(
                        f"WARN: Failed to set Priority={p.priority_label!r} on issue #{p.issue_number}",
                        file=sys.stderr,
                    )
