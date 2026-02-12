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

"""
Derive team security metrics from issue snapshots (Issues-only).

Resurfacing definition (B):
- A fingerprint is considered 'resurfaced' when its occurrence_count transitions
  from 0 in the previous snapshot to >0 in the current snapshot.

Inputs:
- data/issues_snapshot.json (required)
- data/issues_snapshot.prev.json (optional; if missing, resurfacing cannot be computed)

Outputs:
- reports/metrics.json
- reports/summary.md (appends derived metrics)
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


SNAPSHOT_CUR = os.environ.get("SNAPSHOT_CURRENT", "data/issues_snapshot.json")
SNAPSHOT_PREV = os.environ.get("SNAPSHOT_PREVIOUS", "data/issues_snapshot.prev.json")

OUT_METRICS_JSON = os.environ.get("OUT_METRICS_JSON", "reports/metrics.json")
OUT_SUMMARY_MD = os.environ.get("OUT_SUMMARY_MD", "reports/summary.md")

def require_env(key: str) -> str:
    try:
        return os.environ[key]
    except KeyError as exc:
        raise SystemExit(f"Missing required environment variable: {key}") from exc


TEAM_SLUG = require_env("GITHUB_TEAM_SLUG")


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        if isinstance(v, int):
            return v
        s = str(v).strip()
        if s == "":
            return default
        return int(float(s))
    except Exception:
        return default


def _load_json(path: str) -> Optional[Any]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _index_by_fingerprint(snapshot: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for item in snapshot:
        fp = (item.get("secmeta") or {}).get("fingerprint")
        if not fp:
            # If secmeta is missing or malformed, it cannot participate in fingerprint-level stats.
            continue
        idx[fp] = item
    return idx


def _severity_from_labels(labels: List[str]) -> str:
    for l in labels:
        if l.startswith("sec:sev/"):
            return l.split("/", 1)[1]
    return "unknown"


def main() -> None:
    cur = _load_json(SNAPSHOT_CUR)
    if cur is None:
        raise SystemExit(f"Missing current snapshot: {SNAPSHOT_CUR}")

    if not isinstance(cur, list):
        raise SystemExit(f"Current snapshot is not a list: {SNAPSHOT_CUR}")

    prev = _load_json(SNAPSHOT_PREV)

    cur_idx = _index_by_fingerprint(cur)
    prev_idx = _index_by_fingerprint(prev) if isinstance(prev, list) else {}

    # Basic counts
    total = len(cur)
    by_sev: Dict[str, int] = {}
    postponed = 0
    needs_review = 0

    for item in cur:
        labels = item.get("labels") or []
        sev = _severity_from_labels(labels)
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if "sec:state/postponed" in labels:
            postponed += 1
        if "sec:state/needs-review" in labels:
            needs_review += 1

    # Resurfacing (B): prev occurrence_count == 0 and current > 0
    resurfaced: List[Dict[str, Any]] = []
    if prev_idx:
        for fp, cur_item in cur_idx.items():
            cur_occ = _safe_int((cur_item.get("secmeta") or {}).get("occurrence_count"), 0)
            prev_item = prev_idx.get(fp)
            prev_occ = _safe_int(((prev_item or {}).get("secmeta") or {}).get("occurrence_count"), 0)
            if prev_item is not None and prev_occ == 0 and cur_occ > 0:
                resurfaced.append(
                    {
                        "fingerprint": fp,
                        "repo": cur_item.get("repo"),
                        "issue_number": cur_item.get("issue_number"),
                        "title": cur_item.get("title"),
                        "severity": _severity_from_labels(cur_item.get("labels") or []),
                        "prev_occurrence_count": prev_occ,
                        "current_occurrence_count": cur_occ,
                    }
                )

    metrics = {
        "team": TEAM_SLUG,
        "generated_at_utc": datetime.utcnow().isoformat() + "Z",
        "snapshot_current": SNAPSHOT_CUR,
        "snapshot_previous": SNAPSHOT_PREV if prev_idx else None,
        "counts": {
            "total_security_issues": total,
            "postponed": postponed,
            "needs_review": needs_review,
            "by_severity": dict(sorted(by_sev.items())),
        },
        "resurfaced": {
            "definition": "B: fingerprint occurrence_count from 0 (previous snapshot) to >0 (current snapshot)",
            "count": len(resurfaced),
            "items": resurfaced,
        },
    }

    os.makedirs(os.path.dirname(OUT_METRICS_JSON), exist_ok=True)
    os.makedirs(os.path.dirname(OUT_SUMMARY_MD), exist_ok=True)

    with open(OUT_METRICS_JSON, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Append to (or create) summary.md
    summary_lines: List[str] = []
    summary_lines.append(f"\n## Derived metrics\n")
    summary_lines.append(f"Generated at: {metrics['generated_at_utc']}\n")
    if metrics["snapshot_previous"] is None:
        summary_lines.append("- Resurfacing: not computed (no previous snapshot found)\n")
    else:
        summary_lines.append(f"- Resurfaced fingerprints (definition B): {metrics['resurfaced']['count']}\n")
        if resurfaced:
            summary_lines.append("\n### Resurfaced items\n")
            for r in resurfaced[:50]:
                summary_lines.append(
                    f"- {r['severity']} {r['repo']}#{r['issue_number']} (occ {r['prev_occurrence_count']} -> {r['current_occurrence_count']}): {r['title']}\n"
                )
            if len(resurfaced) > 50:
                summary_lines.append(f"- ... and {len(resurfaced) - 50} more\n")

    # Ensure summary exists; if not, create a minimal header.
    if not os.path.exists(OUT_SUMMARY_MD):
        with open(OUT_SUMMARY_MD, "w", encoding="utf-8") as f:
            f.write(f"# Security summary for team `{TEAM_SLUG}`\n\n")

    with open(OUT_SUMMARY_MD, "a", encoding="utf-8") as f:
        f.writelines(summary_lines)


if __name__ == "__main__":
    main()
