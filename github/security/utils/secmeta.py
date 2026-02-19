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

"""``secmeta`` metadata blocks – parsing, rendering, and upserting the hidden
HTML-comment metadata block stored in issue bodies.

Also hosts generic key-value and JSON-list helpers used for secmeta field values.
"""

from __future__ import annotations

import json
import re

SECMETA_RE = re.compile(r"<!--\s*secmeta\r?\n(.*?)\r?\n-->", re.S)
LEGACY_SECMETA_RE = re.compile(r"```secmeta\r?\n(.*?)\r?\n```", re.S)


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
