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
"""

import re


def parse_kv_block(block: str) -> dict[str, str]:
    """Parse a ``key=value``-per-line block into a dict."""
    data: dict[str, str] = {}
    for line in (block or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()
    return data


def load_secmeta(issue_body: str) -> dict[str, str]:
    """Extract the ``secmeta`` key-value block from an issue body."""
    body = issue_body or ""
    match = re.compile(r"<!--\s*secmeta\r?\n(.*?)\r?\n-->", re.S).search(body)
    if match:
        return parse_kv_block(match.group(1))
    # Back-compat for older issues created with a visible fenced block.
    legacy = re.compile(r"```secmeta\r?\n(.*?)\r?\n```", re.S).search(body)
    if legacy:
        return parse_kv_block(legacy.group(1))
    return {}


def render_kv_lines(
    data: dict[str, str],
    preferred_order: list[str],
    *,
    skip_empty: bool = False,
) -> list[str]:
    """Render key=value lines in *preferred_order*, then remaining keys sorted.

    When *skip_empty* is ``True``, keys whose value is empty or whitespace-only
    are omitted.
    """
    lines: list[str] = []
    seen = set(preferred_order)
    for key in preferred_order:
        if key in data:
            val = data.get(key, "")
            if skip_empty and not str(val).strip():
                continue
            lines.append(f"{key}={val}")
    for key in sorted(k for k in data.keys() if k not in seen):
        val = str(data.get(key, ""))
        if skip_empty and not val.strip():
            continue
        lines.append(f"{key}={val}")
    return lines


def render_secmeta(secmeta: dict[str, str]) -> str:
    """Render a secmeta dict as a hidden HTML-comment block for issue bodies."""
    preferred_order = [
        "type",
        "fingerprint",
        "repo",
        "rule_id",
        "severity",
    ]
    lines = render_kv_lines(secmeta, preferred_order)
    return "<!--secmeta\n" + "\n".join(lines) + "\n-->"
