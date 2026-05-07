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

"""Generic ``{{ placeholder }}`` Markdown template rendering engine."""

import json
import re
from typing import Any

from security.constants import NOT_AVAILABLE

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_\.]+)\s*\}\}")


def _get_nested_value(data: dict[str, Any], dotted_key: str) -> Any:
    """Resolve a dot-separated key path against a nested dict."""
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
    """Replace ``{{ key }}`` placeholders in *template* with values from *values*."""

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        v = _get_nested_value(values, key)
        if isinstance(v, (dict, list)):
            return json.dumps(v)
        return str(v)

    return PLACEHOLDER_RE.sub(repl, template)


def strip_na_sections(body: str) -> str:
    """Remove N/A fields and empty sections from a rendered Markdown body.

    - Lines like ``- **Key:** N/A`` (with optional trailing whitespace/italics) are removed.
    - Section headers (``## Heading``) with no remaining content are removed.
    """
    lines = body.split("\n")
    filtered: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]

        # Remove bullet-list N/A fields: "- **Key:** N/A" with optional trailing content
        if re.match(r"^\s*-\s+\*\*[^*]+:\*\*\s*N/A\s*$", line):
            i += 1
            # Also remove subsequent italic description lines
            while i < len(lines) and re.match(r"^\s+\*\(.*\)\*\s*$", lines[i]):
                i += 1
            continue

        filtered.append(line)
        i += 1

    # Second pass: remove ## headings whose section body is empty or just N/A
    result: list[str] = []
    i = 0
    while i < len(filtered):
        line = filtered[i]

        if re.match(r"^##\s+", line):
            # Collect the section body (until next ## heading or end)
            section_header = line
            section_body_lines: list[str] = []
            j = i + 1
            while j < len(filtered) and not re.match(r"^##\s+", filtered[j]):
                section_body_lines.append(filtered[j])
                j += 1

            # Check if section body is effectively empty
            body_text = "\n".join(section_body_lines).strip()
            if not body_text or body_text == NOT_AVAILABLE:
                i = j
                continue

            result.append(section_header)
            result.extend(section_body_lines)
            i = j
        else:
            result.append(line)
            i += 1

    return "\n".join(result)
