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

"""``[sec-event]`` comment blocks – parsing, rendering, and stripping
structured lifecycle-event blocks from issue bodies.
"""


import re


def parse_sec_event_fields(raw: str) -> dict[str, str]:
    """Parse ``key=value`` lines from a raw sec-event block."""
    fields: dict[str, str] = {}
    for line in (raw or "").splitlines():
        s = line.strip()
        if not s or "=" not in s:
            continue
        k, v = s.split("=", 1)
        fields[k.strip()] = v.strip()
    return fields


def render_sec_event(fields: dict[str, str]) -> str:
    """Render a structured ``[sec-event]`` comment block from *fields*."""
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
    text = re.compile(r"\[sec-event\]\s*(.*?)\s*\[/sec-event\]", re.S).sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"
    return text
