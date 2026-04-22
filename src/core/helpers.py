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

"""Pure utility functions"""

import hashlib
import re
from datetime import datetime, timezone

# Matches lines that start with 1-6 '#' followed by a space
_HEADING_RE = re.compile(r"^(#{1,6}\s)", re.MULTILINE)
# Matches '>' at the start of a line (blockquote)
_BLOCKQUOTE_RE = re.compile(r"^(>)", re.MULTILINE)
# Matches horizontal rules: three or more -, *, or _ on a line by themselves
_HR_RE = re.compile(r"^([-*_]{3,})\s*$", re.MULTILINE)
# Matches '|' at the start of a line (table row).
_TABLE_RE = re.compile(r"^(\|)", re.MULTILINE)


def utc_today() -> str:
    """Return today's date in UTC as an ISO-8601 string (``YYYY-MM-DD``)."""
    return datetime.now(timezone.utc).date().isoformat()


def iso_date(iso_dt: str | None) -> str:
    """Extract the date portion from an ISO-8601 datetime string, or return today."""
    if not iso_dt:
        return utc_today()
    if "T" in iso_dt:
        return iso_dt.split("T", 1)[0]
    return iso_dt


def sha256_hex(text: str) -> str:
    """Return the hex SHA-256 digest of *text*."""
    return hashlib.sha256(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def normalize_path(path: str | None) -> str:
    """Normalize a file path to forward-slash, no leading ``./`` or ``/``."""
    if not path:
        return ""
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    p = re.sub(r"/+", "/", p)
    return p


def sanitize_markdown(text: str) -> str:
    """Escape block-level Markdown so text renders as plain content in an issue body."""
    if not text:
        return text

    sanitized = _HEADING_RE.sub(r"\\\1", text)
    sanitized = _BLOCKQUOTE_RE.sub(r"\\\1", sanitized)
    sanitized = _HR_RE.sub(r"\\\1", sanitized)
    sanitized = _TABLE_RE.sub(r"\\\1", sanitized)

    return sanitized
