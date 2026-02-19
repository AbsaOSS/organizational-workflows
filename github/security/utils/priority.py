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

"""Severity-to-priority mapping – parsing the user-defined
``severity=priority`` config string and resolving a severity to its
priority value.
"""

from __future__ import annotations


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
