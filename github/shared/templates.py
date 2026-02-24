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
