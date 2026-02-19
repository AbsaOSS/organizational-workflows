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

"""Markdown templates and ``{{ placeholder }}`` rendering engine."""

from __future__ import annotations

import json
import re
from typing import Any


PARENT_BODY_TEMPLATE = """# Security Alert – {{ avd_id }}

## General Information

- **Category:** {{ category }}
- **AVD ID:** {{ avd_id }}
- **Title:** {{ title }}
- **Severity:** {{ severity }}
- **Published date:** {{ published_date }}
- **Vendor scoring:** {{ vendor_scoring }}

## Affected Package

- **Package name:** {{ package_name }}
- **Fixed version:** {{ fixed_version }}

## Classification

- **CVE:** {{ extraData.cwe }}
- **OWASP:** {{ extraData.owasp }}
- **Category:** {{ extraData.category }}

## Risk Assessment

- **Impact:** {{ extraData.impact }}  
  *(Potential impact if the vulnerability is successfully exploited)*
- **Likelihood:** {{ extraData.likelihood }}  
  *(How easily the vulnerability can be exploited in practice)*
- **Confidence:** {{ extraData.confidence }}  
  *(How confident the finding is; likelihood of false positive)*

## Recommended Remediation

{{ extraData.remediation }}

## References

{{ extraData.references }}
"""


CHILD_BODY_TEMPLATE = """## General Information

- **AVD ID:** {{ avd_id }}
- **Alert hash:** {{ alert_hash }}
- **Title:** {{ title }}

## Vulnerability Description

{{ message }}

## Location

- **Repository:** {{ repository_full_name }}
- **File:** {{ scm_file }}
- **Line:** {{ target_line }}

## Dependency Details

- **Package name:** {{ package_name }}
- **Installed version:** {{ installed_version }}
- **Fixed version:** {{ fixed_version }}
- **Reachable:** {{ reachable }}

## Detection Timeline

- **Scan date:** {{ scan_date }}
- **First seen:** {{ first_seen }}
"""


PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_\.]+)\s*\}\}")


def _get_nested_value(data: dict[str, Any], dotted_key: str) -> Any:
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
    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        v = _get_nested_value(values, key)
        if isinstance(v, (dict, list)):
            return json.dumps(v)
        return str(v)

    return PLACEHOLDER_RE.sub(repl, template)
