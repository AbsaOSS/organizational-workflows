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

"""Security-specific Markdown body templates."""


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



