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

"""Security alert promotion utilities.

Modules
-------
common          Shared low-level utilities (logging, dates, hashing, subprocess).
constants       Domain constants (label names, event strings, secmeta types).
models          Core dataclass definitions (Issue, IssueIndex, NotifiedIssue).
secmeta         ``secmeta`` metadata block parsing / rendering / upserting.
sec_events      ``[sec-event]`` comment block parsing / rendering / stripping.
templates       Markdown body templates and ``{{ placeholder }}`` rendering.
alert_parser    Alert data extraction (message params, CWE, occurrence FP, file loading).
priority        Severity-to-priority mapping configuration and resolution.
github_issues   GitHub Issues REST/CLI operations (CRUD, labels, comments, sub-issues).
github_projects GitHub Projects V2 GraphQL operations and bulk ``ProjectPrioritySync``.
issue_builder   Issue title / body construction from alert dicts.
issue_sync      Core sync orchestration (index, match, create/update/reopen, orphan labelling).
teams           Teams webhook notification building and delivery.
"""
