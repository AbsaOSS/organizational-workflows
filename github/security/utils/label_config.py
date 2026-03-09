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

"""Load label configuration from a YAML file.

The config file (``labels.yml``) is a flat key→value mapping that lets
each consuming repository customise the GitHub label names used by the
security automation pipeline.

When the file is absent, or when a key is not present, the built-in
defaults are used.

The YAML dialect supported here is intentionally minimal (flat scalars
only) so that we avoid an external PyYAML dependency.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

_DEFAULTS: dict[str, str] = {
    # Core
    "scope_security": "scope:security",
    "type_tech_debt": "type:tech-debt",
    "epic": "epic",
    # Lifecycle
    "adept_to_close": "sec:adept-to-close",
    # Source
    "src_aquasec_sarif": "sec:src/aquasec-sarif",
    # State
    "state_postponed": "sec:state/postponed",
    "state_needs_review": "sec:state/needs-review",
    # Severity
    "sev_critical": "sec:sev/critical",
    "sev_high": "sec:sev/high",
    "sev_medium": "sec:sev/medium",
    "sev_low": "sec:sev/low",
    # Closure reasons
    "close_fixed": "sec:close/fixed",
    "close_false_positive": "sec:close/false-positive",
    "close_accepted_risk": "sec:close/accepted-risk",
    "close_not_applicable": "sec:close/not-applicable",
    # Postpone reasons
    "postpone_vendor": "sec:postpone/vendor",
    "postpone_platform": "sec:postpone/platform",
    "postpone_roadmap": "sec:postpone/roadmap",
    "postpone_other": "sec:postpone/other",
}

# Valid keys - anything outside this set is rejected early.
_VALID_KEYS = frozenset(_DEFAULTS.keys())

# Simple YAML scalar parser: ``key: value`` or ``key: "value"`` or ``key: 'value'``
_LINE_RE = re.compile(
    r"^(?P<key>[a-z_]+)"        # key: lowercase + underscores
    r"\s*:\s*"                   # colon separator
    r"(?:"
    r"\"(?P<dq>[^\"]*)\""       # double-quoted value
    r"|'(?P<sq>[^']*)'"         # single-quoted value
    r"|(?P<bare>\S[^\n#]*?)"    # bare (unquoted) value
    r")\s*(?:#.*)?"             # optional trailing comment
    r"$"
)


def _parse_yaml_flat(text: str) -> dict[str, str]:
    """Parse a flat YAML file into a ``{key: value}`` dict.

    Only ``key: value``, ``key: "value"``, and ``key: 'value'`` lines
    are recognised.  Comments (``#``) and blank lines are skipped.
    """
    result: dict[str, str] = {}
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            logging.warning("labels.yml:%d: ignoring unparseable line: %s", lineno, raw_line)
            continue
        key = m.group("key")
        value = m.group("dq") if m.group("dq") is not None else (
            m.group("sq") if m.group("sq") is not None else (m.group("bare") or "").strip()
        )
        result[key] = value
    return result


@dataclass(frozen=True)
class LabelConfig:
    """Resolved label names for the security automation pipeline."""

    # Core
    scope_security: str = _DEFAULTS["scope_security"]
    type_tech_debt: str = _DEFAULTS["type_tech_debt"]
    epic: str = _DEFAULTS["epic"]

    # Lifecycle
    adept_to_close: str = _DEFAULTS["adept_to_close"]

    # Source
    src_aquasec_sarif: str = _DEFAULTS["src_aquasec_sarif"]

    # State
    state_postponed: str = _DEFAULTS["state_postponed"]
    state_needs_review: str = _DEFAULTS["state_needs_review"]

    # Severity
    sev_critical: str = _DEFAULTS["sev_critical"]
    sev_high: str = _DEFAULTS["sev_high"]
    sev_medium: str = _DEFAULTS["sev_medium"]
    sev_low: str = _DEFAULTS["sev_low"]

    # Closure reasons
    close_fixed: str = _DEFAULTS["close_fixed"]
    close_false_positive: str = _DEFAULTS["close_false_positive"]
    close_accepted_risk: str = _DEFAULTS["close_accepted_risk"]
    close_not_applicable: str = _DEFAULTS["close_not_applicable"]

    # Postpone reasons
    postpone_vendor: str = _DEFAULTS["postpone_vendor"]
    postpone_platform: str = _DEFAULTS["postpone_platform"]
    postpone_roadmap: str = _DEFAULTS["postpone_roadmap"]
    postpone_other: str = _DEFAULTS["postpone_other"]

    @property
    def required_labels(self) -> list[str]:
        """Labels that must exist in the target repository.

        Only the four core/lifecycle labels are required.  The remaining
        labels are part of the naming convention but may not be created
        upfront in every repository.
        """
        return [
            self.scope_security,
            self.type_tech_debt,
            self.epic,
            self.adept_to_close,
        ]

    @property
    def all_labels(self) -> list[str]:
        """Every label defined in the config (all categories)."""
        return [
            self.scope_security,
            self.type_tech_debt,
            self.epic,
            self.adept_to_close,
            self.src_aquasec_sarif,
            self.state_postponed,
            self.state_needs_review,
            self.sev_critical,
            self.sev_high,
            self.sev_medium,
            self.sev_low,
            self.close_fixed,
            self.close_false_positive,
            self.close_accepted_risk,
            self.close_not_applicable,
            self.postpone_vendor,
            self.postpone_platform,
            self.postpone_roadmap,
            self.postpone_other,
        ]

    @property
    def severity_labels(self) -> list[str]:
        """Severity labels, ordered critical → low."""
        return [self.sev_critical, self.sev_high, self.sev_medium, self.sev_low]


# Module-level singleton – lazily initialised.
_config: LabelConfig | None = None


def load_label_config(path: str | None = None) -> LabelConfig:
    """Load and return a :class:`LabelConfig` from *path*.

    Parameters
    ----------
    path:
        Filesystem path to a ``labels.yml`` file.  When *None*, the
        function looks for ``labels.yml`` next to *this* module's
        package (i.e. ``github/security/labels.yml``).

    Returns
    -------
    LabelConfig
        A frozen dataclass with the resolved label values.
    """
    if path is None:
        # Default: <security_dir>/labels.yml
        security_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
        path = os.path.join(security_dir, "labels.yml")

    if not os.path.isfile(path):
        logging.debug("Label config file not found at %s – using built-in defaults", path)
        return LabelConfig()

    logging.debug("Loading label config from %s", path)
    with open(path, encoding="utf-8") as fh:
        raw = _parse_yaml_flat(fh.read())

    unknown = set(raw.keys()) - _VALID_KEYS
    if unknown:
        logging.warning("labels.yml: ignoring unknown keys: %s", ", ".join(sorted(unknown)))

    kwargs: dict[str, Any] = {}
    for key in _VALID_KEYS:
        if key in raw:
            kwargs[key] = raw[key]

    return LabelConfig(**kwargs)


def get_label_config(path: str | None = None) -> LabelConfig:
    """Return the module-level :class:`LabelConfig` singleton.

    The config is loaded on first call and cached afterwards.
    Pass *path* to override the default file location (useful in tests
    or when called from a CLI that accepts ``--label-config``).

    Calling with a non-None *path* **always** reloads from disk
    (and replaces the cached singleton).
    """
    global _config
    if _config is None or path is not None:
        _config = load_label_config(path)
    return _config


def reset_label_config() -> None:
    """Clear the cached singleton (for tests)."""
    global _config
    _config = None
