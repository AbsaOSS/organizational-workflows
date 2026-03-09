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

"""Shared constants used across the security workflow utilities.

Label values are configurable via ``labels.yml`` (see
:mod:`utils.label_config`).  The module-level ``LABEL_*`` attributes
expose the *resolved* values so that existing call-sites continue to
work without changes.
"""

# Configurable labels – populated by _load() at the bottom of this module.
LABEL_SCOPE_SECURITY: str
LABEL_TYPE_TECH_DEBT: str
LABEL_EPIC: str
LABEL_SEC_ADEPT_TO_CLOSE: str
LABEL_SRC_AQUASEC_SARIF: str
LABEL_STATE_POSTPONED: str
LABEL_STATE_NEEDS_REVIEW: str
LABEL_SEV_CRITICAL: str
LABEL_SEV_HIGH: str
LABEL_SEV_MEDIUM: str
LABEL_SEV_LOW: str
LABEL_CLOSE_FIXED: str
LABEL_CLOSE_FALSE_POSITIVE: str
LABEL_CLOSE_ACCEPTED_RISK: str
LABEL_CLOSE_NOT_APPLICABLE: str
LABEL_POSTPONE_VENDOR: str
LABEL_POSTPONE_PLATFORM: str
LABEL_POSTPONE_ROADMAP: str
LABEL_POSTPONE_OTHER: str


def _load(config_path: str | None = None) -> None:
    """Populate module-level LABEL_* constants from the label config."""
    from .label_config import get_label_config, reset_label_config  # lazy import
    global LABEL_SCOPE_SECURITY, LABEL_TYPE_TECH_DEBT, LABEL_EPIC
    global LABEL_SEC_ADEPT_TO_CLOSE, LABEL_SRC_AQUASEC_SARIF
    global LABEL_STATE_POSTPONED, LABEL_STATE_NEEDS_REVIEW
    global LABEL_SEV_CRITICAL, LABEL_SEV_HIGH, LABEL_SEV_MEDIUM, LABEL_SEV_LOW
    global LABEL_CLOSE_FIXED, LABEL_CLOSE_FALSE_POSITIVE, LABEL_CLOSE_ACCEPTED_RISK, LABEL_CLOSE_NOT_APPLICABLE
    global LABEL_POSTPONE_VENDOR, LABEL_POSTPONE_PLATFORM, LABEL_POSTPONE_ROADMAP, LABEL_POSTPONE_OTHER
    if config_path is not None:
        reset_label_config()
    cfg = get_label_config(config_path)
    LABEL_SCOPE_SECURITY       = cfg.scope_security
    LABEL_TYPE_TECH_DEBT       = cfg.type_tech_debt
    LABEL_EPIC                 = cfg.epic
    LABEL_SEC_ADEPT_TO_CLOSE   = cfg.adept_to_close
    LABEL_SRC_AQUASEC_SARIF    = cfg.src_aquasec_sarif
    LABEL_STATE_POSTPONED      = cfg.state_postponed
    LABEL_STATE_NEEDS_REVIEW   = cfg.state_needs_review
    LABEL_SEV_CRITICAL         = cfg.sev_critical
    LABEL_SEV_HIGH             = cfg.sev_high
    LABEL_SEV_MEDIUM           = cfg.sev_medium
    LABEL_SEV_LOW              = cfg.sev_low
    LABEL_CLOSE_FIXED          = cfg.close_fixed
    LABEL_CLOSE_FALSE_POSITIVE = cfg.close_false_positive
    LABEL_CLOSE_ACCEPTED_RISK  = cfg.close_accepted_risk
    LABEL_CLOSE_NOT_APPLICABLE = cfg.close_not_applicable
    LABEL_POSTPONE_VENDOR      = cfg.postpone_vendor
    LABEL_POSTPONE_PLATFORM    = cfg.postpone_platform
    LABEL_POSTPONE_ROADMAP     = cfg.postpone_roadmap
    LABEL_POSTPONE_OTHER       = cfg.postpone_other


def reload_labels(config_path: str | None = None) -> None:
    _load(config_path)


# Initialise LABEL_* at module load time 
_load()

# Non-label constants
SEC_EVENT_OPEN = "open"
SEC_EVENT_REOPEN = "reopen"

SECMETA_TYPE_PARENT = "parent"
SECMETA_TYPE_CHILD = "child"

NOT_AVAILABLE = "N/A"
