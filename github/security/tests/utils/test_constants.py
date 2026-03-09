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

"""Unit tests for ``utils.constants``.

These tests verify that the default label values (when no custom
``labels.yml`` is present) match the historically hardcoded values.
"""

import textwrap

import pytest

from utils.label_config import reset_label_config
from utils.constants import (
    LABEL_EPIC,
    LABEL_SCOPE_SECURITY,
    LABEL_SEC_ADEPT_TO_CLOSE,
    LABEL_TYPE_TECH_DEBT,
    LABEL_SRC_AQUASEC_SARIF,
    LABEL_STATE_POSTPONED,
    LABEL_STATE_NEEDS_REVIEW,
    LABEL_SEV_CRITICAL,
    LABEL_SEV_HIGH,
    LABEL_SEV_MEDIUM,
    LABEL_SEV_LOW,
    LABEL_CLOSE_FIXED,
    LABEL_CLOSE_FALSE_POSITIVE,
    LABEL_CLOSE_ACCEPTED_RISK,
    LABEL_CLOSE_NOT_APPLICABLE,
    LABEL_POSTPONE_VENDOR,
    LABEL_POSTPONE_PLATFORM,
    LABEL_POSTPONE_ROADMAP,
    LABEL_POSTPONE_OTHER,
    NOT_AVAILABLE,
    SEC_EVENT_OPEN,
    SEC_EVENT_REOPEN,
    SECMETA_TYPE_CHILD,
    SECMETA_TYPE_PARENT,
    reload_labels,
)


def _reset() -> None:
    """Ensure we test with built-in defaults (no custom labels.yml)."""
    reset_label_config()
    reload_labels()


def test_scope_security() -> None:
    _reset()
    from utils.constants import LABEL_SCOPE_SECURITY
    assert LABEL_SCOPE_SECURITY == "scope:security"

def test_type_tech_debt() -> None:
    _reset()
    from utils.constants import LABEL_TYPE_TECH_DEBT
    assert LABEL_TYPE_TECH_DEBT == "type:tech-debt"

def test_epic() -> None:
    _reset()
    from utils.constants import LABEL_EPIC
    assert LABEL_EPIC == "epic"

def test_adept_to_close() -> None:
    _reset()
    from utils.constants import LABEL_SEC_ADEPT_TO_CLOSE
    assert LABEL_SEC_ADEPT_TO_CLOSE == "sec:adept-to-close"


def test_src_aquasec_sarif() -> None:
    _reset()
    from utils.constants import LABEL_SRC_AQUASEC_SARIF
    assert LABEL_SRC_AQUASEC_SARIF == "sec:src/aquasec-sarif"


def test_state_postponed() -> None:
    _reset()
    from utils.constants import LABEL_STATE_POSTPONED
    assert LABEL_STATE_POSTPONED == "sec:state/postponed"


def test_state_needs_review() -> None:
    _reset()
    from utils.constants import LABEL_STATE_NEEDS_REVIEW
    assert LABEL_STATE_NEEDS_REVIEW == "sec:state/needs-review"


def test_sev_critical() -> None:
    _reset()
    from utils.constants import LABEL_SEV_CRITICAL
    assert LABEL_SEV_CRITICAL == "sec:sev/critical"


def test_sev_high() -> None:
    _reset()
    from utils.constants import LABEL_SEV_HIGH
    assert LABEL_SEV_HIGH == "sec:sev/high"


def test_sev_medium() -> None:
    _reset()
    from utils.constants import LABEL_SEV_MEDIUM
    assert LABEL_SEV_MEDIUM == "sec:sev/medium"


def test_sev_low() -> None:
    _reset()
    from utils.constants import LABEL_SEV_LOW
    assert LABEL_SEV_LOW == "sec:sev/low"


def test_close_fixed() -> None:
    _reset()
    from utils.constants import LABEL_CLOSE_FIXED
    assert LABEL_CLOSE_FIXED == "sec:close/fixed"


def test_close_false_positive() -> None:
    _reset()
    from utils.constants import LABEL_CLOSE_FALSE_POSITIVE
    assert LABEL_CLOSE_FALSE_POSITIVE == "sec:close/false-positive"


def test_close_accepted_risk() -> None:
    _reset()
    from utils.constants import LABEL_CLOSE_ACCEPTED_RISK
    assert LABEL_CLOSE_ACCEPTED_RISK == "sec:close/accepted-risk"


def test_close_not_applicable() -> None:
    _reset()
    from utils.constants import LABEL_CLOSE_NOT_APPLICABLE
    assert LABEL_CLOSE_NOT_APPLICABLE == "sec:close/not-applicable"


def test_postpone_vendor() -> None:
    _reset()
    from utils.constants import LABEL_POSTPONE_VENDOR
    assert LABEL_POSTPONE_VENDOR == "sec:postpone/vendor"


def test_postpone_platform() -> None:
    _reset()
    from utils.constants import LABEL_POSTPONE_PLATFORM
    assert LABEL_POSTPONE_PLATFORM == "sec:postpone/platform"


def test_postpone_roadmap() -> None:
    _reset()
    from utils.constants import LABEL_POSTPONE_ROADMAP
    assert LABEL_POSTPONE_ROADMAP == "sec:postpone/roadmap"


def test_postpone_other() -> None:
    _reset()
    from utils.constants import LABEL_POSTPONE_OTHER
    assert LABEL_POSTPONE_OTHER == "sec:postpone/other"


def test_open() -> None:
    assert SEC_EVENT_OPEN == "open"

def test_reopen() -> None:
    assert SEC_EVENT_REOPEN == "reopen"


def test_parent() -> None:
    assert SECMETA_TYPE_PARENT == "parent"

def test_child() -> None:
    assert SECMETA_TYPE_CHILD == "child"


def test_not_available() -> None:
    assert NOT_AVAILABLE == "N/A"


def test_reload_labels_with_custom_path(tmp_path) -> None:
    """reload_labels() picks up a custom labels.yml and updates LABEL_* globals."""
    f = tmp_path / "labels.yml"
    f.write_text(textwrap.dedent("""\
        epic: "type:epic"
        sev_critical: "sev:critical"
    """))
    reload_labels(str(f))

    import utils.constants as c
    assert c.LABEL_EPIC == "type:epic"
    assert c.LABEL_SEV_CRITICAL == "sev:critical"
    # Unchanged labels still use defaults
    assert c.LABEL_SCOPE_SECURITY == "scope:security"

    # Restore defaults so we don't pollute other tests
    _reset()
