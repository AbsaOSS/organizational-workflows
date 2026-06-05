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

"""Unit tests for ``security.alerts.models``."""

import pytest

from security.alerts.models import AlertMetadata, RuleDetails
from security.constants import NOT_AVAILABLE


# =====================================================================
# AlertMetadata – None-safe __post_init__
# =====================================================================


def test_alert_metadata_none_fields_do_not_crash() -> None:
    """AlertMetadata must not raise when nullable collector fields are None."""
    md = AlertMetadata(
        severity=None,   # type: ignore[arg-type]  – mirrors _normalise_alert output
        rule_id=None,    # type: ignore[arg-type]
        rule_name=None,  # type: ignore[arg-type]
        rule_description=None,  # type: ignore[arg-type]
        state=None,      # type: ignore[arg-type]
        tool=None,       # type: ignore[arg-type]
    )
    assert md.severity == "unknown"
    assert md.rule_id == ""
    assert md.rule_name == ""
    assert md.rule_description == ""
    assert md.state == ""
    assert md.tool == ""


def test_alert_metadata_strips_whitespace() -> None:
    md = AlertMetadata(severity="  high  ", rule_id=" CVE-123 ", tool=" AquaSec ")
    assert md.severity == "high"
    assert md.rule_id == "CVE-123"
    assert md.tool == "AquaSec"


def test_alert_metadata_state_lowercased() -> None:
    md = AlertMetadata(state="  OPEN  ")
    assert md.state == "open"


# =====================================================================
# RuleDetails – whitespace stripping and NOT_AVAILABLE fallback
# =====================================================================


@pytest.mark.parametrize("raw, expected", [
    ("HIGH\n", "HIGH"),
    ("  MEDIUM  ", "MEDIUM"),
    (None, NOT_AVAILABLE),
])
def test_rule_details_normalises_impact_likelihood_confidence(raw: str | None, expected: str) -> None:
    for field in ("impact", "likelihood", "confidence"):
        rd = RuleDetails(**{field: raw})  # type: ignore[arg-type]
        assert expected == getattr(rd, field)
