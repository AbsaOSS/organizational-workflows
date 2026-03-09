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

"""Unit tests for ``utils.label_config``."""

import os
import textwrap

import pytest

from utils.label_config import (
    LabelConfig,
    _parse_yaml_flat,
    load_label_config,
    get_label_config,
    reset_label_config,
)


# ========================dd=============================================
# _parse_yaml_flat
# =====================================================================


def test_parse_empty_string() -> None:
    assert _parse_yaml_flat("") == {}


def test_parse_comments_and_blanks() -> None:
    text = textwrap.dedent("""\
        # Full-line comment
        
        # Another comment
    """)
    assert _parse_yaml_flat(text) == {}


def test_parse_bare_values() -> None:
    text = textwrap.dedent("""\
        scope_security: scope:security
        epic: type:epic
    """)
    result = _parse_yaml_flat(text)
    assert result == {"scope_security": "scope:security", "epic": "type:epic"}


def test_parse_double_quoted_values() -> None:
    text = 'epic: "type:epic"\n'
    assert _parse_yaml_flat(text) == {"epic": "type:epic"}


def test_parse_single_quoted_values() -> None:
    text = "epic: 'type:epic'\n"
    assert _parse_yaml_flat(text) == {"epic": "type:epic"}


def test_parse_trailing_comment() -> None:
    text = 'epic: type:epic  # this is the epic label\n'
    assert _parse_yaml_flat(text) == {"epic": "type:epic"}


def test_parse_trailing_comment_quoted() -> None:
    text = 'epic: "type:epic"  # comment\n'
    assert _parse_yaml_flat(text) == {"epic": "type:epic"}


def test_parse_full_config() -> None:
    text = textwrap.dedent("""\
        # Label config
        scope_security: "scope:security"
        type_tech_debt: "type:tech-debt"
        epic: "type:epic"
        adept_to_close: "sec:adept-to-close"
    """)
    result = _parse_yaml_flat(text)
    assert result == {
        "scope_security": "scope:security",
        "type_tech_debt": "type:tech-debt",
        "epic": "type:epic",
        "adept_to_close": "sec:adept-to-close",
    }


# =====================================================================
# LabelConfig
# =====================================================================


def test_label_config_defaults() -> None:
    cfg = LabelConfig()
    # Core
    assert cfg.scope_security == "scope:security"
    assert cfg.type_tech_debt == "type:tech-debt"
    assert cfg.epic == "epic"
    assert cfg.adept_to_close == "sec:adept-to-close"
    # Source
    assert cfg.src_aquasec_sarif == "sec:src/aquasec-sarif"
    # State
    assert cfg.state_postponed == "sec:state/postponed"
    assert cfg.state_needs_review == "sec:state/needs-review"
    # Severity
    assert cfg.sev_critical == "sec:sev/critical"
    assert cfg.sev_high == "sec:sev/high"
    assert cfg.sev_medium == "sec:sev/medium"
    assert cfg.sev_low == "sec:sev/low"
    # Closure reasons
    assert cfg.close_fixed == "sec:close/fixed"
    assert cfg.close_false_positive == "sec:close/false-positive"
    assert cfg.close_accepted_risk == "sec:close/accepted-risk"
    assert cfg.close_not_applicable == "sec:close/not-applicable"
    # Postpone reasons
    assert cfg.postpone_vendor == "sec:postpone/vendor"
    assert cfg.postpone_platform == "sec:postpone/platform"
    assert cfg.postpone_roadmap == "sec:postpone/roadmap"
    assert cfg.postpone_other == "sec:postpone/other"


def test_label_config_custom() -> None:
    cfg = LabelConfig(epic="type:epic")
    assert cfg.epic == "type:epic"
    # Others stay default
    assert cfg.scope_security == "scope:security"


def test_required_labels() -> None:
    cfg = LabelConfig(epic="type:epic")
    assert cfg.required_labels == [
        "scope:security",
        "type:tech-debt",
        "type:epic",
        "sec:adept-to-close",
    ]


def test_label_config_frozen() -> None:
    cfg = LabelConfig()
    with pytest.raises(AttributeError):
        cfg.epic = "new"  # type: ignore[misc]


def test_severity_labels() -> None:
    cfg = LabelConfig()
    assert cfg.severity_labels == [
        "sec:sev/critical",
        "sec:sev/high",
        "sec:sev/medium",
        "sec:sev/low",
    ]


def test_all_labels_count() -> None:
    cfg = LabelConfig()
    assert len(cfg.all_labels) == 19


def test_all_labels_content() -> None:
    cfg = LabelConfig()
    assert cfg.all_labels == [
        "scope:security",
        "type:tech-debt",
        "epic",
        "sec:adept-to-close",
        "sec:src/aquasec-sarif",
        "sec:state/postponed",
        "sec:state/needs-review",
        "sec:sev/critical",
        "sec:sev/high",
        "sec:sev/medium",
        "sec:sev/low",
        "sec:close/fixed",
        "sec:close/false-positive",
        "sec:close/accepted-risk",
        "sec:close/not-applicable",
        "sec:postpone/vendor",
        "sec:postpone/platform",
        "sec:postpone/roadmap",
        "sec:postpone/other",
    ]


def test_all_labels_no_duplicates() -> None:
    cfg = LabelConfig()
    assert len(cfg.all_labels) == len(set(cfg.all_labels))


def test_all_labels_reflects_custom_values() -> None:
    cfg = LabelConfig(epic="type:epic", sev_critical="sev:critical")
    assert "type:epic" in cfg.all_labels
    assert "sev:critical" in cfg.all_labels
    assert "epic" not in cfg.all_labels
    assert "sec:sev/critical" not in cfg.all_labels


def test_severity_labels_custom() -> None:
    cfg = LabelConfig(sev_high="priority:high", sev_low="priority:low")
    assert cfg.severity_labels == [
        "sec:sev/critical",
        "priority:high",
        "sec:sev/medium",
        "priority:low",
    ]


# =====================================================================
# load_label_config
# =====================================================================


def test_load_missing_file(tmp_path) -> None:
    """Returns defaults when the config file doesn't exist."""
    cfg = load_label_config(str(tmp_path / "nonexistent.yml"))
    assert cfg == LabelConfig()


def test_load_from_file(tmp_path) -> None:
    f = tmp_path / "labels.yml"
    f.write_text('epic: "type:epic"\nadept_to_close: "close-me"\n')
    cfg = load_label_config(str(f))
    assert cfg.epic == "type:epic"
    assert cfg.adept_to_close == "close-me"
    assert cfg.scope_security == "scope:security"  # default


def test_load_unknown_keys_ignored(tmp_path) -> None:
    f = tmp_path / "labels.yml"
    f.write_text('epic: "type:epic"\nbogus_key: "whatever"\n')
    cfg = load_label_config(str(f))
    assert cfg.epic == "type:epic"


# =====================================================================
# get_label_config / reset_label_config (singleton)
# =====================================================================


def test_singleton_caching(tmp_path) -> None:
    reset_label_config()
    f = tmp_path / "labels.yml"
    f.write_text('epic: "cached-value"\n')
    cfg1 = get_label_config(str(f))
    assert cfg1.epic == "cached-value"

    # Second call without path returns cached
    cfg2 = get_label_config()
    assert cfg2 is cfg1

    # Call with a different path reloads
    f2 = tmp_path / "labels2.yml"
    f2.write_text('epic: "other"\n')
    cfg3 = get_label_config(str(f2))
    assert cfg3.epic == "other"
    assert cfg3 is not cfg1


def test_reset_clears_singleton(tmp_path) -> None:
    reset_label_config()
    f = tmp_path / "labels.yml"
    f.write_text('epic: "first"\n')
    cfg1 = get_label_config(str(f))
    assert cfg1.epic == "first"

    reset_label_config()
    # After reset, calling without path falls back to default location
    # (which won't exist in tmp_path context), defaults.
    cfg2 = get_label_config(str(tmp_path / "nonexistent.yml"))
    assert cfg2.epic == "epic"  # built-in default
