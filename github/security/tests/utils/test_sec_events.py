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

"""Unit tests for ``utils.sec_events``."""

import pytest

from utils.sec_events import (
    parse_sec_event_fields,
    render_sec_event,
    strip_sec_events_from_body,
)


# =====================================================================
# parse_sec_event_fields
# =====================================================================


def test_basic_kv() -> None:
    raw = "action=created\nseen_at=2026-01-01\nsource=aquasec"
    result = parse_sec_event_fields(raw)
    assert result == {
        "action": "created",
        "seen_at": "2026-01-01",
        "source": "aquasec",
    }

def test_ignores_blank_and_no_equals() -> None:
    raw = "action=created\n\njust-text\nfoo=bar"
    result = parse_sec_event_fields(raw)
    assert result == {"action": "created", "foo": "bar"}

def test_equals_in_value() -> None:
    raw = "path=a=b"
    result = parse_sec_event_fields(raw)
    assert result == {"path": "a=b"}

def test_empty_string() -> None:
    assert parse_sec_event_fields("") == {}

def test_none_input() -> None:
    assert parse_sec_event_fields(None) == {}

def test_strips_whitespace() -> None:
    raw = "  action = created  \n  seen_at = 2026-01-01  "
    result = parse_sec_event_fields(raw)
    assert result == {"action": "created", "seen_at": "2026-01-01"}


# =====================================================================
# render_sec_event
# =====================================================================


def test_renders_fields_in_preferred_order() -> None:
    fields = {
        "commit_sha": "abc123",
        "action": "created",
        "seen_at": "2026-01-01",
    }
    rendered = render_sec_event(fields)
    lines = rendered.strip().splitlines()
    assert lines[0] == "[sec-event]"
    assert lines[-1] == "[/sec-event]"
    # action should come before commit_sha (preferred order)
    assert lines.index("action=created") < lines.index("commit_sha=abc123")

def test_includes_non_preferred_keys_sorted() -> None:
    fields = {"action": "created", "z_custom": "1", "a_extra": "2"}
    rendered = render_sec_event(fields)
    # extra keys sorted alphabetically after preferred
    assert "a_extra=2" in rendered
    assert "z_custom=1" in rendered
    lines = rendered.strip().splitlines()
    idx_a = lines.index("a_extra=2")
    idx_z = lines.index("z_custom=1")
    assert idx_a < idx_z

def test_skips_blank_values() -> None:
    fields = {"action": "created", "path": "  ", "source": ""}
    rendered = render_sec_event(fields)
    assert "path=" not in rendered
    assert "source=" not in rendered
    assert "action=created" in rendered

def test_roundtrip() -> None:
    fields = {
        "action": "created",
        "seen_at": "2026-01-01",
        "source": "aquasec",
        "gh_alert_number": "42",
        "occurrence_fp": "fp123",
    }
    rendered = render_sec_event(fields)
    # Extract inner content (skip opening/closing tags)
    inner = "\n".join(rendered.strip().splitlines()[1:-1])
    parsed = parse_sec_event_fields(inner)
    assert parsed == fields


# =====================================================================
# strip_sec_events_from_body
# =====================================================================


def test_removes_inline_block() -> None:
    body = "Some text\n[sec-event]\naction=created\n[/sec-event]\nMore text"
    result = strip_sec_events_from_body(body)
    assert "[sec-event]" not in result
    assert "Some text" in result
    assert "More text" in result

def test_removes_section_header() -> None:
    body = "Intro\n\n## Security Events\nold stuff\n"
    result = strip_sec_events_from_body(body)
    assert "## Security Events" not in result
    assert "Intro" in result

def test_empty_body() -> None:
    result = strip_sec_events_from_body("")
    assert result.strip() == ""

def test_none_body() -> None:
    result = strip_sec_events_from_body(None)
    assert result.strip() == ""

def test_no_events() -> None:
    body = "Just regular body text\n"
    result = strip_sec_events_from_body(body)
    assert "Just regular body text" in result

def test_multiple_inline_blocks() -> None:
    body = (
        "Text\n"
        "[sec-event]\naction=created\n[/sec-event]\n"
        "Middle\n"
        "[sec-event]\naction=reopened\n[/sec-event]\n"
        "End\n"
    )
    result = strip_sec_events_from_body(body)
    assert "[sec-event]" not in result
    assert "Text" in result
    assert "Middle" in result
    assert "End" in result

def test_collapses_excessive_newlines() -> None:
    body = "A\n\n\n\n\nB\n"
    result = strip_sec_events_from_body(body)
    assert "\n\n\n" not in result
