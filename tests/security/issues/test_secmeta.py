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

"""Unit tests for ``utils.secmeta``."""

import pytest

from security.issues.secmeta import (
    json_list,
    load_secmeta,
    parse_json_list,
    parse_kv_block,
    render_secmeta,
)


# =====================================================================
# parse_kv_block
# =====================================================================


def test_basic() -> None:
    block = "key1=val1\nkey2=val2"
    assert parse_kv_block(block) == {"key1": "val1", "key2": "val2"}

def test_parse_kv_empty() -> None:
    assert parse_kv_block("") == {}

def test_parse_kv_none() -> None:
    assert parse_kv_block(None) == {}

def test_comments_skipped() -> None:
    assert parse_kv_block("# comment\nk=v") == {"k": "v"}

def test_equals_in_value() -> None:
    result = parse_kv_block("url=https://example.com?a=b")
    assert result["url"] == "https://example.com?a=b"

def test_whitespace_stripped() -> None:
    result = parse_kv_block("  key  =  value  ")
    assert result["key"] == "value"

def test_empty_lines_skipped() -> None:
    result = parse_kv_block("\n\nk=v\n\n")
    assert result == {"k": "v"}


# =====================================================================
# load_secmeta
# =====================================================================


def test_html_comment_format() -> None:
    body = "Some text\n<!--secmeta\nschema=1\ntype=parent\n-->\nMore text"
    result = load_secmeta(body)
    assert result["schema"] == "1"
    assert result["type"] == "parent"

def test_legacy_fenced_format() -> None:
    body = "Some text\n```secmeta\nschema=1\ntype=child\n```\nMore text"
    result = load_secmeta(body)
    assert result["schema"] == "1"
    assert result["type"] == "child"

def test_no_secmeta() -> None:
    assert load_secmeta("No metadata here") == {}

def test_none_body() -> None:
    assert load_secmeta(None) == {}

def test_empty_body() -> None:
    assert load_secmeta("") == {}

def test_prefers_html_comment_over_legacy() -> None:
    """If both formats are present, the HTML comment format wins."""
    body = (
        "<!--secmeta\nformat=html\n-->\n"
        "```secmeta\nformat=legacy\n```"
    )
    result = load_secmeta(body)
    assert result["format"] == "html"


# =====================================================================
# render_secmeta
# =====================================================================


def test_basic_render() -> None:
    rendered = render_secmeta({"schema": "1", "type": "parent"})
    assert rendered.startswith("<!--secmeta")
    assert rendered.endswith("-->")
    assert "schema=1" in rendered
    assert "type=parent" in rendered

def test_preferred_order() -> None:
    data = {
        "type": "child",
        "schema": "1",
        "fingerprint": "abc",
        "severity": "high",
    }
    rendered = render_secmeta(data)
    lines = rendered.strip().split("\n")
    # schema should appear before fingerprint
    schema_idx = next(i for i, l in enumerate(lines) if "schema=" in l)
    fp_idx = next(i for i, l in enumerate(lines) if "fingerprint=" in l)
    assert schema_idx < fp_idx

def test_secmeta_roundtrip() -> None:
    """Render then parse should recover the original data."""
    original = {"schema": "1", "type": "parent", "rule_id": "CVE-123"}
    rendered = render_secmeta(original)
    parsed = load_secmeta(rendered)
    assert parsed == original

def test_extra_keys_sorted() -> None:
    """Keys not in the preferred order are sorted alphabetically."""
    data = {"schema": "1", "zebra": "z", "alpha": "a"}
    rendered = render_secmeta(data)
    lines = rendered.strip().split("\n")
    # Find alpha and zebra positions (after schema)
    alpha_idx = next(i for i, l in enumerate(lines) if "alpha=" in l)
    zebra_idx = next(i for i, l in enumerate(lines) if "zebra=" in l)
    assert alpha_idx < zebra_idx


# =====================================================================
# parse_json_list / json_list
# =====================================================================


def test_json_array() -> None:
    assert parse_json_list('["a","b","c"]') == ["a", "b", "c"]

def test_comma_separated_fallback() -> None:
    assert parse_json_list("a, b, c") == ["a", "b", "c"]

def test_parse_json_list_empty() -> None:
    assert parse_json_list("") == []

def test_parse_json_list_none() -> None:
    assert parse_json_list(None) == []

def test_single_value() -> None:
    assert parse_json_list('["only"]') == ["only"]

def test_numeric_values() -> None:
    assert parse_json_list("[1, 2, 3]") == ["1", "2", "3"]


def test_serialize() -> None:
    result = json_list(["a", "b"])
    assert result == '["a", "b"]'

def test_json_list_empty() -> None:
    assert json_list([]) == "[]"

def test_json_list_roundtrip() -> None:
    original = ["303", "304", "305"]
    assert parse_json_list(json_list(original)) == original
