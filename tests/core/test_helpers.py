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

import pytest

from core.helpers import normalize_bullet_list, sanitize_markdown


# sanitize_markdown


@pytest.mark.parametrize(
    "text",
    [None, "", "Normal text without markdown", "text with numbers 123"],
    ids=["none", "empty", "plain", "numbers"],
)
def test_passthrough_unchanged(text: str | None) -> None:
    assert sanitize_markdown(text) == text


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("# Heading one", r"\# Heading one"),
        ("## Heading two", r"\## Heading two"),
        ("### Deep heading", r"\### Deep heading"),
        ("> quoted text", r"\> quoted text"),
        ("| col1 | col2 |", r"\| col1 | col2 |"),
        ("---", r"\---"),
    ],
    ids=["h1", "h2", "h3", "blockquote", "table", "hr"],
)
def test_block_markdown_escaped(raw: str, expected: str) -> None:
    assert expected == sanitize_markdown(raw)


@pytest.mark.parametrize(
    "text",
    ["some **bold** text", "some __bold__ text", "use `code` here"],
    ids=["bold", "underscore-bold", "backtick"],
)
def test_inline_markdown_preserved(text: str) -> None:
    assert text == sanitize_markdown(text)


def test_heading_in_multiline() -> None:
    text = "First line\n## Second is heading\nThird line"
    result = sanitize_markdown(text)
    assert r"\## Second is heading" in result
    assert result.startswith("First line\n")


def test_real_aquasec_message() -> None:
    msg = (
        "## Black is the uncompromising Python code formatter. "
        "Prior to 26.3.1, Black writes a cache file."
    )
    result = sanitize_markdown(msg)
    assert not result.startswith("## ")
    assert result.startswith(r"\## ")


# normalize_bullet_list


@pytest.mark.parametrize("text", [None, ""], ids=["none", "empty"])
def test_normalize_bullet_list_passthrough_empty(text: str | None) -> None:
    assert normalize_bullet_list(text) == text


def test_normalize_bullet_list_already_flat() -> None:
    text = "- https://example.com/a\n- https://example.com/b"
    assert normalize_bullet_list(text) == text


def test_normalize_bullet_list_normalizes_indented() -> None:
    text = "- https://first.example.com\n  - https://second.example.com\n  - https://third.example.com"
    result = normalize_bullet_list(text)
    assert result == "- https://first.example.com\n- https://second.example.com\n- https://third.example.com"


def test_normalize_bullet_list_preserves_non_bullet_lines() -> None:
    text = "Some intro text\n- https://example.com\n  - https://other.com\nTrailing text"
    result = normalize_bullet_list(text)
    assert result == "Some intro text\n- https://example.com\n- https://other.com\nTrailing text"
