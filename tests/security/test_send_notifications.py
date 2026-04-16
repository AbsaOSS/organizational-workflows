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

"""Unit tests for ``send_to_teams`` – Adaptive Card builder & CLI helpers."""


import json
import logging
import types
from pathlib import Path

import pytest

from security.send_notifications import (
    _build_card_body,
    _parse_args,
    _resolve_body,
    _text_block,
    build_payload,
    main,
    send_to_teams,
)


# =====================================================================
# _text_block
# =====================================================================


def test_defaults() -> None:
    block = _text_block("hello")
    assert block["type"] == "TextBlock"
    assert block["text"] == "hello"
    assert block["wrap"] is True

def test_extra_kwargs() -> None:
    block = _text_block("hello", weight="Bolder", size="Large")
    assert block["weight"] == "Bolder"
    assert block["size"] == "Large"


# =====================================================================
# _build_card_body
# =====================================================================


def test_body_only() -> None:
    elements = _build_card_body("some body")
    assert len(elements) == 1
    assert elements[0]["type"] == "Container"
    assert elements[0]["items"][0]["text"] == "some body"

def test_with_title() -> None:
    elements = _build_card_body("body", title="Title")
    assert len(elements) == 2
    header = elements[0]
    assert header["type"] == "Container"
    assert header["style"] == "accent"
    assert header["items"][0]["text"] == "Title"

def test_with_title_and_subtitle() -> None:
    elements = _build_card_body("body", title="T", subtitle="S")
    header = elements[0]
    assert len(header["items"]) == 2
    assert header["items"][1]["text"] == "S"


# =====================================================================
# build_payload
# =====================================================================


def test_structure() -> None:
    payload = build_payload("msg")
    assert payload["type"] == "message"
    attachment = payload["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = attachment["content"]
    assert card["type"] == "AdaptiveCard"
    assert card["version"] == "1.5"
    assert isinstance(card["body"], list)

def test_body_text_in_card() -> None:
    payload = build_payload("Hello **world**")
    card_body = payload["attachments"][0]["content"]["body"]
    texts = [item["items"][0]["text"] for item in card_body if "items" in item]
    assert any("Hello **world**" in t for t in texts)

def test_serialisable() -> None:
    payload = build_payload("x", title="T", subtitle="S")
    # Must be JSON serialisable without error
    json.dumps(payload)


# =====================================================================
# _parse_args
# =====================================================================


def test_body_arg() -> None:
    args = _parse_args(["--body", "hello"])
    assert args.body == "hello"
    assert args.body_file is None

def test_body_file_arg() -> None:
    args = _parse_args(["--body-file", "/tmp/f.md"])
    assert args.body_file == "/tmp/f.md"
    assert args.body is None

def test_dry_run() -> None:
    args = _parse_args(["--body", "x", "--dry-run"])
    assert args.dry_run is True

def test_title_and_subtitle() -> None:
    args = _parse_args(["--body", "x", "--title", "T", "--subtitle", "S"])
    assert args.title == "T"
    assert args.subtitle == "S"


# =====================================================================
# _resolve_body
# =====================================================================


def test_from_body_arg() -> None:
    args = _parse_args(["--body", "inline text"])
    assert _resolve_body(args) == "inline text"

def test_from_file(tmp_path: Path) -> None:
    f = tmp_path / "msg.md"
    f.write_text("file content", encoding="utf-8")
    args = _parse_args(["--body-file", str(f)])
    assert _resolve_body(args) == "file content"

def test_no_body_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _parse_args([])
    # stdin is a tty in tests, so it should raise
    fake_stdin = types.SimpleNamespace(isatty=lambda: True)
    monkeypatch.setattr("security.send_notifications.sys.stdin", fake_stdin)
    with pytest.raises(SystemExit):
        _resolve_body(args)

def test_from_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Body is read from stdin when neither --body nor --body-file is given."""
    args = _parse_args([])
    fake_stdin = types.SimpleNamespace(isatty=lambda: False, read=lambda: "piped content")
    monkeypatch.setattr("security.send_notifications.sys.stdin", fake_stdin)
    assert _resolve_body(args) == "piped content"


# =====================================================================
# main
# =====================================================================


def test_dry_run_prints_json(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        main(["--body", "hi", "--dry-run"])
    json_text = next(r.message for r in caplog.records if r.message.strip().startswith("{"))
    payload = json.loads(json_text)
    assert payload["type"] == "message"

def test_empty_body_raises(tmp_path: Path) -> None:
    f = tmp_path / "empty.md"
    f.write_text("   ", encoding="utf-8")
    with pytest.raises(SystemExit, match="empty"):
        main(["--body-file", str(f)])

def test_no_webhook_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    with pytest.raises(SystemExit, match="webhook"):
        main(["--body", "x"])

def test_main_sends_when_not_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-dry-run path: main() calls send_to_teams with the webhook URL."""
    calls: list[tuple] = []
    monkeypatch.setattr("security.send_notifications.send_to_teams", lambda url, payload: calls.append((url, payload)))
    main(["--body", "hi", "--webhook-url", "https://hook"])
    assert len(calls) == 1
    assert calls[0][0] == "https://hook"
    assert calls[0][1]["type"] == "message"


# =====================================================================
# send_to_teams (HTTP mocked)
# =====================================================================


def test_success(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple] = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return types.SimpleNamespace(status_code=200, text="1")

    monkeypatch.setattr("security.send_notifications.requests.post", fake_post)
    send_to_teams("https://hook", {"type": "message"})
    assert len(calls) == 1

def test_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post(url, **kwargs):
        return types.SimpleNamespace(status_code=500, text="error")

    monkeypatch.setattr("security.send_notifications.requests.post", fake_post)
    with pytest.raises(SystemExit, match="failed"):
        send_to_teams("https://hook", {"type": "message"})
