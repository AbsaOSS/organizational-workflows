#!/usr/bin/env python3
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

"""
Send a message to a Microsoft Teams channel via an Incoming Webhook.

The script accepts a Markdown body (from a file, CLI argument, or stdin)
and delivers it as an Adaptive Card to the configured Teams webhook URL.

Markdown support note
---------------------
The body is sent as-is into an Adaptive Card `TextBlock`. Teams renders only a
limited Markdown subset in `TextBlock`. Typically supported formatting:

- Bold: **text**
- Italic: *text*
- Links: [label](https://example.com)
- Simple lists (bulleted/numbered)
- Line breaks / paragraphs (newlines)

Any other Markdown (for example: tables, fenced code blocks, images, HTML,
complex/nested formatting) is still delivered exactly as received, but will
likely display as plain text.

Environment variables
---------------------
TEAMS_WEBHOOK_URL  (required)  The Incoming Webhook URL for the target Teams channel.

Usage examples
--------------
# Body from a file
python3 send_to_teams.py --body-file reports/summary.md --title "Security Report"

# Body from a CLI argument
python3 send_to_teams.py --body "All checks **passed** ✅"

# Body from stdin (pipe)
cat reports/summary.md | python3 send_to_teams.py --title "Daily digest"

# Dry-run (print the payload without sending)
python3 send_to_teams.py --body-file reports/summary.md --dry-run
"""


import argparse
import json
import os
import sys
from typing import Any, Dict, List

import requests


# ---------------------------------------------------------------------------
# Adaptive Card helpers
# ---------------------------------------------------------------------------

def _text_block(text: str, **kwargs: Any) -> Dict[str, Any]:
    """Return an Adaptive Card TextBlock element."""
    block: Dict[str, Any] = {
        "type": "TextBlock",
        "text": text,
        "wrap": True,
    }
    block.update(kwargs)
    return block


def _build_card_body(
    body: str,
    title: str | None = None,
    subtitle: str | None = None,
) -> List[Dict[str, Any]]:
    """Assemble the ``body`` array for an Adaptive Card."""
    elements: List[Dict[str, Any]] = []

    # Optional header container
    if title:
        header_items: List[Dict[str, Any]] = [
            _text_block(title, weight="Bolder", size="Large"),
        ]
        if subtitle:
            header_items.append(
                _text_block(subtitle, isSubtle=True, spacing="None"),
            )
        elements.append({
            "type": "Container",
            "style": "accent",
            "bleed": True,
            "items": header_items,
        })

    # Body container
    elements.append({
        "type": "Container",
        "separator": bool(title),
        "items": [_text_block(body)],
    })

    return elements


def build_payload(
    body: str,
    title: str | None = None,
    subtitle: str | None = None,
) -> Dict[str, Any]:
    """Build the full webhook JSON payload (Adaptive Card message)."""
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.5",
                    "body": _build_card_body(body, title, subtitle),
                },
            }
        ],
    }


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def send_to_teams(webhook_url: str, payload: Dict[str, Any]) -> None:
    """POST *payload* to the Teams Incoming Webhook and raise on failure."""
    resp = requests.post(
        webhook_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    # Teams webhooks return 200 with body "1" on success.
    if resp.status_code != 200 or resp.text.strip() not in ("1", ""):
        raise SystemExit(
            f"Teams webhook request failed.\n"
            f"  Status : {resp.status_code}\n"
            f"  Body   : {resp.text}"
        )
    print("Message sent to Teams successfully.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send a Markdown message to a Microsoft Teams channel via Incoming Webhook. "
            "The body is sent as-is into an Adaptive Card TextBlock; only a limited Markdown subset "
            "is rendered (bold, italic, links, simple lists, newlines). Other Markdown will be delivered "
            "as received and may display as plain text."
        ),
    )

    body_group = parser.add_mutually_exclusive_group()
    body_group.add_argument(
        "--body",
        help="Inline Markdown body text.",
    )
    body_group.add_argument(
        "--body-file",
        help="Path to a file whose contents will be used as the message body.",
    )

    parser.add_argument(
        "--title",
        default=None,
        help="Optional bold title displayed in the card header.",
    )
    parser.add_argument(
        "--subtitle",
        default=None,
        help="Optional subtle subtitle displayed below the title.",
    )
    parser.add_argument(
        "--webhook-url",
        default=os.environ.get("TEAMS_WEBHOOK_URL"),
        help="Teams Incoming Webhook URL (default: $TEAMS_WEBHOOK_URL).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the JSON payload to stdout instead of sending it.",
    )

    return parser.parse_args(argv)


def _resolve_body(args: argparse.Namespace) -> str:
    """Return the message body from --body, --body-file, or stdin."""
    if args.body:
        return args.body

    if args.body_file:
        with open(args.body_file, encoding="utf-8") as fh:
            return fh.read()

    if not sys.stdin.isatty():
        return sys.stdin.read()

    raise SystemExit(
        "No message body provided. Use --body, --body-file, or pipe content via stdin."
    )


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    body = _resolve_body(args)
    if not body.strip():
        raise SystemExit("Message body is empty — nothing to send.")

    webhook_url = args.webhook_url
    if not webhook_url and not args.dry_run:
        raise SystemExit(
            "No webhook URL provided. Set TEAMS_WEBHOOK_URL or pass --webhook-url."
        )

    payload = build_payload(body, title=args.title, subtitle=args.subtitle)

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return

    send_to_teams(webhook_url, payload)


if __name__ == "__main__":
    main()
