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

"""Shared low-level utilities – logging control, date helpers, hashing,
path normalisation, and subprocess wrappers for the ``gh`` CLI.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

_verbose_enabled = False


def parse_runner_debug() -> bool:
    raw = os.getenv("RUNNER_DEBUG")
    if raw is None or raw == "":
        return False
    if raw not in {"0", "1"}:
        raise SystemExit("ERROR: RUNNER_DEBUG must be '0' or '1' when set")
    return raw == "1"


def set_verbose_enabled(value: bool) -> None:
    global _verbose_enabled
    _verbose_enabled = bool(value)


def is_verbose() -> bool:
    """Return the current verbose-logging state."""
    return _verbose_enabled


def vprint(msg: str) -> None:
    if _verbose_enabled:
        print(msg)


def utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def iso_date(iso_dt: str | None) -> str:
    if not iso_dt:
        return utc_today()
    if "T" in iso_dt:
        return iso_dt.split("T", 1)[0]
    return iso_dt


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def normalize_path(path: str | None) -> str:
    if not path:
        return ""
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    p = re.sub(r"/+", "/", p)
    return p


def run_cmd(cmd: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=capture_output, text=True)


def run_gh(args: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess:
    cmd = ["gh"] + args
    try:
        return run_cmd(cmd, capture_output=capture_output)
    except FileNotFoundError:
        print("ERROR: gh CLI not found. Install and authenticate gh.", file=sys.stderr)
        raise SystemExit(1)
