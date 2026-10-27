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

"""Scan-history simulation for Child Issue matching in ``security.issues.sync``.

Purpose
-------
Matching has to survive sequences of scans, not single transitions: an ordinal reused in one scan,
a failed closure in the next, a line shift after that. Hand-written scenarios only cover the
sequences someone thought of. This simulation generates them instead and checks invariants after
every sync, so a change to matching is tested against many histories at once.

Model
-----
Each step applies 1-3 random edits to ``sast`` occurrences of one Rule in two files (shift lines,
move a block, add, remove, revert a removed occurrence), renders the scan the way AquaSec does,
and syncs it against the issues left by the previous step:

- the AquaSec Fingerprint is ``<base>_<ordinal>``, numbered by line order per Rule and file;
- the Result Hash changes with the line and differs between findings, even on the same line.

The generator never adds and removes occurrences in the same file within one scan. An added
occurrence can then take over the removed one's ordinal, which is indistinguishable from a line
shift, so the documented limitation applies.

Invariants
----------
1. **No transfer** - an open issue only ever tracks the finding it was created for.
2. **Accounting** - after a run without API failures, every present finding has exactly one open
   issue and no open issue tracks a finding that is gone.
3. **No needless churn** - a finding never gets a new issue when its file's scan is unambiguous
   (see ``_expected_keepers``).

Usage
-----
CI runs a small number of seeds. To simulate more histories, raise the knobs::

    SYNC_SIMULATION_SEEDS=1000 SYNC_SIMULATION_STEPS=50 pytest tests/security/issues/test_sync_simulation.py

A failure names the invariant, the seed and step, the edits of that step, and the occurrences before
and after as ``#<uid>@<line>``. Re-run a single seed (the seed must lie within the configured range)::

    SYNC_SIMULATION_SEEDS=1000 pytest "tests/security/issues/test_sync_simulation.py::test_scan_history_keeps_issue_ownership[42]"

Known gap
---------
With failed closures, the transfer check is off: an issue left open by a failed closure passes to a
new finding that takes over its ordinal. ``test_sync_failed_closure_does_not_hand_issue_to_new_occurrence``
in ``test_sync.py`` pins it as ``xfail``. Once it is fixed, drop that mark and turn the check on below.
"""

import itertools
import os
import random
from collections import defaultdict
from dataclasses import dataclass, replace

import pytest
from pytest_mock import MockerFixture

from core.models import Issue
from security.alerts.models import Alert
from security.issues.secmeta import load_secmeta
from security.issues.sync import sync_alerts_and_issues

REPO = "test-org/test-repo"
FINGERPRINT_BASES = {"src/a.py": "aaaa1111", "src/b.py": "bbbb2222"}
EDITS = ("shift", "move", "add", "add_insert", "remove", "remove_delete", "revert")
SEEDS = range(int(os.environ.get("SYNC_SIMULATION_SEEDS", "10")))
STEPS = int(os.environ.get("SYNC_SIMULATION_STEPS", "25"))


@dataclass(frozen=True)
class Occurrence:
    """One SAST finding in the simulated code; *uid* is its ground-truth identity."""

    uid: int
    file: str
    line: int


class Code:
    """Simulated code: present occurrences, plus the position each resolved one would come back to."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.present: dict[int, Occurrence] = {}
        self.resolved: dict[int, Occurrence] = {}
        self._uids = itertools.count(1)

    def _lines(self, file: str) -> set[int]:
        return {occ.line for occ in self.present.values() if occ.file == file}

    def _free(self, file: str, at: int, count: int) -> bool:
        return not any(at <= line < at + count for line in self._lines(file))

    def _shift(self, file: str, at: int, delta: int) -> None:
        """Insert (*delta* > 0) or delete (*delta* < 0) unrelated lines starting at line *at*."""
        for store in (self.present, self.resolved):
            for uid, occ in list(store.items()):
                if occ.file != file or occ.line < at:
                    continue
                if occ.line < at - delta:  # inside the deleted range
                    del store[uid]
                else:
                    store[uid] = replace(occ, line=occ.line + delta)

    def add(self, file: str, line: int, uid: int | None = None) -> None:
        """Make *line* of *file* a finding - a brand-new one unless *uid* is given."""
        uid = next(self._uids) if uid is None else uid
        self.resolved.pop(uid, None)
        self.present[uid] = Occurrence(uid, file, line)

    def edit(self) -> str:
        """Apply one random edit and describe it."""
        rng = self.rng
        file = rng.choice(list(FINGERPRINT_BASES))
        kind = rng.choice(EDITS)
        at, count = rng.randint(1, 40), rng.randint(1, 3)
        in_file = sorted((occ for occ in self.present.values() if occ.file == file), key=lambda occ: occ.line)
        gone = sorted((occ for occ in self.resolved.values() if occ.file == file), key=lambda occ: occ.uid)

        if kind == "shift" and (rng.random() < 0.5 or not self._free(file, at, count)):
            self._shift(file, at, count)
        elif kind == "shift":
            self._shift(file, at, -count)
        elif kind == "move":  # a block moves down: only the lines in between shift
            end = at + rng.randint(1, 20)
            if self._free(file, end, count):
                self._shift(file, at, count)
                self._shift(file, end + count, -count)
        elif kind == "add" and at not in self._lines(file):
            self.add(file, at)
        elif kind == "add_insert":
            self._shift(file, at, 1)
            self.add(file, at)
        elif kind in ("remove", "remove_delete") and in_file:
            occ = rng.choice(in_file)
            del self.present[occ.uid]
            if kind == "remove_delete":
                self._shift(file, occ.line, -1)
            self.resolved[occ.uid] = occ
        elif kind == "revert" and gone:
            occ = rng.choice(gone)
            if occ.line in self._lines(file) or rng.random() < 0.5:
                self._shift(file, occ.line, 1)
            self.add(file, occ.line, occ.uid)
        else:
            return f"noop:{kind}({file})"
        return f"{kind}({file}, at={at}, count={count})"


class GitHub:
    """In-memory stand-in for the GitHub calls made by the sync."""

    def __init__(self, mocker: MockerFixture, failures: random.Random, close_failure_rate: float) -> None:
        self.issues: dict[int, Issue] = {}
        self.created_for: dict[int, int] = {}  # child issue number -> uid it was created for
        self.tracking: dict[int, int] = {}  # uid -> issue that tracked it when last seen
        self.failed = False
        self._numbers = itertools.count(1)
        self._failures = failures
        self._close_failure_rate = close_failure_rate
        mocker.patch("security.issues.sync.gh_issue_create", side_effect=lambda *_: next(self._numbers))
        mocker.patch("security.issues.sync.gh_issue_edit_body", return_value=True)
        mocker.patch("security.issues.sync.gh_issue_edit_title", return_value=True)
        mocker.patch("security.issues.sync.gh_issue_get_sub_issue_numbers", return_value=set())
        mocker.patch("security.issues.sync.gh_issue_add_sub_issue_by_number", return_value=True)
        mocker.patch("security.issues.sync.gh_issue_edit_state", side_effect=self._edit_state)

    def _edit_state(self, _repo: str, number: int, state: str) -> bool:
        is_child = load_secmeta(self.issues[number].body).get("type") == "child"
        if state == "closed" and is_child and self._failures.random() < self._close_failure_rate:
            self.failed = True
            return False
        return True


def _scan(code: Code) -> dict[int, Alert]:
    """Render the scan as AquaSec would; alerts are keyed by the findings' ground-truth uids."""
    alerts = []
    for file, base in FINGERPRINT_BASES.items():
        in_file = sorted((occ for occ in code.present.values() if occ.file == file), key=lambda occ: occ.line)
        for ordinal, occ in enumerate(in_file):
            raw = {
                "metadata": {
                    "alert_number": occ.uid,
                    "rule_id": "rule-1",
                    "severity": "high",
                    "file": file,
                    "start_line": occ.line,
                    "end_line": occ.line,
                },
                "alert_details": {"identity_key": f"{base}_{ordinal}", "alert_hash": f"hash-{occ.uid}-{occ.line}"},
            }
            alerts.append(Alert.from_dict(raw, repo=REPO))
    code.rng.shuffle(alerts)  # matching must not depend on scan order
    return {alert.metadata.alert_number: alert for alert in alerts}


def _random_step(code: Code) -> list[str]:
    """Apply 1-3 edits, retrying until no file both gains and loses occurrences."""
    while True:
        present, resolved = dict(code.present), dict(code.resolved)
        edits = [code.edit() for _ in range(code.rng.randint(1, 3))]
        if not any(
            {uid for uid, occ in present.items() if occ.file == file} - code.present.keys()
            and {uid for uid, occ in code.present.items() if occ.file == file} - present.keys()
            for file in FINGERPRINT_BASES
        ):
            return edits
        code.present, code.resolved = present, resolved


def _expected_keepers(
    before: dict[int, Occurrence], code: Code, alerts: dict[int, Alert], github: GitHub
) -> dict[int, int]:
    """Return the findings whose file's scan is unambiguous, mapped to the issue that tracked them.

    - Survivors that kept their lines keep their Result Hash, so they must not get a new issue. The
      same applies to a resolved finding that is back with its exact Result Hash.
    - When survivors shifted, a file is unambiguous only if no occurrence was added, removed or
      reverted, every finding still carries the Finding Identity stored on its issue, and the only
      open issues of its Fingerprint base are the ones tracking its findings. A failed closure leaves
      other open issues behind, and Matching rightly treats them as occurrences. A reverted occurrence
      counts as added even on its exact old line, because Matching refuses the base then (known
      limitation, see the review of #138).
    """
    stored = {uid: load_secmeta(github.issues[number].body) for uid, number in github.tracking.items()}
    open_fingerprints = {
        number: meta.get("fingerprint", "")
        for number, meta in ((number, load_secmeta(issue.body)) for number, issue in github.issues.items())
        if meta.get("type") == "child" and github.issues[number].state == "open"
    }
    keepers: dict[int, int] = {}
    for file, base in FINGERPRINT_BASES.items():
        old = {uid for uid, occ in before.items() if occ.file == file}
        new = {uid for uid, occ in code.present.items() if occ.file == file}
        survivors = old & new
        reappearing = (new - old) & stored.keys()
        exact = {
            uid
            for uid in survivors | reappearing
            if stored[uid].get("alert_hash") == alerts[uid].alert_details.alert_hash
        }
        if all(before[uid].line == code.present[uid].line for uid in survivors):
            keepers.update({uid: github.tracking[uid] for uid in exact})
        elif (
            old == survivors == new
            and {number for number, fp in open_fingerprints.items() if fp.startswith(f"{base}_")}
            == {github.tracking[uid] for uid in new}
            and all(stored[uid].get("fingerprint") == alerts[uid].alert_details.identity_key for uid in new)
        ):
            keepers.update({uid: github.tracking[uid] for uid in new})
    return keepers


def _layout(present: dict[int, Occurrence]) -> str:
    """Describe the occurrences per file as ``#<uid>@<line>``."""
    by_line = sorted(present.values(), key=lambda occ: occ.line)
    return "; ".join(
        f"{file}: " + ", ".join(f"#{occ.uid}@{occ.line}" for occ in by_line if occ.file == file)
        for file in FINGERPRINT_BASES
    )


def _simulate(mocker: MockerFixture, seed: int, *, close_failure_rate: float = 0.0, check_transfers: bool = True) -> None:
    """Run one random scan history and assert the invariants after every sync."""
    rng = random.Random(seed)
    code = Code(rng)
    github = GitHub(mocker, random.Random(f"failures-{seed}"), close_failure_rate)
    for file in FINGERPRINT_BASES:
        for line in rng.sample(range(1, 40), rng.randint(1, 4)):
            code.add(file, line)

    before: dict[int, Occurrence] = {}
    edits = ["initial scan"]
    for step in range(STEPS + 1):
        alerts = _scan(code)
        keepers = _expected_keepers(before, code, alerts, github)
        known = set(github.issues)
        github.failed = False

        sync_alerts_and_issues(alerts, github.issues)

        uid_by_hash = {alert.alert_details.alert_hash: uid for uid, alert in alerts.items()}
        for number in github.issues.keys() - known:
            meta = load_secmeta(github.issues[number].body)
            if meta.get("type") == "child":
                github.created_for[number] = uid_by_hash[meta["alert_hash"]]
        open_by_uid: dict[int, list[int]] = defaultdict(list)
        stale: list[int] = []
        for number, issue in sorted(github.issues.items()):
            meta = load_secmeta(issue.body)
            if meta.get("type") == "child" and issue.state == "open":
                uid = uid_by_hash.get(meta.get("alert_hash", ""))
                (stale if uid is None else open_by_uid[uid]).append(number)

        context = (
            f"seed={seed} step={step} edits={edits}\n"
            f"  before: {_layout(before)}\n"
            f"  after:  {_layout(code.present)}"
        )
        if check_transfers:
            transfers = {
                number: (github.created_for[number], uid)
                for uid, numbers in open_by_uid.items()
                for number in numbers
                if github.created_for[number] != uid
            }
            assert not transfers, f"[transfer] issue -> (created for, now tracks): {transfers}\n{context}"
        if not github.failed:
            unaccounted = {uid: open_by_uid.get(uid, []) for uid in alerts if len(open_by_uid.get(uid, [])) != 1}
            assert not unaccounted and not stale, f"[accounting] {unaccounted=} {stale=}\n{context}"
        churned = {
            uid: (number, open_by_uid.get(uid))
            for uid, number in keepers.items()
            if not open_by_uid.get(uid) or set(open_by_uid[uid]) - known
        }
        assert not churned, f"[churn] finding -> (previous issue, open issues): {churned}\n{context}"

        github.tracking.update({uid: numbers[0] for uid, numbers in open_by_uid.items()})
        before = dict(code.present)
        edits = _random_step(code)


@pytest.mark.parametrize("seed", SEEDS)
def test_scan_history_keeps_issue_ownership(mocker: MockerFixture, seed: int) -> None:
    """Across random edits, issues are never transferred, always accounted for, and kept when unambiguous."""
    _simulate(mocker, seed)


@pytest.mark.parametrize("seed", SEEDS)
def test_scan_history_with_failed_closures_keeps_accounting(mocker: MockerFixture, seed: int) -> None:
    """Failed closures are recovered by the next clean run and cause no needless churn.

    The transfer check is off here; see "Known gap" in the module docstring.
    """
    _simulate(mocker, seed, close_failure_rate=0.3, check_transfers=False)
