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

"""Unit tests for ``utils.constants``."""

from security.constants import (
    LABEL_EPIC,
    LABEL_SCOPE_SECURITY,
    LABEL_SEC_ADEPT_TO_CLOSE,
    LABEL_TYPE_TECH_DEBT,
    SEC_EVENT_OPEN,
    SEC_EVENT_REOPEN,
    SECMETA_TYPE_CHILD,
    SECMETA_TYPE_PARENT,
)


def test_scope_security() -> None:
    assert LABEL_SCOPE_SECURITY == "scope:security"

def test_type_tech_debt() -> None:
    assert LABEL_TYPE_TECH_DEBT == "type:tech-debt"

def test_epic() -> None:
    assert LABEL_EPIC == "epic"

def test_adept_to_close() -> None:
    assert LABEL_SEC_ADEPT_TO_CLOSE == "sec:adept-to-close"


def test_open() -> None:
    assert SEC_EVENT_OPEN == "open"

def test_reopen() -> None:
    assert SEC_EVENT_REOPEN == "reopen"


def test_parent() -> None:
    assert SECMETA_TYPE_PARENT == "parent"

def test_child() -> None:
    assert SECMETA_TYPE_CHILD == "child"
