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

"""Tests for security.config module."""

import argparse

import pytest

from security.config import SecurityConfig


def _make_args(**kwargs) -> argparse.Namespace:
    """Create a minimal argparse Namespace for SecurityConfig.load()."""
    defaults = {
        "repo": "my-org/my-repo",
        "dry_run": False,
        "verbose": False,
        "issue_label": "scope:security",
        "severity_priority_map": "",
        "project_number": "",
        "project_org": "",
        "teams_webhook_url": "",
        "min_severity": "",
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_config(**kwargs) -> SecurityConfig:
    """Create a valid SecurityConfig with overridable fields."""
    defaults = {
        "aqua_key": "test-key",
        "aqua_secret": "test-secret",
        "aqua_group_id": "12345",
        "aqua_repository_id": "abc12345-e89b-12d3-a456-426614174000",
        "repo": "my-org/my-repo",
    }
    defaults.update(kwargs)
    return SecurityConfig(**defaults)


# validate


def test_validate_passes_with_valid_config():
    config = _make_config()
    config.validate()


def test_validate_raises_system_exit_when_aqua_key_missing():
    config = _make_config(aqua_key="")

    with pytest.raises(SystemExit):
        config.validate()


def test_validate_raises_system_exit_when_aqua_secret_missing():
    config = _make_config(aqua_secret="")

    with pytest.raises(SystemExit):
        config.validate()


def test_validate_raises_system_exit_when_group_id_missing():
    config = _make_config(aqua_group_id="")

    with pytest.raises(SystemExit):
        config.validate()


def test_validate_raises_system_exit_when_repository_id_missing():
    config = _make_config(aqua_repository_id="")

    with pytest.raises(SystemExit):
        config.validate()


def test_validate_raises_system_exit_when_repository_id_invalid_uuid():
    config = _make_config(aqua_repository_id="not-a-uuid")

    with pytest.raises(SystemExit):
        config.validate()


def test_validate_raises_system_exit_when_repo_missing():
    config = _make_config(repo="")

    with pytest.raises(SystemExit):
        config.validate()


def test_validate_raises_system_exit_when_repo_no_slash():
    config = _make_config(repo="noslash")

    with pytest.raises(SystemExit):
        config.validate()


# load


def test_load_reads_env_vars(monkeypatch):
    monkeypatch.setenv("AQUA_KEY", "env-key")
    monkeypatch.setenv("AQUA_SECRET", "env-secret")
    monkeypatch.setenv("AQUA_GROUP_ID", "env-group")
    monkeypatch.setenv("AQUA_REPOSITORY_ID", "abc12345-e89b-12d3-a456-426614174000")

    config = SecurityConfig.load(_make_args())

    assert "env-key" == config.aqua_key
    assert "env-secret" == config.aqua_secret
    assert "env-group" == config.aqua_group_id
    assert "abc12345-e89b-12d3-a456-426614174000" == config.aqua_repository_id


def test_load_reads_repo_from_args():
    config = SecurityConfig.load(_make_args(repo="org/repo"))

    assert "org/repo" == config.repo


def test_load_falls_back_to_github_repository_env(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "env-org/env-repo")
    monkeypatch.setenv("AQUA_KEY", "k")
    monkeypatch.setenv("AQUA_SECRET", "s")
    monkeypatch.setenv("AQUA_GROUP_ID", "g")
    monkeypatch.setenv("AQUA_REPOSITORY_ID", "r")

    config = SecurityConfig.load(_make_args(repo=""))

    assert "env-org/env-repo" == config.repo


def test_load_reads_project_number_as_int():
    config = SecurityConfig.load(_make_args(project_number="42"))

    assert 42 == config.project_number


def test_load_handles_invalid_project_number():
    config = SecurityConfig.load(_make_args(project_number="not-a-number"))

    assert config.project_number is None


def test_load_min_severity_defaults_to_low():
    config = SecurityConfig.load(_make_args())

    assert "low" == config.min_severity


def test_load_min_severity_normalizes_to_lowercase():
    config = SecurityConfig.load(_make_args(min_severity="HIGH"))

    assert "high" == config.min_severity


def test_load_min_severity_reads_from_env(monkeypatch):
    monkeypatch.setenv("MIN_SEVERITY", "Critical")
    config = SecurityConfig.load(_make_args())

    assert "critical" == config.min_severity


def test_load_min_severity_arg_takes_precedence_over_env(monkeypatch):
    monkeypatch.setenv("MIN_SEVERITY", "low")
    config = SecurityConfig.load(_make_args(min_severity="high"))

    assert "high" == config.min_severity


def test_validate_raises_system_exit_when_min_severity_invalid():
    config = _make_config(min_severity="extreme")

    with pytest.raises(SystemExit):
        config.validate()


def test_validate_passes_for_all_valid_min_severity_values():
    for level in ("low", "medium", "high", "critical"):
        config = _make_config(min_severity=level)
        config.validate()
