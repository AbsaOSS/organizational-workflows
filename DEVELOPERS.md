# Developer Guide — Security Automation

This document covers everything needed to develop, test, and maintain the
scripts in `github/security/`.

## Prerequisites

| Tool | Version | Purpose |
| --- | --- | --- |
| Python | 3.14+ | Runtime for all Python scripts |
| `gh` | latest | GitHub CLI (used by shell scripts) |
| `jq` | latest | JSON processing in shell scripts |

Install runtime **and** development dependencies:

```bash
pip install -r requirements.txt        # runtime deps (requests)
pip install -r requirements-dev.txt    # dev deps     (pytest, pytest-cov)
```

## Project layout

```text
github/security/
├── tests/                   # All unit tests
│   ├── conftest.py          # Shared fixtures (synthetic alert payloads)
│   ├── test_send_to_teams.py
│   └── utils/               # Mirrors utils/ module structure
│       ├── test_alert_parser.py
│       ├── test_constants.py
│       ├── test_issue_builder.py
│       ├── test_issue_sync.py
│       ├── test_models.py
│       ├── test_sec_events.py
│       ├── test_secmeta.py
│       ├── test_teams.py
│       └── test_templates.py
├── utils/                   # Core library modules
├── promote_alerts.py        # Main sync entrypoint (Python)
├── send_to_teams.py         # Teams notification helper
├── pyproject.toml           # pytest & coverage config
├── requirements.txt         # Runtime dependencies
└── requirements-dev.txt     # Development dependencies
```

## Running tests

All commands assume your working directory is the repository root.

### Quick run

```bash
python3 -m pytest tests/ -v
```

### With code coverage

```bash
python3 -m pytest tests/ -v --cov --cov-report=term-missing
```

This prints a per-file summary with uncovered line numbers. Configuration
lives in `pyproject.toml` under `[tool.pytest.ini_options]` and
`[tool.coverage.*]`.

### Generating an HTML coverage report

```bash
python3 -m pytest tests/ --cov --cov-report=html
open htmlcov/index.html
```

### Running a single test file or test

```bash
python3 -m pytest tests/utils/test_alert_parser.py -v
python3 -m pytest tests/utils/test_models.py::test_severity_direction_escalate -v
```

## Test conventions

- **Framework:** [pytest](https://docs.pytest.org/) — strictly plain
  `test_` functions; **no test classes**.
- **Fixtures** are defined in `tests/conftest.py` (shared) or at the top of
  each test module (local).
- **Test data** uses synthetic/generic identifiers (`test-org/test-repo`).
  Do **not** embed real organisation or repository names.
- One test function per behaviour; keep assertions focused.
- Use `monkeypatch` (pytest built-in) for patching external calls
  (subprocess, HTTP, environment variables).

## Code coverage

Coverage is configured in `pyproject.toml`:

```toml
[tool.coverage.run]
source = ["."]
omit = ["tests/*", "__pycache__/*"]

[tool.coverage.report]
show_missing = true
skip_empty = true
exclude_lines = [
    "pragma: no cover",
    "if __name__ == .__main__.",
    "if TYPE_CHECKING:",
]
```

`exclude_lines` tells coverage to ignore lines matching any of these
patterns when calculating percentages:

- `pragma: no cover` — explicit opt-out marker placed in a comment.
- `if __name__ == "__main__":` — script entry-point guard; only runs
  when the file is executed directly, not during tests.
- `if TYPE_CHECKING:` — import block that only runs during static
  analysis (e.g. mypy/pyright), never at runtime.

Modules like `promote_alerts.py`, `extract_team_security_stats.py`, and
`derive_team_security_metrics.py` are integration-heavy and currently have
low unit-test coverage. They would benefit from additional integration or
end-to-end tests.

## Adding new tests

1. Create the test file under `tests/` mirroring the source path
   (e.g. `utils/foo.py` → `tests/utils/test_foo.py`).
2. Import shared fixtures from `conftest.py` where applicable.
3. Write plain `test_` functions — do not wrap them in classes.
4. Run `python3 -m pytest tests/ -v --cov` to verify coverage.

## Style guide

- Formatting follows [Black](https://black.readthedocs.io/) with
  `line-length = 120` (configured in the root `pyproject.toml`).
- Type hints are encouraged; the codebase targets Python 3.14+.
- Use `from __future__ import annotations` where needed for forward
  references.
