# Repository Structure Proposal

## Current Structure Analysis

```
organizational-workflows/
├── pyproject.toml                    # root-level tooling config (black, mypy)
├── README.md
├── .github/workflows/                # reusable GH Actions workflows (the "product")
│   ├── aquasec-scan.yml
│   └── remove-adept-to-close-on-issue-close.yml
└── github/
    ├── shared/                       # cross-solution Python utils
    │   ├── common.py, models.py, templates.py, priority.py
    │   ├── github_issues.py, github_projects.py
    │   └── __init__.py
    └── security/                     # THE ONLY solution today
        ├── pyproject.toml            # pytest/coverage config (standalone)
        ├── requirements.txt / requirements-dev.txt
        ├── promote_alerts.py, send_to_teams.py, ...  # entrypoints
        ├── utils/                    # security-specific helpers
        ├── tests/                    # security tests
        └── workflows/                # example caller snippets (not real workflows)
```

### Key problems

| # | Problem | Detail |
|---|---------|--------|
| 1 | **`sys.path` hacks everywhere** | Every entrypoint and `conftest.py` manually inserts `..` into `sys.path` so `from shared.…` resolves. This is fragile and won't scale to N solutions. |
| 2 | **No installable package** | `shared/` is not a proper Python package — there's no `pyproject.toml` or `setup.py` for it. You can't `pip install -e .` and get clean imports. |
| 3 | **Flat namespace collision risk** | If a second solution (e.g. `github/compliance/`) also has `utils/models.py`, the bare `from shared.*` and `from utils.*` imports collide on `sys.path`. |
| 4 | **Tests are siloed** | `shared/` has zero tests. Each solution has `pythonpath = [".", ".."]` — a second solution would duplicate the same trick. |
| 5 | **Workflow YAML lives far from its code** | The actual reusable workflow (`.github/workflows/aquasec-scan.yml`) checks out `github/security/` — the link is only in the `run:` step, invisible from the directory tree. |
| 6 | **Root `pyproject.toml` is cosmetic** | It configures black/mypy but nothing is installable. A new contributor can't just `pip install -e '.[dev]'` and run all tests. |

---

## Proposed Structure

The key design decisions:
- **One root Python package** (`shared`) that every solution imports cleanly
- **Each solution is a self-contained namespace package** under `solutions/`
- **A single root `pyproject.toml`** provides the installable dev environment
- **`shared` is installed as a package** — no more `sys.path` hacks

```
organizational-workflows/
│
├── pyproject.toml                         # unified project config (see below)
├── README.md
│
├── .github/
│   └── workflows/                         # ALL reusable GH Actions workflows
│       ├── security-aquasec-scan.yml      # prefixed by solution name
│       ├── security-remove-label.yml
│       ├── compliance-xyz.yml             # future solution
│       └── ...
│
├── shared/                                # ← installable shared Python package
│   ├── __init__.py
│   ├── common.py                          # date, hash, subprocess, parse_runner_debug
│   ├── models.py                          # Issue dataclass, etc.
│   ├── templates.py                       # Markdown template engine
│   ├── priority.py                        # severity-to-priority mapping
│   ├── github_issues.py                   # gh CLI issue operations
│   └── github_projects.py                 # gh CLI project operations
│
├── solutions/                             # each sub-folder = one workflow solution
│   │
│   ├── security/                          # existing solution, relocated
│   │   ├── README.md                      # solution-specific docs
│   │   ├── requirements.txt               # runtime deps beyond shared (PyGithub, requests)
│   │   ├── scripts/                       # shell entrypoints
│   │   │   ├── sync_security_alerts.sh
│   │   │   ├── check_labels.sh
│   │   │   └── collect_alert.sh
│   │   ├── security/                      # Python package (solution-specific logic)
│   │   │   ├── __init__.py
│   │   │   ├── promote_alerts.py
│   │   │   ├── send_to_teams.py
│   │   │   ├── extract_team_security_stats.py
│   │   │   ├── derive_team_security_metrics.py
│   │   │   ├── alert_parser.py            # was utils/alert_parser.py
│   │   │   ├── constants.py
│   │   │   ├── issue_builder.py
│   │   │   ├── issue_sync.py
│   │   │   ├── models.py                  # security-specific models
│   │   │   ├── sec_events.py
│   │   │   ├── secmeta.py
│   │   │   ├── teams.py
│   │   │   ├── templates.py               # security-specific templates
│   │   │   └── logging_config.py
│   │   ├── tests/
│   │   │   ├── conftest.py
│   │   │   ├── test_promote_alerts.py
│   │   │   ├── test_send_to_teams.py
│   │   │   └── ...
│   │   └── workflows/                     # example caller snippets for docs
│   │       ├── aquasec-night-scan.yml
│   │       └── remove-adept-to-close-on-issue-close.yml
│   │
│   └── compliance/                        # future solution — same shape
│       ├── README.md
│       ├── requirements.txt
│       ├── compliance/
│       │   ├── __init__.py
│       │   └── ...
│       └── tests/
│
├── tests/                                 # tests for the shared package
│   ├── __init__.py
│   └── shared/
│       ├── test_common.py
│       ├── test_models.py
│       ├── test_templates.py
│       └── test_priority.py
│
└── docs/                                  # optional: cross-solution docs
    └── adding-a-solution.md
```

---

## How shared utils work (the crucial part)

### Root `pyproject.toml` — the single source of truth

```toml
[project]
name = "organizational-workflows"
version = "0.1.0"
requires-python = ">=3.14"

# no runtime deps here — shared is stdlib-only
dependencies = []

[project.optional-dependencies]
# each solution declares its extras
security = ["PyGithub>=2.0", "requests>=2.32"]
# compliance = ["somelib"]
dev = [
    "organizational-workflows[security]",
    "pytest>=8.0",
    "pytest-cov>=6.0",
]

[tool.pytest.ini_options]
testpaths = ["tests", "solutions/security/tests"]    # add each solution
pythonpath = ["."]                                     # root is on path

[tool.coverage.run]
source = ["shared", "solutions"]
omit = ["*/tests/*"]

[tool.black]
line-length = 120
target-version = ["py314"]
```

### Import resolution — zero `sys.path` hacks

With `pip install -e '.[dev]'` from the repo root, `shared` is an importable package. Every solution file just does:

```python
# solutions/security/security/promote_alerts.py
from shared.common import parse_runner_debug
from shared.github_issues import gh_issue_list_by_label
from shared.priority import parse_severity_priority_map

from security.alert_parser import load_open_alerts_from_file   # solution-local
from security.constants import LABEL_SCOPE_SECURITY
```

No `sys.path.insert`, no `pythonpath = [".", ".."]`. The editable install makes both `shared.*` and each solution's package importable naturally.

### In GitHub Actions workflows

The reusable workflow already checks out the whole repo. The only change is the install step:

```yaml
- name: Install dependencies
  working-directory: org-workflows
  run: pip install -e '.[security]'       # installs shared + security extras

- name: Run alert-to-issue sync
  run: org-workflows/solutions/security/scripts/sync_security_alerts.sh
```

### Adding a new solution (e.g. `compliance`)

1. Create `solutions/compliance/compliance/__init__.py` + logic
2. Create `solutions/compliance/tests/`
3. Add `compliance = ["its-deps"]` to `[project.optional-dependencies]`
4. Add `"solutions/compliance/tests"` to `testpaths`
5. Add reusable workflow(s) in `.github/workflows/compliance-*.yml`
6. `from shared.github_issues import …` — it just works

---

## Migration Roadmap

> **Guiding principle:** the reusable workflows in `.github/workflows/` are the
> product — callers reference them by path + ref.  Every intermediate commit on
> `master` must keep those workflows functional.  The roadmap is therefore split
> into **phases**; each phase is a single PR that lands on `master` in a
> working state.

### Overview

| Phase | Title | PR scope | Product impact |
|-------|-------|----------|----------------|
| 0 | Skeleton & installable root | Additive only | None — nothing moves |
| 1 | Relocate `shared/` to repo root | Move + alias | None — old path still importable during transition |
| 2 | Relocate security solution | Move + rename + import rewrite | Workflow YAML paths updated atomically |
| 3 | Clean up legacy artefacts | Delete old dirs, finalize config | None — old code already unused |
| 4 | Shared-package tests & docs | Additive | None |

---

### Phase 0 — Skeleton & installable root

**Goal:** make the repo `pip install`-able without moving any existing code.

**Changes (single PR):**

1. **Upgrade root `pyproject.toml`** — add `[project]` metadata so the repo
   becomes an installable Python package. Merge the existing `[tool.black]`,
   `[tool.mypy]`, and `[tool.coverage.*]` sections into it.

   ```toml
   [project]
   name = "organizational-workflows"
   version = "0.1.0"
   requires-python = ">=3.14"
   dependencies = []

   [project.optional-dependencies]
   security = ["PyGithub>=2.0", "requests>=2.32"]
   dev = [
       "organizational-workflows[security]",
       "pytest>=8.0",
       "pytest-cov>=6.0",
   ]

   [tool.pytest.ini_options]
   # still pointing at old paths — keeps current tests green
   testpaths = ["github/security/tests"]
   pythonpath = [".", "github", "github/security"]

   [tool.black]
   line-length = 120
   target-version = ["py314"]

   [tool.coverage.run]
   source = ["github"]
   omit = ["*/tests/*", "*/htmlcov/*", "*/__pycache__/*"]
   ```

2. **Create empty `solutions/` directory** with a `.gitkeep`.

3. **Create empty `tests/` directory** at repo root with `__init__.py`.

**Validation:** `pip install -e '.[dev]' && pytest` passes from repo root
(tests still run from old locations via `pythonpath`).

**Product impact:** zero — `.github/workflows/` untouched, no files moved.

---

### Phase 1 — Relocate `shared/` to repo root

**Goal:** move `github/shared/` → `shared/` (top-level importable package)
while keeping old imports working during the transition.

**Changes (single PR):**

1. `git mv github/shared shared`

2. **Leave a compatibility shim** at `github/shared/__init__.py`:

   ```python
   """Backward-compat shim — re-exports everything from the relocated shared package."""
   import importlib, sys, pathlib
   # Point "github.shared" imports at the real "shared" package at repo root.
   _real = importlib.import_module("shared")
   sys.modules[__name__] = _real
   ```

   And for each sub-module (`common`, `models`, etc.) add a one-liner shim:

   ```python
   # github/shared/common.py
   from shared.common import *  # noqa: F401,F403
   ```

   This means **all existing `from shared.…` imports keep working** unchanged —
   both the ones that use `sys.path` to resolve via `github/` parent and any
   future code importing from repo root.

3. **Update root `pyproject.toml` `pythonpath`:**

   ```toml
   pythonpath = [".", "github", "github/security"]
   ```

   (no change needed — `"."` already covers `shared/` at repo root)

**Validation:**
- `pip install -e '.[dev]' && pytest` passes — existing security tests
  unchanged, they still do `from shared.common import …` which resolves via
  either the shim or the real package.
- Run `sync_security_alerts.sh --repo <test-repo> --dry-run` locally.

**Product impact:** zero — `.github/workflows/` untouched. The workflow
checks out the whole repo, so `shared/` at root is available.

---

### Phase 2 — Relocate security solution

**Goal:** move `github/security/` → `solutions/security/` and restructure the
inner `utils/` into a proper `security` Python package.  Update the reusable
workflow YAML atomically in the same commit.

> This is the largest phase.  Do it in one PR so the workflow YAML and the
> script paths it references are always in sync.

**Changes (single PR):**

1. **Create the target layout:**

   ```
   solutions/security/
   ├── README.md                        ← from github/security/README.md
   ├── DEVELOPERS.md                    ← from github/security/DEVELOPERS.md
   ├── requirements.txt                 ← from github/security/requirements.txt
   ├── requirements-dev.txt             ← from github/security/requirements-dev.txt
   ├── scripts/
   │   ├── sync_security_alerts.sh      ← from github/security/sync_security_alerts.sh
   │   ├── check_labels.sh              ← from github/security/check_labels.sh
   │   └── collect_alert.sh             ← from github/security/collect_alert.sh
   ├── security/                        ← Python package
   │   ├── __init__.py                  ← from github/security/utils/__init__.py (updated docstring)
   │   ├── promote_alerts.py            ← from github/security/promote_alerts.py
   │   ├── send_to_teams.py             ← from github/security/send_to_teams.py
   │   ├── extract_team_security_stats.py
   │   ├── derive_team_security_metrics.py
   │   ├── alert_parser.py              ← from github/security/utils/alert_parser.py
   │   ├── constants.py                 ← from github/security/utils/constants.py
   │   ├── issue_builder.py             ← from github/security/utils/issue_builder.py
   │   ├── issue_sync.py                ← from github/security/utils/issue_sync.py
   │   ├── logging_config.py            ← from github/security/utils/logging_config.py
   │   ├── models.py                    ← from github/security/utils/models.py
   │   ├── sec_events.py                ← from github/security/utils/sec_events.py
   │   ├── secmeta.py                   ← from github/security/utils/secmeta.py
   │   ├── teams.py                     ← from github/security/utils/teams.py
   │   └── templates.py                 ← from github/security/utils/templates.py
   ├── tests/                           ← from github/security/tests/
   │   ├── conftest.py
   │   ├── test_promote_alerts.py
   │   ├── test_send_to_teams.py
   │   └── ...                          (tests/utils/*.py flattened into tests/)
   └── workflows/                       ← example caller snippets (docs only)
       ├── aquasec-night-scan.yml
       └── remove-adept-to-close-on-issue-close.yml
   ```

2. **Rewrite imports** in every moved Python file:

   | Old import | New import |
   |-----------|-----------|
   | `from utils.alert_parser import …` | `from security.alert_parser import …` |
   | `from utils.constants import …` | `from security.constants import …` |
   | `from utils.issue_sync import …` | `from security.issue_sync import …` |
   | `from utils.models import …` | `from security.models import …` |
   | `from utils.* import …` | `from security.* import …` |
   | `from shared.common import …` | `from shared.common import …` ← **unchanged** |

3. **Remove all `sys.path` hacks** from:
   - `promote_alerts.py` — delete the `_github_root` / `sys.path.insert` block
   - `send_to_teams.py` — delete the `_script_dir` / `_github_root` / `sys.path` block
   - `tests/conftest.py` — delete the `_SECURITY_DIR` / `_GITHUB_DIR` / `sys.path` block

4. **Update shell scripts** — `sync_security_alerts.sh` uses
   `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"` to find
   siblings.  After the move:
   - `check_labels.sh` and `collect_alert.sh` are in the same `scripts/` dir →
     `SCRIPT_DIR` still works for those.
   - `promote_alerts.py` is now at `../security/promote_alerts.py` relative to
     `scripts/`.  Update the `python3` invocation:

     ```bash
     SOLUTION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
     python3 "$SOLUTION_DIR/security/promote_alerts.py" "${PROMOTE_ARGS[@]}"
     ```

5. **Update `.github/workflows/aquasec-scan.yml`** — this is the critical
   change that must land in the **same commit** as the file moves:

   ```yaml
   # Before
   cache-dependency-path: org-workflows/github/security/requirements.txt
   # After
   cache-dependency-path: org-workflows/solutions/security/requirements.txt

   # Before
   run: pip install -r org-workflows/github/security/requirements.txt
   # After
   run: pip install -e org-workflows/.[security]

   # Before
   run: |
     org-workflows/github/security/sync_security_alerts.sh
   # After
   run: |
     org-workflows/solutions/security/scripts/sync_security_alerts.sh
   ```

6. **Update root `pyproject.toml`:**

   ```toml
   [tool.pytest.ini_options]
   testpaths = ["tests", "solutions/security/tests"]
   pythonpath = ["."]     # only repo root needed now

   [tool.coverage.run]
   source = ["shared", "solutions"]
   omit = ["*/tests/*"]
   ```

7. **Delete `github/security/pyproject.toml`** — no longer needed;
   pytest config is in the root.

**Validation:**
- `pip install -e '.[dev]' && pytest` passes from repo root.
- `solutions/security/scripts/sync_security_alerts.sh --repo <test-repo> --dry-run` works locally.
- Push to a feature branch → verify the reusable workflow runs in a test
  caller repo (or use `act` locally).

**Product impact:**

Callers that pin `.github/workflows/aquasec-scan.yml@<sha>` or `@master`
will get the updated paths **only after they update their ref**.  Since the
workflow YAML and the script paths change in the same commit, there is no
window where one is updated without the other.

Callers pinned to an **old SHA** keep working because that SHA still points
to the old tree with `github/security/`.

---

### Phase 3 — Clean up legacy artefacts

**Goal:** remove backward-compat shims and the now-empty `github/` directory.

**Changes (single PR):**

1. Delete `github/shared/` (the shim files from Phase 1).
2. Delete `github/security/` (any remaining files — should be empty after
   Phase 2 moved everything).
3. Delete the `github/` directory itself.
4. Remove the compatibility `pythonpath` entries from `pyproject.toml` if any
   remain.
5. Grep for any lingering `github/security` or `github/shared` references in
   docs/scripts and update them.

**Validation:** `pip install -e '.[dev]' && pytest` — all green, no import
warnings.

**Product impact:** none — the shims were only used during the transition
between Phase 1 and Phase 2.

---

### Phase 4 — Shared-package tests & docs

**Goal:** add test coverage for `shared/` and create the "adding a solution"
developer guide.

**Changes (single PR):**

1. Create `tests/shared/` with test files:
   - `test_common.py` — `utc_today`, `iso_date`, `sha256_hex`, `normalize_path`,
     `parse_runner_debug`
   - `test_models.py` — `Issue` dataclass
   - `test_templates.py` — `render_markdown_template`
   - `test_priority.py` — `parse_severity_priority_map`, `resolve_priority`

2. Create `docs/adding-a-solution.md` — step-by-step guide for adding a new
   workflow solution (directory template, `pyproject.toml` extras, workflow
   naming convention, import patterns).

3. Update root `README.md` to reflect the new structure and link to
   `docs/adding-a-solution.md`.

4. Update `solutions/security/DEVELOPERS.md` — remove references to
   `sys.path`, `pythonpath = [".", ".."]`, and the old `github/` layout.

**Validation:** `pytest --cov` shows coverage for `shared/` modules.

**Product impact:** none — additive only.

---

### Rollback plan

Each phase is a single PR.  If a phase introduces a regression:

- **Phase 0:** revert the PR — no files were moved.
- **Phase 1:** revert the PR — `shared/` moves back to `github/shared/`.
- **Phase 2:** revert the PR — scripts move back, workflow YAML reverts to old
  paths.  Since the workflow and scripts are in the same commit, reverting
  restores consistency.
- **Phase 3–4:** revert — shims/docs reappear or disappear, no runtime effect.

### Caller migration

Callers (application repos) reference the reusable workflow by path + git ref:

```yaml
uses: AbsaOSS/organizational-workflows/.github/workflows/aquasec-scan.yml@<ref>
```

- **Callers pinned to a SHA before Phase 2:** no action needed — that SHA
  points to the old tree and keeps working.
- **Callers on `@master`:** will pick up the new paths automatically after
  Phase 2 lands.  No change needed in the caller workflow file because the
  reusable workflow filename (`aquasec-scan.yml`) stays the same — only the
  *internal* paths (checked-out script dirs, pip install) change.
- **After Phase 2 stabilises:** callers should update their pinned SHA to a
  post-Phase-2 commit to benefit from future fixes.

---

## Summary

| Concern | Current | Proposed |
|---------|---------|----------|
| Shared utils | `sys.path` hacks, non-installable | `pip install -e .`, normal Python package |
| Adding a solution | Copy-paste path hacks, hope for no collisions | `solutions/<name>/` — templated, isolated |
| Running all tests | `cd github/security && pytest` | `pytest` from root — all solutions + shared |
| Namespace isolation | Flat `utils/` collides across solutions | Each solution is its own Python package |
| CI workflow | Hardcoded paths to `github/security/` | `pip install -e '.[security]'` + namespaced scripts |
