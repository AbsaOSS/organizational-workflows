Copilot instructions for Organizational Workflows

Purpose
A collection of reusable GitHub Actions workflows with Python automation backends.
Each workflow domain is a self-contained package under `src/`. The workflows are
designed to be called via `workflow_call` from other repositories.

Structure
```text
src/
├── core/                        # Shared foundation (GitHub API, config, helpers)
│   ├── github/                  # GitHub CLI wrappers (issues, projects)
│   │   ├── client.py            # run_gh / run_cmd subprocess helpers
│   │   ├── issues.py            # Issue CRUD (create, edit, comment, labels)
│   │   └── projects.py          # Projects V2 GraphQL (priority sync)
│   ├── config.py                # Logging setup, RUNNER_DEBUG parsing
│   ├── helpers.py               # Pure utilities (sha256, iso_date, normalize_path)
│   ├── models.py                # Shared data models (Issue)
│   ├── priority.py              # Severity-to-priority mapping
│   └── rendering.py             # Generic Markdown template renderer
│
├── security/                    # Security workflow domain
│   ├── main.py                  # Pipeline orchestrator (validate → check → auth → fetch → parse → sync → notify)
│   ├── config.py                # SecurityConfig dataclass
│   ├── constants.py             # Labels, event types, metadata types, AquaSec API URLs
│   ├── alerts/                  # Alert domain (parsing, models)
│   ├── issues/                  # Issue management (sync, builder, secmeta)
│   └── services/                # Service classes (authenticator, scan_fetcher, label_checker, issue_syncer, notification_sender)
│
tests/                           # Mirrors src/ structure
```

Python style
- Python 3.14
- Type hints for public functions and classes
- Use `logging.getLogger(__name__)`, not print
- Lazy % formatting in logging: `logger.info("msg %s", var)`
- F-strings in exceptions: `raise ValueError(f"Error {var}")`
- Google-style docstrings
- Single blank line at end of file
- No documentation for `__init__` methods and test modules

Patterns
- Classes with `__init__` cannot throw exceptions
- Use private methods (`_method_name`) for internal class helpers
- All logs must start with "<Domain> -" prefix (e.g., "Security -")
- Never disable pylint behavior in the code
- External links should link to a new window

Testing
- Mirror src structure: `src/security/module.py` -> `tests/security/test_module.py`
- Minimal tests, no redundant tests
- All imports at the top of test files (never inside test functions)
- Use conftest.py fixtures for repeated mocking patterns across tests
- Comment sections: `# method_name` before tests
- Use `mocker.patch("module.dependency")` or `mocker.patch.object(Class, "method")`
- Assert pattern: `assert expected == actual`
- Use `pytest.raises(Exception)` for exceptions
- Use `@pytest.mark.parametrize` for data-driven tests (negative/failure scenarios with multiple similar cases)

Quality gates (run after changes, fix only if below threshold)
- Do all changes at once and run the gates afterward
- Run ALWAYS all quality gates at once: `make qa`
- Once a quality gate passes, do not re-run it in different scenarios