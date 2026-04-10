Copilot instructions for Organizational Workflows

Purpose
TBD

Structure
TBD

Python style
- Python 3.14
- Type hints for public functions and classes
- Use `logging.getLogger(__name__)`, not print
- Lazy % formatting in logging: `logger.info("msg %s", var)`
- F-strings in exceptions: `raise ValueError(f"Error {var}")`
- Google-style docstrings
- Single blank line at end of file
- No documentation for `__init__` methods

Patterns
- Classes with `__init__` cannot throw exceptions
- Use private methods (`_method_name`) for internal class helpers
- All info logs must start with "Security workflow -" prefix
- Never disable pylint behaviour in the code

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
- Run all quality gates at once: `make qa`
- Once a quality gate passes, do not re-run it in different scenarios