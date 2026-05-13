# Developer Guide

- [Project Setup](#project-setup)
- [Run Pylint Check Locally \[.py\]](#run-pylint-check-locally-py)
- [Run Black Tool Locally \[.py\]](#run-black-tool-locally-py)
- [Run mypy Tool Locally \[.py\]](#run-mypy-tool-locally-py)
- [Run Unit Tests Locally \[.py\]](#run-unit-tests-locally-py)
- [Code Coverage \[.py\]](#code-coverage-py)
- [Run All Quality Checks](#run-all-quality-checks)
- [Releasing](#releasing)

## Project Setup

If you need to build the project locally, follow the steps for dedicated solution:

- **Security Solution:** [Running Locally](src/security/README.md#running-locally)

---

## Run Pylint Check Locally [.py]

This project uses [Pylint](https://pypi.org/project/pylint/) for static code analysis. Pylint analyses your code without actually running it. It checks for errors, enforces coding standards, and looks for code smells.

Pylint displays a global evaluation score for the code, rated out of a maximum score of 10.0. We are aiming to keep our code quality high above the score 9.0.

### Run Pylint

Run Pylint on all files that are currently tracked by Git in the project.

```bash
pylint $(git ls-files '*.py')
```

To run Pylint on a specific file, follow the pattern `pylint <path_to_file>/<name_of_file>.py`.

Example:

```bash
pylint src/security/promote_alerts.py
```

### Expected Output

This is an example of the expected console output after running the tool:

```
************* Module main
main.py:30:0: C0116: Missing function or method docstring (missing-function-docstring)

------------------------------------------------------------------
Your code has been rated at 9.41/10 (previous run: 8.82/10, +0.59)
```

---

## Run Black Tool Locally [.py]

This project uses [Black](https://github.com/psf/black) for code formatting. Black aims for consistency, generality, readability and reducing git diffs. The coding style used can be viewed as a strict subset of PEP 8.

The root project file `pyproject.toml` defines the Black tool configuration. In this project we accept a line length of 120 characters.

### Run Black

Run Black on all files that are currently tracked by Git in the project.

```bash
black $(git ls-files '*.py')
```

To run Black on a specific file, follow the pattern `black <path_to_file>/<name_of_file>.py`.

Example:

```bash
black src/security/promote_alerts.py
```

### Expected Output

This is an example of the expected console output after running the tool:

```
All done! ✨ 🍰 ✨
1 file reformatted.
```

---

## Run mypy Tool Locally [.py]

This project uses [mypy](https://mypy.readthedocs.io/en/stable/) which is a static type checker for Python.

> Type checkers help ensure that you're using variables and functions in your code correctly. With mypy, add type hints (PEP 484) to your Python programs, and mypy will warn you when you use those types incorrectly.

mypy configuration is in the `pyproject.toml` file.

### Run mypy

Run mypy on all files in the project.

```bash
mypy .
```

To run mypy check on a specific file, follow the pattern `mypy <path_to_file>/<name_of_file>.py`.

Example:

```bash
mypy src/security/promote_alerts.py
```

### Expected Output

This is an example of the expected console output after running the tool:

```
Success: no issues found in 1 source file
```

---

## Run Unit Tests Locally [.py]

Unit tests are written using the Pytest framework.

Execute all tests located in the tests directory:

```bash
pytest tests/
```

Run a single test file:

```bash
pytest tests/security/test_collect_alert.py -q
```

Run a single test function (node id):

```bash
pytest tests/security/test_collect_alert.py::test_collect_successful -q
```

---

## Code Coverage [.py]

This project uses [pytest-cov](https://pypi.org/project/pytest-cov/) to generate test coverage reports. The objective of the project is to achieve a minimum score of 80%.

To generate the coverage report, run the following command:

```bash
pytest tests/ --cov=src --cov-fail-under=80 --cov-report=html
```

See the coverage report on the path:

```bash
open htmlcov/index.html
```

---

## Run All Quality Checks

Use the `Makefile` to run all quality gates at once:

For **Python** related checks run:

```bash
make py-qa
```

This runs Black (formatting check), Pylint (static analysis), mypy (type checking), and pytest (unit tests with coverage) sequentially.

---

## Releasing

This project uses GitHub Actions for deployment draft creation. The deployment process is semi-automated by a workflow defined in `.github/workflows/release_draft.yml`.

- **Trigger the workflow**: The `release_draft.yml` workflow is triggered on workflow_dispatch.
- **Create a new draft release**: The workflow creates a new draft release in the repository.
- **Finalize the release draft**: Edit the draft release to add a title, description, and any other necessary details.
- **Publish the release**: Once the draft is ready, publish the release to make it publicly available.
