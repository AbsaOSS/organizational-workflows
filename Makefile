.PHONY: black pylint mypy pytest-unit qa

PYTHON   := .venv/bin/python
PY_FILES := $(shell git ls-files '*.py')
MIN_PYLINT_SCORE = 9.0
MIN_COVERAGE = 80

black: ## Run Black formatter
	$(PYTHON) -m black .

pylint: ## Run Pylint (threshold >= 9.5)
	$(PYTHON) -m pylint --fail-under=$(MIN_PYLINT_SCORE) $(PY_FILES)

mypy: ## Run mypy static type checker
	$(PYTHON) -m mypy .

pytest-unit: ## Run unit tests with coverage (threshold >= 80%)
	$(PYTHON) -m pytest tests/ --cov=src --cov-fail-under=$(MIN_COVERAGE)

qa: black pylint mypy pytest-unit
