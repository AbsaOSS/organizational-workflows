# Organizational Workflows

A toolkit of repeatable, organization-level GitHub Actions workflows.
Each solution is self-contained: a reusable workflow, Python automation scripts, and a dedicated documentation page.

## Solutions

| Solution | Description | Docs |
|----------|-------------|------|
| **Security** | Turns Code Scanning alerts (SARIF-based, e.g. AquaSec) into a managed GitHub Issues backlog | [docs/security/](docs/security/security.md) |

## Quick start

```bash
# install the project (editable) with all dev dependencies
pip install -e '.[dev]'

# run all tests
pytest
```

## Repository layout

```
.github/workflows/          # reusable GitHub Actions workflows (the product)
src/
  shared/                   # shared Python utilities used across solutions
  security/                 # security automation scripts & code
    utils/                  # security-specific helper modules
tests/                      # all tests (security + shared)
docs/                       # per-solution documentation
  security/                 # security solution docs & example workflows
    example_workflows/      # example caller workflows ready to copy into target repos
```

## Shared workflows

Application repositories adopt a solution by adding a short **caller workflow** that delegates to the reusable workflow in this repo.
Ready-to-copy example caller workflows are located in [`docs/security/example_workflows/`](docs/security/example_workflows/).
See each solution's documentation for details and required secrets.

## Next

More workflow solutions will be added over time.
