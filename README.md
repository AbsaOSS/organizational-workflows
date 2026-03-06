# Organizational Workflows

A toolkit of repeatable, organization-level GitHub Actions workflows.
Each solution is self-contained: a reusable workflow, Python automation scripts, and a dedicated documentation page.

## Solutions

| Solution | Description | Docs |
|----------|-------------|------|
| **Security** | Turns Code Scanning alerts (SARIF-based, e.g. AquaSec) into a managed GitHub Issues backlog | [docs/security.md](docs/security.md) |

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
shared/                     # shared Python utilities used across solutions
security/                   # security automation scripts & code
  utils/                    # security-specific helper modules
  workflows/                # example caller workflow snippets
tests/                      # all tests (security + shared)
docs/                       # per-solution documentation
```

## Shared workflows

Application repositories adopt a solution by adding a short **caller workflow** that delegates to the reusable workflow in this repo.
See each solution's documentation for caller examples and required secrets.

## Next

More workflow solutions will be added over time.
