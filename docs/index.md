---
title: Overview
order: 1
---

# Organizational Workflows

A collection of reusable GitHub Actions workflows with Python automation backends, designed to be
shared across an organization. Each solution is self-contained: a reusable workflow and dedicated
documentation.

## Solutions

| Solution | What it does |
| --- | --- |
| [Security Automation](security/security.md) | Turns AquaSec scan findings into a managed GitHub Issues backlog with full lifecycle automation. |

## Repository Layout

```text
.github/workflows/          # reusable GitHub Actions workflows (the product)
src/
  core/                     # shared utilities (GitHub API, config, helpers)
  security/                 # security automation scripts & modules
docs/
  security/                 # business-level documentation & example workflows
tests/                      # all tests (mirrors src/ structure)
```

## Links

- [Developer Guide](https://github.com/AbsaOSS/organizational-workflows/blob/master/DEVELOPERS.md)
- [Contributing Guide](https://github.com/AbsaOSS/organizational-workflows/blob/master/CONTRIBUTING.md)
- [Issues](https://github.com/AbsaOSS/organizational-workflows/issues)
- [Discussions](https://github.com/AbsaOSS/organizational-workflows/discussions)
