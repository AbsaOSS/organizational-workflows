# Organizational Workflows

A collection of reusable GitHub Actions workflows with Python automation backends, designed to be shared across an organization. Each solution is self-contained: a reusable workflow and dedicated documentation.

---

## Solutions

| Solution     | Description                                                                                              | Docs                             |
|--------------|----------------------------------------------------------------------------------------------------------|----------------------------------|
| **Security** | Turns Code Scanning alerts (e.g. AquaSec) into a managed GitHub Issues backlog with lifecycle automation | [README](src/security/README.md) |

---

## Repository Layout

```
.github/workflows/          # reusable GitHub Actions workflows (the product)
src/
  core/                     # shared utilities (GitHub API, config, helpers)
  security/                 # security automation scripts & modules
docs/
  security/                 # business-level documentation & example workflows
tests/                      # all tests (mirrors src/ structure)
```

---

## Business Documentation

For a high-level overview of each solution's purpose and value:

- [Security Automation](docs/security/security.md): what it does, how it works, and why it matters

---

## Developer & Contribution Guide

We welcome community contributions!

- [Developer Guide](DEVELOPERS.md)
- [Contributing Guide](CONTRIBUTING.md)

---

## License & Support

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for full terms.

- [Issues](https://github.com/AbsaOSS/organizational-workflows/issues)
- [Discussions](https://github.com/AbsaOSS/organizational-workflows/discussions)
