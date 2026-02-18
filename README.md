# Organizational workflows

This repository is a small toolkit of repeatable, organization-level workflows for GitHub repositories.
Each workflow lives next to its automation code under `github/` and is documented in a folder-level README.

## Workflows

### Security automation (Code Scanning → Issues)

Turns GitHub Code Scanning alerts (SARIF-based tools such as AquaSec) into a managed GitHub Issues backlog.
Issues become the system of record for ownership, postponement, lifecycle events, and reporting.

- Documentation and usage: [github/security/README.md](github/security/README.md)

## Next

More workflows will be added over time, each with its own folder and README under `github/`.
