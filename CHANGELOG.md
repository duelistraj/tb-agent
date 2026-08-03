# Changelog

All notable changes to this project will be documented in this file.

## 0.5.0 - 2026-08-03

### Added

- Publish the Tether Brain local task-execution daemon as the installable `tb-agent` package.
- Provide the canonical `tb-agent` command and a deprecated `tether-agent` compatibility alias.
- Preserve existing profiles, environment variables, OAuth client identity, server protocol, and operating-system service identities.
- Add trusted PyPI publishing, cross-platform CI, package smoke tests, and dependency auditing.

### Deprecated

- The `tether-agent` executable alias is deprecated and will be removed in 0.6.0.
