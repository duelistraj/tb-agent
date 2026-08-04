# Changelog

All notable changes to this project will be documented in this file.

## 0.7.1 - 2026-08-04

### Fixed

- Reconcile legacy reauthentication state once so browser-revoked installations enter guided replacement instead of a stale reauthorization flow.
- Preserve refresh recovery metadata while classifying installation revocation and avoid repeated retries of terminal credentials.
- Use browser approval as the single confirmation for fresh-installation replacement.

## 0.7.0 - 2026-08-04

### Added

- Add guided replacement of browser-revoked installations through the existing `tb-agent init` command.
- Add `profile list` and guarded `profile remove` commands for explicit local profile management.
- Add online status reconciliation and local-only `status --offline` variants.

### Changed

- Make initialization idempotent for healthy profiles and route new repositories through workspace setup.
- Distinguish a revoked installation from a credential family that only needs reauthorization.
- Clear server-bound leases and Codex thread state atomically only after replacement credentials are validated.

## 0.6.1 - 2026-08-04

### Fixed

- Render the local OAuth callback as a secure HTML confirmation page so browsers return to guided setup instead of displaying raw markup.

## 0.6.0 - 2026-08-04

### Removed

- Remove the `tether-agent` console-script alias so the package installs only the canonical `tb-agent` executable.

### Changed

- Detect service definitions that invoke the removed executable and direct users to reinstall the service definition with `tb-agent service install`.
- Send an explicit setup intent so the guided browser flow can distinguish initialization, reauthorization, migration, workspace addition, and workspace removal.
- Resolve OAuth workspace additions from the current Git remote without prompting for a logical project ID.

## 0.5.0 - 2026-08-03

### Added

- Publish the Tether Brain local task-execution daemon as the installable `tb-agent` package.
- Provide the canonical `tb-agent` command and a deprecated `tether-agent` compatibility alias.
- Preserve existing profiles, environment variables, OAuth client identity, server protocol, and operating-system service identities.
- Add trusted PyPI publishing, cross-platform CI, package smoke tests, and dependency auditing.

### Deprecated

- The `tether-agent` executable alias is deprecated and will be removed in 0.6.0.
