# Changelog

All notable changes to this project will be documented in this file.

## 0.10.0 - 2026-08-08

### Added

- Give every writable run one deterministic, persisted `feat/<agent>/<task>-<run-id>` branch based on an explicitly resolved remote default branch.
- Add crash-safe, non-force GitHub pull request publication with exact accepted-revision reconciliation, cancellation races, merge detection, and configurable retained cleanup.
- Add `tb-agent changes path <run-id>` for opening the isolated execution worktree and `tb-agent changes publication <run-id>` for reconciling a browser-approved publication.

### Changed

- Keep execution worktrees detached and preserve the user's current checkout during acceptance and handoff.
- Require explicit remote selection when remotes or default branches are ambiguous instead of guessing.
- Delete local feature and snapshot refs only after confirmed merge and `handoff_retention_days`, using expected-head checks so modified refs are never removed.
- Tolerate GitHub automatically deleting a merged pull request branch while retaining publication audit state.

## 0.9.3 - 2026-08-08

### Fixed

- Persist bounded local Git handoff retries so daemon restarts and transient server failures resume without applying an accepted snapshot twice.
- Recover when Git was applied locally but the completion response was lost, while keeping blocked handoffs isolated from other pending results.
- Show handoff attempts, retry timing, and safe failure details through `tb-agent changes status`.

## 0.9.2 - 2026-08-08

### Fixed

- Repair permissions on existing agent-owned daemon logs during startup and create every rotated log with mode `0600`.
- Continue rejecting symlinked, non-regular, and foreign-owned daemon log files instead of modifying them.

## 0.7.2 - 2026-08-05

### Changed

- Send the local configuration revision with OAuth setup and capability registration.
- Stop retrying terminal registration conflicts and show the server's safe recovery message.
- Keep interactive initialization alive through capability approval and model catalogue reporting.

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
