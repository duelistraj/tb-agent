# tb-agent

`tb-agent` runs Tether Brain tasks on a local machine using the authenticated Codex CLI.
Tether Brain coordinates runs and persists their results, but it never executes local commands.

OAuth is the default authentication method.
The browser authenticates the user and records explicit workspace and local-execution consent, then the server gives the daemon a separate installation-scoped rotating credential.
The daemon never retains a broad user OAuth token.
PAT remains available as an advanced fallback.

## Install

Install the published package with `uv`:

```bash
uv tool install tb-agent
```

For a repository checkout, install the local package instead:

```bash
uv tool install .
```

The source is maintained at [github.com/duelistraj/tb-agent](https://github.com/duelistraj/tb-agent).

The package installs only the `tb-agent` executable.
Releases before 0.6.0 also installed a `tether-agent` compatibility alias.
After upgrading from an older release, use `uv tool upgrade tb-agent` and update scripts to invoke `tb-agent`.

The Codex CLI must already be installed and authenticated.
Verify it with `codex login status` before initialization.

## Initialize

Initialize the default local profile:

```bash
tb-agent init \
  --server https://tetherbrain.net \
  --path .
```

The CLI opens the guided Tether Brain setup page for sign-in, repository mapping, derived workspace access, capability approval, model selection, and final readiness.
Optional board workflow configuration is available after the installation is connected.
For OAuth setup, the server resolves the normalized Git remote to exactly one accessible logical project, so the user does not copy a project ID.
If the browser cannot be opened, the CLI prints the authorization URL without printing authorization codes or credentials.
Initialization validates the Git worktree, resolves its canonical root, discovers and normalizes its remote, checks Codex authentication, registers or reuses the stored installation identity, and reports whether capability approval is pending.
Initialization never installs a background service.
Running the same command again is safe.
For a healthy profile it reports that the repository is already configured, and for a browser-revoked installation it offers to create a fresh installation through the same guided OAuth flow.
The replacement keeps safe local repository and runtime settings but clears revoked credentials, leases, Codex thread state, and old server identities only after the new credential is validated.

Use PAT fallback only when browser OAuth is unavailable or the server does not support it:

```bash
tb-agent init --auth pat --server https://tetherbrain.net --path .
```

PAT input uses a hidden prompt and is never accepted as a command-line option.

Use `--remote URL` when the repository has ambiguous remotes.
Use `--allow-no-remote` only when a repository intentionally has no remote.

Start the daemon in the foreground:

```bash
tb-agent run
```

Inspect local state without revealing credentials:

```bash
tb-agent status
tb-agent status --offline
```

## Profiles

Every command accepts a global profile option before the command name.
The profile defaults to `default`.

```bash
tb-agent --profile work init --server https://tetherbrain.net
tb-agent --profile work run
tb-agent --profile work status
```

Each profile has an independent configuration, credential, installation identity, daemon lock, and optional service.
Only one daemon process may run for a profile.
`default` is only the local profile name used when `--profile` is omitted.

List or remove local profiles without manually finding platform-specific directories:

```bash
tb-agent profile list
tb-agent --profile work profile remove
```

Profile removal revokes the stored server credential when possible and removes the profile's local configuration, credentials, and service definition.
Use `--local-only` only after browser revocation or when intentionally leaving server cleanup for later.

## Workspaces

Add a workspace mapping without copying a new credential or editing JSON:

```bash
tb-agent workspace add \
  --path .
```

For OAuth profiles, the browser matches the normalized Git remote to the accessible logical projects and asks you to choose when more than one workspace uses that remote.
Workspace access is derived from the confirmed repository instead of being selected independently.
You can also generate this command from workspace Agent execution settings to include a single-use setup reference that identifies the logical project without exposing a credential.
The reference expires quickly, is bound to the selected installation and workspace, and is consumed once.
Direct `--project-id` remains available for advanced and recovery workflows.

List and remove mappings:

```bash
tb-agent workspace list
tb-agent workspace remove 00000000-0000-0000-0000-000000000001
```

OAuth-backed workspace changes reopen browser authorization so workspace expansion always receives explicit user consent.
Workspace mutations coordinate maintenance mode with a running daemon, reject active executions, write the new revision atomically, and trigger live capability re-registration.
The daemon pauses task claims until the changed capability manifest is approved.
PAT-backed profiles retain the Phase 1 manual workspace-grant behavior.

## Codex skill

Install the bundled Codex skill:

```bash
tb-agent codex skill install
```

Inspect or remove it with:

```bash
tb-agent codex skill status
tb-agent codex skill uninstall
```

The skill distinguishes interactive Codex MCP access from persistent board-task execution, detects the current Git repository, and uses the supported `tb-agent` commands.
It never requests, reads, prints, stores, or places PATs or OAuth credentials in prompts or shell history.
Start a new Codex session if a newly installed skill or MCP server is not yet available.

## Authentication

Start or repeat OAuth onboarding:

```bash
tb-agent auth login
```

Migrate an existing PAT installation without changing its installation identity, Agent Profile, mappings, leases, revisions, or Codex threads:

```bash
tb-agent auth migrate
```

Refresh or revoke an OAuth installation credential explicitly:

```bash
tb-agent auth refresh
tb-agent auth revoke
```

`auth revoke` requires the daemon to be stopped, revokes the installation credential server-side, and removes it locally.
Use `auth revoke --purge` only when the profile configuration and state should also be removed.

Configure PAT fallback through a hidden prompt:

```bash
tb-agent auth set-pat
```

Inspect or remove local authentication:

```bash
tb-agent auth status
tb-agent auth logout
```

Logout removes local OAuth or PAT material without revoking server-side credentials.
It preserves the installation identity, Agent Profile identity, configuration, leases, and Codex thread state.

Switching an OAuth installation back to PAT requires typing an explicit confirmation phrase.
The CLI never silently reuses an older PAT.

## Migrate an environment installation

Existing `TETHER_AGENT_*` configurations continue to run without migration.
Environment variables and the current `.env` file remain higher-precedence runtime overrides.

Preview migration while the existing environment is still configured:

```bash
tb-agent migrate env --dry-run
```

Perform the migration:

```bash
tb-agent migrate env
```

Migration copies the PAT, project mappings, installation identity, Agent Profile identity, leases, configuration revision, worktree records, and Codex thread state.
It backs up the legacy SQLite database, is idempotent, and preserves the previous state if any local mutation fails.
It never edits shell startup files.

After successful migration, remove or unset the migrated overrides before using workspace or authentication mutation commands.
The CLI refuses a stored mutation when a relevant environment value would shadow it.

## Background service

Service installation is optional and must be requested explicitly.
Linux uses a user-level systemd unit and macOS uses a LaunchAgent.
Windows supports foreground execution only.

```bash
tb-agent service install
tb-agent service start
tb-agent service stop
tb-agent service restart
tb-agent service status
tb-agent service logs
tb-agent service uninstall
```

Service definitions contain only the resolved `tb-agent` executable, profile name, and service metadata.
They never contain a PAT or repository path.

Existing systemd and LaunchAgent service identities are preserved during the executable rename.
After upgrading from a release before 0.6.0, run `tb-agent service install` once to rewrite an older service definition that invokes the removed executable.

## Local security and state

The CLI stores non-secret settings in a mode-0600 TOML file under the platform configuration directory.
It stores PAT fallback, OAuth setup recovery, installation access and rotating refresh credentials, credential generations, limited refresh recovery state, and execution state in a mode-0600 SQLite database inside a mode-0700 profile directory under the platform state directory.
SQLite uses WAL mode, transactions, and a busy timeout.
TOML replacements are atomic.

Only one process may refresh a profile credential at a time.
The daemon refreshes early, pauses new claims when refresh fails, and never falls back silently to an old PAT.

Repository mappings contain canonical absolute paths only on the local machine.
Capability manifests use logical project IDs and one-way mapping revisions.
Outbound progress, comments, errors, and completion payloads scrub configured repository and worktree paths before transmission.

## Legacy environment reference

The current `TETHER_AGENT_*` variables remain supported for existing deployments, including `TETHER_AGENT_ACCESS_TOKEN`, `TETHER_AGENT_SERVER_URL`, `TETHER_AGENT_INSTALLATION_ID`, `TETHER_AGENT_AGENT_PROFILE_ID`, `TETHER_AGENT_STATE_PATH`, `TETHER_AGENT_RUNTIME_ADAPTERS`, `TETHER_AGENT_PROJECT_MAPPINGS`, and `TETHER_AGENT_WORKTREES`.
An environment `TETHER_AGENT_ACCESS_TOKEN` remains the effective PAT when present and shadows stored OAuth credentials.
OAuth commands report the shadow and print the exact `unset TETHER_AGENT_ACCESS_TOKEN` instruction.
Profile configuration continues to accept only the `codex_cli` runtime.
