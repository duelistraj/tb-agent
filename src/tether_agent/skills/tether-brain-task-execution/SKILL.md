---
name: tether-brain-task-execution
description: Set up, extend, or diagnose Tether Brain from Codex. Use when asked to connect a repository to Tether Brain, configure persistent board-task execution, add a repository or workspace to tb-agent, check the local daemon, or distinguish interactive Codex MCP access from unattended local task execution.
---

# Tether Brain Task Execution

Use the official CLIs for every setup and management operation.
Never request, read, print, store, or place a PAT, OAuth token, authorization code, installation credential, or setup secret in a prompt, Markdown file, log, or shell history.
Never edit tb-agent TOML, SQLite state, environment variables, or service definitions by hand when an official command exists.

## Choose the connection

- For interactive access in the current Codex session, use Codex MCP.
- For persistent execution of assigned Tether Brain board tasks, use `tb-agent`.
- Explain that these are separate connections and that MCP does not create a background task worker.

## Inspect first

1. Confirm the current directory is a Git worktree with `git rev-parse --show-toplevel`.
2. Inspect direct MCP configuration with `codex mcp get tether-brain --json` or `codex mcp list --json`.
3. Inspect persistent execution with `tb-agent status` and `tb-agent auth status`.
4. Use `--profile <name>` on every tb-agent command when the user names a non-default profile.

Do not treat a configured MCP server as evidence that the daemon is configured, or the reverse.

## Configure persistent task execution

For a new installation, run:

```bash
tb-agent init --path .
```

For an initialized profile that needs this repository added, run:

```bash
tb-agent workspace add --path .
```

If Tether Brain supplies a short-lived workspace setup reference, pass it exactly through the supported CLI flag.
Do not decode it or reproduce the setup protocol.

When the CLI opens or prints a browser URL, pause and tell the user to finish sign-in, workspace consent, repository confirmation, and capability approval in the browser.
After the user confirms completion, run `tb-agent status` again.
Report authentication, daemon state, capability approval, mappings, service state, and any remaining action without exposing credential values or local paths outside the terminal response.

Use `tb-agent service install` only when the user explicitly asks to install a background service.
Use `tb-agent service start` only when the user explicitly asks to start it.

## Configure direct Codex MCP

Use the server URL shown by Tether Brain Connections.
For Tether Brain Cloud, the supported flow is:

```bash
codex mcp add tether-brain --url https://tetherbrain.net/mcp --oauth-resource https://tetherbrain.net/mcp
codex mcp login tether-brain --scopes content:read,content:write
```

Prefer OAuth.
Use PAT-based MCP configuration only when the user explicitly chooses the advanced fallback.
After adding or changing the MCP server, explain that it becomes available in a new Codex session.
Do not imply that this enables persistent board-task execution.

## Recover safely

- If authentication is required, use `tb-agent auth login`.
- If a PAT installation should migrate, use `tb-agent auth migrate`.
- If capability approval is pending, direct the user back to the guided browser setup or Tether Brain Agent execution settings.
- If model configuration is incomplete, keep the installation usable and direct the user to retry from setup or Agent execution settings.
- If the daemon is stopped, report the foreground command and optional service commands without running either unless requested.
- If a command reports an active execution, do not mutate configuration or credentials.

Always resume by checking official CLI status.
