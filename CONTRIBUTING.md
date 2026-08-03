# Contributing

## Development setup

Install the locked development environment and run the checks:

```bash
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv build
```

Run `uv run pip-audit` before submitting dependency changes.

## Compatibility

Treat `TETHER_AGENT_*` environment variables, profile paths, SQLite state, OAuth client identity, installation identity, and server protocol fields as compatibility boundaries.
Do not rename or migrate them without an explicit migration design and regression tests.

Never send absolute repository paths, credentials, or setup-session secrets to the server or logs.

## Pull requests

Keep changes focused and include tests for behavior changes.
Update `CHANGELOG.md` for user-visible changes.
Do not commit local configuration, state databases, credentials, or generated distributions.
