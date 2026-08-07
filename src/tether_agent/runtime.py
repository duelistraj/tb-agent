"""Codex SDK adapter constrained to the explicitly supplied context."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import time
from collections.abc import Awaitable, Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from openai_codex import AsyncCodex, CodexConfig, Sandbox

from tether_agent.config import RuntimeAdapterSettings
from tether_agent.state import StateStore

ProgressCallback = Callable[[str, dict[str, Any]], Awaitable[None]]
TokenUsageCallback = Callable[[dict[str, Any]], Awaitable[None]]
TOKEN_USAGE_REPORT_INTERVAL_SECONDS = 2.0
DAEMON_SECRET_ENVIRONMENT_KEYS = frozenset(
    {
        "TETHER_AGENT_ACCESS_TOKEN",
        "TETHER_AGENT_OAUTH_REFRESH_TOKEN",
    }
)


def _child_environment(overrides: dict[str, str]) -> dict[str, str]:
    return {
        **{
            key: value
            for key, value in os.environ.items()
            if key not in DAEMON_SECRET_ENVIRONMENT_KEYS
        },
        **overrides,
    }


def _enum_value(value: Any) -> str | None:
    raw = getattr(value, "value", value)
    return str(raw) if raw is not None else None


def _token_usage_breakdown(value: Any) -> dict[str, int] | None:
    field_by_wire_name = {
        "cached_input_tokens": "cached_input_tokens",
        "input_tokens": "input_tokens",
        "output_tokens": "output_tokens",
        "reasoning_output_tokens": "reasoning_output_tokens",
        "total_tokens": "total_tokens",
    }
    breakdown = {
        wire_name: getattr(value, attribute_name, None)
        for wire_name, attribute_name in field_by_wire_name.items()
    }
    if not all(isinstance(item, int) and item >= 0 for item in breakdown.values()):
        return None
    if breakdown["cached_input_tokens"] > breakdown["input_tokens"]:
        return None
    return breakdown


def _token_usage_payload(value: Any) -> dict[str, Any] | None:
    usage = getattr(value, "token_usage", None)
    last = _token_usage_breakdown(getattr(usage, "last", None))
    total = _token_usage_breakdown(getattr(usage, "total", None))
    context_window = getattr(usage, "model_context_window", None)
    if last is None or total is None:
        return None
    if context_window is not None and (
        not isinstance(context_window, int) or context_window < 1
    ):
        return None
    return {
        "last": last,
        "total": total,
        "model_context_window": context_window,
    }


class TokenUsageReporter:
    def __init__(
        self,
        callback: TokenUsageCallback,
        *,
        interval_seconds: float = TOKEN_USAGE_REPORT_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.callback = callback
        self.interval_seconds = interval_seconds
        self.clock = clock
        self.pending: dict[str, Any] | None = None
        self.last_sent_at: float | None = None

    async def observe(self, payload: dict[str, Any]) -> None:
        self.pending = payload
        now = self.clock()
        if (
            self.last_sent_at is not None
            and now - self.last_sent_at < self.interval_seconds
        ):
            return
        await self._send(now)

    async def flush(self) -> None:
        if self.pending is not None:
            await self._send(self.clock())

    async def _send(self, sent_at: float) -> None:
        payload = self.pending
        if payload is None:
            return
        await self.callback(payload)
        self.pending = None
        self.last_sent_at = sent_at


def _repository_relative_path(path: str, working_directory: Path) -> str | None:
    candidate = Path(path)
    try:
        relative = (
            candidate.resolve().relative_to(working_directory.resolve())
            if candidate.is_absolute()
            else candidate
        )
    except (OSError, ValueError):
        return None
    normalized = relative.as_posix()
    if (
        not normalized
        or normalized.startswith(("/", "~"))
        or ".." in normalized.split("/")
        or ":" in normalized.split("/")[0]
    ):
        return None
    return normalized


def _item_activity(
    item: Any,
    *,
    working_directory: Path,
    completed: bool,
) -> tuple[str, dict[str, Any]] | None:
    value = getattr(item, "root", item)
    item_type = _enum_value(getattr(value, "type", None))
    if item_type == "commandExecution":
        action_types = {
            _enum_value(getattr(getattr(action, "root", action), "type", None))
            for action in getattr(value, "command_actions", [])
        }
        inspecting = bool(action_types) and action_types.issubset(
            {"read", "listFiles", "search"}
        )
        return (
            (
                "Repository inspection completed"
                if completed
                else "Codex is inspecting the repository"
            )
            if inspecting
            else (
                "Local operation completed"
                if completed
                else "Codex is running a local operation"
            ),
            {
                "activity_category": "inspecting" if inspecting else "working",
                "semantic_key": "repository_inspection"
                if inspecting
                else "local_operation",
                "phase": "running",
                "milestone": False,
            },
        )
    if item_type == "fileChange":
        paths = [
            relative
            for change in getattr(value, "changes", [])
            if (
                relative := _repository_relative_path(
                    str(getattr(change, "path", "")), working_directory
                )
            )
        ][:20]
        if not paths:
            return None
        label = "Updated" if completed else "Editing"
        suffix = "" if len(paths) == 1 else "s"
        return (
            f"{label} {len(paths)} repository file{suffix}",
            {
                "activity_category": "editing",
                "semantic_key": "files_updated" if completed else "editing_files",
                "phase": "running",
                "repository_paths": paths,
                "milestone": completed,
            },
        )
    if item_type == "webSearch":
        return (
            "Reference research completed"
            if completed
            else "Codex is researching references",
            {
                "activity_category": "researching",
                "semantic_key": "reference_research",
                "phase": "running",
                "milestone": False,
            },
        )
    if item_type in {"mcpToolCall", "dynamicToolCall"}:
        return (
            "Integration step completed"
            if completed
            else "Codex is using an integration",
            {
                "activity_category": "integrating",
                "semantic_key": "integration",
                "phase": "running",
                "milestone": False,
            },
        )
    if item_type in {"collabAgentToolCall", "subAgentActivity"}:
        return (
            "Delegated work completed"
            if completed
            else "Codex is coordinating delegated work",
            {
                "activity_category": "integrating",
                "semantic_key": "delegated_work",
                "phase": "running",
                "milestone": False,
            },
        )
    if item_type == "imageView":
        path = _repository_relative_path(
            str(getattr(value, "path", "")), working_directory
        )
        return (
            "Repository image inspected"
            if completed
            else "Codex is inspecting a repository image",
            {
                "activity_category": "inspecting",
                "semantic_key": "image_inspection",
                "phase": "running",
                "repository_paths": [path] if path else [],
                "milestone": False,
            },
        )
    if item_type == "contextCompaction":
        return (
            "Codex is organizing the working context",
            {
                "activity_category": "compacting",
                "semantic_key": "context_compaction",
                "phase": "running",
                "milestone": False,
            },
        )
    return None


def _final_response_from_items(items: list[Any]) -> str | None:
    fallback: str | None = None
    for item in reversed(items):
        value = getattr(item, "root", item)
        if _enum_value(getattr(value, "type", None)) != "agentMessage":
            continue
        text = getattr(value, "text", None)
        if not isinstance(text, str):
            continue
        phase = _enum_value(getattr(value, "phase", None))
        if phase == "final_answer":
            return text
        if phase is None and fallback is None:
            fallback = text
    return fallback


class RuntimeAdapter(Protocol):
    runtime_kind: str

    def capability(self) -> dict[str, str | None]: ...

    async def catalog(self) -> dict[str, Any]: ...

    async def run(
        self,
        *,
        run_id: UUID,
        context: dict[str, Any],
        working_directory: Path,
        model_id: str,
        reasoning_effort: str | None,
        environment: dict[str, str],
        progress: ProgressCallback,
        token_usage: TokenUsageCallback,
    ) -> dict[str, Any]: ...


def _nullable(schema_type: str) -> dict[str, Any]:
    return {
        "anyOf": [
            {"type": schema_type},
            {"type": "null"},
        ]
    }


def _output_schema(
    kind: str,
    payload_properties: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": [kind],
            },
            "payload": {
                "type": "object",
                "properties": payload_properties,
                "required": list(payload_properties),
                "additionalProperties": False,
            },
        },
        "required": ["kind", "payload"],
        "additionalProperties": False,
    }


RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["completed", "question", "blocked", "failed"],
        },
        "message": {"type": "string"},
        "outputs": {
            "type": "array",
            "items": {
                "anyOf": [
                    _output_schema(
                        "pull_request",
                        {
                            "project_id": {"type": "string"},
                            "url": {"type": "string"},
                            "number": _nullable("integer"),
                            "title": _nullable("string"),
                        },
                    ),
                    _output_schema(
                        "commit",
                        {
                            "project_id": {"type": "string"},
                            "sha": {"type": "string"},
                            "url": _nullable("string"),
                            "message": _nullable("string"),
                        },
                    ),
                    _output_schema(
                        "branch",
                        {
                            "project_id": {"type": "string"},
                            "name": {"type": "string"},
                            "url": _nullable("string"),
                        },
                    ),
                    _output_schema(
                        "file",
                        {
                            "project_id": {"type": "string"},
                            "path": {"type": "string"},
                        },
                    ),
                    _output_schema(
                        "url",
                        {
                            "url": {"type": "string"},
                            "label": _nullable("string"),
                        },
                    ),
                ]
            },
        },
        "completion_note": {
            "anyOf": [
                {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "markdown": {"type": "string"},
                    },
                    "required": ["title", "markdown"],
                    "additionalProperties": False,
                },
                {"type": "null"},
            ]
        },
    },
    "required": ["status", "message", "outputs", "completion_note"],
    "additionalProperties": False,
}


def _parse_result(response: str) -> dict[str, Any]:
    parsed = json.loads(response)
    for output in parsed["outputs"]:
        output["payload"] = {
            key: value for key, value in output["payload"].items() if value is not None
        }
    return parsed


class CodexRuntime:
    runtime_kind = "codex_cli"

    def __init__(self, store: StateStore, sandbox: str) -> None:
        self.store = store
        self.sandbox = (
            Sandbox.read_only if sandbox == "read_only" else Sandbox.workspace_write
        )

    def capability(self) -> dict[str, str | None]:
        package_version = version("openai-codex")
        return {
            "runtime_kind": self.runtime_kind,
            "runtime_identity": f"openai-codex-sdk/{package_version}",
            "runtime_version": package_version,
        }

    async def catalog(self) -> dict[str, Any]:
        async with AsyncCodex() as codex:
            response = await codex.models()
        models = [
            {
                "id": model.id,
                "display_name": model.display_name,
                "supported_reasoning_efforts": [
                    option.reasoning_effort
                    for option in model.supported_reasoning_efforts
                ],
                "default_reasoning_effort": model.default_reasoning_effort,
                "is_default": model.is_default,
            }
            for model in response.data
            if not model.hidden
        ]
        default_model_id = next(
            (model["id"] for model in models if model["is_default"]),
            models[0]["id"] if models else None,
        )
        if not models:
            raise RuntimeError("Codex reported an empty model catalog")
        return {
            "runtime_kind": self.runtime_kind,
            "default_model_id": default_model_id,
            "models": models,
        }

    async def run(
        self,
        *,
        run_id: UUID,
        context: dict[str, Any],
        working_directory: Path,
        model_id: str,
        reasoning_effort: str | None,
        environment: dict[str, str],
        progress: ProgressCallback,
        token_usage: TokenUsageCallback,
    ) -> dict[str, Any]:
        prompt = self._prompt(context)
        await progress(
            "Codex is preparing the local workspace",
            {
                "activity_category": "preparing",
                "semantic_key": "runtime_preparing",
                "phase": "preparing",
                "milestone": True,
            },
        )
        child_environment = _child_environment(environment)
        async with AsyncCodex(CodexConfig(env=child_environment)) as codex:
            saved_thread_id = self.store.thread_id(run_id)
            if saved_thread_id:
                thread = await codex.thread_resume(
                    saved_thread_id,
                    cwd=str(working_directory),
                    sandbox=self.sandbox,
                )
            else:
                thread = await codex.thread_start(
                    cwd=str(working_directory),
                    sandbox=self.sandbox,
                    developer_instructions=(
                        "Use only the context in this request and files under the "
                        "provided local working directory. Do not search "
                        "for or ingest unrelated Tether Brain workspace content. "
                        "Before changing files, check whether a missing user decision "
                        "would materially change the result and cannot be discovered "
                        "from the task, comments, or repository. If so, stop before "
                        "editing and return one precise question."
                    ),
                )
                self.store.save_thread(run_id, thread.id)
            await progress(
                "Codex is working",
                {
                    "activity_category": "working",
                    "semantic_key": "runtime_working",
                    "phase": "running",
                    "milestone": False,
                },
            )
            turn = await thread.turn(
                prompt,
                model=model_id,
                effort=reasoning_effort,
                output_schema=RESULT_SCHEMA,
            )
            items: list[Any] = []
            turn_error: str | None = None
            usage_reporter = TokenUsageReporter(token_usage)
            async for notification in turn.stream():
                payload = notification.payload
                if notification.method in {"item/started", "item/completed"}:
                    item = getattr(payload, "item", None)
                    if item is not None:
                        if notification.method == "item/completed":
                            items.append(item)
                        activity = _item_activity(
                            item,
                            working_directory=working_directory,
                            completed=notification.method == "item/completed",
                        )
                        if activity is not None:
                            await progress(*activity)
                elif notification.method == "turn/plan/updated":
                    plan = getattr(payload, "plan", [])
                    current = next(
                        (
                            getattr(step, "step", None)
                            for step in plan
                            if _enum_value(getattr(step, "status", None))
                            == "inProgress"
                        ),
                        None,
                    )
                    if isinstance(current, str) and current.strip():
                        await progress(
                            current.strip(),
                            {
                                "activity_category": "planning",
                                "semantic_key": "plan_step",
                                "phase": "running",
                                "milestone": True,
                            },
                        )
                elif notification.method == "context/compacted":
                    await progress(
                        "Codex is organizing the working context",
                        {
                            "activity_category": "compacting",
                            "semantic_key": "context_compaction",
                            "phase": "running",
                            "milestone": False,
                        },
                    )
                elif notification.method == "thread/tokenUsage/updated":
                    usage_payload = _token_usage_payload(payload)
                    if usage_payload is not None:
                        await usage_reporter.observe(usage_payload)
                elif notification.method == "turn/completed":
                    completed_turn = getattr(payload, "turn", None)
                    status_value = _enum_value(getattr(completed_turn, "status", None))
                    if status_value == "failed":
                        error = getattr(completed_turn, "error", None)
                        turn_error = str(
                            getattr(error, "message", None) or "Codex turn failed"
                        )
            await usage_reporter.flush()
            if turn_error is not None:
                raise RuntimeError(turn_error)
            final_response = _final_response_from_items(items)
        if final_response is None:
            return {
                "status": "failed",
                "message": "Codex returned no final response",
                "outputs": [],
                "completion_note": None,
                "effective_model_id": model_id,
                "effective_reasoning_effort": reasoning_effort,
            }
        try:
            await progress(
                "Codex finished local work and is saving the result",
                {
                    "activity_category": "finalizing",
                    "semantic_key": "finalizing_result",
                    "phase": "finalizing",
                    "milestone": True,
                },
            )
            parsed = _parse_result(final_response)
            return {
                **parsed,
                "effective_model_id": model_id,
                "effective_reasoning_effort": reasoning_effort,
            }
        except json.JSONDecodeError:
            return {
                "status": "failed",
                "message": "Codex returned an invalid structured response",
                "outputs": [],
                "completion_note": None,
                "effective_model_id": model_id,
                "effective_reasoning_effort": reasoning_effort,
            }

    @staticmethod
    def _prompt(context: dict[str, Any]) -> str:
        return (
            "Perform the assigned task using only the bounded Tether Brain context "
            "below and the provided local working directory. Attachments are intentionally "
            "unavailable. Ask only when a material decision is required and cannot be "
            "resolved from the supplied context or repository. "
            "Routine progress belongs in the run timeline, not task comments.\n\n"
            "When a durable implementation summary would help, return it as a "
            "completion note.\n\n"
            f"{json.dumps(context, ensure_ascii=False, indent=2)}"
        )


class CommandRuntime:
    """Headless Claude Code or AGY adapter using an explicit local catalog."""

    def __init__(self, settings: RuntimeAdapterSettings) -> None:
        self.runtime_kind = settings.runtime_kind
        self.settings = settings
        self.executable = (
            settings.executable
            or {
                "claude_code": "claude",
                "agy": "agy",
            }[settings.runtime_kind]
        )
        resolved = shutil.which(self.executable)
        if resolved is None:
            raise RuntimeError(
                f"Configured {settings.runtime_kind} executable was not found: "
                f"{self.executable}"
            )
        self.executable = resolved
        result = subprocess.run(
            [self.executable, "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.runtime_version = (result.stdout or result.stderr).strip()[:64]

    def capability(self) -> dict[str, str | None]:
        return {
            "runtime_kind": self.runtime_kind,
            "runtime_identity": (
                f"{self.runtime_kind}-cli/{self.runtime_version or 'unknown'}"
            ),
            "runtime_version": self.runtime_version or None,
        }

    async def catalog(self) -> dict[str, Any]:
        models = [model.model_dump(mode="json") for model in self.settings.models]
        return {
            "runtime_kind": self.runtime_kind,
            "default_model_id": next(
                model["id"] for model in models if model["is_default"]
            ),
            "models": models,
        }

    async def run(
        self,
        *,
        run_id: UUID,
        context: dict[str, Any],
        working_directory: Path,
        model_id: str,
        reasoning_effort: str | None,
        environment: dict[str, str],
        progress: ProgressCallback,
        token_usage: TokenUsageCallback,
    ) -> dict[str, Any]:
        del run_id, token_usage
        prompt = CodexRuntime._prompt(context) + (
            "\n\nReturn only one JSON object matching this JSON Schema:\n"
            f"{json.dumps(RESULT_SCHEMA, ensure_ascii=False)}"
        )
        command = [self.executable, "-p", prompt, "--model", model_id]
        if reasoning_effort is not None:
            command.extend(["--effort", reasoning_effort])
        command.extend(["--output-format", "json"])
        await progress(
            f"{self.capability()['runtime_kind']} is working",
            {"semantic_key": "runtime_working", "phase": "running"},
        )
        result = await asyncio.to_thread(
            subprocess.run,
            command,
            cwd=working_directory,
            env=_child_environment(environment),
            check=True,
            capture_output=True,
            text=True,
        )
        raw = result.stdout.strip()
        try:
            wrapper = json.loads(raw)
            response = (
                wrapper.get("result")
                if isinstance(wrapper, dict) and isinstance(wrapper.get("result"), str)
                else raw
            )
            parsed = _parse_result(response)
        except (json.JSONDecodeError, TypeError, KeyError):
            return {
                "status": "failed",
                "message": (
                    f"{self.runtime_kind} returned an invalid structured response"
                ),
                "outputs": [],
                "completion_note": None,
                "effective_model_id": model_id,
                "effective_reasoning_effort": reasoning_effort,
            }
        return {
            **parsed,
            "effective_model_id": model_id,
            "effective_reasoning_effort": reasoning_effort,
        }


class RuntimeRegistry:
    def __init__(
        self,
        *,
        store: StateStore,
        sandbox: str,
        settings: list[RuntimeAdapterSettings],
    ) -> None:
        adapters: list[RuntimeAdapter] = []
        for runtime in settings:
            if runtime.runtime_kind == "codex_cli":
                adapters.append(CodexRuntime(store, sandbox))
            else:
                adapters.append(CommandRuntime(runtime))
        self._adapters = {adapter.runtime_kind: adapter for adapter in adapters}

    def capabilities(self) -> list[dict[str, str | None]]:
        return [adapter.capability() for adapter in self._adapters.values()]

    async def catalogs(self) -> list[dict[str, Any]]:
        return [await adapter.catalog() for adapter in self._adapters.values()]

    def get(self, runtime_kind: str) -> RuntimeAdapter:
        adapter = self._adapters.get(runtime_kind)
        if adapter is None:
            raise RuntimeError(f"Run requested unavailable runtime: {runtime_kind}")
        return adapter
