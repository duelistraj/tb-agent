"""Codex SDK adapter constrained to the explicitly supplied context."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from collections.abc import Awaitable, Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from openai_codex import AsyncCodex, Sandbox

from tether_agent.config import RuntimeAdapterSettings
from tether_agent.state import StateStore

ProgressCallback = Callable[[str, dict[str, Any]], Awaitable[None]]


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
        progress: ProgressCallback,
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
        progress: ProgressCallback,
    ) -> dict[str, Any]:
        prompt = self._prompt(context)
        await progress(
            "Codex is preparing the local workspace",
            {"semantic_key": "runtime_preparing", "phase": "preparing"},
        )
        async with AsyncCodex() as codex:
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
                        "for or ingest unrelated Tether Brain workspace content."
                    ),
                )
                self.store.save_thread(run_id, thread.id)
            await progress(
                "Codex is working",
                {"semantic_key": "runtime_working", "phase": "running"},
            )
            result = await thread.run(
                prompt,
                model=model_id,
                effort=reasoning_effort,
                output_schema=RESULT_SCHEMA,
            )
        if result.final_response is None:
            return {
                "status": "failed",
                "message": "Codex returned no final response",
                "outputs": [],
                "completion_note": None,
                "effective_model_id": model_id,
                "effective_reasoning_effort": reasoning_effort,
            }
        try:
            parsed = _parse_result(result.final_response)
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
            "unavailable. Return a question only when user input is required. "
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
        progress: ProgressCallback,
    ) -> dict[str, Any]:
        del run_id
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
