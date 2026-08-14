"""Runtime contract detection for optional native Codex planning support."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from openai_codex import CodexConfig, CodexError
from openai_codex.client import CodexClient

PLAN_FEATURES = ("plan_runs_v1", "structured_user_input_v1")


@dataclass(frozen=True, slots=True)
class CodexPlanningContract:
    collaboration_mode: bool
    plan_items: bool
    structured_user_input: bool
    thread_resume: bool
    turn_interrupt: bool
    read_only_sandbox: bool

    @property
    def supported(self) -> bool:
        return all(
            (
                self.collaboration_mode,
                self.plan_items,
                self.structured_user_input,
                self.thread_resume,
                self.turn_interrupt,
                self.read_only_sandbox,
            )
        )


def _contains(value: Any, needle: str) -> bool:
    if isinstance(value, dict):
        return needle in value or any(
            _contains(item, needle) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains(item, needle) for item in value)
    return isinstance(value, str) and needle in value


def contract_from_schema_documents(
    documents: list[dict[str, Any]],
) -> CodexPlanningContract:
    """Derive support from generated app-server contracts, never a version string."""
    return CodexPlanningContract(
        collaboration_mode=any(
            (
                _contains(document, "TurnStartParams")
                or document.get("title") == "TurnStartParams"
            )
            and _contains(document, "collaborationMode")
            and _contains(document, "plan")
            for document in documents
        ),
        plan_items=any(
            _contains(document, "turn/plan/updated")
            or (_contains(document, "PlanItem") and _contains(document, "completed"))
            for document in documents
        ),
        structured_user_input=any(
            _contains(document, "item/tool/requestUserInput")
            or _contains(document, "RequestUserInput")
            for document in documents
        ),
        thread_resume=any(
            _contains(document, "thread/resume") or _contains(document, "ThreadResume")
            for document in documents
        ),
        turn_interrupt=any(
            _contains(document, "turn/interrupt")
            or _contains(document, "TurnInterrupt")
            for document in documents
        ),
        read_only_sandbox=any(
            _contains(document, "sandboxPolicy")
            and (_contains(document, "readOnly") or _contains(document, "read-only"))
            for document in documents
        ),
    )


def detect_codex_planning_contract(codex_binary: Path) -> CodexPlanningContract:
    """Generate schemas from the installed binary and validate required contracts."""
    with TemporaryDirectory(prefix="tb-agent-codex-contract-") as directory:
        root = Path(directory)
        state = root / "state"
        state.mkdir(mode=0o700)
        try:
            with CodexClient(
                CodexConfig(
                    codex_bin=str(codex_binary),
                    env={**os.environ, "CODEX_HOME": str(state)},
                )
            ) as client:
                client.initialize()
        except (CodexError, OSError, RuntimeError, TimeoutError):
            return CodexPlanningContract(False, False, False, False, False, False)
        output = root / "schema"
        output.mkdir()
        result = subprocess.run(
            [
                str(codex_binary),
                "app-server",
                "generate-json-schema",
                "--out",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return CodexPlanningContract(False, False, False, False, False, False)
        documents: list[dict[str, Any]] = []
        for path in output.rglob("*.json"):
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(parsed, dict):
                documents.append(
                    {
                        **parsed,
                        "__schema_file__": str(path.relative_to(output)),
                    }
                )
        return contract_from_schema_documents(documents)
