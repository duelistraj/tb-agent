from pathlib import Path

from tether_agent.codex_contract import (
    PLAN_FEATURES,
    CodexPlanningContract,
    contract_from_schema_documents,
    detect_codex_planning_contract,
)
from tether_agent.runtime import CodexRuntime


def complete_contract() -> list[dict[str, object]]:
    return [
        {
            "title": "TurnStartParams",
            "collaborationMode": {"mode": ["plan"]},
            "sandboxPolicy": {"type": ["readOnly"]},
        },
        {"method": "turn/plan/updated", "item": "PlanItem", "status": "completed"},
        {"method": "item/tool/requestUserInput", "type": "RequestUserInput"},
        {"method": "thread/resume", "params": "ThreadResume"},
        {"method": "turn/interrupt", "params": "TurnInterrupt"},
    ]


def test_planning_features_require_every_runtime_contract() -> None:
    detected = contract_from_schema_documents(complete_contract())

    assert detected.supported is True
    for index in range(len(complete_contract())):
        incomplete = complete_contract()
        incomplete.pop(index)
        assert contract_from_schema_documents(incomplete).supported is False


def test_failed_app_server_startup_disables_plan_only(
    monkeypatch, tmp_path: Path
) -> None:
    class BrokenClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            raise RuntimeError("app-server cannot start")

        def __exit__(self, *_args) -> None:
            pass

    monkeypatch.setattr("tether_agent.codex_contract.CodexClient", BrokenClient)

    detected = detect_codex_planning_contract(tmp_path / "codex")
    runtime = CodexRuntime.__new__(CodexRuntime)
    runtime.planning_contract = detected

    assert detected.supported is False
    assert runtime.supported_features() == ()
    assert callable(runtime.run)


def test_complete_runtime_contract_advertises_both_plan_features() -> None:
    runtime = CodexRuntime.__new__(CodexRuntime)
    runtime.planning_contract = CodexPlanningContract(
        collaboration_mode=True,
        plan_items=True,
        structured_user_input=True,
        thread_resume=True,
        turn_interrupt=True,
        read_only_sandbox=True,
    )

    assert runtime.supported_features() == PLAN_FEATURES
