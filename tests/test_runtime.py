import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from tether_agent.runtime import (
    RESULT_SCHEMA,
    _final_response_from_items,
    _item_activity,
    _parse_result,
    _repository_relative_path,
)


def object_schemas(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield value
        for nested in value.values():
            yield from object_schemas(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from object_schemas(nested)


def test_result_schema_uses_strict_objects_with_required_fields() -> None:
    schemas = list(object_schemas(RESULT_SCHEMA))

    assert schemas
    for schema in schemas:
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])


def test_result_schema_has_a_closed_payload_for_each_output_kind() -> None:
    output_variants = RESULT_SCHEMA["properties"]["outputs"]["items"]["anyOf"]

    kind_by_variant = {
        variant["properties"]["kind"]["enum"][0]: variant for variant in output_variants
    }
    assert set(kind_by_variant) == {
        "pull_request",
        "commit",
        "branch",
        "file",
        "url",
    }
    assert set(kind_by_variant["commit"]["properties"]["payload"]["properties"]) == {
        "project_id",
        "sha",
        "url",
        "message",
    }


def test_parse_result_removes_null_optional_output_fields() -> None:
    parsed = _parse_result(
        json.dumps(
            {
                "status": "completed",
                "message": "Implemented the change",
                "outputs": [
                    {
                        "kind": "commit",
                        "payload": {
                            "project_id": "8aeeee80-5fd0-4c97-a109-0df0364178d3",
                            "sha": "abc123",
                            "url": None,
                            "message": None,
                        },
                    }
                ],
                "completion_note": None,
            }
        )
    )

    assert parsed["outputs"][0]["payload"] == {
        "project_id": "8aeeee80-5fd0-4c97-a109-0df0364178d3",
        "sha": "abc123",
    }


def test_progress_paths_never_escape_the_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    assert (
        _repository_relative_path(str(repository / "src/app.py"), repository)
        == "src/app.py"
    )
    assert _repository_relative_path(str(tmp_path / "secret.txt"), repository) is None
    assert _repository_relative_path("../secret.txt", repository) is None


def test_item_activity_exposes_safe_file_names_but_not_commands(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    file_item = SimpleNamespace(
        type="fileChange",
        changes=[SimpleNamespace(path=str(repository / "src/app.py"))],
    )
    command_item = SimpleNamespace(
        type="commandExecution",
        command="print-secret-token",
        aggregated_output="secret-token",
        command_actions=[],
    )

    file_message, file_payload = _item_activity(
        file_item, working_directory=repository, completed=True
    ) or ("", {})
    command_message, command_payload = _item_activity(
        command_item, working_directory=repository, completed=False
    ) or ("", {})

    assert file_message == "Updated 1 repository file"
    assert file_payload["repository_paths"] == ["src/app.py"]
    assert "print-secret-token" not in command_message
    assert "secret-token" not in command_message
    assert set(command_payload) == {
        "activity_category",
        "semantic_key",
        "phase",
        "milestone",
    }


def test_reasoning_events_are_never_mapped_to_remote_progress(tmp_path: Path) -> None:
    item = SimpleNamespace(type="reasoning", summary=["private chain of thought"])

    assert _item_activity(item, working_directory=tmp_path, completed=True) is None


def test_final_response_prefers_the_final_answer() -> None:
    items = [
        SimpleNamespace(type="agentMessage", phase="commentary", text="working"),
        SimpleNamespace(
            type="agentMessage", phase="final_answer", text='{"status":"completed"}'
        ),
    ]

    assert _final_response_from_items(items) == '{"status":"completed"}'
