import json
from collections.abc import Iterator
from typing import Any

from tether_agent.runtime import RESULT_SCHEMA, _parse_result


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
