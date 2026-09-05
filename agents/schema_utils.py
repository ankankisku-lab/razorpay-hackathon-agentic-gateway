from typing import Any, Dict, Type

from pydantic import BaseModel


def to_strict_schema(model: Type[BaseModel]) -> Dict[str, Any]:
    """Groq's strict json_schema mode requires every property listed in
    "required" (even ones with a Python-level default — strict mode has
    no concept of optional-with-default, the model must always emit the
    field) and every object to set "additionalProperties": false.
    Pydantic's default model_json_schema() satisfies neither.

    Recurses into nested properties and $defs (Pydantic's home for
    sub-model schemas), not just the top level — a flat, top-level-only
    fix works fine for today's models (none of them nest a sub-model),
    but silently leaves any nested object non-compliant the moment one
    does, which Groq rejects with a 400 the same as a top-level miss.

    Lives in its own module, not inside planner.py or intent_layer.py,
    specifically so both can import it without importing each other.
    """
    schema = model.model_json_schema()

    def _make_strict(node: Dict[str, Any]) -> None:
        if node.get("type") == "object" or "properties" in node:
            node["additionalProperties"] = False
            node["required"] = list(node.get("properties", {}).keys())
            for prop in node.get("properties", {}).values():
                if isinstance(prop, dict):
                    _make_strict(prop)
        for definition in node.get("$defs", {}).values():
            if isinstance(definition, dict):
                _make_strict(definition)

    _make_strict(schema)
    return schema