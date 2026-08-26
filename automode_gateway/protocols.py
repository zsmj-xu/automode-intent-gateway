from __future__ import annotations

from copy import deepcopy
from typing import Any


PROTOCOL_BY_PATH = {
    "/v1/messages": "anthropic_messages",
    "/v1/chat/completions": "openai_chat_completions",
    "/v1/responses": "openai_responses",
}


def protocol_for_path(path: str) -> str | None:
    return PROTOCOL_BY_PATH.get(path.rstrip("/") or "/")


def classification_payload(protocol: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Create an analysis-only copy. The upstream always receives original bytes."""
    if protocol != "openai_responses":
        return payload

    adapted = deepcopy(payload)
    if isinstance(adapted.get("messages"), list):
        return adapted

    messages: list[dict[str, Any]] = []
    instructions = adapted.get("instructions")
    if isinstance(instructions, str) and instructions:
        messages.append({"role": "system", "content": instructions})

    input_value = adapted.get("input")
    if isinstance(input_value, str):
        messages.append({"role": "user", "content": input_value})
    elif isinstance(input_value, list):
        for item in input_value:
            message = _response_item_to_message(item)
            if message is not None:
                messages.append(message)
    adapted["messages"] = messages
    return adapted


def _response_item_to_message(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    item_type = item.get("type")
    if item_type in {"function_call_output", "computer_call_output"}:
        return None
    if item_type == "function_call":
        return {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": item.get("call_id") or item.get("id"),
                    "type": "function",
                    "function": {
                        "name": item.get("name"),
                        "arguments": item.get("arguments", "{}"),
                    },
                }
            ],
        }
    if item_type == "message" or isinstance(item.get("role"), str):
        role = item.get("role", "user")
        content = item.get("content", "")
        return {"role": role, "content": content}
    return None


def session_evidence_from(payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    candidates: list[dict[str, str]] = []
    for name in ("x-claude-code-session-id", "x-session-id"):
        value = headers.get(name)
        if value:
            candidates.append({"source": "header", "field": name, "value": value})
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        for key in ("session_id", "conversation_id", "trace_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                candidates.append({"source": "metadata", "field": f"metadata.{key}", "value": value})
    for key in ("conversation", "previous_response_id", "response_id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            candidates.append({"source": "responses", "field": key, "value": value})
    selected = next((item for item in candidates if item["field"] in {
        "x-claude-code-session-id", "x-session-id", "metadata.session_id",
        "metadata.conversation_id", "conversation", "previous_response_id",
    }), None)
    return {
        "status": "provided" if selected else "missing",
        "selected": selected,
        "candidates": candidates,
    }


def session_id_from(payload: dict[str, Any], headers: dict[str, str]) -> str | None:
    evidence = session_evidence_from(payload, headers)
    selected = evidence.get("selected")
    return selected.get("value") if selected else None
