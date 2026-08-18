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


def session_id_from(payload: dict[str, Any], headers: dict[str, str]) -> str | None:
    for name in ("x-claude-code-session-id", "x-session-id", "x-trace-id"):
        value = headers.get(name)
        if value:
            return value
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        for key in ("session_id", "trace_id", "conversation_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value
    return None
