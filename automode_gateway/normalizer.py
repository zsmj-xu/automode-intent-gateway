from __future__ import annotations

import json
from typing import Any, Iterable

from .models import NormalizedRequest


MESSAGE_PATHS = (
    ("data", "proxy_server_request", "messages"),
    ("messages",),
    ("request", "messages"),
    ("body", "messages"),
    ("kwargs", "messages"),
    ("proxy_server_request", "body", "messages"),
    ("kwargs", "litellm_params", "messages"),
    ("kwargs", "litellm_params", "proxy_server_request", "body", "messages"),
)

TOOL_PATHS = tuple(path[:-1] + ("tools",) for path in MESSAGE_PATHS)

MODEL_PATHS = (
    ("data", "proxy_server_request", "model"),
    ("data", "response", "model"),
    ("model",),
    ("request", "model"),
    ("body", "model"),
    ("kwargs", "model"),
    ("proxy_server_request", "body", "model"),
    ("kwargs", "litellm_params", "model"),
)

ID_PATHS = (
    ("data", "response", "id"),
    ("request_id",),
    ("litellm_call_id",),
    ("call_id",),
    ("id",),
    ("kwargs", "litellm_call_id"),
    ("kwargs", "litellm_params", "litellm_call_id"),
)


def _maybe_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return value
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return value


def _get(payload: Any, path: Iterable[str]) -> Any:
    current = payload
    for key in path:
        current = _maybe_json(current)
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return _maybe_json(current)


def _first(payload: dict[str, Any], paths: Iterable[tuple[str, ...]], expected: type) -> Any:
    for path in paths:
        value = _get(payload, path)
        if isinstance(value, expected):
            return value
    return expected()


def extract_messages(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the conversation message list from a request payload, wherever it lives."""
    messages = _first(payload, MESSAGE_PATHS, list)
    return [message for message in messages if isinstance(message, dict)]


def normalize(payload: dict[str, Any], source_format_override: str | None = None) -> NormalizedRequest:
    if not isinstance(payload, dict):
        raise ValueError("request log must be a JSON object")

    messages = extract_messages(payload)
    if not messages:
        raise ValueError(
            "no messages found; supported locations include messages, request.messages, "
            "kwargs.messages and proxy_server_request.body.messages"
        )

    tools = _first(payload, TOOL_PATHS, list)
    tools = [tool for tool in tools if isinstance(tool, dict)]

    model = _first(payload, MODEL_PATHS, str) or None
    request_id = _first(payload, ID_PATHS, str) or None
    metadata = (
        _get(payload, ("data", "proxy_server_request", "metadata"))
        or _get(payload, ("metadata",))
        or _get(payload, ("kwargs", "litellm_params", "metadata"))
        or {}
    )
    if not isinstance(metadata, dict):
        metadata = {}

    if source_format_override:
        source_format = source_format_override
    elif _get(payload, ("data", "proxy_server_request")) is not None:
        source_format = "ai_portal_litellm_detail"
    elif _get(payload, ("proxy_server_request",)) is not None:
        source_format = "litellm_proxy"
    elif _get(payload, ("kwargs",)) is not None:
        source_format = "litellm_callback"
    elif _get(payload, ("request",)) is not None:
        source_format = "nested_request"
    else:
        source_format = "openai_request"

    return NormalizedRequest(
        request_id=request_id,
        model=model,
        messages=messages,
        tools=tools,
        metadata=metadata,
        source_format=source_format,
    )
