from __future__ import annotations

import json
import gzip
import zlib
from typing import Any


def extract_tool_calls(
    protocol: str,
    body: bytes,
    content_type: str = "",
    content_encoding: str = "",
) -> list[dict[str, Any]]:
    if not body:
        return []
    try:
        body = _decompress_for_analysis(body, content_encoding)
    except (OSError, zlib.error) as exc:
        return [_analysis_incomplete(f"decompression_{type(exc).__name__}")]
    if "text/event-stream" in content_type or body.lstrip().startswith((b"data:", b"event:")):
        events = _sse_json_events(body)
        return _extract_stream(protocol, events)
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [_analysis_incomplete(f"response_parse_{type(exc).__name__}")]
    return _extract_json(protocol, payload)


def _decompress_for_analysis(body: bytes, content_encoding: str) -> bytes:
    encoding = content_encoding.lower().strip()
    if encoding == "gzip":
        return gzip.decompress(body)
    if encoding == "deflate":
        return zlib.decompress(body)
    return body


def _analysis_incomplete(error: str) -> dict[str, Any]:
    return {"name": "response_analysis_incomplete", "arguments": {"error": error}}


def _extract_json(protocol: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    if protocol == "anthropic_messages":
        return [
            {"id": item.get("id"), "name": item.get("name"), "arguments": item.get("input", {})}
            for item in payload.get("content", [])
            if isinstance(item, dict) and item.get("type") == "tool_use"
        ]
    if protocol == "openai_chat_completions":
        calls: list[dict[str, Any]] = []
        for choice in payload.get("choices", []):
            message = choice.get("message", {}) if isinstance(choice, dict) else {}
            for item in message.get("tool_calls", []) or []:
                if isinstance(item, dict):
                    function = item.get("function", {})
                    calls.append({"id": item.get("id"), "name": function.get("name"), "arguments": function.get("arguments", "{}")})
            function_call = message.get("function_call")
            if isinstance(function_call, dict):
                calls.append({"name": function_call.get("name"), "arguments": function_call.get("arguments", "{}")})
        return calls
    if protocol == "openai_responses":
        return [
            {"id": item.get("call_id") or item.get("id"), "name": item.get("name"), "arguments": item.get("arguments", "{}")}
            for item in payload.get("output", [])
            if isinstance(item, dict) and item.get("type") == "function_call"
        ]
    return []


def _extract_stream(protocol: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if protocol == "anthropic_messages":
        return _anthropic_stream(events)
    if protocol == "openai_chat_completions":
        return _chat_stream(events)
    if protocol == "openai_responses":
        return _responses_stream(events)
    return []


def _anthropic_stream(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    calls: dict[int, dict[str, Any]] = {}
    for event in events:
        index = event.get("index")
        if not isinstance(index, int):
            continue
        block = event.get("content_block")
        if event.get("type") == "content_block_start" and isinstance(block, dict) and block.get("type") == "tool_use":
            calls[index] = {"id": block.get("id"), "name": block.get("name"), "arguments": json.dumps(block.get("input", {})) if block.get("input") else ""}
        delta = event.get("delta")
        if index in calls and isinstance(delta, dict) and delta.get("type") == "input_json_delta":
            calls[index]["arguments"] += str(delta.get("partial_json", ""))
    return [_finalize_arguments(item) for _, item in sorted(calls.items())]


def _chat_stream(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    calls: dict[int, dict[str, Any]] = {}
    for event in events:
        for choice in event.get("choices", []):
            delta = choice.get("delta", {}) if isinstance(choice, dict) else {}
            for item in delta.get("tool_calls", []) or []:
                if not isinstance(item, dict):
                    continue
                index = item.get("index", 0)
                call = calls.setdefault(index, {"id": None, "name": "", "arguments": ""})
                call["id"] = item.get("id") or call["id"]
                function = item.get("function", {})
                call["name"] += str(function.get("name", ""))
                call["arguments"] += str(function.get("arguments", ""))
    return [_finalize_arguments(item) for _, item in sorted(calls.items())]


def _responses_stream(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    calls: dict[str, dict[str, Any]] = {}
    completed_response: dict[str, Any] | None = None
    for event in events:
        if event.get("type") == "response.completed" and isinstance(event.get("response"), dict):
            completed_response = event["response"]
        item = event.get("item")
        if isinstance(item, dict) and item.get("type") == "function_call":
            key = str(item.get("call_id") or item.get("id") or event.get("output_index", len(calls)))
            calls[key] = {"id": key, "name": item.get("name"), "arguments": item.get("arguments", "")}
        if event.get("type") == "response.function_call_arguments.delta":
            key = str(event.get("call_id") or event.get("item_id") or event.get("output_index", "0"))
            call = calls.setdefault(key, {"id": key, "name": event.get("name"), "arguments": ""})
            call["arguments"] += str(event.get("delta", ""))
    if completed_response is not None:
        extracted = _extract_json("openai_responses", completed_response)
        if extracted:
            return extracted
    return [_finalize_arguments(item) for item in calls.values()]


def _sse_json_events(body: bytes) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line.startswith(b"data:"):
            continue
        data = line[5:].strip()
        if not data or data == b"[DONE]":
            continue
        try:
            parsed = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


def _finalize_arguments(call: dict[str, Any]) -> dict[str, Any]:
    if call.get("arguments") == "":
        call["arguments"] = "{}"
    return call
