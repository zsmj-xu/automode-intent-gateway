from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from .models import NormalizedRequest


@dataclass
class ToolIntent:
    name: str
    arguments: Any
    capability: str
    target: str | None
    side_effect: str
    risk: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewContext:
    user_messages: list[str]
    historical_tool_calls: list[ToolIntent]
    proposed_tool_calls: list[ToolIntent]
    events: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_messages": self.user_messages,
            "historical_tool_calls": [item.to_dict() for item in self.historical_tool_calls],
            "proposed_tool_calls": [item.to_dict() for item in self.proposed_tool_calls],
        }

    def classifier_transcript(self, max_chars: int = 24000) -> list[dict[str, Any]]:
        """A reasoning-free transcript: human text and tool-call intent only."""
        events = [*self.events]
        serialized = json.dumps(events, ensure_ascii=False)
        if len(serialized) <= max_chars:
            return events
        # Keep the latest evidence when a long Agent session exceeds the review budget.
        trimmed: list[dict[str, Any]] = []
        size = 2
        for event in reversed(events):
            event_size = len(json.dumps(event, ensure_ascii=False)) + 1
            if trimmed and size + event_size > max_chars:
                break
            trimmed.append(event)
            size += event_size
        return list(reversed(trimmed))


def build_review_context(
    request: NormalizedRequest,
    proposed_tool_calls: list[dict[str, Any]] | None = None,
) -> ReviewContext:
    user_messages: list[str] = []
    historical: list[ToolIntent] = []
    events: list[dict[str, Any]] = []
    for message in request.messages:
        role = message.get("role")
        if role == "user":
            text = _direct_user_text(message)
            if text:
                user_messages.append(text)
                events.append({"type": "user", "text": text})
        elif role == "assistant":
            message_calls = _assistant_tool_calls(message, source="history")
            historical.extend(message_calls)
            events.extend(
                {"type": "tool_call", "phase": "historical", **call.to_dict()}
                for call in message_calls
            )

    proposed = [normalize_tool_call(item, source="response") for item in proposed_tool_calls or []]
    events.extend(
        {"type": "tool_call", "phase": "proposed", **call.to_dict()}
        for call in proposed
    )
    return ReviewContext(
        user_messages=user_messages,
        historical_tool_calls=historical,
        proposed_tool_calls=proposed,
        events=events,
    )


def normalize_tool_call(call: dict[str, Any], source: str) -> ToolIntent:
    name = str(call.get("name") or call.get("function", {}).get("name") or "unknown")
    arguments = call.get("arguments", call.get("input", {}))
    arguments = _parse_arguments(arguments)
    searchable = f"{name} {json.dumps(arguments, ensure_ascii=False, default=str)}"
    capability = _capability(name, searchable)
    risk = "high" if capability in {"delete", "publish"} else "medium" if capability in {"write", "execute"} else "low"
    side_effect = "external_state_change" if capability == "publish" else "state_change" if capability in {"write", "execute", "delete"} else "read_only"
    return ToolIntent(
        name=name,
        arguments=arguments,
        capability=capability,
        target=_target(arguments),
        side_effect=side_effect,
        risk=risk,
        source=source,
    )


def _direct_user_text(message: dict[str, Any]) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return _strip_harness_context(content)
    if not isinstance(content, list):
        return ""
    return _strip_harness_context("\n".join(
        str(item.get("text", ""))
        for item in content
        if isinstance(item, dict) and item.get("type") in {"text", "input_text"}
    ))


def _assistant_tool_calls(message: dict[str, Any], source: str) -> list[ToolIntent]:
    calls: list[dict[str, Any]] = []
    content = message.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") in {"tool_use", "function_call"}:
                calls.append(item)
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        calls.extend(item for item in tool_calls if isinstance(item, dict))
    function_call = message.get("function_call")
    if isinstance(function_call, dict):
        calls.append(function_call)
    return [normalize_tool_call(call, source=source) for call in calls]


def _parse_arguments(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _capability(name: str, searchable: str) -> str:
    lower_name = re.sub(r"[^a-z0-9]+", " ", name.lower())
    text = searchable.lower()
    if re.search(r"\b(delete|remove|destroy|drop|truncate|rm)\b", f"{lower_name} {text}"):
        return "delete"
    if re.search(r"\b(push|publish|deploy|send|upload|post|create pr|merge)\b", f"{lower_name} {text}"):
        return "publish"
    if re.search(r"(?:^|\s)(?:tee|touch|mkdir|cp|mv)(?:\s|$)|sed\s+-i|>{1,2}\s*[^&]", text):
        return "write"
    if "bash" in lower_name or "shell" in lower_name or "command" in lower_name:
        command = ""
        try:
            parsed = json.loads(searchable[searchable.index("{"):])
            if isinstance(parsed, dict):
                command = str(parsed.get("command", ""))
        except (ValueError, json.JSONDecodeError):
            pass
        if re.match(r"^\s*(?:git\s+(?:status|diff|log|show|branch)|pwd|ls|rg|grep|cat|head|tail|curl|wget)\b", command):
            return "read"
    if re.search(r"\b(write|edit|patch|update|create|insert|put)\b", lower_name):
        return "write"
    if re.search(r"\b(bash|shell|exec|execute|terminal|command|python|node)\b", lower_name):
        return "execute"
    if re.search(r"\b(read|grep|glob|find|search|fetch|get|retrieve|download|list|view|status)\b", lower_name):
        return "read"
    return "unknown"


def _target(arguments: Any) -> str | None:
    if not isinstance(arguments, dict):
        return None
    for key in ("path", "file_path", "url", "command", "query", "target", "resource", "repo"):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return value[:1000]
    return None


def _strip_harness_context(text: str) -> str:
    # Claude Code injects these into user-role content, but they are harness
    # context rather than text typed by the human.
    cleaned = re.sub(
        r"<system-reminder>.*?</system-reminder>",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return cleaned.strip()
