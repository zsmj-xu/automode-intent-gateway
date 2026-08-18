from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class NormalizedRequest:
    request_id: str | None
    model: str | None
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    metadata: dict[str, Any]
    source_format: str

    @property
    def user_text(self) -> str:
        return "\n".join(
            text
            for message in self.messages
            if message.get("role") == "user"
            for text in [_message_text(message)]
            if text
        )

    @property
    def latest_user_text(self) -> str:
        """Return the latest human text, skipping Anthropic tool_result messages."""
        for message in reversed(self.messages):
            if message.get("role") != "user":
                continue
            text = _message_text(message)
            if text:
                return text
        return ""

    @property
    def system_text(self) -> str:
        return "\n".join(
            str(message.get("content", ""))
            for message in self.messages
            if message.get("role") in {"system", "developer"}
        )


@dataclass
class Classification:
    request_id: str | None
    model: str | None
    intent: str
    speech_act: str
    risk: str
    data_sensitivity: list[str]
    requested_capabilities: list[str]
    forbidden_capabilities: list[str]
    declared_tool_count: int
    reviewed_user_message_count: int
    historical_tool_call_count: int
    proposed_tool_calls: list[dict[str, Any]]
    action_alignment: str
    review_transcript: list[dict[str, Any]]
    decision: str
    reason_codes: list[str] = field(default_factory=list)
    summary: str = ""
    classifier_stage: str = "rules"
    source_format: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _message_text(message: dict[str, Any]) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    chunks: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") in {"text", "input_text"}:
            chunks.append(str(item.get("text", "")))
    return "\n".join(chunks)
