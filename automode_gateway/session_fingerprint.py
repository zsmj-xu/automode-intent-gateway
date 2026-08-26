from __future__ import annotations

import hashlib
import json
from typing import Any

# Keys that a client may regenerate or reorder without the conversation changing.
_IGNORED_MESSAGE_KEYS = {"id", "index", "cache_control"}


def conversation_fingerprint(messages: list[dict[str, Any]]) -> str | None:
    """A stable, content-derived identity for a conversation carried in a request.

    The anchor is the conversation opener: the first system/developer message plus
    the first direct user message. Both are stable across every turn of the same
    conversation, so consecutive requests match even when the client never sends an
    explicit session id. Returns None when the payload carries no user text.
    """
    first_system = ""
    first_user = ""
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role in {"system", "developer"} and not first_system:
            first_system = _text_of(message)
        elif role == "user" and not first_user:
            first_user = _text_of(message)
            break
    if not first_user:
        return None
    anchor = f"{first_system}\x00{first_user}"
    return hashlib.sha256(anchor.encode("utf-8", "ignore")).hexdigest()[:16]


def messages_are_continuation(previous: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> bool:
    """True when `incoming` is the same conversation as `previous` plus more turns.

    Compares normalized message signatures so id/cache fields and harmless client
    mutations do not break continuity. A divergent conversation (different content
    after the shared opener) fails the check and starts its own session.
    """
    if not previous:
        return True
    if len(incoming) < len(previous):
        return False
    previous_keys = [_message_signature(item) for item in previous]
    incoming_keys = [_message_signature(item) for item in incoming[: len(previous)]]
    return previous_keys == incoming_keys


def _message_signature(message: dict[str, Any]) -> str:
    pruned = {key: value for key, value in message.items() if key not in _IGNORED_MESSAGE_KEYS}
    return json.dumps(pruned, ensure_ascii=False, sort_keys=True, default=str)


def _text_of(message: dict[str, Any]) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") in {"text", "input_text"}:
                chunks.append(str(item.get("text", "")))
        return "\n".join(chunks).strip()
    return ""
