from __future__ import annotations

import json
from typing import Any

from .classifier import classify
from .dlp import evaluate_dlp
from .normalizer import normalize
from .reviewer import review, reviewer_configured


def classify_payload(
    payload: dict[str, Any],
    source_format: str | None = None,
    proposed_tool_calls: list[dict[str, Any]] | None = None,
    run_reviewer: bool = True,
) -> dict[str, Any]:
    request = normalize(payload, source_format_override=source_format)
    result = classify(request, proposed_tool_calls=proposed_tool_calls)
    if proposed_tool_calls is None and run_reviewer:
        # Keep normalized purpose fields for compatibility while making the
        # default classify endpoint evaluate outbound data compliance.
        return {**result.to_dict(), **evaluate_dlp(
            payload, protocol=source_format or request.source_format, upstream="offline",
            identity={"trusted": False, "roles": []}, targets=(), policies=(),
        )}
    if (
        run_reviewer
        and reviewer_configured()
        and result.decision != "deny"
        and (result.decision != "allow" or bool(proposed_tool_calls))
    ):
        result = review(request, result)
    return result.to_dict()
