from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Iterable

from .classifier import classify
from .decision import StageResult
from .models import NormalizedRequest


@dataclass(frozen=True)
class CompiledRule:
    id: str
    version: int
    name: str
    effect: str
    priority: int
    protocols: tuple[str, ...]
    models: tuple[str, ...]
    tools: tuple[str, ...]
    capabilities: tuple[str, ...]
    target_environment: tuple[str, ...]
    target_contains: tuple[str, ...]
    reason_code: str
    reason: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CompiledRule":
        scope = value.get("scope") or {}
        conditions = value.get("conditions") or {}
        return cls(
            id=str(value.get("id", "preview")),
            version=int(value.get("version", 1)),
            name=str(value.get("name", "Unnamed rule")),
            effect=str(value.get("effect", "escalate")),
            priority=int(value.get("priority", 50)),
            protocols=tuple(scope.get("protocols") or ["*"]),
            models=tuple(scope.get("models") or ["*"]),
            tools=tuple(scope.get("tools") or ["*"]),
            capabilities=tuple(conditions.get("capabilities") or []),
            target_environment=tuple(conditions.get("target_environment") or []),
            target_contains=tuple(conditions.get("target_contains") or []),
            reason_code=str(value.get("reason_code", "CUSTOM_RULE")),
            reason=str(value.get("reason", value.get("name", "Custom policy matched"))),
        )


def evaluate_rules(
    request: NormalizedRequest,
    proposed_tool_calls: list[dict[str, Any]],
    rules: Iterable[dict[str, Any]] = (),
    session_baseline: dict[str, Any] | None = None,
) -> tuple[StageResult, dict[str, Any]]:
    started = time.perf_counter()
    baseline = classify(request, proposed_tool_calls, session_baseline=session_baseline)
    actions = baseline.proposed_tool_calls
    matches: list[CompiledRule] = []
    for raw in rules:
        rule = CompiledRule.from_dict(raw)
        if _matches(rule, request, actions):
            matches.append(rule)
    matches.sort(key=lambda item: item.priority, reverse=True)

    if any(rule.effect == "always_alert" for rule in matches):
        selected = next(rule for rule in matches if rule.effect == "always_alert")
        verdict, risk = "ALWAYS_ALERT", "critical"
        reason_code, reason = selected.reason_code, selected.reason
    elif baseline.decision == "deny":
        verdict, risk = "RISKY", baseline.risk
        reason_code = baseline.reason_codes[-1]
        reason = baseline.summary
    elif any(rule.effect == "escalate" for rule in matches):
        selected = next(rule for rule in matches if rule.effect == "escalate")
        verdict, risk = "RISKY", max_risk(baseline.risk, "high")
        reason_code, reason = selected.reason_code, selected.reason
    elif actions and any(action.get("capability") == "unknown" for action in actions):
        verdict, risk = "UNKNOWN", max_risk(baseline.risk, "medium")
        reason_code, reason = "UNKNOWN_TOOL_CAPABILITY", baseline.summary
    elif baseline.decision == "review":
        verdict, risk = "RISKY", baseline.risk
        reason_code = baseline.reason_codes[-1]
        reason = baseline.summary
    elif any(rule.effect == "safe" for rule in matches):
        selected = next(rule for rule in matches if rule.effect == "safe")
        verdict, risk = "SAFE", baseline.risk
        reason_code, reason = selected.reason_code, selected.reason
    else:
        verdict, risk = "SAFE", baseline.risk
        reason_code = baseline.reason_codes[-1]
        reason = baseline.summary

    evidence_sources: list[str] = []
    if session_baseline:
        evidence_sources.extend(
            str(item.get("text", ""))
            for item in (session_baseline.get("statements") or [])
            if isinstance(item, dict) and item.get("text")
        )
    evidence_sources.extend([*request.user_text.splitlines(), *[rule.reason for rule in matches]])
    evidence = list(dict.fromkeys(evidence_sources))[:8]
    stage = StageResult(
        stage="rules",
        status="completed",
        verdict=verdict,
        risk=risk,  # type: ignore[arg-type]
        reason_code=reason_code,
        reason=reason,
        action_alignment=baseline.action_alignment,
        latency_ms=(time.perf_counter() - started) * 1000,
        matched_rule_ids=[rule.id for rule in matches],
        matched_rule_versions=[f"{rule.id}:{rule.version}" for rule in matches],
        evidence=evidence,
    )
    return stage, baseline.to_dict()


def _matches(rule: CompiledRule, request: NormalizedRequest, actions: list[dict[str, Any]]) -> bool:
    def wildcard(values: tuple[str, ...], candidate: str) -> bool:
        return "*" in values or candidate in values

    if not wildcard(rule.protocols, request.source_format):
        return False
    if not wildcard(rule.models, request.model or ""):
        return False
    if not actions:
        return False
    for action in actions:
        tool = str(action.get("name", ""))
        capability = str(action.get("capability", ""))
        target = str(action.get("target") or "")
        haystack = json.dumps(action, ensure_ascii=False).lower()
        if not wildcard(rule.tools, tool):
            continue
        if rule.capabilities and capability not in rule.capabilities:
            continue
        if rule.target_environment and not any(env.lower() in haystack for env in rule.target_environment):
            continue
        if rule.target_contains and not any(fragment.lower() in target.lower() for fragment in rule.target_contains):
            continue
        return True
    return False


def max_risk(left: str, right: str) -> str:
    values = ["low", "medium", "high", "critical"]
    return values[max(values.index(left), values.index(right))]
