from __future__ import annotations

import time
from typing import Any, Iterable

from .decision import PipelineResult, StageResult
from .llm_classifier import LLMClassifier, ReviewerSettings, Transport
from .models import NormalizedRequest
from .policy import evaluate_rules, max_risk
from .review_context import build_review_context


class DecisionPipeline:
    def __init__(
        self,
        fast_transport: Transport | None = None,
        deep_transport: Transport | None = None,
    ) -> None:
        self.fast = LLMClassifier(ReviewerSettings.from_env("fast"), fast_transport)
        self.deep = LLMClassifier(ReviewerSettings.from_env("deep"), deep_transport)

    def classify(
        self,
        request: NormalizedRequest,
        proposed_tool_calls: list[dict[str, Any]],
        rules: Iterable[dict[str, Any]] = (),
        session_baseline: dict[str, Any] | None = None,
    ) -> PipelineResult:
        started = time.perf_counter()
        context = build_review_context(request, proposed_tool_calls, session_baseline=session_baseline)
        transcript = context.classifier_transcript()
        rule_stage, baseline = evaluate_rules(request, proposed_tool_calls, rules, session_baseline=session_baseline)
        stages: list[StageResult] = [rule_stage]

        if rule_stage.verdict == "SAFE":
            return self._final("allow", rule_stage, stages, baseline, transcript, started)
        if rule_stage.verdict == "ALWAYS_ALERT":
            return self._final("alert", rule_stage, stages, baseline, transcript, started)

        fast = self.fast.run(transcript, [rule_stage.to_dict()])
        stages.append(fast)
        if fast.status == "completed" and fast.verdict == "allow":
            return self._final("allow", fast, stages, baseline, transcript, started)

        deep = self.deep.run(transcript, [stage.to_dict() for stage in stages])
        stages.append(deep)
        decision = "allow" if deep.status == "completed" and deep.verdict == "allow" else "alert"
        return self._final(decision, deep, stages, baseline, transcript, started)

    @staticmethod
    def _final(
        decision: str,
        final: StageResult,
        stages: list[StageResult],
        baseline: dict[str, Any],
        transcript: list[dict[str, Any]],
        started: float,
    ) -> PipelineResult:
        risk = final.risk
        for stage in stages:
            risk = max_risk(risk, stage.risk)  # type: ignore[assignment]
        alignment = final.action_alignment
        if final.status == "error":
            for stage in reversed(stages[:-1]):
                if stage.status == "completed" and stage.action_alignment != "ambiguous":
                    alignment = stage.action_alignment
                    break
        return PipelineResult(
            final_decision=decision,  # type: ignore[arg-type]
            final_stage=final.stage,
            risk=risk,  # type: ignore[arg-type]
            action_alignment=alignment,
            reason_code=final.reason_code,
            reason=final.reason,
            authorization_evidence=stages[0].evidence,
            proposed_actions=baseline.get("proposed_tool_calls", []),
            matched_rules=stages[0].matched_rule_versions,
            stages=stages,
            total_latency_ms=(time.perf_counter() - started) * 1000,
            review_transcript=transcript,
        )
