from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Risk = Literal["low", "medium", "high", "critical"]
Alignment = Literal["aligned", "out_of_scope", "contradicted", "ambiguous", "high_impact", "no_action"]


@dataclass
class StageResult:
    stage: Literal["rules", "fast_llm", "deep_llm"]
    status: Literal["completed", "error", "skipped"]
    verdict: str
    risk: Risk
    reason_code: str
    reason: str
    latency_ms: float
    action_alignment: str = "ambiguous"
    matched_rule_ids: list[str] = field(default_factory=list)
    matched_rule_versions: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    model: str | None = None
    input_hash: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PipelineResult:
    final_decision: Literal["allow", "alert"]
    final_stage: Literal["rules", "fast_llm", "deep_llm"]
    risk: Risk
    action_alignment: str
    reason_code: str
    reason: str
    authorization_evidence: list[str]
    proposed_actions: list[dict[str, Any]]
    matched_rules: list[str]
    stages: list[StageResult]
    total_latency_ms: float
    review_transcript: list[dict[str, Any]]
    review_object: str = "tool_action"
    request_safety: str = "not_reviewed"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        # Compatibility with the original trace/classify API.
        value["decision"] = "deny" if self.final_decision == "alert" else "allow"
        value["classifier_stage"] = self.final_stage
        value["reason_codes"] = [self.reason_code]
        value["proposed_tool_calls"] = self.proposed_actions
        return value
