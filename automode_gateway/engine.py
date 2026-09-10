from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .classifier import authorization_signals, classify as classify_intent
from .dlp import (
    _policy_matches,
    _request_purpose,
    _review_signals,
    canonical_schema_fingerprint,
    redact_payload,
    resolve_destination,
    scan_payload,
    trusted_identity,
)
from .events import EventBroker
from .llm_classifier import LLMClassifier, ReviewerSettings, Transport
from .normalizer import normalize
from .protocols import classification_payload, protocol_for_path, session_evidence_from, session_id_from
from .response_parser import extract_tool_calls
from .review_context import build_review_context
from .session_fingerprint import conversation_fingerprint
from .session_risk import assess as assess_session_risk
from .storage import TraceStore


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def max_severity(s1: str | None, s2: str | None) -> str | None:
    if not s1:
        return s2
    if not s2:
        return s1
    return s1 if SEVERITY_ORDER.get(s1, 0) >= SEVERITY_ORDER.get(s2, 0) else s2


@dataclass(frozen=True)
class DualChannelVerdict:
    alert: bool
    severity: str | None
    rule_severity: str | None
    llm_severity: str | None
    llm_status: str          # "completed", "failed", "skipped", "not_needed", "pending"
    review_status: str       # "resolved", "needs_review", "skipped", "failed", "not_needed", "pending"
    divergence: bool
    hit_source: str | None   # "rule_only", "llm_only", "dual", None
    final_decision: str      # "alert", "allow", "review"
    final_stage: str
    reason_code: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuleEvaluationResult:
    rule_decision: str       # "alert", "allow"
    rule_severity: str | None # "critical", "high", "medium", "low", None
    reason_code: str
    reason: str
    data_findings: list[dict[str, Any]]
    unapproved_findings: list[dict[str, Any]]
    approved_findings: list[dict[str, Any]]
    destination: dict[str, Any]
    matched_rules: list[str]
    stages: list[dict[str, Any]]
    needs_llm_review: bool
    evidence_id: str | None = None
    request_purpose: str = "normal"
    run_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_decision": self.rule_decision,
            "rule_severity": self.rule_severity,
            "risk": self.rule_severity or "low",
            "reason_code": self.reason_code,
            "reason": self.reason,
            "data_findings": self.data_findings,
            "unapproved_findings": self.unapproved_findings,
            "approved_findings": self.approved_findings,
            "destination": self.destination,
            "matched_rules": self.matched_rules,
            "stages": self.stages,
            "needs_llm_review": self.needs_llm_review,
            "evidence_id": self.evidence_id,
            "request_purpose": self.request_purpose,
            "run_id": self.run_id,
            "authorization_evidence": [item.get("snippet", "") for item in self.data_findings[:8]],
            "proposed_actions": [],
        }


@dataclass
class LLMEvaluationResult:
    llm_status: str          # "completed", "failed", "skipped", "not_needed"
    llm_verdict: str | None  # "allow", "reject", "uncertain", None
    llm_severity: str | None # "critical", "high", "medium", "low", None
    final_stage: str
    reason_code: str
    reason: str
    stages: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    trace_id: str
    verdict: DualChannelVerdict
    rule_result: RuleEvaluationResult
    llm_result: LLMEvaluationResult | None
    alert_id: str | None
    run_id: str | None
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "verdict": self.verdict.to_dict(),
            "rule_result": self.rule_result.to_dict(),
            "llm_result": self.llm_result.to_dict() if self.llm_result else None,
            "alert_id": self.alert_id,
            "run_id": self.run_id,
            "session_id": self.session_id,
        }


def aggregate_dual_channel(
    rule_severity: str | None,
    llm_severity: str | None,
    llm_status: str,
    llm_verdict: str | None,
    *,
    rule_reason_code: str = "RULE_MATCH",
    rule_reason: str = "Rule matched",
    llm_reason_code: str = "LLM_REVIEW",
    llm_reason: str = "LLM review completed",
    final_stage: str = "rules",
) -> DualChannelVerdict:
    """Implement Section 3 dual-channel alert aggregation matrix."""
    # 1. Rule channel is High or Critical
    if rule_severity in ("high", "critical"):
        alert = True
        final_decision = "alert"
        stage = final_stage
        if llm_status == "completed":
            if llm_verdict == "reject":
                # Confirmed alert, adopts higher if LLM is higher
                final_sev = max_severity(rule_severity, llm_severity)
                hit_source = "dual"
                divergence = False
                review_status = "resolved"
                code = llm_reason_code if llm_severity and SEVERITY_ORDER.get(llm_severity, 0) > SEVERITY_ORDER.get(rule_severity, 0) else rule_reason_code
                rsn = llm_reason if llm_severity and SEVERITY_ORDER.get(llm_severity, 0) > SEVERITY_ORDER.get(rule_severity, 0) else rule_reason
            elif llm_verdict == "allow":
                # LLM says safe, retain rule severity, mark divergence
                final_sev = rule_severity
                hit_source = "rule_only"
                divergence = True
                review_status = "resolved"
                code = rule_reason_code
                rsn = rule_reason
            else:
                # LLM uncertain / unable to judge
                final_sev = rule_severity
                hit_source = "rule_only"
                divergence = False
                review_status = "needs_review"
                code = rule_reason_code
                rsn = rule_reason
        elif llm_status == "skipped":
            final_sev = rule_severity
            hit_source = "rule_only"
            divergence = False
            review_status = "skipped"
            code = rule_reason_code
            rsn = rule_reason
        elif llm_status == "failed":
            final_sev = rule_severity
            hit_source = "rule_only"
            divergence = False
            review_status = "failed"
            code = rule_reason_code
            rsn = rule_reason
        elif llm_status == "not_needed":
            final_sev = rule_severity
            hit_source = "rule_only"
            divergence = False
            review_status = "not_needed"
            code = rule_reason_code
            rsn = rule_reason
        else:  # pending or unfinished
            final_sev = rule_severity
            hit_source = "rule_only"
            divergence = False
            review_status = "pending"
            code = rule_reason_code
            rsn = rule_reason
        return DualChannelVerdict(
            alert=alert, severity=final_sev, rule_severity=rule_severity,
            llm_severity=llm_severity if llm_verdict == "reject" else None,
            llm_status=llm_status, review_status=review_status,
            divergence=divergence, hit_source=hit_source, final_decision=final_decision,
            final_stage=stage, reason_code=code, reason=rsn,
        )

    # 2. Rule channel is Medium
    if rule_severity == "medium":
        alert = True
        final_decision = "alert"
        stage = final_stage
        if llm_status == "completed":
            if llm_verdict == "reject":
                # Confirmed alert, at least upgraded to high (critical if LLM is critical)
                final_sev = "critical" if llm_severity == "critical" else "high"
                hit_source = "dual"
                divergence = False
                review_status = "resolved"
                code = llm_reason_code or rule_reason_code
                rsn = llm_reason or rule_reason
            elif llm_verdict == "allow":
                # LLM explicitly no alert, keep medium, divergence=True
                final_sev = "medium"
                hit_source = "rule_only"
                divergence = True
                review_status = "resolved"
                code = rule_reason_code
                rsn = rule_reason
            else:
                # LLM uncertain / unable to judge
                final_sev = "medium"
                hit_source = "rule_only"
                divergence = False
                review_status = "needs_review"
                code = rule_reason_code
                rsn = rule_reason
        elif llm_status == "skipped":
            final_sev = "medium"
            hit_source = "rule_only"
            divergence = False
            review_status = "skipped"
            code = rule_reason_code
            rsn = rule_reason
        elif llm_status == "failed":
            final_sev = "medium"
            hit_source = "rule_only"
            divergence = False
            review_status = "failed"
            code = rule_reason_code
            rsn = rule_reason
        elif llm_status == "not_needed":
            final_sev = "medium"
            hit_source = "rule_only"
            divergence = False
            review_status = "not_needed"
            code = rule_reason_code
            rsn = rule_reason
        else:  # pending or unfinished
            final_sev = "medium"
            hit_source = "rule_only"
            divergence = False
            review_status = "pending"
            code = rule_reason_code
            rsn = rule_reason
        return DualChannelVerdict(
            alert=alert, severity=final_sev, rule_severity=rule_severity,
            llm_severity=llm_severity if llm_verdict == "reject" else None,
            llm_status=llm_status, review_status=review_status,
            divergence=divergence, hit_source=hit_source, final_decision=final_decision,
            final_stage=stage, reason_code=code, reason=rsn,
        )

    # 3. Rule channel is Low
    if rule_severity == "low":
        alert = True
        final_decision = "alert"
        stage = final_stage
        if llm_status == "completed":
            if llm_verdict == "reject":
                final_sev = max_severity("low", llm_severity)
                hit_source = "dual"
                divergence = False
                review_status = "resolved"
                code = llm_reason_code or rule_reason_code
                rsn = llm_reason or rule_reason
            elif llm_verdict == "allow":
                final_sev = "low"
                hit_source = "rule_only"
                divergence = True
                review_status = "resolved"
                code = rule_reason_code
                rsn = rule_reason
            else:
                final_sev = "low"
                hit_source = "rule_only"
                divergence = False
                review_status = "needs_review"
                code = rule_reason_code
                rsn = rule_reason
        else:
            final_sev = "low"
            hit_source = "rule_only"
            divergence = False
            review_status = "skipped" if llm_status == "skipped" else "failed" if llm_status == "failed" else "not_needed" if llm_status == "not_needed" else "pending"
            code = rule_reason_code
            rsn = rule_reason
        return DualChannelVerdict(
            alert=alert, severity=final_sev, rule_severity=rule_severity,
            llm_severity=llm_severity if llm_verdict == "reject" else None,
            llm_status=llm_status, review_status=review_status,
            divergence=divergence, hit_source=hit_source, final_decision=final_decision,
            final_stage=stage, reason_code=code, reason=rsn,
        )

    # 4. Rule channel has NO alert (rule_severity is None)
    if llm_status == "completed":
        if llm_verdict == "reject":
            # Rule none, LLM alerts: adopt LLM severity
            return DualChannelVerdict(
                alert=True,
                severity=llm_severity or "medium",
                rule_severity=None,
                llm_severity=llm_severity or "medium",
                llm_status="completed",
                review_status="resolved",
                divergence=False,
                hit_source="llm_only",
                final_decision="alert",
                final_stage=final_stage,
                reason_code=llm_reason_code,
                reason=llm_reason,
            )
        if llm_verdict == "allow":
            # Rule none, LLM explicitly allow: safe, no alert
            return DualChannelVerdict(
                alert=False,
                severity=None,
                rule_severity=None,
                llm_severity=None,
                llm_status="completed",
                review_status="resolved",
                divergence=False,
                hit_source=None,
                final_decision="allow",
                final_stage=final_stage,
                reason_code="NO_DLP_POLICY_MATCH",
                reason="No outbound data policy requires attention.",
            )
        # LLM uncertain
        return DualChannelVerdict(
            alert=False,
            severity=None,
            rule_severity=None,
            llm_severity=None,
            llm_status="completed",
            review_status="needs_review",
            divergence=False,
            hit_source=None,
            final_decision="review",
            final_stage=final_stage,
            reason_code="REVIEW_REQUIRED",
            reason="Outbound evaluation requires human review.",
        )

    if llm_status in ("not_needed", "skipped"):
        return DualChannelVerdict(
            alert=False,
            severity=None,
            rule_severity=None,
            llm_severity=None,
            llm_status=llm_status,
            review_status="not_needed" if llm_status == "not_needed" else "skipped",
            divergence=False,
            hit_source=None,
            final_decision="allow",
            final_stage="rules",
            reason_code="NO_DLP_POLICY_MATCH",
            reason="No outbound data policy requires attention.",
        )

    # llm_status == "failed" or pending
    return DualChannelVerdict(
        alert=False,
        severity=None,
        rule_severity=None,
        llm_severity=None,
        llm_status=llm_status,
        review_status="failed" if llm_status == "failed" else "needs_review",
        divergence=False,
        hit_source=None,
        final_decision="review",
        final_stage=final_stage,
        reason_code="REVIEWER_FAILED" if llm_status == "failed" else "REVIEW_REQUIRED",
        reason="Outbound evaluation failed reviewer check; pending review." if llm_status == "failed" else "Outbound evaluation requires human review.",
    )


class AnalysisEngine:
    """Independent Analysis Engine decoupling protocol ingestion, session analysis,

    DLP rules, LLM Reviewer scheduling, response corroborate extraction, and
    session risk assessment from upstream proxy logic.
    """

    def __init__(
        self,
        store: TraceStore,
        broker: EventBroker | None = None,
        upstream: str | None = None,
        fast_transport: Transport | None = None,
        deep_transport: Transport | None = None,
        trusted_cidrs: str | None = None,
    ) -> None:
        self.store = store
        self.broker = broker or EventBroker()
        self.upstream = upstream.rstrip("/") if upstream else ""
        self.fast_transport = fast_transport
        self.deep_transport = deep_transport
        self.trusted_cidrs = trusted_cidrs or os.getenv("AUTOMODE_TRUSTED_PROXY_CIDRS")
        self.fast_classifier = LLMClassifier(ReviewerSettings.from_env("fast"), fast_transport)
        self.deep_classifier = LLMClassifier(ReviewerSettings.from_env("deep"), deep_transport)
        self.background_tasks: set[asyncio.Task[Any]] = set()

    def prepare_request(
        self,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        *,
        protocol: str | None = None,
        path: str = "",
        remote: str | None = None,
    ) -> dict[str, Any]:
        """Tidy protocol input, extract session evidence, identity, and normalized text."""
        inbound_headers = {key.lower(): value for key, value in (headers or {}).items()}
        resolved_protocol = protocol or protocol_for_path(path) or "openai_chat_completions"
        session_evidence = session_evidence_from(payload, inbound_headers)
        identity = trusted_identity(inbound_headers, remote, self.trusted_cidrs)
        session_id = session_id_from(payload, inbound_headers)

        analysis_payload: dict[str, Any] | None = None
        latest_user_text = ""
        declared_tool_count = 0
        session_signals: dict[str, Any] | None = None

        try:
            analysis_payload = classification_payload(resolved_protocol, payload)
            normalized = normalize(analysis_payload, source_format_override=resolved_protocol)
            review_context = build_review_context(normalized)
            latest_user_text = review_context.user_messages[-1] if review_context.user_messages else ""
            declared_tool_count = len(normalized.tools)
            session_evidence["fingerprint"] = conversation_fingerprint(normalized.messages)
            session_signals = authorization_signals(review_context.user_messages)
            session_signals["statements"] = []
        except (ValueError, TypeError, KeyError):
            analysis_payload = None
            latest_user_text = ""
            declared_tools = payload.get("tools")
            declared_tool_count = len(declared_tools) if isinstance(declared_tools, list) else 0

        return {
            "protocol": resolved_protocol,
            "headers": inbound_headers,
            "identity": identity,
            "session_id": session_id,
            "session_evidence": session_evidence,
            "conversation_fingerprint": session_evidence.get("fingerprint"),
            "session_signals": session_signals,
            "latest_user_text": latest_user_text,
            "declared_tool_count": declared_tool_count,
            "analysis_payload": analysis_payload,
        }

    def evaluate_rule_channel(
        self,
        payload: dict[str, Any],
        *,
        protocol: str = "openai_chat_completions",
        identity: dict[str, Any] | None = None,
        upstream: str | None = None,
        trace_id: str | None = None,
    ) -> RuleEvaluationResult:
        """Evaluate deterministic DLP rules channel (credentials, PII, source, keywords, policies)."""
        started = time.perf_counter()
        ident = identity or {"trusted": False, "source": "untrusted", "user_id": None, "department": None, "roles": [], "agent_id": None}
        target_upstream = upstream or self.upstream

        targets, policies, disabled_detectors, custom_detectors, tool_schemas = (
            self.store.list_destinations(),
            self.store.list_dlp_policies(enabled_only=True),
            self.store.get_disabled_detectors(),
            self.store.get_custom_detectors(),
            self.store.get_tool_schemas(),
        )

        findings = scan_payload(payload, policies, disabled_detectors=disabled_detectors, custom_detectors=custom_detectors)
        destination = resolve_destination(str(payload.get("model") or "") or None, target_upstream, targets)

        # Match active tool schemas (Security boundary: credentials & PII never exempted!)
        active_schemas = [s for s in tool_schemas if s.get("enabled", True)]
        for f in findings:
            if f.get("path_type") == "tool_description" and f.get("category") not in ("credential", "pii"):
                for s in active_schemas:
                    s_fp = s.get("content_fingerprint")
                    if s_fp and s_fp in (f.get("fingerprint"), f.get("canonical_fingerprint")):
                        f["disposition"] = "approved_metadata"
                        f["schema_id"] = s.get("id")
                        break

        unapproved_findings = [f for f in findings if f.get("disposition") != "approved_metadata"]
        approved_findings = [f for f in findings if f.get("disposition") == "approved_metadata"]
        categories = sorted({str(item["category"]) for item in findings})
        unapproved_categories = sorted({str(item["category"]) for item in unapproved_findings})
        purpose = _request_purpose(payload, protocol)
        matched: list[str] = []

        hard_alert = False
        review_match = False
        rule_severity: str | None = None

        if destination["trust"] == "external":
            has_critical_or_body = any(
                f.get("category") in ("credential", "pii") or f.get("path_type") != "tool_description"
                for f in unapproved_findings
            )
            if has_critical_or_body:
                hard_alert = True
                matched.append("builtin-sensitive-external")
                rule_severity = "critical" if "credential" in unapproved_categories else "high"
            elif unapproved_findings:
                review_match = True
                matched.append("unapproved-tool-schema-review")
                rule_severity = "medium"

        for policy in policies:
            if not policy.get("enabled", True) or not _policy_matches(policy, categories, destination, ident, payload):
                continue
            matched.append(f"{policy.get('id')}:{policy.get('version', 1)}")
            policy_sev = policy.get("severity") or ("high" if policy.get("effect") == "alert" else "medium")
            if policy.get("effect") == "alert":
                hard_alert = True
                rule_severity = max_severity(rule_severity, policy_sev)
            elif policy.get("effect") == "review":
                review_match = True
                rule_severity = max_severity(rule_severity, policy_sev or "medium")

        if hard_alert:
            rule_decision = "alert"
            rule_verdict = "ALWAYS_ALERT"
            rule_severity = rule_severity or ("critical" if "credential" in unapproved_categories else "high")
            reason_code = "SENSITIVE_DATA_TO_EXTERNAL" if "builtin-sensitive-external" in matched else "DLP_POLICY_MATCH"
            reason = "Sensitive outbound data matched an external-destination policy."
        elif review_match:
            rule_decision = "alert"
            rule_verdict = "RISKY"
            rule_severity = rule_severity or "medium"
            reason_code = "TOOL_SCHEMA_REVIEW" if "unapproved-tool-schema-review" in matched else "DLP_POLICY_MATCH"
            reason = "Outbound data candidate matched a review policy."
        else:
            rule_decision = "allow"
            rule_verdict = "SAFE"
            rule_severity = None
            if approved_findings:
                reason_code = "TOOL_SCHEMA_APPROVED"
                reason = "Outbound tool schemas matched approved controlled metadata."
            else:
                reason_code = "NO_DLP_POLICY_MATCH"
                reason = "No outbound data policy requires attention."

        # Candidate clue for LLM review: unapproved findings, review policies, or hard alert
        needs_llm_review = bool(unapproved_findings or review_match or hard_alert)

        evidence_id = None
        if trace_id and findings:
            try:
                evidence_id = self.store.store_evidence(trace_id, payload, findings, destination)
            except Exception:
                pass

        stage_entry = {
            "stage": "rules",
            "status": "completed",
            "verdict": rule_verdict,
            "risk": rule_severity or "low",
            "reason_code": reason_code,
            "reason": reason,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "action_alignment": purpose,
            "matched_rule_ids": matched,
            "matched_rule_versions": matched,
            "evidence": [item.get("snippet", "") for item in findings[:8]],
        }

        return RuleEvaluationResult(
            rule_decision=rule_decision,
            rule_severity=rule_severity,
            reason_code=reason_code,
            reason=reason,
            data_findings=findings,
            unapproved_findings=unapproved_findings,
            approved_findings=approved_findings,
            destination=destination,
            matched_rules=matched,
            stages=[stage_entry],
            needs_llm_review=needs_llm_review,
            evidence_id=evidence_id,
            request_purpose=purpose,
        )

    def evaluate_llm_channel(
        self,
        rule_result: RuleEvaluationResult,
        *,
        identity: dict[str, Any] | None = None,
        prompts: dict[str, str] | None = None,
    ) -> LLMEvaluationResult:
        """Evaluate LLM Reviewer channel (Fast / Deep)."""
        if not rule_result.needs_llm_review:
            return LLMEvaluationResult(
                llm_status="not_needed",
                llm_verdict=None,
                llm_severity=None,
                final_stage="rules",
                reason_code=rule_result.reason_code,
                reason=rule_result.reason,
                stages=[],
            )

        ident = identity or {"trusted": False, "source": "untrusted", "user_id": None, "department": None, "roles": [], "agent_id": None}
        prompt_dict = prompts if prompts is not None else self.store.get_prompts()
        signals = _review_signals(rule_result.data_findings, rule_result.destination, ident)
        stages: list[dict[str, Any]] = []

        # Fast reviewer
        fast_settings = ReviewerSettings.from_env("fast", prompt_override=prompt_dict)
        fast_classifier = LLMClassifier(fast_settings, self.fast_transport)
        fast_configured = fast_classifier.configured or self.fast_transport is not None

        # Deep reviewer
        deep_settings = ReviewerSettings.from_env("deep", prompt_override=prompt_dict)
        deep_classifier = LLMClassifier(deep_settings, self.deep_transport)
        deep_configured = deep_classifier.configured or self.deep_transport is not None

        if not fast_configured and not deep_configured:
            return LLMEvaluationResult(
                # A candidate reached this method because deterministic rules
                # found a clue or a review policy requested review.  Treat an
                # absent reviewer as an unresolved failure; ``skipped`` would
                # aggregate to an unsafe-looking allow for rule-none events.
                llm_status="failed",
                llm_verdict=None,
                llm_severity=None,
                final_stage="rules",
                reason_code="REVIEWER_NOT_CONFIGURED",
                reason="Reviewer is not configured; outbound safety remains unresolved.",
                stages=[],
            )

        if fast_configured:
            try:
                fast = fast_classifier.run(signals, rule_result.stages, review_object="outbound_dlp")
                stages.append(fast.to_dict())
                if fast.status == "completed":
                    if fast.verdict in ("allow", "reject"):
                        return LLMEvaluationResult(
                            llm_status="completed",
                            llm_verdict=fast.verdict,
                            llm_severity=fast.risk if fast.verdict == "reject" else None,
                            final_stage="fast_llm",
                            reason_code=fast.reason_code,
                            reason=fast.reason,
                            stages=stages,
                        )
                    # Uncertain: fall through to deep
            except Exception as exc:
                stages.append({"stage": "fast_llm", "status": "failed", "verdict": "uncertain", "risk": "high", "reason_code": "FAST_FAILED", "reason": str(exc), "latency_ms": 0})

        if deep_configured:
            try:
                deep = deep_classifier.run(signals, rule_result.stages + stages, review_object="outbound_dlp")
                stages.append(deep.to_dict())
                if deep.status == "completed":
                    if deep.verdict in ("allow", "reject"):
                        return LLMEvaluationResult(
                            llm_status="completed",
                            llm_verdict=deep.verdict,
                            llm_severity=deep.risk if deep.verdict == "reject" else None,
                            final_stage="deep_llm",
                            reason_code=deep.reason_code,
                            reason=deep.reason,
                            stages=stages,
                        )
                    return LLMEvaluationResult(
                        llm_status="completed",
                        llm_verdict="uncertain",
                        llm_severity=None,
                        final_stage="deep_llm",
                        reason_code=deep.reason_code,
                        reason=deep.reason,
                        stages=stages,
                    )
                return LLMEvaluationResult(
                    llm_status="failed",
                    llm_verdict=None,
                    llm_severity=None,
                    final_stage="deep_llm",
                    reason_code=deep.reason_code or "DEEP_FAILED",
                    reason=deep.reason or "Deep reviewer failed",
                    stages=stages,
                )
            except Exception as exc:
                stages.append({"stage": "deep_llm", "status": "failed", "verdict": "uncertain", "risk": "high", "reason_code": "DEEP_FAILED", "reason": str(exc), "latency_ms": 0})
                return LLMEvaluationResult(
                    llm_status="failed",
                    llm_verdict=None,
                    llm_severity=None,
                    final_stage="deep_llm",
                    reason_code="REVIEWER_FAILED",
                    reason=str(exc),
                    stages=stages,
                )

        return LLMEvaluationResult(
            llm_status="failed",
            llm_verdict=None,
            llm_severity=None,
            final_stage="fast_llm" if fast_configured else "rules",
            reason_code="REVIEWER_FAILED",
            reason="Reviewer failed to reach a terminal verdict",
            stages=stages,
        )

    def aggregate(
        self,
        rule_result: RuleEvaluationResult,
        llm_result: LLMEvaluationResult,
    ) -> DualChannelVerdict:
        """Combine rule and LLM channel results per Section 3 matrix."""
        final_stage = llm_result.final_stage if llm_result.stages else "rules"
        return aggregate_dual_channel(
            rule_result.rule_severity,
            llm_result.llm_severity,
            llm_result.llm_status,
            llm_result.llm_verdict,
            rule_reason_code=rule_result.reason_code,
            rule_reason=rule_result.reason,
            llm_reason_code=llm_result.reason_code,
            llm_reason=llm_result.reason,
            final_stage=final_stage,
        )

    async def analyze_request(
        self,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        *,
        trace_id: str | None = None,
        protocol: str | None = None,
        path: str = "",
        method: str = "POST",
        remote: str | None = None,
        wait_for_llm: bool = True,
    ) -> AnalysisResult:
        """Complete orchestrated analysis: ingest trace, evaluate rules, create immediate

        alert if rule triggered, observe session risk, and schedule/execute LLM review.
        """
        tid = trace_id or str(uuid.uuid4())
        prepared = self.prepare_request(payload, headers=headers, protocol=protocol, path=path, remote=remote)
        session_id = prepared["session_id"]

        # Persist trace
        await asyncio.to_thread(
            self.store.create,
            trace_id=tid,
            protocol=prepared["protocol"],
            method=method,
            path=path or f"/{prepared['protocol']}",
            payload=payload,
            headers=prepared["headers"],
            session_id=session_id,
            latest_user_text=prepared["latest_user_text"],
            declared_tool_count=prepared["declared_tool_count"],
            session_evidence=prepared["session_evidence"],
            conversation_fingerprint=prepared["conversation_fingerprint"],
            session_signals=prepared["session_signals"],
        )
        self.broker.publish("trace.created", {"id": tid, "protocol": prepared["protocol"], "model": payload.get("model")})

        # Evaluate rule channel
        rule_result = await asyncio.to_thread(
            self.evaluate_rule_channel,
            payload,
            protocol=prepared["protocol"],
            identity=prepared["identity"],
            upstream=self.upstream,
            trace_id=tid,
        )

        # Immediate rule alert generation
        alert_id: str | None = None
        if rule_result.rule_severity in ("critical", "high", "medium", "low"):
            alert_id = await asyncio.to_thread(self.store.create_immediate_rule_alert, tid, rule_result.to_dict())
            self.broker.publish(
                "alert.created",
                {
                    "id": alert_id,
                    "trace_id": tid,
                    "severity": rule_result.rule_severity,
                    "reason_code": rule_result.reason_code,
                    "source": "rule",
                },
            )

        # Observe user session intent risk
        if prepared["latest_user_text"]:
            await self.observe_session_risk(tid, prepared["latest_user_text"])

        if wait_for_llm:
            llm_result = await asyncio.to_thread(
                self.evaluate_llm_channel,
                rule_result,
                identity=prepared["identity"],
            )
            verdict = self.aggregate(rule_result, llm_result)
            run_id, updated_alert_id = await asyncio.to_thread(
                self._save_pipeline_record,
                tid,
                rule_result,
                llm_result,
                verdict,
            )
            alert_id = updated_alert_id or alert_id

            if alert_id:
                if rule_result.rule_severity:
                    self.broker.publish(
                        "alert.updated",
                        {
                            "id": alert_id,
                            "trace_id": tid,
                            "severity": verdict.severity,
                            "reason_code": verdict.reason_code,
                            "divergence": verdict.divergence,
                            "review_status": verdict.review_status,
                        },
                    )
                else:
                    self.broker.publish(
                        "alert.created",
                        {
                            "id": alert_id,
                            "trace_id": tid,
                            "severity": verdict.severity,
                            "reason_code": verdict.reason_code,
                            "source": "llm",
                        },
                    )

            self.broker.publish("classification.completed", {"trace_id": tid, "run_id": run_id, "decision": verdict.final_decision, "risk": verdict.severity or "low"})
            return AnalysisResult(trace_id=tid, verdict=verdict, rule_result=rule_result, llm_result=llm_result, alert_id=alert_id, run_id=run_id, session_id=session_id)

        # Non-waiting mode: schedule background LLM task and return immediate rule verdict
        if rule_result.needs_llm_review:
            task = asyncio.create_task(self._async_llm_and_update(tid, rule_result, prepared["identity"], alert_id))
            self.background_tasks.add(task)
            task.add_done_callback(self.background_tasks.discard)

        verdict = DualChannelVerdict(
            alert=bool(alert_id),
            severity=rule_result.rule_severity,
            rule_severity=rule_result.rule_severity,
            llm_severity=None,
            llm_status="pending" if rule_result.needs_llm_review else "not_needed",
            review_status="pending" if rule_result.needs_llm_review else "not_needed",
            divergence=False,
            hit_source="rule_only" if alert_id else None,
            final_decision=rule_result.rule_decision,
            final_stage="rules",
            reason_code=rule_result.reason_code,
            reason=rule_result.reason,
        )
        return AnalysisResult(trace_id=tid, verdict=verdict, rule_result=rule_result, llm_result=None, alert_id=alert_id, run_id=rule_result.run_id, session_id=session_id)

    async def _async_llm_and_update(
        self,
        trace_id: str,
        rule_result: RuleEvaluationResult,
        identity: dict[str, Any],
        initial_alert_id: str | None,
    ) -> None:
        """Run LLM channel asynchronously and update alert in store."""
        try:
            llm_result = await asyncio.to_thread(self.evaluate_llm_channel, rule_result, identity=identity)
            verdict = self.aggregate(rule_result, llm_result)
            run_id, updated_alert_id = await asyncio.to_thread(self._save_pipeline_record, trace_id, rule_result, llm_result, verdict)
            final_alert_id = updated_alert_id or initial_alert_id
            if final_alert_id and initial_alert_id:
                self.broker.publish(
                    "alert.updated",
                    {
                        "id": final_alert_id,
                        "trace_id": trace_id,
                        "severity": verdict.severity,
                        "reason_code": verdict.reason_code,
                        "divergence": verdict.divergence,
                        "review_status": verdict.review_status,
                    },
                )
            elif final_alert_id and not initial_alert_id:
                self.broker.publish(
                    "alert.created",
                    {
                        "id": final_alert_id,
                        "trace_id": trace_id,
                        "severity": verdict.severity,
                        "reason_code": verdict.reason_code,
                        "source": "llm",
                    },
                )
            self.broker.publish("classification.completed", {"trace_id": trace_id, "run_id": run_id, "decision": verdict.final_decision, "risk": verdict.severity or "low"})
        except Exception:
            return

    def persist_pipeline_result(
        self,
        trace_id: str,
        rule_result: RuleEvaluationResult,
        llm_result: LLMEvaluationResult,
        verdict: DualChannelVerdict,
    ) -> tuple[str, str | None]:
        return self._save_pipeline_record(trace_id, rule_result, llm_result, verdict)

    def _save_pipeline_record(
        self,
        trace_id: str,
        rule_result: RuleEvaluationResult,
        llm_result: LLMEvaluationResult,
        verdict: DualChannelVerdict,
    ) -> tuple[str, str | None]:
        return self.store.save_pipeline(trace_id, self.pipeline_record(rule_result, llm_result, verdict))

    def pipeline_record(
        self,
        rule_result: RuleEvaluationResult,
        llm_result: LLMEvaluationResult,
        verdict: DualChannelVerdict,
    ) -> dict[str, Any]:
        """Build the common read model without choosing a persistence adapter."""
        all_stages = list(rule_result.stages) + list(llm_result.stages)
        pipeline_dict = {
            "final_decision": verdict.final_decision,
            "policy_decision": verdict.final_decision,
            "final_stage": verdict.final_stage,
            "risk": verdict.severity or "low",
            "decision": verdict.final_decision,
            "classifier_stage": verdict.final_stage,
            "reason_codes": [verdict.reason_code],
            "reason_code": verdict.reason_code,
            "reason": verdict.reason,
            "action_alignment": rule_result.request_purpose,
            "request_purpose": rule_result.request_purpose,
            "data_findings": rule_result.data_findings,
            "destination": rule_result.destination,
            "matched_policies": rule_result.matched_rules,
            "matched_rules": rule_result.matched_rules,
            "evidence_id": rule_result.evidence_id,
            "review_object": "outbound_request",
            "semantic_status": verdict.review_status,
            "request_safety": "safe" if verdict.final_decision == "allow" else "harmful" if verdict.alert else "ambiguous",
            "authorization_evidence": [item.get("snippet", "") for item in rule_result.data_findings[:8]],
            "proposed_actions": [],
            "review_transcript": _review_signals(rule_result.data_findings, rule_result.destination, {}),
            "stages": all_stages,
            "rule_severity": verdict.rule_severity,
            "llm_severity": verdict.llm_severity,
            "llm_status": verdict.llm_status,
            "review_status": verdict.review_status,
            "divergence": verdict.divergence,
            "hit_source": verdict.hit_source,
        }
        return pipeline_dict

    async def process_response(
        self,
        trace_id: str,
        *,
        response_capture: bytes = b"",
        response_bytes: int | None = None,
        protocol: str = "openai_chat_completions",
        content_type: str = "",
        content_encoding: str = "",
        status: int | None = None,
        latency_ms: float | None = None,
        error: str | None = None,
        response_capture_complete: bool = True,
    ) -> dict[str, Any]:
        """Extract tool call corroborations and store them. Does not emit response DLP.

        If trace does not exist yet, marks correlation_status='request_missing' without waiting.
        """
        byte_count = response_bytes if response_bytes is not None else len(response_capture)
        if response_capture_complete:
            tool_calls = extract_tool_calls(
                protocol,
                response_capture,
                content_type,
                content_encoding,
            )
        else:
            tool_calls = [{"name": "response_capture_incomplete", "arguments": {"bytes": byte_count}}]

        trace = await asyncio.to_thread(self.store.get, trace_id)
        if trace is None:
            correlation_status = "request_missing"
            await asyncio.to_thread(
                self.store.record_orphan_response,
                trace_id,
                protocol=protocol,
                tool_calls=tool_calls,
                status=status,
                response_bytes=byte_count,
                latency_ms=latency_ms,
                error=error,
                response_capture_complete=response_capture_complete,
            )
        else:
            correlation_status = "correlated"
            await asyncio.to_thread(
                self.store.finish,
                trace_id,
                status=status,
                response_bytes=byte_count,
                latency_ms=latency_ms,
                error=error,
                response_body=response_capture if response_capture_complete else None,
                response_content_type=content_type,
                response_capture_complete=response_capture_complete,
            )
            await asyncio.to_thread(self.store.record_tool_actions, trace_id, tool_calls)

        self.broker.publish("trace.completed", {"id": trace_id, "status": status, "error": error, "correlation_status": correlation_status})
        return {
            "trace_id": trace_id,
            "tool_calls": tool_calls,
            "correlation_status": correlation_status,
            "status": status,
        }

    async def observe_session_risk(self, trace_id: str, raw_user_text: str) -> dict[str, Any] | None:
        """Observe user intent risk without persisting raw user text."""
        try:
            trace = await asyncio.to_thread(self.store.get, trace_id)
            session_id = trace.get("session_record_id") if trace else None
            prior = await asyncio.to_thread(self.store.session_risk_summary, session_id) if session_id else None
            prompts = await asyncio.to_thread(self.store.get_prompts)
            assessment = await asyncio.to_thread(assess_session_risk, raw_user_text, prior, prompts)
            segment, alert_id = await asyncio.to_thread(self.store.record_session_risk, trace_id, assessment.to_dict())
            self.broker.publish("session_risk.updated", {"trace_id": trace_id, "session_id": segment["session_id"], "summary": segment})
            if alert_id:
                self.broker.publish(
                    "alert.created",
                    {
                        "id": alert_id,
                        "trace_id": trace_id,
                        "severity": segment["severity"],
                        "reason_code": segment["reason_code"],
                        "source": "session_risk",
                    },
                )
            return segment
        except Exception:
            return None
