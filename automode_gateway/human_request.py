from __future__ import annotations

import re
import time
from typing import Any, Iterable

from .classifier import classify
from .decision import PipelineResult, StageResult
from .llm_classifier import LLMClassifier, ReviewerSettings, Transport
from .models import NormalizedRequest
from .policy import max_risk
from .review_context import build_review_context


# These patterns are deliberately only a routing layer. A match does not by
# itself declare the user malicious; it sends dual-use or dangerous-looking
# requests to the semantic reviewers, which can consider benign context.
RISK_SIGNALS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("UNAUTHORIZED_ACCESS", (
        r"\b(?:hack|breach|break into|unauthori[sz]ed access|privilege escalation)\b",
        r"未授权.{0,8}(?:访问|入侵)|入侵.{0,8}(?:账号|系统|服务器)|提权",
    )),
    ("MALWARE_OR_PERSISTENCE", (
        r"\b(?:malware|ransomware|keylogger|botnet|backdoor|credential stealer)\b",
        r"勒索软件|木马|键盘记录|僵尸网络|后门|窃密软件",
    )),
    ("CREDENTIAL_THEFT_OR_EXFILTRATION", (
        r"\b(?:steal|exfiltrate|dump|harvest).{0,40}(?:password|credential|token|secret|private key)\b",
        r"(?:窃取|导出|收集|泄露).{0,30}(?:密码|凭据|令牌|密钥|私钥)",
    )),
    ("SAFETY_EVASION", (
        r"\b(?:bypass|disable|evade).{0,30}(?:safety|guardrail|policy|detection|antivirus|edr)\b",
        r"绕过.{0,20}(?:安全|策略|限制|检测|杀毒|EDR)|关闭.{0,12}(?:安全防护|审计)",
    )),
    ("DESTRUCTIVE_HARM", (
        r"\b(?:wipe|destroy|sabotage|delete).{0,30}(?:production|database|backups?|system)\b",
        r"(?:销毁|破坏|清空|删除).{0,25}(?:生产|数据库|备份|系统)",
    )),
    ("FRAUD_OR_IMPERSONATION", (
        r"\b(?:phishing|scam|fraud|impersonate).{0,40}\b",
        r"钓鱼邮件|诈骗|冒充.{0,12}(?:领导|银行|客服|他人)",
    )),
    ("PRIVACY_INVASION", (
        r"\b(?:doxx|stalk|track).{0,30}(?:person|victim|employee|partner)\b",
        r"人肉搜索|跟踪.{0,12}(?:某人|员工|伴侣)|窃取.{0,12}隐私",
    )),
    ("PHYSICAL_HARM", (
        r"\b(?:kill|poison|injure|make a bomb|explosive device)\b",
        r"杀死|下毒|伤害.{0,8}(?:某人|他人)|制作.{0,8}(?:炸弹|爆炸物)",
    )),
)


class HumanRequestPipeline:
    """Judge whether the human's request is safe, independently of model actions."""

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
        rules: Iterable[dict[str, Any]] = (),
    ) -> PipelineResult:
        started = time.perf_counter()
        context = build_review_context(request)
        transcript = [
            {**event, "text": _redact_human_text(str(event.get("text", "")))}
            for event in context.classifier_transcript()
            if event.get("type") == "user"
        ]
        rule_stage = self._rules(request, transcript, rules)
        stages = [rule_stage]

        # Human harm is open-ended: absence of a regex signal is not proof of
        # safety. When semantic reviewers are configured, every human request
        # reaches them; Rules-only remains a usable fallback for local setups.
        if rule_stage.verdict == "SAFE" and not (self.fast.configured or self.deep.configured):
            return self._final("allow", "safe", rule_stage, stages, transcript, started)
        if rule_stage.verdict == "ALWAYS_ALERT":
            return self._final("alert", "harmful", rule_stage, stages, transcript, started)

        fast = self.fast.run(transcript, [rule_stage.to_dict()], review_object="human_request")
        stages.append(fast)
        if fast.status == "completed" and fast.verdict == "allow":
            return self._final("allow", "safe", fast, stages, transcript, started)

        deep = self.deep.run(transcript, [stage.to_dict() for stage in stages], review_object="human_request")
        stages.append(deep)
        decision = "allow" if deep.status == "completed" and deep.verdict == "allow" else "alert"
        safety = "safe" if decision == "allow" else "harmful" if deep.status == "completed" and deep.verdict == "reject" else "needs_review"
        return self._final(decision, safety, deep, stages, transcript, started)

    @staticmethod
    def _rules(
        request: NormalizedRequest,
        transcript: list[dict[str, Any]],
        rules: Iterable[dict[str, Any]],
    ) -> StageResult:
        del rules  # Action rules are retained for compatibility but do not judge people.
        started = time.perf_counter()
        baseline = classify(request, [])
        text = "\n".join(str(event.get("text", "")) for event in transcript)
        signals = [code for code, patterns in RISK_SIGNALS if any(re.search(pattern, text, re.I | re.S) for pattern in patterns)]

        if baseline.decision == "deny":
            verdict = "ALWAYS_ALERT"
            risk = baseline.risk
            reason_code = baseline.reason_codes[-1]
            reason = "The human request contains an explicit harmful or exfiltration instruction."
        elif signals or baseline.decision == "review":
            verdict = "RISKY"
            risk = max_risk(baseline.risk, "high")
            reason_code = signals[0] if signals else baseline.reason_codes[-1]
            reason = "The human request needs semantic safety review before it is trusted."
        else:
            verdict = "SAFE"
            risk = baseline.risk
            reason_code = "LOW_RISK_HUMAN_REQUEST"
            reason = "No human-request safety risk signal was found."

        return StageResult(
            stage="rules",
            status="completed",
            verdict=verdict,
            risk=risk,  # type: ignore[arg-type]
            reason_code=reason_code,
            reason=reason,
            action_alignment="safe" if verdict == "SAFE" else "harmful" if verdict == "ALWAYS_ALERT" else "ambiguous",
            latency_ms=(time.perf_counter() - started) * 1000,
            evidence=[event["text"] for event in transcript[-3:] if event.get("text")],
        )

    @staticmethod
    def _final(
        decision: str,
        request_safety: str,
        final: StageResult,
        stages: list[StageResult],
        transcript: list[dict[str, Any]],
        started: float,
    ) -> PipelineResult:
        risk = final.risk
        if final.stage == "rules" or final.status == "error":
            for stage in stages:
                risk = max_risk(risk, stage.risk)  # type: ignore[assignment]
        return PipelineResult(
            final_decision=decision,  # type: ignore[arg-type]
            final_stage=final.stage,
            risk=risk,  # type: ignore[arg-type]
            action_alignment=request_safety,
            reason_code=final.reason_code,
            reason=final.reason,
            authorization_evidence=[event["text"] for event in transcript[-3:] if event.get("text")],
            proposed_actions=[],
            matched_rules=[],
            stages=stages,
            total_latency_ms=(time.perf_counter() - started) * 1000,
            review_transcript=transcript,
            review_object="human_request",
            request_safety=request_safety,
        )


def _redact_human_text(text: str) -> str:
    text = re.sub(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
        text,
        flags=re.I | re.S,
    )
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[REDACTED_TOKEN]", text)
    text = re.sub(
        r"(?i)\b(api[_ -]?key|access[_ -]?token|password|passwd|secret)\b(\s*[:=]\s*)([^\s,;]+)",
        r"\1\2[REDACTED]",
        text,
    )
    return text
