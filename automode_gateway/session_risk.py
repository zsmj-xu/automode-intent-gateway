"""Observe-only assessment of a user's evolving session-risk intent.

The caller supplies the current raw user turn.  This module intentionally never
persists that text: its result is a small, explainable derived record.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

from .llm_classifier import ReviewerSettings, Transport, _http_transport


PURPOSE_RISKS = {
    "benign", "dual_use", "unauthorized_access", "credential_exfiltration",
    "malware", "safety_evasion", "destructive_harm", "fraud",
    "privacy_invasion", "physical_harm", "unknown",
}
TRANSFER_INTENTS = {"none", "prepare", "external_transfer"}
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

PURPOSE_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("credential_exfiltration", "critical", (r"(?:窃取|导出|收集|泄露|上传).{0,40}(?:密码|凭据|令牌|密钥|私钥)", r"(?:steal|exfiltrate|dump|harvest).{0,50}(?:password|credential|token|secret|private key)")),
    ("unauthorized_access", "high", (r"未授权.{0,12}(?:访问|入侵)|(?:入侵|提权).{0,12}(?:账号|系统|服务器)", r"(?:hack|breach|break into|unauthori[sz]ed access|privilege escalation)")),
    ("safety_evasion", "high", (r"绕过.{0,20}(?:安全|策略|限制|检测|杀毒|EDR)", r"(?:bypass|disable|evade).{0,30}(?:safety|guardrail|policy|detection|antivirus|edr)")),
    ("destructive_harm", "high", (r"(?:销毁|破坏|清空|删除).{0,25}(?:生产|数据库|备份|系统)", r"(?:wipe|destroy|sabotage|delete).{0,30}(?:production|database|backups?|system)")),
    ("fraud", "high", (r"钓鱼邮件|诈骗|冒充.{0,12}(?:领导|银行|客服|他人)", r"(?:phishing|scam|fraud|impersonate)")),
    ("privacy_invasion", "high", (r"人肉搜索|跟踪.{0,12}(?:某人|员工|伴侣)|窃取.{0,12}隐私", r"(?:doxx|stalk|track).{0,30}(?:person|victim|employee|partner)")),
    ("physical_harm", "critical", (r"杀死|下毒|伤害.{0,8}(?:某人|他人)|制作.{0,8}(?:炸弹|爆炸物)", r"(?:kill|poison|injure|make a bomb|explosive device)")),
    ("malware", "high", (r"(?:勒索软件|木马|键盘记录|僵尸网络|窃密软件)", r"(?:ransomware|keylogger|botnet|credential stealer)")),
)
DUAL_USE = (r"(?:分析|检测|研究|样本|测试环境).{0,24}(?:后门|木马|恶意软件|漏洞)", r"(?:analy[sz]e|research|sample|test).{0,40}(?:backdoor|malware|exploit)")
EXTERNAL_TARGET = r"(?:网盘|drive|dropbox|onedrive|google\s*drive|github|gitlab|gitee|代码仓库|repo(?:sitory)?|s3|oss|外部(?:仓库|服务|地址|网站))"
TRANSFER = (rf"(?:上传|推送|分享|发布|发送).{{0,40}}{EXTERNAL_TARGET}", rf"(?:upload|push|share|publish|send).{{0,50}}{EXTERNAL_TARGET}")
PREPARE_TRANSFER = (rf"(?:准备|配置|打包|同步).{{0,40}}{EXTERNAL_TARGET}", rf"(?:prepare|configure|package|sync).{{0,50}}{EXTERNAL_TARGET}")


@dataclass(frozen=True)
class SessionRiskAssessment:
    purpose_risk: str
    transfer_intent: str
    severity: str
    state: str
    reason_code: str
    summary: str
    source: str

    def to_dict(self) -> dict[str, str]:
        return {
            "purpose_risk": self.purpose_risk,
            "transfer_intent": self.transfer_intent,
            "severity": self.severity,
            "state": self.state,
            "reason_code": self.reason_code,
            "summary": self.summary,
            "source": self.source,
            "version": "session-risk-v1",
        }


def assess(
    user_text: str,
    prior_summary: dict[str, Any] | None = None,
    prompts: dict[str, str] | None = None,
    fast_transport: Transport | None = None,
    deep_transport: Transport | None = None,
) -> SessionRiskAssessment:
    """Assess one raw user turn and a derived (never raw) prior session state."""
    purpose, severity, reason_code = _local_purpose(user_text)
    transfer = _transfer_intent(user_text)
    needs_review = purpose == "dual_use" or transfer == "prepare"
    if not needs_review:
        return _result(purpose, transfer, severity, "resolved", reason_code, "local")

    review_input = [{"type": "user", "text": user_text}]
    prior = [{"type": "session_risk_summary", **(prior_summary or {})}]
    for stage in ("fast", "deep"):
        settings = ReviewerSettings.from_env(stage, prompt_override=prompts)
        if not settings.url or not settings.model:
            continue
        try:
            parsed = (fast_transport if stage == "fast" and fast_transport else deep_transport if stage == "deep" and deep_transport else _http_transport)(settings, {
                "review_object": "session_risk_intent", "stripped_transcript": review_input, "prior_stages": prior,
            })
            reviewed = _validated_review(parsed)
            return _result(reviewed["purpose_risk"], reviewed["transfer_intent"], reviewed["severity"], "resolved", reviewed["reason_code"], f"{stage}_llm")
        except Exception:
            continue
    # A locally suspicious request that cannot be disambiguated is observed as
    # high risk, causing an alert without changing the forwarded request.
    return _result(purpose, transfer, "high", "needs_review", "SESSION_RISK_REVIEW_UNAVAILABLE", "fallback")


def _local_purpose(text: str) -> tuple[str, str, str]:
    if _matches(text, DUAL_USE):
        return "dual_use", "medium", "DUAL_USE_SIGNAL"
    for purpose, severity, patterns in PURPOSE_PATTERNS:
        if _matches(text, patterns):
            return purpose, severity, purpose.upper()
    return "benign", "low", "LOW_RISK_SESSION_INTENT"


def _transfer_intent(text: str) -> str:
    if _matches(text, TRANSFER):
        return "external_transfer"
    if _matches(text, PREPARE_TRANSFER):
        return "prepare"
    return "none"


def _matches(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text, re.I | re.S) for pattern in patterns)


def _validated_review(value: dict[str, Any]) -> dict[str, str]:
    purpose = str(value.get("purpose_risk") or "unknown")
    transfer = str(value.get("transfer_intent") or "none")
    severity = str(value.get("severity") or "high")
    if purpose not in PURPOSE_RISKS or transfer not in TRANSFER_INTENTS or severity not in RISK_ORDER:
        raise ValueError("invalid session-risk reviewer schema")
    return {"purpose_risk": purpose, "transfer_intent": transfer, "severity": severity, "reason_code": str(value.get("reason_code") or "SESSION_RISK_REVIEW")[:80]}


def _result(purpose: str, transfer: str, severity: str, state: str, reason_code: str, source: str) -> SessionRiskAssessment:
    summary = f"Purpose risk: {purpose}; external-transfer intent: {transfer}."
    return SessionRiskAssessment(purpose, transfer, severity, state, reason_code, summary, source)
