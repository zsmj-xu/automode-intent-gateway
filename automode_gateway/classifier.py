from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .models import Classification, NormalizedRequest
from .review_context import ReviewContext, build_review_context


PATTERNS: dict[str, tuple[str, ...]] = {
    "analysis": (r"\b(analy[sz]e|investigate|diagnose|inspect|check)\b", r"分析", r"调查", r"排查", r"诊断", r"检查"),
    "translation": (r"\btranslate\b", r"翻译", r"译成"),
    "summarization": (r"\bsummari[sz]e\b", r"总结", r"摘要", r"概括"),
    "code_generation": (r"\b(code|implement|refactor|debug|function|class)\b", r"代码", r"实现", r"重构", r"修复.*bug"),
    "data_processing": (r"\b(csv|xlsx|spreadsheet|dataset|sql|analy[sz]e data)\b", r"表格", r"数据处理", r"数据分析"),
    "content_generation": (r"\b(write|draft|compose)\b", r"撰写", r"写一篇", r"生成文案"),
    "agent_action": (r"\b(deploy|delete|publish|send|upload|execute|run command)\b", r"部署", r"删除", r"发布", r"发送", r"上传", r"执行"),
}

CAPABILITY_PATTERNS: dict[str, tuple[str, ...]] = {
    "read": (r"\b(read|check|inspect)\b", r"查看", r"读取", r"分析", r"检查"),
    "write": (r"\b(write|edit|modify|update|create)\b", r"写入", r"编辑", r"修改", r"更新", r"创建"),
    "execute": (r"\b(execute|run|deploy)\b", r"执行", r"运行", r"重新部署", r"部署(?:到|至|上)"),
    "delete": (r"\b(delete|remove|drop|destroy)\b", r"删除", r"清空", r"销毁"),
    "publish": (r"\b(publish|push|send|upload|post)\b", r"发布", r"推送", r"发送", r"上传"),
}

SENSITIVITY_PATTERNS: dict[str, tuple[str, ...]] = {
    "credentials": (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"\b(?:api[_ -]?key|access[_ -]?token|password|passwd|secret)\b\s*[:=]",
        r"\bsk-[a-zA-Z0-9_-]{16,}\b",
    ),
    "personal_data": (r"\b(?:SSN|身份证|手机号|电话号码|家庭住址)\b", r"\b\d{3}-\d{2}-\d{4}\b"),
    "source_code": (r"```(?:python|javascript|typescript|java|go|rust|sql|bash)", r"\b(?:def|class|function)\s+\w+[({]"),
    "internal": (r"\b(?:internal|confidential|proprietary)\b", r"内部资料", r"机密", r"保密"),
}

PROMPT_INJECTION = (
    r"ignore (?:all |any )?(?:previous|prior) instructions",
    r"reveal (?:the )?(?:system|developer) prompt",
    r"bypass (?:the )?(?:policy|safety|guardrail)",
    r"忽略.{0,8}(?:之前|以上|前面).{0,8}指令",
    r"泄露.{0,8}(?:系统|开发者).{0,4}(?:提示词|指令)",
    r"绕过.{0,8}(?:安全|策略|限制)",
)

DESTRUCTIVE = (
    r"\b(?:delete|drop|destroy|wipe|truncate|force push|production deploy)\b",
    r"\brm\s+-rf\b",
    r"删除", r"清空", r"销毁", r"强推", r"生产.{0,4}部署",
)

EXFILTRATION = (
    r"(?:send|upload|post|exfiltrate).{0,60}(?:credential|secret|password|private key|token)",
    r"(?:发送|上传|泄露).{0,40}(?:凭据|密钥|密码|令牌|私钥)",
)


def _matches(text: str, patterns: Iterable[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL) for pattern in patterns)


def _labels(text: str, groups: dict[str, tuple[str, ...]]) -> list[str]:
    return [name for name, patterns in groups.items() if _matches(text, patterns)]


def classify(
    request: NormalizedRequest,
    proposed_tool_calls: list[dict[str, Any]] | None = None,
) -> Classification:
    context = build_review_context(request, proposed_tool_calls)
    latest_user_text = context.user_messages[-1] if context.user_messages else ""
    all_user_text = "\n".join(context.user_messages)
    positive_text, capabilities, forbidden_capabilities = _capabilities_and_constraints(all_user_text)
    latest_positive, _, latest_forbidden = _capabilities_and_constraints(latest_user_text)
    intents = _labels(latest_positive, PATTERNS)
    intent = intents[0] if intents else "general_chat"
    capabilities = _infer_capabilities(intent, capabilities)

    sensitivities = _labels(all_user_text, SENSITIVITY_PATTERNS) or ["public"]
    reason_codes: list[str] = []

    if _matches(latest_user_text, (r"\?$", r"吗[？?]?\s*$", r"是否", r"能不能", r"how (?:can|do|would)")):
        speech_act = "question"
    elif latest_forbidden and latest_positive.strip():
        speech_act = "directive_with_constraints"
    elif latest_forbidden:
        speech_act = "constraint"
    else:
        speech_act = "directive"

    decision, risk, action_alignment = _evaluate_actions(
        context,
        speech_act=speech_act,
        capabilities=capabilities,
        forbidden_capabilities=forbidden_capabilities,
        reason_codes=reason_codes,
    )

    if _matches(positive_text, EXFILTRATION):
        decision, risk = "deny", "critical"
        action_alignment = "unsafe"
        reason_codes.append("CREDENTIAL_EXFILTRATION")
    elif _matches(all_user_text, PROMPT_INJECTION) and decision != "deny":
        decision, risk = "review", "high"
        action_alignment = "ambiguous"
        reason_codes.append("PROMPT_INJECTION_SIGNAL")
    elif _matches(positive_text, DESTRUCTIVE) and not context.proposed_tool_calls:
        decision, risk = "review", "high"
        action_alignment = "pending_action"
        reason_codes.append("HIGH_IMPACT_ACTION")
    elif "credentials" in sensitivities and decision == "allow":
        decision, risk = "review", "high"
        reason_codes.append("CREDENTIALS_PRESENT")
    elif any(item in sensitivities for item in ("personal_data", "internal")) and decision == "allow":
        decision, risk = "review", "medium"
        reason_codes.append("SENSITIVE_DATA_PRESENT")
    elif not reason_codes:
        reason_codes.append("LOW_RISK_TEXT_REQUEST")

    proposed = [item.to_dict() for item in context.proposed_tool_calls]
    summary = _summary(intent, decision, risk, sensitivities, capabilities, proposed, action_alignment)
    return Classification(
        request_id=request.request_id,
        model=request.model,
        intent=intent,
        speech_act=speech_act,
        risk=risk,
        data_sensitivity=sensitivities,
        requested_capabilities=capabilities,
        forbidden_capabilities=forbidden_capabilities,
        declared_tool_count=len(request.tools),
        reviewed_user_message_count=len(context.user_messages),
        historical_tool_call_count=len(context.historical_tool_calls),
        proposed_tool_calls=proposed,
        action_alignment=action_alignment,
        review_transcript=context.classifier_transcript(),
        decision=decision,
        reason_codes=reason_codes,
        summary=summary,
        classifier_stage="rules+intent_alignment" if proposed else "rules+authorization",
        source_format=request.source_format,
    )


def _summary(
    intent: str,
    decision: str,
    risk: str,
    sensitivities: list[str],
    capabilities: list[str],
    proposed: list[dict[str, Any]],
    alignment: str,
) -> str:
    caps = ", ".join(capabilities) if capabilities else "text generation"
    data = ", ".join(sensitivities)
    action = ", ".join(str(item["name"]) for item in proposed) if proposed else "none"
    return f"{intent}; authorized={caps}; proposed={action}; alignment={alignment}; {risk} risk, {data} data; decision={decision}."


def _capabilities_and_constraints(text: str) -> tuple[str, list[str], list[str]]:
    positive_segments: list[str] = []
    requested: list[str] = []
    forbidden: list[str] = []
    negation = (r"\b(?:do not|don't|never|must not)\b", r"不要", r"禁止", r"不得")
    for segment in re.split(r"[\n。.!！?？,，;；]+", text):
        labels = _labels(segment, CAPABILITY_PATTERNS)
        if _matches(segment, negation):
            forbidden.extend(label for label in labels if label not in forbidden)
        else:
            positive_segments.append(segment)
            requested.extend(label for label in labels if label not in requested)
    return "\n".join(positive_segments), requested, forbidden


def _infer_capabilities(intent: str, explicit: list[str]) -> list[str]:
    result = list(explicit)
    inferred = {
        "analysis": ("read",),
        "code_generation": ("read", "write", "execute"),
        "data_processing": ("read", "write"),
        "summarization": ("read",),
        "translation": ("read",),
    }.get(intent, ())
    for capability in inferred:
        if capability not in result:
            result.append(capability)
    return result


def _evaluate_actions(
    context: ReviewContext,
    *,
    speech_act: str,
    capabilities: list[str],
    forbidden_capabilities: list[str],
    reason_codes: list[str],
) -> tuple[str, str, str]:
    if not context.proposed_tool_calls:
        return "allow", "low", "no_action"

    proposed = {call.capability for call in context.proposed_tool_calls}
    forbidden = proposed.intersection(forbidden_capabilities)
    if forbidden:
        reason_codes.append("ACTION_CONTRADICTS_USER_CONSTRAINT")
        return "deny", "high", "contradicted"

    if any(call.capability == "delete" for call in context.proposed_tool_calls):
        reason_codes.append("DESTRUCTIVE_TOOL_ACTION")
        return "review", "high", "high_impact"

    side_effects = proposed.intersection({"write", "execute", "publish", "unknown"})
    if speech_act == "question" and side_effects:
        reason_codes.append("QUESTION_NOT_EXECUTION_AUTHORIZATION")
        return "review", "high" if "publish" in side_effects else "medium", "out_of_scope"

    if "unknown" in proposed:
        reason_codes.append("UNKNOWN_TOOL_CAPABILITY")
        return "review", "medium", "ambiguous"

    outside_scope = proposed.difference(capabilities).difference({"read"})
    if outside_scope:
        reason_codes.append("ACTION_OUTSIDE_EXPLICIT_SCOPE")
        return "review", "high" if "publish" in outside_scope else "medium", "out_of_scope"

    if "publish" in proposed:
        reason_codes.append("EXTERNAL_STATE_CHANGE")
        return "review", "high", "high_impact"

    reason_codes.append("ACTION_WITHIN_USER_SCOPE")
    risk = "medium" if proposed.intersection({"write", "execute"}) else "low"
    return "allow", risk, "aligned"
