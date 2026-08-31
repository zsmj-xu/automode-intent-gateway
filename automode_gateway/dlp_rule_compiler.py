from __future__ import annotations

import re
from typing import Any


class DLPPolicyCompileError(ValueError):
    pass


def compile_dlp_policy(text: str) -> dict[str, Any]:
    original = text.strip()
    if not original:
        raise DLPPolicyCompileError("策略不能为空")
    if len(original) > 2000 or re.search(r"```|__import__|subprocess\.|\b(?:SELECT|INSERT|UPDATE|DELETE)\s+\w+", original, re.I):
        raise DLPPolicyCompileError("策略只能包含自然语言，且长度不能超过 2000 字符")
    lower = original.lower()
    categories: list[str] = []
    category_patterns = {
        "credential": r"凭据|密钥|密码|token|secret|credential|private key",
        "pii": r"个人信息|隐私|身份证|手机号|邮箱|pii|personal data",
        "source_code": r"源码|代码|配置|source code|configuration",
        "admin_keyword": r"关键词|keyword",
    }
    for category, pattern in category_patterns.items():
        if re.search(pattern, lower):
            categories.append(category)
    destination = ["external"] if re.search(r"外部|未受信|external|untrusted", lower) else ["trusted"] if re.search(r"内部模型|受信|trusted", lower) else []
    effect = "alert" if re.search(r"告警|报警|alert|禁止|不得", lower) else "review"
    keywords = re.findall(r"[“\"]([^”\"]{2,80})[”\"]", original)
    departments = _values(original, r"(?:部门|department)\s*(?:为|是|=|:|：)?\s*[“\"]?([\w.-]{2,40})")
    roles = _values(original, r"(?:角色|role)\s*(?:为|是|=|:|：)?\s*[“\"]?([\w.-]{2,40})")
    agent_ids = _values(original, r"(?:Agent|智能体)\s*(?:为|是|=|:|：)?\s*[“\"]?([\w.*-]{2,80})")
    models = _values(original, r"(?:模型|model)\s*(?:为|是|=|:|：)?\s*[“\"]?([\w.*:/-]{2,120})")
    if not categories and not keywords:
        raise DLPPolicyCompileError("无法识别数据类别；请描述凭据、PII、源码、配置或用引号提供关键词")
    compiled = {
        "name": (original[:36] + "…") if len(original) > 36 else original,
        "original_text": original,
        "effect": effect,
        "priority": 100 if effect == "alert" else 60,
        "conditions": {
            "data_categories": categories,
            "destination_trust": destination,
            "departments": departments, "roles": roles, "agent_ids": agent_ids, "models": models, "keywords": keywords,
        },
        "reason_code": "CUSTOM_DLP_ALERT" if effect == "alert" else "CUSTOM_DLP_REVIEW",
        "reason": original[:300],
    }
    return compiled


def _values(text: str, pattern: str) -> list[str]:
    return list(dict.fromkeys(match.rstrip("”\"") for match in re.findall(pattern, text, re.I)))
