from __future__ import annotations

import re
from typing import Any

from .storage import validate_rule


class RuleCompileError(ValueError):
    def __init__(self, field: str, message: str, suggestion: str) -> None:
        super().__init__(message)
        self.field = field
        self.suggestion = suggestion

    def to_dict(self) -> dict[str, str]:
        return {"field": self.field, "message": str(self), "suggestion": self.suggestion}


def compile_rule(text: str) -> dict[str, Any]:
    original = text.strip()
    if not original:
        raise RuleCompileError("original_text", "规则不能为空", "描述要关注或允许的工具动作。")
    if len(original) > 2000:
        raise RuleCompileError("original_text", "规则长度超过 2000 字符", "拆分成多个范围更小的规则。")
    if re.search(r"```|__import__|subprocess\.|\b(?:SELECT|INSERT|UPDATE|DELETE)\s+\w+", original, re.I):
        raise RuleCompileError("original_text", "规则不能包含代码或 SQL", "仅使用自然语言描述动作、范围与效果。")

    lower = original.lower()
    capability = _capability(lower)
    effect = _effect(lower)
    environment = ["production"] if re.search(r"生产|production|prod\b", lower) else []
    external_data = bool(re.search(r"外部数据|external\s+data|remote\s+data|网络数据|互联网数据", lower))
    tools = []
    if re.search(r"git\s+push|push|推送", lower):
        tools = ["Bash", "git_push"]
    elif re.search(r"deploy|部署", lower):
        tools = ["Bash", "deploy"]
    elif re.search(r"delete|remove|删除|清空|销毁", lower):
        tools = ["*"]
    elif external_data or re.search(r"read|view|inspect|check|fetch|get|retrieve|download|查看|读取|检查|获取|抓取|拉取|下载", lower):
        tools = ["*"]
    else:
        raise RuleCompileError("conditions", "无法识别规则针对的动作", "加入如 push、部署、删除、读取、获取外部数据等动作词。")

    reason_code = _reason_code(capability, environment, effect)
    name = _name(capability, environment, effect)
    compiled: dict[str, Any] = {
        "name": name,
        "original_text": original,
        "scope": {
            "protocols": ["anthropic_messages", "openai_chat_completions", "openai_responses"],
            "models": ["*"],
            "tools": tools,
        },
        "conditions": {
            "capabilities": [capability],
            "target_environment": environment,
            "target_contains": ["http://", "https://", "external", "外部"] if external_data else [],
        },
        "effect": effect,
        "priority": 100 if effect == "always_alert" else 60 if effect == "escalate" else 20,
        "reason_code": reason_code,
        "reason": original[:300],
    }
    try:
        validate_rule(compiled)
    except ValueError as exc:
        raise RuleCompileError("schema", str(exc), "调整规则描述后重新编译。") from exc
    return compiled


def compile_preview(text: str) -> dict[str, Any]:
    compiled = compile_rule(text)
    return {
        "valid": True,
        "compiled": compiled,
        "requires_confirmation": compiled["effect"] == "always_alert",
        "enabled": False,
        "explanation": f"匹配 {', '.join(compiled['conditions']['capabilities'])} 动作，效果为 {compiled['effect']}。",
        "warnings": ["always_alert 需要明确确认后才能保存"] if compiled["effect"] == "always_alert" else [],
    }


def _capability(text: str) -> str:
    if re.search(r"push|publish|deploy|upload|send|推送|发布|部署|上传|发送", text):
        return "publish"
    if re.search(r"delete|remove|destroy|drop|删除|清空|销毁", text):
        return "delete"
    if re.search(r"write|edit|modify|update|写入|编辑|修改", text):
        return "write"
    if re.search(r"execute|run|执行|运行", text):
        return "execute"
    if re.search(r"read|view|inspect|check|fetch|get|retrieve|download|查看|读取|检查|获取|抓取|拉取|下载|外部数据", text):
        return "read"
    return "unknown"


def _effect(text: str) -> str:
    if re.search(r"告警|报警|alert|必须.*关注|never allow|禁止", text):
        return "always_alert"
    if re.search(r"安全|允许|放行|safe|allow", text):
        return "safe"
    return "escalate"


def _reason_code(capability: str, environment: list[str], effect: str) -> str:
    if environment and capability == "publish":
        return "PRODUCTION_DEPLOYMENT"
    if capability == "publish":
        return "PUBLISH_ACTION_POLICY"
    if capability == "delete":
        return "DESTRUCTIVE_ACTION_POLICY"
    return f"{capability.upper()}_{effect.upper()}_POLICY"


def _name(capability: str, environment: list[str], effect: str) -> str:
    scope = "生产环境" if environment else ""
    action = {"publish": "发布", "delete": "删除", "write": "写入", "execute": "执行", "read": "读取"}.get(capability, "未知动作")
    suffix = {"always_alert": "告警", "safe": "放行", "escalate": "复核"}[effect]
    return f"{scope}{action}{suffix}规则"
