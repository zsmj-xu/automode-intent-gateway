from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import time
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .classifier import classify as classify_intent
from .llm_classifier import LLMClassifier, ReviewerSettings, Transport
from .normalizer import normalize


IDENTITY_HEADERS = {
    "user_id": "x-automode-user-id",
    "department": "x-automode-department",
    "roles": "x-automode-roles",
    "agent_id": "x-automode-agent-id",
}


@dataclass(frozen=True)
class DataFinding:
    category: str
    path: str
    confidence: str
    start: int
    end: int
    fingerprint: str
    snippet: str
    detector: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def trusted_identity(headers: dict[str, str], peer: str | None, trusted_cidrs: str | None) -> dict[str, Any]:
    if not peer or not _trusted_peer(peer, trusted_cidrs):
        return {"trusted": False, "source": "untrusted", "user_id": None, "department": None, "roles": [], "agent_id": None}
    roles = [item.strip() for item in headers.get(IDENTITY_HEADERS["roles"], "").split(",") if item.strip()]
    return {
        "trusted": True,
        "source": "trusted_proxy",
        "user_id": headers.get(IDENTITY_HEADERS["user_id"]) or None,
        "department": headers.get(IDENTITY_HEADERS["department"]) or None,
        "roles": roles,
        "agent_id": headers.get(IDENTITY_HEADERS["agent_id"]) or None,
    }


def _trusted_peer(peer: str, trusted_cidrs: str | None) -> bool:
    if not trusted_cidrs:
        return False
    try:
        address = ipaddress.ip_address(peer.split("%", 1)[0])
        return any(address in ipaddress.ip_network(item.strip(), strict=False) for item in trusted_cidrs.split(",") if item.strip())
    except ValueError:
        return False


BUILTIN_DETECTORS: list[dict[str, Any]] = [
    {
        "id": "private_key",
        "name": "RSA/EC/SSH 私钥",
        "category": "credential",
        "description": "检测 PEM 格式的私钥证书内容 (BEGIN PRIVATE KEY)",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    },
    {
        "id": "bearer_token",
        "name": "Bearer 认证令牌",
        "category": "credential",
        "description": "检测请求文本中硬编码的 Bearer Token",
        "pattern": r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}",
    },
    {
        "id": "openai_key",
        "name": "OpenAI API Key",
        "category": "credential",
        "description": "检测 sk-... 格式的 OpenAI / 兼容模型 API Key",
        "pattern": r"\bsk-[A-Za-z0-9_-]{12,}\b",
    },
    {
        "id": "aws_access_key",
        "name": "AWS Access Key ID",
        "category": "credential",
        "description": "检测 AKIA... 格式的 AWS 访问密钥 ID",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
    },
    {
        "id": "secret_assignment",
        "name": "敏感变量/密码赋值",
        "category": "credential",
        "description": "检测 password/api_key/secret 等变量显式赋值",
        "pattern": r"(?i)\b(?:api[_ -]?key|access[_ -]?token|password|passwd|secret)\b\s*[:=]\s*[^\s,;]{4,}",
    },
    {
        "id": "connection_string",
        "name": "数据库连接串 URI",
        "category": "credential",
        "description": "检测包含账密的 postgres/mysql/mongodb/redis 连接字符串",
        "pattern": r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@[^\s]+",
    },
    {
        "id": "cn_identity",
        "name": "中国大陆居民身份证号",
        "category": "pii",
        "description": "检测 18 位大陆身份证号（含生日校验位与校验码）",
        "pattern": r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)",
    },
    {
        "id": "us_ssn",
        "name": "美国社会安全号 (SSN)",
        "category": "pii",
        "description": "检测 xxx-xx-xxxx 格式的 SSN",
        "pattern": r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
    },
    {
        "id": "cn_phone",
        "name": "中国大陆手机号",
        "category": "pii",
        "description": "检测 1[3-9] 开头的 11 位手机号码",
        "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)",
    },
    {
        "id": "email",
        "name": "电子邮箱地址",
        "category": "pii",
        "description": "检测符合 RFC 格式的标准电子邮箱地址",
        "pattern": r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    },
    {
        "id": "source_or_config",
        "name": "源码片段与配置文件",
        "category": "source_code",
        "description": "检测代码块 (Python/JS/SQL/Go/YAML/INI等) 与服务配置文本",
        "pattern": "multi-line regex signals",
    },
]


def scan_payload(
    payload: Any,
    keyword_policies: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    keywords: list[tuple[str, str]] = []
    for policy in keyword_policies:
        policy_id = str(policy.get("id", "policy"))
        for keyword in (policy.get("conditions") or {}).get("keywords") or []:
            if isinstance(keyword, str) and keyword:
                keywords.append((policy_id, keyword))
    findings: list[DataFinding] = []
    for path, text in _walk_strings(payload):
        findings.extend(_scan_text(path, text, keywords))
    unique: dict[tuple[str, str, int, int, str], DataFinding] = {}
    for finding in findings:
        key = (finding.category, finding.path, finding.start, finding.end, finding.fingerprint)
        unique[key] = finding
    return [item.to_dict() for item in unique.values()]


def _walk_strings(value: Any, path: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_strings(item, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def _scan_text(
    path: str,
    text: str,
    keywords: list[tuple[str, str]],
) -> list[DataFinding]:
    import hashlib

    matches: list[tuple[str, int, int, str, str]] = []
    patterns = (
        ("credential", "private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ("credential", "bearer_token", r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
        ("credential", "openai_key", r"\bsk-[A-Za-z0-9_-]{12,}\b"),
        ("credential", "aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("credential", "secret_assignment", r"(?i)\b(?:api[_ -]?key|access[_ -]?token|password|passwd|secret)\b\s*[:=]\s*[^\s,;]{4,}"),
        ("credential", "connection_string", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@[^\s]+"),
        ("pii", "cn_identity", r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)"),
        ("pii", "us_ssn", r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        ("pii", "cn_phone", r"(?<!\d)1[3-9]\d{9}(?!\d)"),
        ("pii", "email", r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    )
    for category, detector, pattern in patterns:
        for match in re.finditer(pattern, text, re.S):
            matches.append((category, match.start(), match.end(), detector, match.group(0)))

    if _looks_like_source_or_config(text):
        matches.append(("source_code", 0, len(text), "source_or_config", text))
    for policy_id, keyword in keywords:
        for match in re.finditer(re.escape(keyword), text, re.I):
            matches.append(("admin_keyword", match.start(), match.end(), f"keyword:{policy_id}", match.group(0)))

    result: list[DataFinding] = []
    for category, start, end, detector, raw in matches:
        fingerprint = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
        snippet = _safe_snippet(text, start, end, category)
        result.append(DataFinding(category, path, "high", start, end, fingerprint, snippet, detector))
    return result


def _looks_like_source_or_config(text: str) -> bool:
    if len(text) < 24:
        return False
    signals = (
        r"```(?:python|javascript|typescript|java|go|rust|sql|bash|sh|yaml|json|toml)",
        r"(?m)^\s*(?:def|class|function|interface|package|import|from)\s+[A-Za-z_$]",
        r"(?m)^#!\s*/(?:usr/)?bin/(?:env\s+)?(?:bash|sh|python|node)",
        r"(?m)^\s*\[[A-Za-z0-9_.-]+\]\s*$",
        r"(?m)^(?:services|version|database|server|logging):\s*$",
    )
    return any(re.search(pattern, text, re.I) for pattern in signals)


def _safe_snippet(text: str, start: int, end: int, category: str) -> str:
    if category == "source_code":
        return "[SOURCE_CODE_REDACTED]"
    left = max(0, start - 80)
    right = min(len(text), end + 80)
    snippet = text[left:start] + f"[REDACTED:{category.upper()}]" + text[end:right]
    snippet = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "[REDACTED:TOKEN]", snippet)
    snippet = re.sub(r"(?<!\d)\d{11,18}(?!\d)", "[REDACTED:NUMBER]", snippet)
    return snippet[:220]


def redact_payload(payload: Any, findings: list[dict[str, Any]]) -> Any:
    import copy

    result = copy.deepcopy(payload)
    by_path: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        by_path.setdefault(str(finding["path"]), []).append(finding)
    for path, path_findings in by_path.items():
        current = _path_get(result, path)
        if not isinstance(current, str):
            continue
        if any(item["category"] == "source_code" for item in path_findings):
            _path_set(result, path, "[REDACTED:SOURCE_CODE]")
            continue
        text = current
        for item in sorted(path_findings, key=lambda value: int(value["start"]), reverse=True):
            start, end = int(item["start"]), int(item["end"])
            text = text[:start] + f"[REDACTED:{str(item['category']).upper()}]" + text[end:]
        _path_set(result, path, text)
    return result


def _path_parts(path: str) -> list[str | int]:
    parts: list[str | int] = []
    for key, index in re.findall(r"\.([^.[\]]+)|\[(\d+)\]", path[1:]):
        parts.append(int(index) if index else key)
    return parts


def _path_get(value: Any, path: str) -> Any:
    current = value
    for part in _path_parts(path):
        current = current[part]
    return current


def _path_set(value: Any, path: str, replacement: str) -> None:
    parts = _path_parts(path)
    current = value
    for part in parts[:-1]:
        current = current[part]
    if parts:
        current[parts[-1]] = replacement


def resolve_destination(model: str | None, upstream: str, targets: Iterable[dict[str, Any]]) -> dict[str, Any]:
    for target in targets:
        if not target.get("enabled", True):
            continue
        upstream_pattern = str(target.get("upstream_pattern") or "*")
        model_pattern = str(target.get("model_pattern") or "*")
        if fnmatch.fnmatch(upstream, upstream_pattern) and fnmatch.fnmatch(model or "", model_pattern):
            return {
                "id": target.get("id"), "name": target.get("name"), "provider": target.get("provider"),
                "region": target.get("region"), "trust": target.get("trust", "external"),
                "model": model, "upstream": upstream, "matched": True,
            }
    return {"id": None, "name": "Unregistered target", "provider": None, "region": None, "trust": "external", "model": model, "upstream": upstream, "matched": False}


def evaluate_dlp(
    payload: dict[str, Any],
    *,
    protocol: str,
    upstream: str,
    identity: dict[str, Any],
    targets: Iterable[dict[str, Any]] = (),
    policies: Iterable[dict[str, Any]] = (),
    prompts: dict[str, str] | None = None,
    fast_transport: Transport | None = None,
    deep_transport: Transport | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    policies = list(policies)
    findings = scan_payload(payload, policies)
    destination = resolve_destination(str(payload.get("model") or "") or None, upstream, targets)
    categories = sorted({str(item["category"]) for item in findings})
    purpose = _request_purpose(payload, protocol)
    matched: list[str] = []
    hard_alert = bool(findings and destination["trust"] == "external")
    if hard_alert:
        matched.append("builtin-sensitive-external")
    review_match = False
    for policy in policies:
        if not policy.get("enabled", True) or not _policy_matches(policy, categories, destination, identity, payload):
            continue
        matched.append(f"{policy.get('id')}:{policy.get('version', 1)}")
        if policy.get("effect") == "alert":
            hard_alert = True
        elif policy.get("effect") == "review":
            review_match = True
    decision = "alert" if hard_alert or review_match else "allow"
    reason_code = "SENSITIVE_DATA_TO_EXTERNAL" if hard_alert and "builtin-sensitive-external" in matched else "DLP_POLICY_MATCH" if matched else "NO_DLP_POLICY_MATCH"
    risk = "critical" if "credential" in categories and decision == "alert" else "high" if decision == "alert" else "medium" if findings else "low"
    reason = "Sensitive outbound data matched an external-destination policy." if decision == "alert" else "No outbound data policy requires attention."
    stages: list[dict[str, Any]] = [{
        "stage": "rules", "status": "completed", "verdict": "ALWAYS_ALERT" if hard_alert else "RISKY" if review_match else "SAFE",
        "risk": risk, "reason_code": reason_code, "reason": reason, "latency_ms": (time.perf_counter() - started) * 1000,
        "action_alignment": purpose, "matched_rule_ids": matched, "matched_rule_versions": matched,
        "evidence": [item["snippet"] for item in findings[:8]],
    }]
    final_stage = "rules"
    semantic_status = "not_needed"
    if review_match and not hard_alert:
        semantic_status = "needs_review"
        signals = _review_signals(findings, destination, identity)
        fast = LLMClassifier(ReviewerSettings.from_env("fast", prompt_override=prompts), fast_transport).run(signals, stages, review_object="outbound_dlp")
        stages.append(fast.to_dict())
        final = fast
        if fast.status == "completed" and fast.verdict == "allow":
            decision, semantic_status = "allow", "resolved"
        else:
            deep = LLMClassifier(ReviewerSettings.from_env("deep", prompt_override=prompts), deep_transport).run(signals, stages, review_object="outbound_dlp")
            stages.append(deep.to_dict())
            final = deep
            if deep.status == "completed" and deep.verdict == "allow":
                decision, semantic_status = "allow", "resolved"
            elif deep.status == "completed" and deep.verdict == "reject":
                decision, semantic_status = "alert", "resolved"
            else:
                decision, semantic_status = "alert", "needs_review"
        final_stage, reason_code, reason = final.stage, final.reason_code, final.reason
        risk = final.risk if final.status == "completed" else "high"
    return {
        "final_decision": decision, "policy_decision": decision, "final_stage": final_stage, "risk": risk,
        "decision": decision, "classifier_stage": final_stage, "reason_codes": [reason_code],
        "reason_code": reason_code, "reason": reason, "action_alignment": purpose,
        "request_purpose": purpose, "data_findings": findings, "destination": destination,
        "destination_trust": destination["trust"], "matched_policies": matched,
        "identity": identity, "evidence_id": None, "review_object": "outbound_request", "semantic_status": semantic_status,
        "request_safety": "not_reviewed", "authorization_evidence": [item["snippet"] for item in findings[:8]],
        "proposed_actions": [], "proposed_tool_calls": [], "matched_rules": matched, "review_transcript": _review_signals(findings, destination, identity),
        "stages": stages,
        "total_latency_ms": (time.perf_counter() - started) * 1000,
    }


def _request_purpose(payload: dict[str, Any], protocol: str) -> str:
    try:
        baseline = classify_intent(normalize(payload, source_format_override=protocol), [])
    except (ValueError, TypeError):
        return "unknown"
    return "suspicious" if baseline.decision in {"deny", "review"} and baseline.risk in {"high", "critical"} else "normal"


def _policy_matches(policy: dict[str, Any], categories: list[str], destination: dict[str, Any], identity: dict[str, Any], payload: dict[str, Any]) -> bool:
    conditions = policy.get("conditions") or {}
    if conditions.get("data_categories") and not set(conditions["data_categories"]).intersection(categories):
        return False
    if conditions.get("destination_trust") and destination["trust"] not in conditions["destination_trust"]:
        return False
    if conditions.get("departments") and identity.get("department") not in conditions["departments"]:
        return False
    if conditions.get("roles") and not set(identity.get("roles") or []).intersection(conditions["roles"]):
        return False
    if conditions.get("agent_ids") and identity.get("agent_id") not in conditions["agent_ids"]:
        return False
    if conditions.get("models") and not any(fnmatch.fnmatch(str(payload.get("model") or ""), pattern) for pattern in conditions["models"]):
        return False
    return bool(categories or conditions.get("keywords"))


def _review_signals(findings: list[dict[str, Any]], destination: dict[str, Any], identity: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"type": "dlp_finding", "category": item["category"], "path": item["path"], "confidence": item["confidence"], "snippet": item["snippet"]} for item in findings] + [
        {"type": "destination", **destination},
        {"type": "identity", **identity},
    ]
