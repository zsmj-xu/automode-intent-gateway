from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
from typing import Any

from aiohttp import web

from .events import EVENT_BROKER_KEY
from .dlp import evaluate_dlp
from .dlp_rule_compiler import DLPPolicyCompileError, compile_dlp_policy
from .llm_classifier import LLMClassifier, ReviewerSettings
from .normalizer import normalize
from .pipeline import DecisionPipeline
from .policy import evaluate_rules
from .protocols import classification_payload
from .rule_compiler import RuleCompileError, compile_preview
from .review_context import build_review_context
from .storage import TraceStore


STORE_KEY = web.AppKey("admin_trace_store", TraceStore)
ADMIN_TOKEN_KEY = web.AppKey("admin_token", object)
BIND_HOST_KEY = web.AppKey("bind_host", str)
UPSTREAM_KEY = web.AppKey("upstream", str)


def register_admin_routes(app: web.Application, store: TraceStore) -> None:
    app[STORE_KEY] = store
    routes = app.router
    routes.add_get("/api/dashboard", dashboard)
    routes.add_get("/api/sessions", sessions)
    routes.add_get("/api/sessions/{session_id}", session)
    routes.add_get("/api/sessions/{session_id}/timeline", timeline)
    routes.add_get("/api/sessions/{session_id}/detail", session_detail)
    routes.add_post("/api/sessions/backfill", backfill_sessions)
    routes.add_get("/api/traces/{trace_id}/classification", classification)
    routes.add_get("/api/events", events)
    routes.add_get("/api/alerts", alerts)
    routes.add_get("/api/alerts/{alert_id}", alert)
    routes.add_patch("/api/alerts/{alert_id}", update_alert)
    routes.add_post("/api/alerts/{alert_id}/feedback", alert_feedback)
    routes.add_get("/api/prompts", get_prompts_handler)
    routes.add_patch("/api/prompts", update_prompts_handler)
    routes.add_post("/api/prompts/reset", reset_prompts_handler)
    routes.add_get("/api/detectors", get_detectors_handler)
    routes.add_post("/api/detectors", create_detector_handler)
    routes.add_patch("/api/detectors/{detector_id}", update_detector_handler)
    routes.add_delete("/api/detectors/{detector_id}", delete_detector_handler)
    routes.add_get("/api/tool-schemas", get_tool_schemas_handler)
    routes.add_post("/api/tool-schemas", create_tool_schema_handler)
    routes.add_patch("/api/tool-schemas/{schema_id}", update_tool_schema_handler)
    routes.add_delete("/api/tool-schemas/{schema_id}", delete_tool_schema_handler)
    routes.add_get("/api/rules", rules)
    routes.add_post("/api/rules/compile", compile_rule)
    routes.add_post("/api/rules/test", test_rule)
    routes.add_post("/api/rules", create_rule)
    routes.add_get("/api/rules/{rule_id}", rule)
    routes.add_patch("/api/rules/{rule_id}", update_rule)
    routes.add_delete("/api/rules/{rule_id}", delete_rule)
    routes.add_post("/api/rules/{rule_id}/enable", enable_rule)
    routes.add_post("/api/rules/{rule_id}/disable", disable_rule)
    routes.add_get("/api/rules/{rule_id}/versions", versions)
    routes.add_post("/api/rules/{rule_id}/rollback", rollback)
    routes.add_post("/api/playground/classify", playground_classify)
    routes.add_post("/api/playground/replay/{trace_id}", replay)
    routes.add_get("/api/settings", settings)
    routes.add_patch("/api/settings", update_settings)
    routes.add_post("/api/settings/test-fast-model", test_fast)
    routes.add_post("/api/settings/test-deep-model", test_deep)
    routes.add_get("/api/destinations", destinations)
    routes.add_post("/api/destinations", create_destination)
    routes.add_patch("/api/destinations/{destination_id}", update_destination)
    routes.add_delete("/api/destinations/{destination_id}", delete_destination)
    routes.add_get("/api/dlp-policies", dlp_policies)
    routes.add_post("/api/dlp-policies/compile", compile_dlp)
    routes.add_post("/api/dlp-policies/test", test_dlp)
    routes.add_post("/api/dlp-policies", create_dlp_policy)
    routes.add_patch("/api/dlp-policies/{policy_id}", update_dlp_policy)
    routes.add_delete("/api/dlp-policies/{policy_id}", delete_dlp_policy)
    routes.add_post("/api/dlp-policies/{policy_id}/enable", enable_dlp_policy)
    routes.add_post("/api/dlp-policies/{policy_id}/disable", disable_dlp_policy)
    routes.add_get("/api/dlp-policies/{policy_id}/versions", dlp_policy_versions)
    routes.add_get("/api/evidence/{evidence_id}/raw", raw_evidence)
    routes.add_post("/api/evidence/purge", purge_evidence)


async def dashboard(request: web.Request) -> web.Response:
    return web.json_response(await _store_call(request, "dashboard"))


async def sessions(request: web.Request) -> web.Response:
    filters = {key: request.query.get(key) for key in ("protocol", "model", "risk", "decision", "capability", "since", "category")}
    return web.json_response({"data": await _store_call(request, "sessions", _limit(request), **filters)})


async def session(request: web.Request) -> web.Response:
    value = await _store_call(request, "session", request.match_info["session_id"])
    if value is None:
        raise web.HTTPNotFound(text="session not found")
    return web.json_response(value)


async def timeline(request: web.Request) -> web.Response:
    return web.json_response({"data": await _store_call(request, "timeline", request.match_info["session_id"])})


async def session_detail(request: web.Request) -> web.Response:
    value = await _store_call(request, "session_detail", request.match_info["session_id"])
    if value is None:
        raise web.HTTPNotFound(text="session not found")
    return web.json_response(value)


async def backfill_sessions(request: web.Request) -> web.Response:
    """Regroup historical traces into conversation sessions and rebuild the
    session-level read model. Non-destructive to per-trace classification records."""
    stats = await _store_call(request, "backfill_sessions")
    request.app[EVENT_BROKER_KEY].publish("sessions.backfilled", {"stats": stats})
    return web.json_response(stats)


async def classification(request: web.Request) -> web.Response:
    value = await _store_call(request, "classification", request.match_info["trace_id"])
    if value is None:
        raise web.HTTPNotFound(text="classification not found")
    return web.json_response(value)


async def events(request: web.Request) -> web.StreamResponse:
    return await request.app[EVENT_BROKER_KEY].stream(request)


async def alerts(request: web.Request) -> web.Response:
    alert_type = request.query.get("alert_type") or request.query.get("category")
    return web.json_response({"data": await _store_call(request, "alerts", _limit(request), request.query.get("status"), alert_type)})


async def get_prompts_handler(request: web.Request) -> web.Response:
    prompts = await _store_call(request, "get_prompts")
    defaults = await _store_call(request, "get_default_prompts")
    return web.json_response({"data": prompts, "defaults": defaults})


async def update_prompts_handler(request: web.Request) -> web.Response:
    body = await _json(request)
    prompts = body.get("prompts")
    if not isinstance(prompts, dict) or not prompts:
        raise web.HTTPBadRequest(text="prompts object is required")
    try:
        updated = await _store_call(request, "update_prompts", prompts)
        defaults = await _store_call(request, "get_default_prompts")
        return web.json_response({"data": updated, "defaults": defaults})
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc


async def reset_prompts_handler(request: web.Request) -> web.Response:
    body = await _json(request) if request.can_read_body else {}
    name = body.get("name") if isinstance(body, dict) else None
    try:
        updated = await _store_call(request, "reset_prompts", name)
        defaults = await _store_call(request, "get_default_prompts")
        return web.json_response({"data": updated, "defaults": defaults})
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc


async def get_detectors_handler(request: web.Request) -> web.Response:
    data = await _store_call(request, "get_detectors")
    return web.json_response({"data": data})


async def create_detector_handler(request: web.Request) -> web.Response:
    body = await _json(request)
    name = str(body.get("name", "")).strip()
    category = str(body.get("category", "")).strip()
    description = str(body.get("description", "")).strip()
    pattern = str(body.get("pattern", "")).strip()
    if not name or not pattern or not category:
        raise web.HTTPBadRequest(text="name, category, and pattern are required")
    try:
        created = await _store_call(request, "add_custom_detector", name, category, description, pattern)
        return web.json_response({"data": created}, status=201)
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc


async def update_detector_handler(request: web.Request) -> web.Response:
    body = await _json(request)
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        raise web.HTTPBadRequest(text="enabled boolean is required")
    detector_id = request.match_info["detector_id"]
    try:
        value = await _store_call(request, "set_detector_enabled", detector_id, enabled)
        return web.json_response({"data": value})
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc


async def delete_detector_handler(request: web.Request) -> web.Response:
    detector_id = request.match_info["detector_id"]
    try:
        await _store_call(request, "delete_custom_detector", detector_id)
        return web.json_response({"deleted": True, "id": detector_id})
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc


async def get_tool_schemas_handler(request: web.Request) -> web.Response:
    data = await _store_call(request, "get_tool_schemas")
    return web.json_response({"data": data})


async def create_tool_schema_handler(request: web.Request) -> web.Response:
    body = await _json(request)
    tool_name = str(body.get("tool_name", "")).strip()
    content_fingerprint = str(body.get("content_fingerprint", "")).strip()
    agent_id = str(body.get("agent_id", "claude_code")).strip()
    schema_version = str(body.get("schema_version", "v1.0")).strip()
    description_snippet = str(body.get("description_snippet", "")).strip()
    reason = str(body.get("reason", "受控内置工具")).strip()
    if not tool_name or not content_fingerprint:
        raise web.HTTPBadRequest(text="tool_name and content_fingerprint are required")
    try:
        created = await _store_call(
            request,
            "add_tool_schema",
            tool_name,
            content_fingerprint,
            agent_id=agent_id,
            schema_version=schema_version,
            description_snippet=description_snippet,
            reason=reason,
        )
        return web.json_response({"data": created}, status=201)
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc


async def update_tool_schema_handler(request: web.Request) -> web.Response:
    body = await _json(request)
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        raise web.HTTPBadRequest(text="enabled boolean is required")
    schema_id = request.match_info["schema_id"]
    try:
        value = await _store_call(request, "set_tool_schema_enabled", schema_id, enabled)
        return web.json_response({"data": value})
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc


async def delete_tool_schema_handler(request: web.Request) -> web.Response:
    schema_id = request.match_info["schema_id"]
    try:
        await _store_call(request, "delete_tool_schema", schema_id)
        return web.json_response({"deleted": True, "id": schema_id})
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc


async def alert(request: web.Request) -> web.Response:
    value = await _store_call(request, "alert", request.match_info["alert_id"])
    if value is None:
        raise web.HTTPNotFound(text="alert not found")
    return web.json_response(value)


async def update_alert(request: web.Request) -> web.Response:
    body = await _json(request)
    try:
        value = await _store_call(request, "update_alert", request.match_info["alert_id"], status=body.get("status", "open"), note=body.get("operator_note", ""))
    except (ValueError, KeyError) as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    request.app[EVENT_BROKER_KEY].publish("alert.updated", {"id": value["id"], "status": value["status"]})
    return web.json_response(value)


async def alert_feedback(request: web.Request) -> web.Response:
    body = await _json(request)
    feedback = str(body.get("feedback", ""))
    if feedback not in {"correct", "false_positive", "unsure"}:
        raise web.HTTPBadRequest(text="invalid feedback")
    status = "false_positive" if feedback == "false_positive" else body.get("status", "acknowledged")
    value = await _store_call(request, "update_alert", request.match_info["alert_id"], status=status, note=body.get("operator_note", ""), feedback=feedback)
    request.app[EVENT_BROKER_KEY].publish("alert.updated", {"id": value["id"], "status": value["status"]})
    return web.json_response(value)


async def rules(request: web.Request) -> web.Response:
    return web.json_response({"data": await _store_call(request, "list_rules")})


async def compile_rule(request: web.Request) -> web.Response:
    body = await _json(request)
    try:
        return web.json_response(compile_preview(str(body.get("text", ""))))
    except RuleCompileError as exc:
        return web.json_response({"valid": False, "errors": [exc.to_dict()]}, status=422)


async def test_rule(request: web.Request) -> web.Response:
    body = await _json(request)
    compiled = body.get("rule")
    if compiled is None:
        try:
            compiled = compile_preview(str(body.get("text", "")))["compiled"]
        except RuleCompileError as exc:
            return web.json_response({"valid": False, "errors": [exc.to_dict()]}, status=422)
    payload = body.get("payload") or {"model": "playground", "messages": [{"role": "user", "content": body.get("user_message", "")}]}
    protocol = str(body.get("protocol", "openai_chat_completions"))
    try:
        analysis = classification_payload(protocol, payload)
        normalized = normalize(analysis, source_format_override=protocol)
        stage, _ = evaluate_rules(normalized, body.get("proposed_tool_calls") or [], [{**compiled, "id": compiled.get("id", "preview"), "version": compiled.get("version", 0)}])
    except (ValueError, TypeError) as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    result = {"matched": bool(stage.matched_rule_ids), "stage": stage.to_dict(), "executed_tools": False, "forwarded_to_agent": False}
    result["test_run_id"] = await _store_call(request, "record_test_run", {"protocol": protocol, "payload": payload, "proposed_tool_calls": body.get("proposed_tool_calls") or []}, compiled, result)
    return web.json_response(result)


async def create_rule(request: web.Request) -> web.Response:
    body = await _json(request)
    compiled = body.get("compiled")
    if not isinstance(compiled, dict):
        raise web.HTTPBadRequest(text="compiled rule is required")
    try:
        value = await _store_call(request, "create_rule", compiled, confirmed=bool(body.get("confirmed")))
    except ValueError as exc:
        raise web.HTTPUnprocessableEntity(text=str(exc)) from exc
    request.app[EVENT_BROKER_KEY].publish("rule.updated", {"id": value["id"], "version": value["version"]})
    return web.json_response(value, status=201)


async def rule(request: web.Request) -> web.Response:
    value = await _store_call(request, "get_rule", request.match_info["rule_id"])
    if value is None:
        raise web.HTTPNotFound(text="rule not found")
    return web.json_response(value)


async def update_rule(request: web.Request) -> web.Response:
    body = await _json(request)
    compiled = body.get("compiled")
    if not isinstance(compiled, dict):
        raise web.HTTPBadRequest(text="compiled rule is required")
    try:
        value = await _store_call(request, "update_rule", request.match_info["rule_id"], compiled, confirmed=bool(body.get("confirmed")))
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc
    except ValueError as exc:
        raise web.HTTPUnprocessableEntity(text=str(exc)) from exc
    request.app[EVENT_BROKER_KEY].publish("rule.updated", {"id": value["id"], "version": value["version"]})
    return web.json_response(value)


async def delete_rule(request: web.Request) -> web.Response:
    await _store_call(request, "delete_rule", request.match_info["rule_id"])
    request.app[EVENT_BROKER_KEY].publish("rule.updated", {"id": request.match_info["rule_id"], "enabled": False})
    return web.Response(status=204)


async def enable_rule(request: web.Request) -> web.Response:
    return await _enable(request, True)


async def disable_rule(request: web.Request) -> web.Response:
    return await _enable(request, False)


async def _enable(request: web.Request, enabled: bool) -> web.Response:
    try:
        value = await _store_call(request, "set_rule_enabled", request.match_info["rule_id"], enabled)
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc
    request.app[EVENT_BROKER_KEY].publish("rule.updated", {"id": value["id"], "enabled": enabled})
    return web.json_response(value)


async def versions(request: web.Request) -> web.Response:
    return web.json_response({"data": await _store_call(request, "rule_versions", request.match_info["rule_id"])})


async def rollback(request: web.Request) -> web.Response:
    body = await _json(request)
    try:
        value = await _store_call(request, "rollback_rule", request.match_info["rule_id"], int(body["version"]))
    except (KeyError, ValueError) as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    request.app[EVENT_BROKER_KEY].publish("rule.updated", {"id": value["id"], "version": value["version"]})
    return web.json_response(value)


async def playground_classify(request: web.Request) -> web.Response:
    body = await _json(request)
    protocol = str(body.get("protocol", "openai_chat_completions"))
    payload = body.get("payload") or body
    result = await asyncio.to_thread(
        evaluate_dlp, payload, protocol=protocol, upstream=request.app[UPSTREAM_KEY],
        identity={"trusted": False, "roles": []}, targets=await _store_call(request, "list_destinations"),
        policies=await _store_call(request, "list_dlp_policies", True),
        prompts=await _store_call(request, "get_prompts"),
    )
    return web.json_response(result)


async def replay(request: web.Request) -> web.Response:
    trace = await _store_call(request, "get", request.match_info["trace_id"])
    if trace is None or trace.get("request_body") is None:
        raise web.HTTPNotFound(text="trace or raw request not found")
    body = {"protocol": trace["protocol"], "payload": trace["request_body"]}
    result = await asyncio.to_thread(
        evaluate_dlp, body["payload"], protocol=body["protocol"], upstream=request.app[UPSTREAM_KEY],
        identity={"trusted": False, "roles": []}, targets=await _store_call(request, "list_destinations"),
        policies=await _store_call(request, "list_dlp_policies", True),
        prompts=await _store_call(request, "get_prompts"),
    )
    return web.json_response({"replay_of": request.match_info["trace_id"], "result": result, "redacted_input": True})


async def settings(request: web.Request) -> web.Response:
    return web.json_response(await _store_call(request, "settings"))


async def update_settings(request: web.Request) -> web.Response:
    body = await _json(request)
    try:
        value = await _store_call(request, "update_settings", body)
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    return web.json_response(value)


async def test_fast(request: web.Request) -> web.Response:
    return await _test_model("fast")


async def test_deep(request: web.Request) -> web.Response:
    return await _test_model("deep")


async def _test_model(stage: str) -> web.Response:
    classifier = LLMClassifier(ReviewerSettings.from_env(stage))
    result = await asyncio.to_thread(classifier.run, [{"type": "user", "text": "只读检查"}], [])
    return web.json_response({"configured": classifier.configured, "result": result.to_dict()}, status=200 if result.status == "completed" else 503)


async def destinations(request: web.Request) -> web.Response:
    return web.json_response({"data": await _store_call(request, "list_destinations")})


async def create_destination(request: web.Request) -> web.Response:
    try:
        return web.json_response(await _store_call(request, "create_destination", await _json(request)), status=201)
    except ValueError as exc:
        raise web.HTTPUnprocessableEntity(text=str(exc)) from exc


async def update_destination(request: web.Request) -> web.Response:
    try:
        return web.json_response(await _store_call(request, "update_destination", request.match_info["destination_id"], await _json(request)))
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc
    except ValueError as exc:
        raise web.HTTPUnprocessableEntity(text=str(exc)) from exc


async def delete_destination(request: web.Request) -> web.Response:
    await _store_call(request, "delete_destination", request.match_info["destination_id"])
    return web.Response(status=204)


async def dlp_policies(request: web.Request) -> web.Response:
    return web.json_response({"data": await _store_call(request, "list_dlp_policies")})


async def compile_dlp(request: web.Request) -> web.Response:
    try:
        return web.json_response({"valid": True, "compiled": compile_dlp_policy(str((await _json(request)).get("text", "")))})
    except DLPPolicyCompileError as exc:
        return web.json_response({"valid": False, "errors": [{"field": "text", "message": str(exc)}]}, status=422)


async def test_dlp(request: web.Request) -> web.Response:
    body = await _json(request)
    payload = body.get("payload") or {"model": body.get("model", "playground"), "messages": [{"role": "user", "content": body.get("text", "")}]}
    policy = body.get("policy")
    policies = await _store_call(request, "list_dlp_policies", True)
    if isinstance(policy, dict):
        policies = [*policies, {**policy, "id": "temporary", "version": 0, "enabled": True}]
    result = await asyncio.to_thread(
        evaluate_dlp, payload, protocol=str(body.get("protocol", "openai_chat_completions")),
        upstream=request.app[UPSTREAM_KEY], identity={"trusted": False, "roles": []},
        targets=await _store_call(request, "list_destinations"), policies=policies,
    )
    return web.json_response(result)


async def create_dlp_policy(request: web.Request) -> web.Response:
    body = await _json(request)
    compiled = body.get("compiled")
    if not isinstance(compiled, dict):
        raise web.HTTPBadRequest(text="compiled policy is required")
    try:
        return web.json_response(await _store_call(request, "create_dlp_policy", compiled, bool(body.get("enabled"))), status=201)
    except ValueError as exc:
        raise web.HTTPUnprocessableEntity(text=str(exc)) from exc


async def update_dlp_policy(request: web.Request) -> web.Response:
    body = await _json(request)
    compiled = body.get("compiled") or body
    try:
        return web.json_response(await _store_call(request, "update_dlp_policy", request.match_info["policy_id"], compiled))
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc
    except ValueError as exc:
        raise web.HTTPUnprocessableEntity(text=str(exc)) from exc


async def delete_dlp_policy(request: web.Request) -> web.Response:
    await _store_call(request, "delete_dlp_policy", request.match_info["policy_id"])
    return web.Response(status=204)


async def enable_dlp_policy(request: web.Request) -> web.Response:
    return web.json_response(await _store_call(request, "set_dlp_policy_enabled", request.match_info["policy_id"], True))


async def disable_dlp_policy(request: web.Request) -> web.Response:
    return web.json_response(await _store_call(request, "set_dlp_policy_enabled", request.match_info["policy_id"], False))


async def dlp_policy_versions(request: web.Request) -> web.Response:
    return web.json_response({"data": await _store_call(request, "dlp_policy_versions", request.match_info["policy_id"])})


async def raw_evidence(request: web.Request) -> web.Response:
    token = request.app[ADMIN_TOKEN_KEY]
    if not isinstance(token, str) or not token:
        raise web.HTTPForbidden(text="AUTOMODE_ADMIN_TOKEN is required to decrypt evidence")
    supplied = request.headers.get("x-automode-admin-token")
    authorization = request.headers.get("authorization", "")
    if not supplied and authorization.lower().startswith("bearer "):
        supplied = authorization[7:]
    if not supplied or not hmac.compare_digest(supplied, token):
        raise web.HTTPUnauthorized(text="admin authentication required")
    try:
        peer = ipaddress.ip_address((request.remote or "").split("%", 1)[0])
    except ValueError as exc:
        raise web.HTTPForbidden(text="raw evidence is loopback-only") from exc
    if not peer.is_loopback or not _bind_is_loopback(request.app[BIND_HOST_KEY]):
        raise web.HTTPForbidden(text="raw evidence is loopback-only")
    try:
        value = await _store_call(
            request, "evidence", request.match_info["evidence_id"], actor=request.headers.get("x-automode-operator", "admin-token"),
            purpose=request.query.get("purpose", "incident_review"), source=request.remote or "loopback",
        )
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc
    except RuntimeError as exc:
        raise web.HTTPServiceUnavailable(text=str(exc)) from exc
    return web.json_response(value)


async def purge_evidence(request: web.Request) -> web.Response:
    return web.json_response({"deleted": await _store_call(request, "purge_expired_evidence")})


def _bind_is_loopback(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


async def _store_call(request: web.Request, method: str, *args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(getattr(request.app[STORE_KEY], method), *args, **kwargs)


async def _json(request: web.Request) -> dict[str, Any]:
    try:
        value = await request.json()
    except json.JSONDecodeError as exc:
        raise web.HTTPBadRequest(text="invalid JSON") from exc
    if not isinstance(value, dict):
        raise web.HTTPBadRequest(text="JSON body must be an object")
    return value


def _limit(request: web.Request) -> int:
    try:
        return int(request.query.get("limit", "100"))
    except ValueError as exc:
        raise web.HTTPBadRequest(text="limit must be an integer") from exc
