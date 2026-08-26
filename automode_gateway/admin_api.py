from __future__ import annotations

import asyncio
import json
from typing import Any

from aiohttp import web

from .events import EVENT_BROKER_KEY
from .llm_classifier import LLMClassifier, ReviewerSettings
from .normalizer import normalize
from .pipeline import DecisionPipeline
from .policy import evaluate_rules
from .protocols import classification_payload
from .rule_compiler import RuleCompileError, compile_preview
from .storage import TraceStore


STORE_KEY = web.AppKey("admin_trace_store", TraceStore)


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


async def dashboard(request: web.Request) -> web.Response:
    return web.json_response(await _store_call(request, "dashboard"))


async def sessions(request: web.Request) -> web.Response:
    filters = {key: request.query.get(key) for key in ("protocol", "model", "risk", "decision", "capability", "since")}
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
    return web.json_response({"data": await _store_call(request, "alerts", _limit(request), request.query.get("status"))})


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
    proposed = body.get("proposed_tool_calls") or []
    analysis = classification_payload(protocol, payload)
    normalized = normalize(analysis, source_format_override=protocol)
    active_rules = await _store_call(request, "enabled_rules")
    temporary_rule = body.get("temporary_rule")
    if isinstance(temporary_rule, dict):
        active_rules = [*active_rules, {**temporary_rule, "id": "temporary", "version": 0}]
    if body.get("stage") == "rules":
        rule_stage, baseline = evaluate_rules(normalized, proposed, active_rules)
        return web.json_response({
            "final_decision": "allow" if rule_stage.verdict == "SAFE" else "alert",
            "final_stage": "rules", "risk": rule_stage.risk,
            "action_alignment": rule_stage.action_alignment, "reason_code": rule_stage.reason_code,
            "reason": rule_stage.reason, "proposed_actions": baseline.get("proposed_tool_calls", []),
            "review_transcript": baseline.get("review_transcript", []), "stages": [rule_stage.to_dict()],
        })
    result = await asyncio.to_thread(DecisionPipeline().classify, normalized, proposed, active_rules)
    return web.json_response(result.to_dict())


async def replay(request: web.Request) -> web.Response:
    trace = await _store_call(request, "get", request.match_info["trace_id"])
    if trace is None or trace.get("request_body") is None:
        raise web.HTTPNotFound(text="trace or raw request not found")
    classification_value = trace.get("classification") or {}
    body = {"protocol": trace["protocol"], "payload": trace["request_body"], "proposed_tool_calls": classification_value.get("proposed_actions") or classification_value.get("proposed_tool_calls") or []}
    analysis = classification_payload(body["protocol"], body["payload"])
    normalized = normalize(analysis, source_format_override=body["protocol"])
    result = await asyncio.to_thread(DecisionPipeline().classify, normalized, body["proposed_tool_calls"], await _store_call(request, "enabled_rules"))
    return web.json_response({"replay_of": request.match_info["trace_id"], "result": result.to_dict()})


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
