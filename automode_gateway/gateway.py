from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
import mimetypes
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from aiohttp import ClientSession, ClientTimeout, web
from multidict import CIMultiDict

from .admin_api import ADMIN_TOKEN_KEY, BIND_HOST_KEY, UPSTREAM_KEY, register_admin_routes
from .classifier import authorization_signals
from .decision import PipelineResult
from .disk_buffer import DiskBuffer
from .dlp import evaluate_dlp, trusted_identity
from .engine import AnalysisEngine
from .event_ingress import DISK_BUFFER_KEY, StandardEvent, accept_standard_event, register_ingress_routes
from .event_worker import EventWorker
from .events import EVENT_BROKER_KEY, EventBroker
from .normalizer import normalize
from .pipeline import DecisionPipeline
from .protocols import classification_payload, protocol_for_path, session_evidence_from, session_id_from
from .response_parser import extract_tool_calls
from .review_context import build_review_context
from .service import classify_payload
from .session_fingerprint import conversation_fingerprint
from .session_risk import assess as assess_session_risk
from .storage import TraceStore


logger = logging.getLogger(__name__)

DEFAULT_PROXY_BUFFER_EVENTS = 100
DEFAULT_PROXY_BUFFER_BYTES = 64 * 1024 * 1024
PROXY_SOURCE_ID = "proxy-adapter"


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


class Gateway:
    def __init__(
        self,
        upstream: str | None,
        store: TraceStore,
        broker: EventBroker,
        engine: AnalysisEngine | None = None,
        disk_buffer: DiskBuffer | None = None,
        event_worker: EventWorker | None = None,
    ) -> None:
        self.upstream = upstream.rstrip("/") if upstream else None
        self.store = store
        self.broker = broker
        self.engine = engine or AnalysisEngine(store=store, broker=broker, upstream=self.upstream)
        self.disk_buffer = disk_buffer
        self.event_worker = event_worker
        self.client: ClientSession | None = None
        self._accepting_proxy_audit = True
        self.proxy_buffer_max_events = max(1, int(os.getenv("AUTOMODE_PROXY_BUFFER_EVENTS", str(DEFAULT_PROXY_BUFFER_EVENTS))))
        self.proxy_buffer_max_bytes = max(1, int(os.getenv("AUTOMODE_PROXY_BUFFER_BYTES", str(DEFAULT_PROXY_BUFFER_BYTES))))
        # A bounded queue is used in both modes.  Bytes are reserved before an
        # item is queued and released only after persistence/analysis finishes,
        # so an in-flight disk write counts against the limit as required.
        self.proxy_audit_queue: asyncio.Queue[tuple[dict[str, Any], bytes, asyncio.Future[str | None]]] = asyncio.Queue(
            maxsize=self.proxy_buffer_max_events
        )
        self.proxy_audit_buffer_bytes = 0
        self.proxy_audit_active = False
        self.proxy_dropped_count = 0
        self.proxy_failed_count = 0
        self.proxy_dropped_by_reason: dict[str, int] = {}
        self.proxy_failed_by_reason: dict[str, int] = {}
        self.proxy_audit_worker: asyncio.Task[Any] | None = None

    @property
    def reliability_mode(self) -> str:
        # Proxy delivery is asynchronous even with an encrypted buffer: a
        # process crash before the worker fsyncs an item can lose that audit
        # event.  Keep this distinct from the reliable /v1/events contract.
        if not self.upstream:
            return "standard_event_only"
        return "proxy_async_encrypted" if self.disk_buffer is not None and self.event_worker is not None else "proxy_best_effort"

    @property
    def proxy_buffer_bytes(self) -> int:
        return self.proxy_audit_buffer_bytes

    @property
    def proxy_buffer_events(self) -> int:
        return self.proxy_audit_queue.qsize() + (1 if self.proxy_audit_active else 0)

    async def start(self, app: web.Application) -> None:
        if self.upstream:
            timeout = ClientTimeout(total=None, connect=30, sock_read=None)
            self.client = ClientSession(timeout=timeout, auto_decompress=False)
        self._accepting_proxy_audit = True
        self.proxy_audit_worker = asyncio.create_task(self._proxy_audit_loop())

    async def stop(self, app: web.Application) -> None:
        self._accepting_proxy_audit = False
        if self.proxy_audit_worker is not None:
            try:
                await asyncio.wait_for(self.proxy_audit_queue.join(), timeout=30.0)
            except asyncio.TimeoutError:
                # The audit path is best effort from the proxy's perspective;
                # do not hold process shutdown indefinitely on a slow reviewer
                # or disk.  Queued items are explicitly counted as undelivered.
                pending = self.proxy_audit_queue.qsize() + (1 if self.proxy_audit_active else 0)
                if pending:
                    self._record_proxy_drop("shutdown_timeout", pending)
            self.proxy_audit_worker.cancel()
            await asyncio.gather(self.proxy_audit_worker, return_exceptions=True)
            self.proxy_audit_worker = None
        if self.client is not None:
            await self.client.close()
            self.client = None

    async def proxy(self, request: web.Request) -> web.StreamResponse:
        protocol = protocol_for_path(request.path)
        if protocol is None:
            raise web.HTTPNotFound(text="unsupported model endpoint")
        if not self.upstream:
            raise web.HTTPServiceUnavailable(text="upstream is not configured; event service is running independently")
        if self.client is None:
            raise web.HTTPServiceUnavailable(text="gateway is starting")

        started = time.monotonic()
        body = await request.read()
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object")
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            raise web.HTTPBadRequest(text=str(exc)) from exc

        inbound_headers = {key.lower(): value for key, value in request.headers.items()}
        trace_id = str(uuid.uuid4())
        analysis_payload: dict[str, Any] | None = None
        self.broker.publish("trace.created", {"id": trace_id, "protocol": protocol, "model": payload.get("model")})

        # Human-request review starts from the request copy, independently of
        # whether the model later emits a tool call. Persistence and review run
        # off the forwarding critical path, so Observe mode stays transparent.
        session_evidence = session_evidence_from(payload, inbound_headers)
        session_signals: dict[str, Any] | None = None
        identity = trusted_identity(inbound_headers, request.remote, os.getenv("AUTOMODE_TRUSTED_PROXY_CIDRS"))
        try:
            analysis_payload = classification_payload(protocol, payload)
            normalized = normalize(analysis_payload, source_format_override=protocol)
            review_context = build_review_context(normalized)
            latest_user_text = review_context.user_messages[-1] if review_context.user_messages else ""
            declared_tool_count = len(normalized.tools)
            session_evidence["fingerprint"] = conversation_fingerprint(normalized.messages)
            session_signals = authorization_signals(review_context.user_messages)
            session_signals["statements"] = []
        except (ValueError, TypeError, KeyError):
            # Analysis is an observer: malformed-but-upstream-accepted input
            # must never replace the upstream response with our error.
            analysis_payload = None
            latest_user_text = ""
            declared_tools = payload.get("tools")
            declared_tool_count = len(declared_tools) if isinstance(declared_tools, list) else 0
        persist_task = self._enqueue_proxy_audit({
            "trace_id": trace_id,
            "protocol": protocol,
            "method": request.method,
            "path": request.path_qs,
            "payload": payload,
            "headers": inbound_headers,
            "session_id": session_id_from(payload, inbound_headers),
            "session_evidence": session_evidence,
            "conversation_fingerprint": session_evidence.get("fingerprint"),
            "session_signals": session_signals,
            "latest_user_text": latest_user_text,
            "declared_tool_count": declared_tool_count,
            "analysis_payload": analysis_payload,
            "identity": identity,
        }, payload, identity, session_evidence)

        upstream_url = _join_url(self.upstream, request.path_qs)
        outbound_headers = _request_headers(request.headers, trace_id)
        status: int | None = None
        response_bytes = 0
        response_capture = bytearray()
        capture_limit = int(os.getenv("AUTOMODE_RESPONSE_CAPTURE_BYTES", str(8 * 1024**2)))
        capture_complete = True
        response_content_type = ""
        response_content_encoding = ""
        error: str | None = None
        proposed_tool_calls: list[dict[str, Any]] = []
        pre_upstream_ms = (time.monotonic() - started) * 1000
        try:
            async with self.client.request(
                request.method,
                upstream_url,
                data=body,
                headers=outbound_headers,
                allow_redirects=False,
            ) as upstream_response:
                status = upstream_response.status
                response_content_type = upstream_response.headers.get("content-type", "")
                response_content_encoding = upstream_response.headers.get("content-encoding", "")
                response = web.StreamResponse(
                    status=status,
                    reason=upstream_response.reason,
                    headers=_response_headers(upstream_response.headers),
                )
                response.headers["x-automode-trace-id"] = trace_id
                response.headers["server-timing"] = f"automode;dur={pre_upstream_ms:.3f}"
                await response.prepare(request)
                async for chunk in upstream_response.content.iter_any():
                    response_bytes += len(chunk)
                    if capture_complete:
                        remaining = capture_limit - len(response_capture)
                        if len(chunk) <= remaining:
                            response_capture.extend(chunk)
                        else:
                            capture_complete = False
                            response_capture.clear()
                    await response.write(chunk)
                await response.write_eof()
                if capture_complete:
                    proposed_tool_calls = extract_tool_calls(
                        protocol,
                        bytes(response_capture),
                        response_content_type,
                        response_content_encoding,
                    )
                else:
                    proposed_tool_calls = [{"name": "response_capture_incomplete", "arguments": {"bytes": response_bytes}}]
                return response
        except (ConnectionResetError, asyncio.CancelledError):
            error = "client_disconnected"
            raise
        except Exception as exc:
            error = type(exc).__name__
            raise web.HTTPBadGateway(text=f"upstream request failed: {error}") from exc
        finally:
            latency_ms = (time.monotonic() - started) * 1000
            if self.disk_buffer is not None and self.event_worker is not None:
                # Responses are a separate standard event.  They are queued
                # without waiting for encryption or analysis and therefore do
                # not add a second DLP analysis path in Gateway.
                response_payload = bytes(response_capture) if capture_complete else b""
                self._enqueue_proxy_audit(
                    {
                        "trace_id": trace_id,
                        "protocol": protocol,
                        "method": request.method,
                        "path": request.path_qs,
                        "payload": response_payload,
                        "headers": {},
                        "session_id": None,
                        "session_evidence": {},
                        "conversation_fingerprint": None,
                        "session_signals": None,
                        "latest_user_text": "",
                        "declared_tool_count": 0,
                        "event_type": "response",
                        "response_bytes": response_bytes,
                        "response_status": status,
                        "response_content_type": response_content_type,
                        "response_content_encoding": response_content_encoding,
                        "response_capture_complete": capture_complete,
                        "error": error,
                    },
                    response_payload,
                    {},
                    {},
                )
            else:
                # In best-effort mode keep the historical TraceStore contract
                # and session intent behavior.  A dropped audit item must
                # never replace an upstream response with an audit exception.
                persisted_trace_id = await persist_task
                if persisted_trace_id:
                    await self.engine.process_response(
                        persisted_trace_id,
                        response_capture=bytes(response_capture) if capture_complete else b"",
                        response_bytes=response_bytes,
                        protocol=protocol,
                        content_type=response_content_type,
                        content_encoding=response_content_encoding,
                        status=status,
                        latency_ms=latency_ms,
                        error=error,
                        response_capture_complete=capture_complete,
                    )

    async def _classify_after_persistence(
        self,
        persist_task: asyncio.Future[str],
        trace_id: str,
        payload: dict[str, Any],
        protocol: str,
        identity: dict[str, Any],
        raw_user_text: str,
    ) -> None:
        await persist_task
        await self._classify_dlp(trace_id, payload, protocol, identity)
        if raw_user_text:
            await self.engine.observe_session_risk(trace_id, raw_user_text)

    async def _classify_dlp(
        self,
        trace_id: str,
        payload: dict[str, Any],
        protocol: str,
        identity: dict[str, Any],
    ) -> None:
        try:
            rule_result = await asyncio.to_thread(
                self.engine.evaluate_rule_channel,
                payload,
                protocol=protocol,
                identity=identity,
                upstream=self.upstream,
                trace_id=trace_id,
            )
            alert_id: str | None = None
            if rule_result.rule_severity in ("critical", "high", "medium", "low"):
                alert_id = await asyncio.to_thread(self.store.create_immediate_rule_alert, trace_id, rule_result.to_dict())
                self.broker.publish(
                    "alert.created",
                    {
                        "id": alert_id,
                        "trace_id": trace_id,
                        "severity": rule_result.rule_severity,
                        "reason_code": rule_result.reason_code,
                        "source": "rule",
                    },
                )

            llm_result = await asyncio.to_thread(self.engine.evaluate_llm_channel, rule_result, identity=identity)
            verdict = self.engine.aggregate(rule_result, llm_result)
            run_id, updated_alert_id = await asyncio.to_thread(self.engine._save_pipeline_record, trace_id, rule_result, llm_result, verdict)
            final_alert_id = updated_alert_id or alert_id
            for stage in (rule_result.stages + llm_result.stages):
                self.broker.publish(
                    f"classification.{stage['stage'].replace('_llm', '')}.completed",
                    {"trace_id": trace_id, "run_id": run_id, "stage": stage["stage"], "status": stage["status"], "verdict": stage["verdict"]}
                )
            self.broker.publish("classification.completed", {"trace_id": trace_id, "run_id": run_id, "decision": verdict.final_decision, "risk": verdict.severity or "low"})
            if final_alert_id:
                if alert_id and verdict.alert:
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
                elif not alert_id and verdict.alert:
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
        except Exception as exc:
            await asyncio.to_thread(
                self.store.set_classification,
                trace_id,
                {
                    "intent": "unknown",
                    "speech_act": "unknown",
                    "risk": "unknown",
                    "decision": "analysis_error",
                    "reason_codes": [type(exc).__name__],
                    "proposed_tool_calls": [],
                },
            )

    def _record_proxy_drop(self, reason: str, count: int = 1) -> None:
        self.proxy_dropped_count += count
        self.proxy_dropped_by_reason[reason] = self.proxy_dropped_by_reason.get(reason, 0) + count

    def _record_proxy_failure(self, reason: str, count: int = 1) -> None:
        self.proxy_failed_count += count
        self.proxy_failed_by_reason[reason] = self.proxy_failed_by_reason.get(reason, 0) + count

    def _enqueue_proxy_audit(
        self,
        arguments: dict[str, Any],
        payload: Any,
        identity: dict[str, Any],
        session_evidence: dict[str, Any],
    ) -> asyncio.Future[str | None]:
        future: asyncio.Future[str | None] = asyncio.get_running_loop().create_future()
        trace_id = str(arguments.get("trace_id") or uuid.uuid4())
        event_type = str(arguments.get("event_type") or "request")
        if event_type == "response":
            arguments = {**arguments, "response_capture": bytes(payload) if isinstance(payload, (bytes, bytearray)) else b""}
            # EventWorker consumes JSON payloads.  Preserve response metadata
            # in the event row while keeping its temporary body parseable.
            if isinstance(payload, (bytes, bytearray)):
                try:
                    payload = json.loads(bytes(payload).decode("utf-8"))
                except Exception:
                    payload = {}
            if not isinstance(payload, dict):
                payload = {}
        try:
            payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            payload_bytes = b"{}"
            payload = {}
        arguments = {**arguments, "payload": payload}
        size = len(payload_bytes)
        if not self._accepting_proxy_audit:
            self._record_proxy_drop("shutdown")
            future.set_result(None)
            return future
        if size > self.proxy_buffer_max_bytes:
            self._record_proxy_drop("event_too_large")
            future.set_result(None)
            return future
        if self.proxy_buffer_events >= self.proxy_buffer_max_events or self.proxy_audit_buffer_bytes + size > self.proxy_buffer_max_bytes:
            self._record_proxy_drop("buffer_full")
            future.set_result(None)
            return future

        standard = {
            "event_id": f"proxy_{trace_id}_{event_type}",
            "source_id": PROXY_SOURCE_ID,
            "call_id": trace_id,
            "attempt_id": None,
            "event_type": event_type,
            "protocol": arguments.get("protocol", "openai_chat_completions"),
            "capture_stage": "model_outbound",
            "content_integrity": "complete" if arguments.get("response_capture_complete", True) else "truncated",
            "timestamp": _utc_now(),
            "metadata": {
                "model_destination": {
                    "upstream": self.upstream or "external",
                    "model": (arguments.get("payload") or {}).get("model") if isinstance(arguments.get("payload"), dict) else None,
                },
                "identity": identity,
                "session_id": arguments.get("session_id"),
                "trace_id": trace_id,
                "response_status": arguments.get("response_status"),
                "response_bytes": arguments.get("response_bytes"),
                "response_content_type": arguments.get("response_content_type"),
                "response_content_encoding": arguments.get("response_content_encoding"),
                "error": arguments.get("error"),
            },
        }
        self.proxy_audit_buffer_bytes += size
        try:
            self.proxy_audit_queue.put_nowait((
                {**arguments, "trace_id": trace_id, "event": standard, "payload": payload},
                payload_bytes,
                future,
            ))
        except asyncio.QueueFull:
            self.proxy_audit_buffer_bytes = max(0, self.proxy_audit_buffer_bytes - size)
            self._record_proxy_drop("buffer_full")
            future.set_result(None)
        return future

    async def _proxy_audit_loop(self) -> None:
        while True:
            arguments, payload_bytes, future = await self.proxy_audit_queue.get()
            self.proxy_audit_active = True
            try:
                if self.disk_buffer is not None and self.event_worker is not None:
                    event = arguments["event"]
                    payload = arguments.get("payload")
                    external_event_id = event["event_id"]
                    # Create the legacy compatibility trace before publishing
                    # the durable event.  The worker may finish a small rules
                    # event before the audit loop gets another turn; the
                    # stable trace_id in source_metadata then always resolves
                    # to an existing trace.  Trace failure is observational
                    # only and must not reject durable event acceptance.
                    if event["event_type"] == "request":
                        try:
                            await asyncio.to_thread(self.store.create, **{
                                key: value for key, value in arguments.items()
                                if key in {"trace_id", "protocol", "method", "path", "payload", "headers", "session_id", "latest_user_text", "declared_tool_count", "session_evidence", "conversation_fingerprint", "session_signals"}
                            })
                        except Exception as exc:
                            logger.warning("proxy trace compatibility persistence failed: %s", type(exc).__name__)
                    standard_event = StandardEvent(
                        version="1",
                        event_id=external_event_id,
                        source_id=event["source_id"],
                        call_id=event["call_id"],
                        attempt_id=event.get("attempt_id"),
                        event_type=event["event_type"],
                        protocol=event["protocol"],
                        capture_stage=event["capture_stage"],
                        content_integrity=event["content_integrity"],
                        timestamp=event["timestamp"],
                        payload=payload or {},
                        is_realtime=True,
                        model_destination=event["metadata"].get("model_destination"),
                        identity=event["metadata"].get("identity"),
                        session_id=event["metadata"].get("session_id"),
                        metadata=event["metadata"],
                    )
                    accepted = await accept_standard_event(
                        standard_event, self.store, self.disk_buffer, worker=self.event_worker
                    )
                    if accepted.status != 202:
                        raise RuntimeError(f"proxy event acceptance returned {accepted.status}")
                    event_id = self.store.resolve_event_id(external_event_id, source_id=event["source_id"])
                    if not event_id:
                        raise RuntimeError("proxy event acceptance returned no internal event ID")
                    if event["event_type"] == "response":
                        try:
                            await self.engine.process_response(
                                event["call_id"],
                                response_capture=arguments.get("response_capture", b""),
                                response_bytes=arguments.get("response_bytes"),
                                protocol=event["protocol"],
                                content_type=arguments.get("response_content_type", ""),
                                content_encoding=arguments.get("response_content_encoding", ""),
                                status=arguments.get("response_status"),
                                latency_ms=arguments.get("latency_ms"),
                                error=arguments.get("error"),
                                response_capture_complete=arguments.get("response_capture_complete", True),
                            )
                        except Exception as exc:
                            logger.warning("proxy response evidence persistence failed: %s", type(exc).__name__)
                    if not future.cancelled():
                        future.set_result(external_event_id)
                else:
                    trace_id = await asyncio.to_thread(self.store.create, **{
                        key: value for key, value in arguments.items()
                        if key in {"trace_id", "protocol", "method", "path", "payload", "headers", "session_id", "latest_user_text", "declared_tool_count", "session_evidence", "conversation_fingerprint", "session_signals"}
                    })
                    if not future.cancelled():
                        future.set_result(trace_id)
                    if arguments.get("analysis_payload") is not None:
                        await self._classify_dlp(
                            trace_id,
                            arguments["analysis_payload"],
                            arguments["protocol"],
                            arguments.get("identity", {"trusted": False, "roles": []}),
                        )
                        if arguments.get("latest_user_text"):
                            await self.engine.observe_session_risk(trace_id, arguments["latest_user_text"])
            except asyncio.CancelledError:
                if not future.cancelled() and not future.done():
                    future.set_result(None)
                raise
            except Exception as exc:
                self._record_proxy_failure(type(exc).__name__)
                logger.warning("proxy audit persistence failed: %s", type(exc).__name__)
                if not future.cancelled():
                    future.set_result(None)
            finally:
                self.proxy_audit_active = False
                self.proxy_audit_buffer_bytes = max(0, self.proxy_audit_buffer_bytes - len(payload_bytes))
                self.proxy_audit_queue.task_done()


GATEWAY_KEY = web.AppKey("gateway", Gateway)
TRACE_STORE_KEY = web.AppKey("trace_store", TraceStore)


def create_app(
    upstream: str | None = None,
    db_path: str = "automode.db",
    store_raw: bool = True,
    bind_host: str = "127.0.0.1",
    admin_token: str | None = None,
) -> web.Application:
    token = admin_token or os.getenv("AUTOMODE_ADMIN_TOKEN")
    if not _is_loopback(bind_host) and not token:
        raise RuntimeError("AUTOMODE_ADMIN_TOKEN is required for non-loopback binding")
    store = TraceStore(db_path, store_raw=store_raw)
    broker = EventBroker()
    engine = AnalysisEngine(store=store, broker=broker, upstream=upstream)
    disk_buffer: DiskBuffer | None = None
    event_worker: EventWorker | None = None
    if store.evidence_key:
        buffer_dir = Path(os.getenv("AUTOMODE_DISK_BUFFER_DIR") or (Path(db_path).parent / "disk_buffer"))
        disk_buffer = DiskBuffer(buffer_dir, evidence_key=store.evidence_key)
        event_worker = EventWorker(store, disk_buffer, engine=engine)
    gateway = Gateway(upstream, store, broker, engine=engine, disk_buffer=disk_buffer, event_worker=event_worker)

    @web.middleware
    async def admin_auth(request: web.Request, handler: Any) -> web.StreamResponse:
        if token and (
            request.path.startswith("/api/")
            or request.path == "/traces"
            or request.path.startswith("/traces/")
        ):
            supplied = request.headers.get("x-automode-admin-token")
            authorization = request.headers.get("authorization", "")
            if not supplied and authorization.lower().startswith("bearer "):
                supplied = authorization[7:]
            if not supplied or not hmac.compare_digest(supplied, token):
                raise web.HTTPUnauthorized(text="admin authentication required")
        return await handler(request)

    app = web.Application(client_max_size=32 * 1024**2, middlewares=[admin_auth])
    app[GATEWAY_KEY] = gateway
    app[TRACE_STORE_KEY] = store
    app[EVENT_BROKER_KEY] = broker
    app[ADMIN_TOKEN_KEY] = token
    app[BIND_HOST_KEY] = bind_host
    app[UPSTREAM_KEY] = gateway.upstream
    app.on_startup.append(gateway.start)
    app.on_cleanup.append(gateway.stop)
    app.router.add_get("/health", _health)
    app.router.add_post("/v1/classify", _classify)
    app.router.add_post("/v1/classify/litellm", _classify)
    app.router.add_get("/traces", _list_traces)
    app.router.add_get("/traces/{trace_id}", _get_trace)
    if event_worker is not None:
        app.on_startup.append(event_worker.start)
        app.on_cleanup.append(event_worker.stop)
    register_ingress_routes(app, store, disk_buffer, event_worker)
    register_admin_routes(app, store)
    for path in ("/v1/messages", "/v1/chat/completions", "/v1/responses"):
        app.router.add_post(path, gateway.proxy)
    app.router.add_get("/", _frontend)
    app.router.add_get("/{asset:.*}", _frontend)
    return app


def run_gateway(host: str, port: int, upstream: str | None, db_path: str, store_raw: bool) -> None:
    app = create_app(upstream=upstream, db_path=db_path, store_raw=store_raw, bind_host=host)
    mode = f"proxy -> {upstream}" if upstream else "event analysis service (no upstream proxy)"
    print(f"auto-intent gateway: http://{host}:{port} ({mode})")
    print(f"trace database: {Path(db_path).resolve()}")
    web.run_app(app, host=host, port=port, print=None)


async def _health(request: web.Request) -> web.Response:
    gateway = request.app[GATEWAY_KEY]
    pipeline = DecisionPipeline()
    return web.json_response(
        {
            "status": "ok",
            "upstream": gateway.upstream,
            "proxy_enabled": bool(gateway.upstream),
            "event_ingress_enabled": request.app.get(DISK_BUFFER_KEY) is not None,
            "protocols": ["anthropic_messages", "openai_chat_completions", "openai_responses"],
            "classifiers": {
                "fast": {"configured": pipeline.fast.configured, "model": pipeline.fast.settings.model},
                "deep": {"configured": pipeline.deep.configured, "model": pipeline.deep.settings.model},
            },
            "operating_mode": "observe",
        }
    )


async def _classify(request: web.Request) -> web.Response:
    try:
        payload = await request.json()
        return web.json_response(classify_payload(payload))
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc


async def _list_traces(request: web.Request) -> web.Response:
    store = request.app[TRACE_STORE_KEY]
    try:
        limit = int(request.query.get("limit", "50"))
    except ValueError as exc:
        raise web.HTTPBadRequest(text="limit must be an integer") from exc
    rows = await asyncio.to_thread(store.list, limit, request.query.get("session_id"))
    return web.json_response({"data": rows})


async def _get_trace(request: web.Request) -> web.Response:
    store = request.app[TRACE_STORE_KEY]
    row = await asyncio.to_thread(store.get, request.match_info["trace_id"])
    if row is None:
        raise web.HTTPNotFound(text="trace not found")
    return web.json_response(row)


async def _frontend(request: web.Request) -> web.StreamResponse:
    configured = os.getenv("AUTOMODE_WEB_DIST")
    root = Path(configured).resolve() if configured else Path(__file__).resolve().parent.parent / "web" / "dist"
    requested = request.match_info.get("asset", "")
    target = (root / requested).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise web.HTTPNotFound(text="asset not found") from exc
    if requested and target.is_file():
        return web.FileResponse(target, headers={"content-type": mimetypes.guess_type(target.name)[0] or "application/octet-stream"})
    index = root / "index.html"
    if index.is_file():
        return web.FileResponse(index, headers={"content-type": "text/html; charset=utf-8"})
    raise web.HTTPNotFound(text="console is not built; run npm run build in web/")


def _request_headers(headers: Any, trace_id: str) -> CIMultiDict[str]:
    result: CIMultiDict[str] = CIMultiDict()
    for key, value in headers.items():
        if key.lower() not in HOP_BY_HOP:
            result.add(key, value)
    override_key = os.getenv("AUTOMODE_UPSTREAM_API_KEY")
    if override_key:
        result.popall("authorization", None)
        result.popall("x-api-key", None)
        result.popall("api-key", None)
        result["authorization"] = f"Bearer {override_key}"
    result["x-automode-trace-id"] = trace_id
    return result


def _response_headers(headers: Any) -> CIMultiDict[str]:
    result: CIMultiDict[str] = CIMultiDict()
    for key, value in headers.items():
        if key.lower() not in HOP_BY_HOP:
            result.add(key, value)
    return result


def _join_url(base: str, path_qs: str) -> str:
    split = urlsplit(base)
    base_path = split.path.rstrip("/")
    request_path = path_qs if path_qs.startswith("/") else f"/{path_qs}"
    return urlunsplit((split.scheme, split.netloc, f"{base_path}{request_path}", "", ""))


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}
