from __future__ import annotations

import asyncio
import hmac
import json
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
from .dlp import evaluate_dlp, trusted_identity
from .events import EVENT_BROKER_KEY, EventBroker
from .normalizer import normalize
from .pipeline import DecisionPipeline
from .protocols import classification_payload, protocol_for_path, session_evidence_from, session_id_from
from .response_parser import extract_tool_calls
from .review_context import build_review_context
from .service import classify_payload
from .session_fingerprint import conversation_fingerprint
from .storage import TraceStore


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
    def __init__(self, upstream: str, store: TraceStore, broker: EventBroker) -> None:
        self.upstream = upstream.rstrip("/")
        self.store = store
        self.broker = broker
        self.client: ClientSession | None = None
        self.tasks: set[asyncio.Task[Any]] = set()
        self.persistence_queue: asyncio.Queue[tuple[dict[str, Any], asyncio.Future[str]]] = asyncio.Queue()
        self.persistence_worker: asyncio.Task[Any] | None = None

    async def start(self, app: web.Application) -> None:
        timeout = ClientTimeout(total=None, connect=30, sock_read=None)
        self.client = ClientSession(timeout=timeout, auto_decompress=False)
        self.persistence_worker = asyncio.create_task(self._persistence_loop())

    async def stop(self, app: web.Application) -> None:
        await self.persistence_queue.join()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.persistence_worker is not None:
            self.persistence_worker.cancel()
            await asyncio.gather(self.persistence_worker, return_exceptions=True)
        if self.client is not None:
            await self.client.close()

    async def proxy(self, request: web.Request) -> web.StreamResponse:
        protocol = protocol_for_path(request.path)
        if protocol is None:
            raise web.HTTPNotFound(text="unsupported model endpoint")
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
        persist_task = self._enqueue_persistence({
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
        })
        if analysis_payload is not None:
            self._background(self._classify_after_persistence(persist_task, trace_id, analysis_payload, protocol, identity))

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
            await persist_task
            latency_ms = (time.monotonic() - started) * 1000
            await asyncio.to_thread(
                self.store.finish,
                trace_id,
                status=status,
                response_bytes=response_bytes,
                latency_ms=latency_ms,
                error=error,
                response_body=bytes(response_capture) if capture_complete else None,
                response_content_type=response_content_type,
                response_capture_complete=capture_complete,
            )
            self.broker.publish("trace.completed", {"id": trace_id, "status": status, "error": error})
            try:
                await asyncio.to_thread(self.store.record_tool_actions, trace_id, proposed_tool_calls)
            except Exception:
                # Response-action evidence is secondary and must not affect the proxy.
                pass

    async def _classify_after_persistence(
        self,
        persist_task: asyncio.Future[str],
        trace_id: str,
        payload: dict[str, Any],
        protocol: str,
        identity: dict[str, Any],
    ) -> None:
        await persist_task
        await self._classify_dlp(trace_id, payload, protocol, identity)

    async def _classify_dlp(
        self,
        trace_id: str,
        payload: dict[str, Any],
        protocol: str,
        identity: dict[str, Any],
    ) -> None:
        try:
            targets, policies = await asyncio.gather(
                asyncio.to_thread(self.store.list_destinations),
                asyncio.to_thread(self.store.list_dlp_policies, True),
            )
            result = await asyncio.to_thread(
                evaluate_dlp, payload, protocol=protocol, upstream=self.upstream,
                identity=identity, targets=targets, policies=policies,
            )
            result["evidence_id"] = await asyncio.to_thread(
                self.store.store_evidence, trace_id, payload, result["data_findings"], result["destination"]
            )
            run_id, alert_id = await asyncio.to_thread(self.store.save_pipeline, trace_id, result)
            for stage in result["stages"]:
                self.broker.publish(f"classification.{stage['stage'].replace('_llm', '')}.completed", {"trace_id": trace_id, "run_id": run_id, "stage": stage["stage"], "status": stage["status"], "verdict": stage["verdict"]})
            self.broker.publish("classification.completed", {"trace_id": trace_id, "run_id": run_id, "decision": result["final_decision"], "risk": result["risk"]})
            if alert_id:
                self.broker.publish("alert.created", {"id": alert_id, "trace_id": trace_id, "severity": result["risk"], "reason_code": result["reason_code"]})
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
                },
            )

    def _background(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def _enqueue_persistence(self, arguments: dict[str, Any]) -> asyncio.Future[str]:
        future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self.persistence_queue.put_nowait((arguments, future))
        return future

    async def _persistence_loop(self) -> None:
        while True:
            arguments, future = await self.persistence_queue.get()
            try:
                # Coalesce request bursts so SQLite work cannot starve response headers.
                if self.persistence_queue.qsize() == 0:
                    await asyncio.sleep(float(os.getenv("AUTOMODE_DB_FLUSH_INTERVAL_MS", "25")) / 1000)
                trace_id = await asyncio.to_thread(self.store.create, **arguments)
                if not future.cancelled():
                    future.set_result(trace_id)
            except Exception as exc:
                if not future.cancelled():
                    future.set_exception(exc)
            finally:
                self.persistence_queue.task_done()


GATEWAY_KEY = web.AppKey("gateway", Gateway)
TRACE_STORE_KEY = web.AppKey("trace_store", TraceStore)


def create_app(
    upstream: str,
    db_path: str,
    store_raw: bool = True,
    bind_host: str = "127.0.0.1",
    admin_token: str | None = None,
) -> web.Application:
    token = admin_token or os.getenv("AUTOMODE_ADMIN_TOKEN")
    if not _is_loopback(bind_host) and not token:
        raise RuntimeError("AUTOMODE_ADMIN_TOKEN is required for non-loopback binding")
    store = TraceStore(db_path, store_raw=store_raw)
    broker = EventBroker()
    gateway = Gateway(upstream, store, broker)

    @web.middleware
    async def admin_auth(request: web.Request, handler: Any) -> web.StreamResponse:
        if request.path.startswith("/api/") and token:
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
    register_admin_routes(app, store)
    for path in ("/v1/messages", "/v1/chat/completions", "/v1/responses"):
        app.router.add_post(path, gateway.proxy)
    app.router.add_get("/", _frontend)
    app.router.add_get("/{asset:.*}", _frontend)
    return app


def run_gateway(host: str, port: int, upstream: str, db_path: str, store_raw: bool) -> None:
    app = create_app(upstream=upstream, db_path=db_path, store_raw=store_raw, bind_host=host)
    print(f"auto-intent gateway: http://{host}:{port} -> {upstream}")
    print(f"trace database: {Path(db_path).resolve()}")
    web.run_app(app, host=host, port=port, print=None)


async def _health(request: web.Request) -> web.Response:
    gateway = request.app[GATEWAY_KEY]
    pipeline = DecisionPipeline()
    return web.json_response(
        {
            "status": "ok",
            "upstream": gateway.upstream,
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
