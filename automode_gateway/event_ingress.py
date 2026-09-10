from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import logging
import asyncio
from datetime import datetime
from typing import Any
from urllib.parse import quote

from aiohttp import web

from .disk_buffer import DiskBuffer, DiskBufferFullError, EventPayloadTooLargeError
from .event_worker import EventWorker
from .storage import TraceStore, _sanitize_event_metadata


logger = logging.getLogger(__name__)

DISK_BUFFER_KEY = web.AppKey("disk_buffer", DiskBuffer)
EVENT_WORKER_KEY = web.AppKey("event_worker", EventWorker)
TRACE_STORE_KEY = web.AppKey("trace_store", TraceStore)
INGRESS_LOCK_KEY = web.AppKey("event_ingress_lock", asyncio.Lock)


def _get_store(app: web.Application) -> TraceStore:
    try:
        s = app.get(TRACE_STORE_KEY)
        if isinstance(s, TraceStore):
            return s
    except Exception:
        pass
    try:
        s = app.get("trace_store")
        if isinstance(s, TraceStore):
            return s
    except Exception:
        pass
    for v in app.values():
        if isinstance(v, TraceStore):
            return v
    raise RuntimeError("TraceStore not found in application")


SUPPORTED_EVENT_TYPES = {"request", "response", "full_call"}
SUPPORTED_PROTOCOLS = {"anthropic_messages", "openai_chat_completions", "openai_responses"}
SUPPORTED_CAPTURE_STAGES = {"inbound_request", "model_outbound", "unknown"}
SUPPORTED_INTEGRITY = {"complete", "truncated", "redacted", "missing"}
MAX_EVENT_ID_LENGTH = 256


@dataclass
class StandardEvent:
    version: str
    event_id: str
    source_id: str
    call_id: str
    event_type: str
    protocol: str
    capture_stage: str
    content_integrity: str
    timestamp: str
    payload: Any
    attempt_id: str | None = None
    is_realtime: bool = True
    model_destination: dict[str, Any] | None = None
    identity: dict[str, Any] | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def validate_event_data(data: dict[str, Any], source: dict[str, Any]) -> StandardEvent:
    if not isinstance(data, dict):
        raise ValueError("event payload must be a JSON object")

    required_keys = [
        "version", "event_id", "source_id", "call_id",
        "event_type", "protocol", "capture_stage", "content_integrity",
        "timestamp",
    ]
    missing = [k for k in required_keys if not data.get(k)]
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")

    event_id = str(data["event_id"]).strip()
    source_id = str(data["source_id"]).strip()
    call_id = str(data["call_id"]).strip()
    event_type = str(data["event_type"]).strip().lower()
    protocol = str(data["protocol"]).strip()
    capture_stage = str(data["capture_stage"]).strip().lower()
    content_integrity = str(data["content_integrity"]).strip().lower()

    if not event_id:
        raise ValueError("event_id cannot be empty")
    if not source_id:
        raise ValueError("source_id cannot be empty")
    if not call_id:
        raise ValueError("call_id cannot be empty")
    for field_name, value in (("event_id", event_id), ("source_id", source_id), ("call_id", call_id)):
        if len(value) > MAX_EVENT_ID_LENGTH or any(ord(char) < 0x20 for char in value):
            raise ValueError(f"{field_name} is too long or contains control characters")
    if str(data["version"]).strip() != "1":
        raise ValueError("unsupported event version; expected '1'")
    timestamp_value = str(data["timestamp"]).strip()
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be a valid ISO-8601 datetime") from exc
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset")

    if event_type not in SUPPORTED_EVENT_TYPES:
        raise ValueError(f"unsupported event_type: {event_type}; must be one of {SUPPORTED_EVENT_TYPES}")
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol}; must be one of {SUPPORTED_PROTOCOLS}")
    if capture_stage not in SUPPORTED_CAPTURE_STAGES:
        raise ValueError(f"unsupported capture_stage: {capture_stage}; must be one of {SUPPORTED_CAPTURE_STAGES}")
    if content_integrity not in SUPPORTED_INTEGRITY:
        raise ValueError(f"unsupported content_integrity: {content_integrity}; must be one of {SUPPORTED_INTEGRITY}")

    if source_id != source["id"]:
        raise PermissionError(f"source token does not grant access to source '{source_id}'")
    if source_id == "proxy-adapter":
        raise PermissionError("proxy-adapter is reserved for the in-process proxy")

    payload = data.get("payload")
    if content_integrity != "missing" and payload is None:
        raise ValueError(f"payload is required when content_integrity is '{content_integrity}'")

    # Authorize trusted_identity
    identity = data.get("identity")
    if isinstance(identity, dict):
        identity_copy = dict(identity)
        if "trusted" in identity_copy and not isinstance(identity_copy["trusted"], bool):
            raise ValueError("identity.trusted must be a boolean")
        if not source.get("allow_trusted_identity"):
            identity_copy["trusted"] = False
    else:
        identity_copy = {"trusted": False, "roles": []}

    destination = data.get("model_destination")
    if destination is not None and not isinstance(destination, dict):
        raise ValueError("model_destination must be an object if provided")

    is_realtime = data.get("is_realtime", True)
    if not isinstance(is_realtime, bool):
        raise ValueError("is_realtime must be a boolean")

    return StandardEvent(
        version=str(data["version"]),
        event_id=event_id,
        source_id=source_id,
        call_id=call_id,
        event_type=event_type,
        protocol=protocol,
        capture_stage=capture_stage,
        content_integrity=content_integrity,
        timestamp=str(data["timestamp"]),
        payload=payload,
        attempt_id=str(data["attempt_id"]).strip() if data.get("attempt_id") else None,
        is_realtime=is_realtime,
        model_destination=destination,
        identity=identity_copy,
        session_id=str(data["session_id"]).strip() if data.get("session_id") else None,
        metadata=data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {},
    )


def authenticate_source(request: web.Request, store: TraceStore) -> dict[str, Any]:
    token = request.headers.get("x-automode-source-token")
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    if not token:
        raise web.HTTPUnauthorized(text="source authentication required: Bearer token or x-automode-source-token header")

    source = store.get_source_by_token(token)
    if not source or not source.get("enabled"):
        raise web.HTTPUnauthorized(text="invalid or disabled source token")
    return source


def canonical_event_bytes(event: StandardEvent) -> bytes:
    """Canonical identity for idempotency, including the event envelope.

    The body is intentionally not reduced to ``payload``: changing the source
    identity, destination, event type, capture stage, or attempt must conflict
    with an already accepted external event ID.
    """
    value = {
        "version": event.version,
        "event_id": event.event_id,
        "source_id": event.source_id,
        "call_id": event.call_id,
        "attempt_id": event.attempt_id,
        "event_type": event.event_type,
        "protocol": event.protocol,
        "capture_stage": event.capture_stage,
        "content_integrity": event.content_integrity,
        "timestamp": event.timestamp,
        "is_realtime": event.is_realtime,
        "model_destination": event.model_destination,
        "identity": event.identity,
        "session_id": event.session_id,
        "metadata": event.metadata,
        "payload": event.payload,
    }
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def canonical_event_hash(event: StandardEvent) -> str:
    return hashlib.sha256(canonical_event_bytes(event)).hexdigest()


def _accepted_response(event: dict[str, Any], *, duplicate: bool = False) -> web.Response:
    external_id = event.get("external_event_id") or event.get("event_id") or event.get("id")
    internal_id = event.get("id") or event.get("internal_id")
    body: dict[str, Any] = {
        "status": "accepted",
        "event_id": external_id,
        "internal_event_id": internal_id,
        "status_url": f"/v1/events/{quote(str(external_id), safe='')}",
    }
    if duplicate:
        body["duplicate"] = True
    return web.json_response(body, status=202)


async def accept_standard_event(
    event: StandardEvent,
    store: TraceStore,
    disk_buffer: DiskBuffer,
    worker: EventWorker | None = None,
    lock: asyncio.Lock | None = None,
) -> web.Response:
    """Reliably accept a validated event for HTTP and proxy adapters."""
    payload_canonical = json.dumps(event.payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    payload_hash = canonical_event_hash(event)
    body_hash = hashlib.sha256(payload_canonical).hexdigest()
    metadata = _sanitize_event_metadata({
        "source_metadata": event.metadata,
        "model_destination": event.model_destination,
        "identity": event.identity,
        "session_id": event.session_id,
    })
    active_lock = lock or asyncio.Lock()
    async with active_lock:
        reservation = store.reserve_event(
            external_event_id=event.event_id, source_id=event.source_id, call_id=event.call_id,
            attempt_id=event.attempt_id, event_type=event.event_type, protocol=event.protocol,
            capture_stage=event.capture_stage, content_integrity=event.content_integrity,
            is_realtime=event.is_realtime, timestamp=event.timestamp,
            payload_hash=payload_hash, body_hash=body_hash, metadata=metadata,
        )
        status = reservation["status"]
        if status == "conflict":
            raise web.HTTPConflict(text=f"event_id '{event.event_id}' already exists with different content")
        if status == "duplicate":
            return _accepted_response(reservation["event"], duplicate=True)
        if status == "pending":
            return web.Response(status=503, text="event persistence is still in progress; retry the request", headers={"Retry-After": "2"})

        internal_id = str(reservation["internal_id"])
        disk_path: str | None = None
        try:
            disk_path = await disk_buffer.async_write(internal_id, payload_canonical)
            event_row = store.finalize_event_storage(internal_id, disk_path)
        except EventPayloadTooLargeError as exc:
            if disk_path:
                await disk_buffer.async_delete(internal_id)
            store.remove_event_reservation(internal_id)
            raise web.HTTPRequestEntityTooLarge(max_size=disk_buffer.max_event_bytes, actual_size=len(payload_canonical), text=str(exc))
        except DiskBufferFullError as exc:
            store.remove_event_reservation(internal_id)
            return web.Response(status=507, text=str(exc), headers={"Retry-After": "5"})
        except Exception:
            if disk_path:
                await disk_buffer.async_delete(internal_id)
            store.remove_event_reservation(internal_id)
            raise

        if worker is not None:
            await worker.enqueue_rule(internal_id)
            worker.engine.broker.publish("event.received", {"id": internal_id, "source_id": event.source_id})
        return _accepted_response(event_row)


async def handle_post_events(request: web.Request) -> web.Response:
    store = _get_store(request.app)
    disk_buffer: DiskBuffer | None = request.app.get(DISK_BUFFER_KEY)
    if disk_buffer is None:
        raise web.HTTPInternalServerError(text="encrypted disk buffer not configured for event ingress")

    source = authenticate_source(request, store)

    body = await request.read()
    if len(body) > disk_buffer.max_event_bytes:
        raise web.HTTPRequestEntityTooLarge(
            max_size=disk_buffer.max_event_bytes,
            actual_size=len(body),
            text=f"event payload {len(body)} exceeds maximum limit of {disk_buffer.max_event_bytes} bytes",
        )

    try:
        raw_json = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise web.HTTPBadRequest(text=f"invalid JSON payload: {exc}")

    try:
        event = validate_event_data(raw_json, source)
    except PermissionError as exc:
        raise web.HTTPForbidden(text=str(exc))
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc))

    lock = request.app.get(INGRESS_LOCK_KEY)
    if lock is None:
        lock = asyncio.Lock()
        request.app[INGRESS_LOCK_KEY] = lock

    worker: EventWorker | None = request.app.get(EVENT_WORKER_KEY)
    return await accept_standard_event(event, store, disk_buffer, worker=worker, lock=lock)


async def handle_get_event(request: web.Request) -> web.Response:
    store = _get_store(request.app)
    source = authenticate_source(request, store)
    event_id = request.match_info["event_id"]

    event = store.get_event_by_source_and_id(source["id"], event_id)
    if not event or event["source_id"] != source["id"]:
        raise web.HTTPNotFound(text="event not found")

    rule_verdict = json.loads(event["rule_verdict_json"] or "null")
    llm_verdict = json.loads(event["llm_verdict_json"] or "null")

    return web.json_response(
        {
            "event_id": event["external_event_id"] or event["id"],
            "internal_event_id": event["id"],
            "source_id": event["source_id"],
            "call_id": event["call_id"],
            "attempt_id": event["attempt_id"],
            "event_type": event["event_type"],
            "protocol": event["protocol"],
            "capture_stage": event["capture_stage"],
            "content_integrity": event["content_integrity"],
            "is_realtime": bool(event["is_realtime"]),
            "processing_status": event["processing_status"],
            "association_status": event["association_status"],
            "rule_status": event["rule_status"],
            "llm_status": event["llm_status"],
            "retry_count": event["retry_count"],
            "error_message": event["error_message"],
            "created_at": event["received_at"],
            "completed_at": event["completed_at"],
            "rule_verdict": rule_verdict,
            "llm_verdict": llm_verdict,
            "response_evidence": json.loads(event.get("response_evidence_json") or "[]"),
        }
    )


def register_ingress_routes(
    app: web.Application,
    store: TraceStore,
    disk_buffer: DiskBuffer | None = None,
    worker: EventWorker | None = None,
) -> None:
    app[TRACE_STORE_KEY] = store
    if disk_buffer is not None:
        app[DISK_BUFFER_KEY] = disk_buffer
    if worker is not None:
        app[EVENT_WORKER_KEY] = worker
    app.router.add_post("/v1/events", handle_post_events)
    app.router.add_get("/v1/events/{event_id}", handle_get_event)
