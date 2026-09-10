from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import inspect
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

from .disk_buffer import DiskBuffer
from .dlp import redact_payload, scan_payload
from .engine import AnalysisEngine, LLMEvaluationResult, RuleEvaluationResult
from .response_parser import extract_tool_calls
from .protocols import classification_payload
from .normalizer import normalize
from .session_risk import assess as assess_session_risk
from .review_context import normalize_tool_call
from .storage import TraceStore, _now

logger = logging.getLogger(__name__)
DEFAULT_RULE_CONCURRENCY = 2
DEFAULT_REVIEWER_CONCURRENCY = 5
MAX_RETRIES = 3


class EventWorker:
    """Run standard events through the same rule and reviewer engine as the proxy."""

    def __init__(self, store: TraceStore, disk_buffer: DiskBuffer,
                 rule_concurrency: int | None = None,
                 reviewer_concurrency: int | None = None,
                 reviewer_fn: Callable[..., Any] | None = None,
                 engine: AnalysisEngine | None = None) -> None:
        self.store = store
        self.disk_buffer = disk_buffer
        self.rule_concurrency = max(1, rule_concurrency if rule_concurrency is not None else int(os.getenv("AUTOMODE_RULE_CONCURRENCY", str(DEFAULT_RULE_CONCURRENCY))))
        self.reviewer_concurrency = max(1, reviewer_concurrency if reviewer_concurrency is not None else int(os.getenv("AUTOMODE_REVIEWER_CONCURRENCY", str(DEFAULT_REVIEWER_CONCURRENCY))))
        self.reviewer_fn = reviewer_fn
        self.engine = engine or AnalysisEngine(store)
        queue_limit = max(4, (self.rule_concurrency + self.reviewer_concurrency) * 4)
        self.rule_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=queue_limit)
        self.reviewer_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=queue_limit)
        self._queued_rules: set[str] = set()
        self._queued_reviewers: set[str] = set()
        self._dispatcher_task: asyncio.Task[Any] | None = None
        self._rule_executor = ThreadPoolExecutor(max_workers=self.rule_concurrency, thread_name_prefix="automode-rule")
        self._reviewer_executor = ThreadPoolExecutor(max_workers=self.reviewer_concurrency, thread_name_prefix="automode-reviewer")
        self._rule_tasks: list[asyncio.Task[Any]] = []
        self._reviewer_tasks: list[asyncio.Task[Any]] = []
        self._running = False

    async def start(self, app: Any = None) -> None:
        if self._running:
            return
        self._running = True
        await self.recover()
        self._rule_tasks = [asyncio.create_task(self._rule_worker_loop(f"rule-worker-{i}")) for i in range(self.rule_concurrency)]
        self._reviewer_tasks = [asyncio.create_task(self._reviewer_worker_loop(f"reviewer-worker-{i}")) for i in range(self.reviewer_concurrency)]
        self._dispatcher_task = asyncio.create_task(self._dispatch_pending_loop())

    async def stop(self, app: Any = None) -> None:
        self._running = False
        tasks = self._rule_tasks + self._reviewer_tasks + ([self._dispatcher_task] if self._dispatcher_task else [])
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._rule_tasks.clear()
        self._reviewer_tasks.clear()
        self._dispatcher_task = None
        self._queued_rules.clear()
        self._queued_reviewers.clear()
        # Cancelling an asyncio waiter does not stop its executor thread. Drain
        # in-flight work before the application closes storage or replaces the
        # worker; otherwise old tasks can write into a new/recovered instance.
        try:
            await asyncio.wait_for(asyncio.gather(
                asyncio.to_thread(self._rule_executor.shutdown, wait=True, cancel_futures=True),
                asyncio.to_thread(self._reviewer_executor.shutdown, wait=True, cancel_futures=True),
            ), timeout=30)
        except asyncio.TimeoutError:
            logger.warning("analysis executors did not drain within 30 seconds; persisted events remain recoverable")

    async def drain(self) -> None:
        await self.rule_queue.join()
        await self.reviewer_queue.join()

    async def enqueue_rule(self, event_id: str) -> None:
        if event_id in self._queued_rules:
            return
        try:
            self.rule_queue.put_nowait(event_id)
            self._queued_rules.add(event_id)
        except asyncio.QueueFull:
            # The durable DB row remains pending and the dispatcher will retry.
            return

    async def enqueue_reviewer(self, event_id: str) -> None:
        if event_id in self._queued_reviewers:
            return
        try:
            self.reviewer_queue.put_nowait(event_id)
            self._queued_reviewers.add(event_id)
        except asyncio.QueueFull:
            return

    async def _dispatch_pending_loop(self) -> None:
        while self._running:
            try:
                with self.store._connect() as conn:
                    rules = conn.execute(
                        "SELECT id FROM events WHERE rule_status='pending' AND processing_status='pending' ORDER BY received_at LIMIT ?",
                        (self.rule_queue.maxsize,),
                    ).fetchall()
                    reviewers = conn.execute(
                        "SELECT id FROM events WHERE rule_status='completed' AND llm_status='pending' AND processing_status='pending' ORDER BY received_at LIMIT ?",
                        (self.reviewer_queue.maxsize,),
                    ).fetchall()
                for row in rules:
                    await self.enqueue_rule(str(row["id"]))
                for row in reviewers:
                    await self.enqueue_reviewer(str(row["id"]))
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.25)

    async def recover(self) -> dict[str, int]:
        """Requeue unfinished stages without re-running completed rule results."""
        # Complete or remove reservations left between encrypted-file commit
        # and SQLite finalization. This prevents durable-ingress retries from
        # remaining stuck at 503 forever after a process crash.
        for row in self.store.list_persisting_events():
            internal_id = str(row["id"])
            if self.disk_buffer.exists(internal_id):
                self.store.finalize_event_storage(internal_id, str(self.disk_buffer.directory / f"{internal_id}.enc"))
            else:
                self.store.remove_event_reservation(internal_id)
        with self.store._connect() as conn:
            rows = conn.execute("SELECT * FROM events WHERE processing_status IN ('pending', 'processing') ORDER BY received_at ASC").fetchall()
        recovered_rules = recovered_reviewers = missing_files = 0
        for row in rows:
            event_id = row["id"]
            event = dict(row)
            buffer_id = self._buffer_id(event_id, event)
            if not self.disk_buffer.exists(buffer_id):
                self.store.update_event_status(event_id, processing_status="failed",
                    rule_status="failed" if row["rule_status"] in ("pending", "processing") else row["rule_status"],
                    llm_status="failed" if row["llm_status"] in ("pending", "processing") else row["llm_status"],
                    error_message="disk_buffer_file_missing_on_recovery")
                missing_files += 1
                continue
            if row["rule_status"] in ("pending", "processing"):
                self.store.update_event_status(event_id, rule_status="pending", processing_status="pending")
                await self.enqueue_rule(event_id)
                recovered_rules += 1
            elif row["rule_status"] == "completed" and row["llm_status"] in ("pending", "processing"):
                self.store.update_event_status(event_id, llm_status="pending", processing_status="pending")
                await self.enqueue_reviewer(event_id)
                recovered_reviewers += 1
        # Reap bodies left behind by a crash after the result commit. Pending
        # bodies remain protected for retry or reviewer processing.
        for buffer_id in self.disk_buffer.list_event_ids():
            row = self.store.get_event(buffer_id)
            if row and row.get("processing_status") == "completed":
                await self.disk_buffer.async_delete(buffer_id)
        return {"recovered_rules": recovered_rules, "recovered_reviewers": recovered_reviewers, "missing_files": missing_files}

    async def _rule_worker_loop(self, name: str) -> None:
        while self._running:
            try:
                event_id = await self.rule_queue.get()
                self._queued_rules.discard(event_id)
            except asyncio.CancelledError:
                break
            try:
                await self._process_rule_event(event_id)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Error in rule worker %s for event %s", name, event_id)
                await self._handle_failure(event_id, "rule", exc)
            finally:
                self.rule_queue.task_done()

    async def _reviewer_worker_loop(self, name: str) -> None:
        while self._running:
            try:
                event_id = await self.reviewer_queue.get()
                self._queued_reviewers.discard(event_id)
            except asyncio.CancelledError:
                break
            try:
                await self._process_reviewer_event(event_id)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Error in reviewer worker %s for event %s", name, event_id)
                await self._handle_failure(event_id, "reviewer", exc)
            finally:
                self.reviewer_queue.task_done()

    @staticmethod
    def _payload(data: bytes) -> Any:
        return json.loads(data.decode("utf-8"))

    async def _rule_call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._rule_executor, lambda: fn(*args, **kwargs))

    async def _reviewer_call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._reviewer_executor, lambda: fn(*args, **kwargs))

    def _buffer_id(self, event_id: str, event: dict[str, Any]) -> str:
        """Return the disk key, honoring the row's exact bound file path."""
        internal_id = str(event.get("id") or event_id)
        if self.disk_buffer.exists(internal_id):
            return internal_id
        # Legacy direct record_event callers may have written under the old
        # path. Use only the basename recorded on that row, after validating it
        # resolves inside this buffer directory; never search by external ID.
        bound = str(event.get("disk_buffer_path") or "")
        if bound:
            try:
                path = Path(bound).resolve()
                root = self.disk_buffer.directory.resolve()
                if path.parent == root and path.suffix == ".enc" and path.is_file():
                    return path.stem
            except (OSError, RuntimeError):
                pass
        return internal_id

    def _metadata(self, event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        metadata = json.loads(event.get("metadata_json") or "{}")
        identity = metadata.get("identity")
        destination = metadata.get("model_destination")
        return (identity if isinstance(identity, dict) else {"trusted": False, "roles": []},
                destination if isinstance(destination, dict) else {})

    @staticmethod
    def _incomplete_rule(event: dict[str, Any]) -> RuleEvaluationResult:
        integrity = event.get("content_integrity") or "missing"
        code = "CONTENT_MISSING" if integrity == "missing" else "CONTENT_INCOMPLETE"
        reason = f"Outbound body is {integrity}; a complete safety evaluation is unavailable."
        # ``review`` is intentional here: incomplete content must never be
        # represented as an allow result even though no deterministic finding
        # can be made from the missing bytes.
        return RuleEvaluationResult("review", None, code, reason, [], [], [],
            {"trust": "unknown", "name": "unknown", "upstream": None}, [],
            [{"stage": "rules", "status": "completed", "verdict": "INCOMPLETE", "risk": "low",
              "reason_code": code, "reason": reason, "latency_ms": 0,
              "matched_rule_ids": [], "matched_rule_versions": [], "evidence": []}], False)

    @staticmethod
    def _rule_from_dict(value: dict[str, Any]) -> RuleEvaluationResult:
        return RuleEvaluationResult(
            value.get("rule_decision", value.get("decision", "allow")), value.get("rule_severity"),
            value.get("reason_code", "RULE_MATCH"), value.get("reason", "Rule evaluation completed."),
            list(value.get("data_findings") or []), list(value.get("unapproved_findings") or []),
            list(value.get("approved_findings") or []), dict(value.get("destination") or {}),
            list(value.get("matched_rules") or value.get("matched_policies") or []), list(value.get("stages") or []),
            bool(value.get("needs_llm_review")), value.get("evidence_id"), value.get("request_purpose", "normal"), value.get("run_id"))

    async def _process_rule_event(self, event_id: str) -> None:
        event = self.store.get_event(event_id)
        if not event or event["rule_status"] != "pending":
            return
        self.store.update_event_status(event_id, rule_status="processing", processing_status="processing")
        buffer_id = self._buffer_id(event_id, event)
        data_bytes = await self.disk_buffer.async_read(buffer_id)
        payload = self._payload(data_bytes)

        if event["event_type"] == "response":
            response_bytes = payload.encode("utf-8") if isinstance(payload, str) else data_bytes
            calls = extract_tool_calls(event["protocol"], response_bytes)
            self._persist_response_evidence(event_id, event, calls)
            matches = self.store.find_correlated_events(event["source_id"], event["call_id"], event.get("attempt_id"), event_type="request")
            self.store.update_event_status(event_id, association_status="associated" if matches else "request_missing", rule_status="completed", llm_status="skipped", processing_status="completed", completed_at=_now())
            for matched in matches:
                self.store.update_event_status(matched["id"], association_status="associated")
            await self.disk_buffer.async_delete(buffer_id)
            self.engine.broker.publish("event.completed", {"id": event_id})
            return

        # A full_call envelope contains both directions. Only its request is a
        # DLP object; response content is reduced to tool-call corroboration.
        if event["event_type"] == "full_call":
            if isinstance(payload, dict):
                response = payload.get("response")
                if response is not None:
                    response_bytes = response.encode("utf-8") if isinstance(response, str) else json.dumps(response, ensure_ascii=False).encode("utf-8")
                    self._persist_response_evidence(event_id, event, extract_tool_calls(event["protocol"], response_bytes))
                payload = payload.get("request")
            else:
                payload = None

        matches = self.store.find_correlated_events(event["source_id"], event["call_id"], event.get("attempt_id"), event_type="response")
        self.store.update_event_status(event_id, association_status="associated" if matches else "none")
        for matched in matches:
            self.store.update_event_status(matched["id"], association_status="associated")

        identity, destination = self._metadata(event)
        is_complete = event.get("content_integrity") == "complete" and isinstance(payload, dict)
        if event.get("content_integrity") in ("complete", "truncated", "redacted") and isinstance(payload, dict):
            rule_result = await self._rule_call(self.engine.evaluate_rule_channel, payload,
                protocol=event["protocol"], identity=identity,
                upstream=destination.get("upstream") or self.engine.upstream, trace_id=str(event.get("id") or event_id))
        else:
            rule_result = self._incomplete_rule(event)
        if not is_complete and rule_result.rule_severity is None:
            # Visible fragments may be scanned, but their absence of findings
            # cannot establish safety. Preserve a review decision in the event
            # result so API clients do not mistake the rules channel for allow.
            rule_result.rule_decision = "review"
            rule_result.reason_code = "CONTENT_INCOMPLETE"
            rule_result.reason = "Content is incomplete; a complete safety evaluation is unavailable."
        rule_dict = rule_result.to_dict()
        rule_dict["classification_complete"] = bool(is_complete)
        rule_dict["needs_review"] = bool(not is_complete or rule_result.needs_llm_review)
        if not is_complete:
            rule_dict["decision"] = "review"
        alert_id = None
        if rule_result.rule_severity in ("low", "medium", "high", "critical"):
            # Event rows have their own alert path. The trace compatibility
            # helper cannot associate an event UUID with the event alert index.
            alert_id = self.store.create_event_alert(
                event_id=event_id,
                severity=rule_result.rule_severity,
                rule_severity=rule_result.rule_severity,
                llm_status="pending",
                channel_source="rule",
                reason_code=rule_result.reason_code,
                title=f"{rule_result.rule_severity.upper()}: Outbound Data Rule Hit",
                reason=rule_result.reason,
                evidence=rule_result.to_dict().get("authorization_evidence", []),
                evidence_id=rule_result.evidence_id,
                data_findings=rule_result.data_findings,
                destination=rule_result.destination,
            )
            self.engine.broker.publish("alert.created", {"id": alert_id, "event_id": event_id, "severity": rule_result.rule_severity})
        # Alert creation is idempotent. Commit it before publishing the
        # completed rule stage so a crash cannot leave a rule hit unalerted.
        self.store.update_event_status(event_id, rule_status="completed", rule_verdict=rule_dict)

        if rule_result.needs_llm_review or self._proxy_session_text(event, payload)[1]:
            pending = LLMEvaluationResult("pending", None, None, "rules", rule_result.reason_code, rule_result.reason, [])
            self._project_result(event_id, rule_result, pending)
            self.store.update_event_status(event_id, llm_status="pending", processing_status="pending", retry_count=0)
            await self.enqueue_reviewer(event_id)
            return

        llm_result = (LLMEvaluationResult("failed", None, None, "rules", "CONTENT_INCOMPLETE", "Complete content is required to establish safety.", [])
                      if event.get("content_integrity") != "complete" else
                      LLMEvaluationResult("not_needed", None, None, "rules", rule_result.reason_code, rule_result.reason, []))
        verdict = self.engine.aggregate(rule_result, llm_result)
        if alert_id:
            self._update_alert(event_id, verdict, llm_result)
        self._project_result(event_id, rule_result, llm_result)
        self.store.update_event_status(event_id, llm_status=llm_result.llm_status, llm_verdict=llm_result.to_dict(), processing_status="completed", completed_at=_now())
        self.engine.broker.publish("event.completed", {"id": event_id})
        await self.disk_buffer.async_delete(buffer_id)

    @staticmethod
    def _proxy_session_text(event: dict[str, Any], payload: Any) -> tuple[str | None, str]:
        # This source is reserved by HTTP ingress for the in-process adapter.
        if event.get("source_id") != "proxy-adapter" or not event.get("is_realtime"):
            return None, ""
        metadata = json.loads(event.get("metadata_json") or "{}")
        trace_id = metadata.get("source_metadata", {}).get("trace_id")
        try:
            normalized = normalize(classification_payload(event["protocol"], payload), source_format_override=event["protocol"])
            return trace_id, normalized.latest_user_text
        except (ValueError, TypeError, KeyError, AttributeError):
            return trace_id, ""

    async def _review_proxy_session(self, event: dict[str, Any], payload: Any) -> None:
        trace_id, text = self._proxy_session_text(event, payload)
        if not trace_id or not text:
            return
        with self.store._connect() as connection:
            existing = connection.execute("SELECT id FROM session_risk_segments WHERE trace_id=? LIMIT 1", (trace_id,)).fetchone()
        if existing:
            return
        trace = self.store.get(trace_id)
        if not trace:
            raise RuntimeError("proxy trace is not ready for session analysis")
        prior = self.store.session_risk_summary(trace["session_record_id"]) if trace.get("session_record_id") else None
        assessment = await self._reviewer_call(assess_session_risk, text, prior, self.store.get_prompts())
        segment, alert_id = self.store.record_session_risk(trace_id, assessment.to_dict())
        self.engine.broker.publish("session_risk.updated", {"trace_id": trace_id, "summary": segment})
        if alert_id:
            self.engine.broker.publish("alert.created", {"id": alert_id, "trace_id": trace_id, "source": "session_risk"})

    def _project_result(self, event_id: str, rule: RuleEvaluationResult, llm: LLMEvaluationResult) -> None:
        event = self.store.get_event(event_id)
        if not event or event.get("source_id") != "proxy-adapter":
            return
        verdict = self.engine.aggregate(rule, llm)
        self.store.project_event_analysis(event_id, self.engine.pipeline_record(rule, llm, verdict))

    async def _custom_review(self, event: dict[str, Any], payload: Any) -> LLMEvaluationResult:
        rule_result = self._rule_from_dict(json.loads(event.get("rule_verdict_json") or "{}"))
        if self.reviewer_fn is None:
            return await self._reviewer_call(self.engine.evaluate_llm_channel, rule_result, identity=self._metadata(event)[0])
        try:
            if inspect.iscoroutinefunction(self.reviewer_fn):
                result = self.reviewer_fn(event, payload)
            else:
                result = await self._reviewer_call(self.reviewer_fn, event, payload)
            if inspect.isawaitable(result):
                result = await result
            if not isinstance(result, dict):
                raise ValueError("reviewer result must be an object")
            decision = str(result.get("decision", result.get("verdict", "uncertain"))).lower()
            risk = str(result.get("risk", "low")).lower()
            if decision not in {"allow", "reject", "uncertain"} or risk not in {"low", "medium", "high", "critical"}:
                raise ValueError("invalid reviewer result")
            stage = str(result.get("stage", "fast_llm"))
            code = str(result.get("reason_code") or "LLM_REVIEW")
            reason = str(result.get("summary") or result.get("reason") or "Reviewer completed.")
            stage_result = {**result, "stage": stage, "status": "completed", "verdict": decision, "risk": risk, "reason_code": code, "reason": reason}
            return LLMEvaluationResult("completed", decision, risk if decision == "reject" else None, stage, code, reason, [stage_result])
        except Exception as exc:
            stage = {"stage": "fast_llm", "status": "failed", "verdict": "uncertain", "risk": "high", "reason_code": "REVIEWER_FAILED", "reason": "Reviewer failed.", "error_code": type(exc).__name__, "matched_rule_ids": [], "matched_rule_versions": [], "evidence": []}
            return LLMEvaluationResult("failed", None, None, "fast_llm", "REVIEWER_FAILED", f"Reviewer failed: {type(exc).__name__}.", [stage])

    async def _process_reviewer_event(self, event_id: str) -> None:
        event = self.store.get_event(event_id)
        if not event or event["llm_status"] != "pending":
            return
        self.store.update_event_status(event_id, llm_status="processing", processing_status="processing")
        buffer_id = self._buffer_id(event_id, event)
        payload = self._payload(await self.disk_buffer.async_read(buffer_id))
        if not isinstance(payload, dict):
            raise ValueError("event payload is not an object")
        llm_result = await self._custom_review(event, payload)
        await self._review_proxy_session(event, payload)
        rule_result = self._rule_from_dict(json.loads(event.get("rule_verdict_json") or "{}"))
        verdict = self.engine.aggregate(rule_result, llm_result)
        self._update_alert(event_id, verdict, llm_result)
        self._project_result(event_id, rule_result, llm_result)
        if llm_result.llm_status == "failed":
            # A reviewer outage is retryable and must retain encrypted input;
            # marking it completed would make administrator retry impossible.
            self.store.update_event_status(event_id, llm_status="failed", llm_verdict=llm_result.to_dict(), processing_status="failed", error_message=llm_result.reason)
            self.engine.broker.publish("event.failed", {"id": event_id})
            return
        self.store.update_event_status(event_id, llm_status=llm_result.llm_status, llm_verdict=llm_result.to_dict(), processing_status="completed", completed_at=_now())
        self.engine.broker.publish("event.completed", {"id": event_id})
        await self.disk_buffer.async_delete(buffer_id)

    def _persist_response_evidence(self, event_id: str, event: dict[str, Any], calls: list[dict[str, Any]]) -> None:
        normalized = []
        for call in calls:
            derived = normalize_tool_call(call, source="response").to_dict()
            # Tool arguments are corroboration, never a raw-response archive.
            findings = scan_payload(derived)
            normalized.append(redact_payload(derived, findings))
        self.store.record_event_tool_actions(event_id, normalized)
        if event.get("source_id") == "proxy-adapter":
            metadata = json.loads(event.get("metadata_json") or "{}")
            trace_id = metadata.get("trace_id") or (metadata.get("source_metadata") or {}).get("trace_id") or event.get("call_id")
            if trace_id:
                try:
                    self.store.record_tool_actions(trace_id, calls)
                except Exception:
                    pass

    def _update_alert(self, event_id: str, verdict: Any, llm_result: LLMEvaluationResult) -> None:
        alert_id = self.store.update_event_alert(event_id, verdict=verdict.to_dict(), llm_result=llm_result.to_dict())
        if alert_id:
            self.engine.broker.publish("alert.updated", {"id": alert_id, "event_id": event_id})

    async def _handle_failure(self, event_id: str, stage: str, exc: Exception) -> None:
        event = self.store.get_event(event_id)
        if not event:
            return
        retries = int(event.get("retry_count") or 0) + 1
        if retries < MAX_RETRIES:
            self.store.update_event_status(event_id, retry_count=retries,
                error_message=f"{stage} attempt {retries} failed: {type(exc).__name__}: {exc}",
                rule_status="pending" if stage == "rule" else event.get("rule_status"),
                llm_status="pending" if stage == "reviewer" else event.get("llm_status"), processing_status="pending")
            await (self.enqueue_rule(event_id) if stage == "rule" else self.enqueue_reviewer(event_id))
            return
        self.store.update_event_status(event_id, retry_count=retries,
            error_message=f"{stage} stage failed after {MAX_RETRIES} attempts: {type(exc).__name__}: {exc}",
            rule_status="failed" if stage == "rule" else event.get("rule_status"),
            llm_status="failed" if stage == "reviewer" else event.get("llm_status"), processing_status="failed")
