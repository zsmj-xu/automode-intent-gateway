import json
import os
import tempfile
import unittest
from pathlib import Path

from automode_gateway.disk_buffer import DiskBuffer
from automode_gateway.event_worker import EventWorker
from automode_gateway.storage import TraceStore


class EventWorkerRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = TraceStore(root / "events.db", evidence_key=os.urandom(32))
        self.buffer = DiskBuffer(root / "buffer", evidence_key=self.store.evidence_key)
        self.store.create_source(id="src-a", name="A", token="a")
        self.store.create_source(id="src-b", name="B", token="b")
        self.worker = EventWorker(self.store, self.buffer, rule_concurrency=1, reviewer_concurrency=1)
        await self.worker.start()

    async def asyncTearDown(self):
        await self.worker.stop()
        self.tmp.cleanup()

    async def add_event(self, external_id, *, source="src-a", event_type="request", payload=None,
                        integrity="complete", call_id="call-1", attempt_id=None, enqueue=True):
        internal_id = f"internal-{source}-{external_id}-{attempt_id or 'none'}"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        path = await self.buffer.async_write(internal_id, body)
        self.store.record_event(
            event_id=external_id, internal_id=internal_id, source_id=source,
            call_id=call_id, attempt_id=attempt_id, event_type=event_type,
            protocol="openai_chat_completions", capture_stage="model_outbound",
            content_integrity=integrity, timestamp="2026-09-09T00:00:00Z",
            payload_hash="hash-" + internal_id, disk_buffer_path=path,
        )
        if enqueue:
            await self.worker.enqueue_rule(internal_id)
            await self.worker.drain()
        return self.store.get_event_by_source_and_id(source, external_id)

    async def test_incomplete_visible_body_is_review_not_allow(self):
        event = await self.add_event(
            "truncated", integrity="truncated",
            payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "partial body"}]},
        )
        self.assertEqual(event["processing_status"], "completed")
        verdict = json.loads(event["rule_verdict_json"])
        self.assertFalse(verdict["classification_complete"])
        self.assertTrue(verdict["needs_review"])
        self.assertEqual(verdict["decision"], "review")
        self.assertEqual(event["llm_status"], "failed")

    async def test_response_string_is_unwrapped_and_saved_as_redacted_evidence(self):
        response = "data: " + json.dumps({
            "choices": [{"delta": {"tool_calls": [{
                "index": 0, "id": "tc-1", "function": {"name": "read_file", "arguments": json.dumps({"path": "/tmp/a"})},
            }]}}]}) + "\n\ndata: [DONE]\n"
        event = await self.add_event("response", event_type="response", payload=response, call_id="call-response")
        self.assertEqual(event["association_status"], "request_missing")
        evidence = json.loads(event["response_evidence_json"])
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["name"], "read_file")
        self.assertFalse(self.buffer.exists(event["id"]))

    async def test_full_call_without_request_cannot_be_allow(self):
        event = await self.add_event(
            "bad-full-call", event_type="full_call",
            payload={"response": {"choices": []}},
            call_id="call-full",
        )
        verdict = json.loads(event["rule_verdict_json"])
        self.assertEqual(verdict["decision"], "review")
        self.assertFalse(verdict["classification_complete"])

    async def test_same_call_across_sources_and_attempts_stays_isolated(self):
        first = await self.add_event("same-a", source="src-a", call_id="shared", attempt_id="one")
        second = await self.add_event("same-b", source="src-b", call_id="shared", attempt_id="two")
        self.assertEqual(first["source_id"], "src-a")
        self.assertEqual(second["source_id"], "src-b")
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["association_status"], "none")
        self.assertEqual(second["association_status"], "none")

    async def test_restart_recovers_pending_attempt_without_cross_source_lookup(self):
        await self.worker.stop()
        pending = await self.add_event(
            "restart-a", source="src-a", call_id="shared-call", attempt_id="attempt-2", enqueue=False,
        )
        recovered = EventWorker(self.store, self.buffer, rule_concurrency=1, reviewer_concurrency=1)
        await recovered.start()
        await recovered.drain()
        self.assertEqual(self.store.get_event(pending["id"])["processing_status"], "completed")
        await recovered.stop()


if __name__ == "__main__":
    unittest.main()
