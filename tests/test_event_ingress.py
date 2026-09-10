import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from automode_gateway.disk_buffer import DiskBuffer
from automode_gateway.event_ingress import (
    DISK_BUFFER_KEY,
    EVENT_WORKER_KEY,
    register_ingress_routes,
)
from automode_gateway.event_worker import EventWorker
from automode_gateway.storage import TraceStore


class EventIngressTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "test_ingress.db"
        self.evidence_key = os.urandom(32)
        self.store = TraceStore(self.db_path, evidence_key=self.evidence_key)
        self.buffer_dir = Path(self.tempdir.name) / "disk_buffer"
        self.disk_buffer = DiskBuffer(
            self.buffer_dir,
            evidence_key=self.evidence_key,
            max_event_bytes=1024 * 1024,  # 1 MiB for test
            max_buffer_bytes=2 * 1024 * 1024,  # 2 MiB for test
        )
        self.worker = EventWorker(
            self.store,
            self.disk_buffer,
            rule_concurrency=2,
            reviewer_concurrency=2,
        )

        # Create sources in database
        self.store.create_source(
            id="src_untrusted",
            name="Untrusted Source",
            token="token_untrusted_123",
            allow_trusted_identity=False,
        )
        self.store.create_source(
            id="src_trusted",
            name="Trusted Source",
            token="token_trusted_456",
            allow_trusted_identity=True,
        )

        self.app = web.Application()
        register_ingress_routes(self.app, self.store, self.disk_buffer, self.worker)
        self.app.on_startup.append(self.worker.start)
        self.app.on_cleanup.append(self.worker.stop)

        self.server = TestServer(self.app)
        await self.server.start_server()
        self.client = ClientSession()

    async def asyncTearDown(self):
        await self.client.close()
        await self.server.close()
        self.tempdir.cleanup()

    def _sample_event(self, event_id="evt_01", source_id="src_untrusted", event_type="request"):
        return {
            "version": "1",
            "event_id": event_id,
            "source_id": source_id,
            "call_id": f"call_{event_id}",
            "event_type": event_type,
            "protocol": "openai_chat_completions",
            "capture_stage": "model_outbound",
            "content_integrity": "complete",
            "timestamp": "2026-09-09T10:00:00Z",
            "payload": {
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Hello, world!"}],
            },
            "identity": {"user_id": "alice", "trusted": True},
            "model_destination": {"upstream": "https://api.openai.com", "model": "gpt-4o"},
        }

    async def test_auth_missing_or_invalid_token(self):
        url = self.server.make_url("/v1/events")
        event = self._sample_event()

        # No token
        async with self.client.post(url, json=event) as resp:
            self.assertEqual(resp.status, 401)

        # Invalid token
        headers = {"Authorization": "Bearer wrong_token"}
        async with self.client.post(url, json=event, headers=headers) as resp:
            self.assertEqual(resp.status, 401)

    async def test_auth_source_mismatch_forbidden(self):
        url = self.server.make_url("/v1/events")
        # Token belongs to src_untrusted, but payload claims source_id is src_trusted
        event = self._sample_event(source_id="src_trusted")
        headers = {"Authorization": "Bearer token_untrusted_123"}
        async with self.client.post(url, json=event, headers=headers) as resp:
            self.assertEqual(resp.status, 403)

    async def test_trusted_identity_coercion(self):
        url = self.server.make_url("/v1/events")

        # 1. Untrusted source claims identity.trusted = True -> coerced to False
        event_untrusted = self._sample_event(event_id="evt_untrusted_1", source_id="src_untrusted")
        headers_untrusted = {"Authorization": "Bearer token_untrusted_123"}
        async with self.client.post(url, json=event_untrusted, headers=headers_untrusted) as resp:
            self.assertEqual(resp.status, 202)

        ev1 = self.store.get_event("evt_untrusted_1")
        meta1 = json.loads(ev1["metadata_json"])
        self.assertFalse(meta1["identity"]["trusted"])

        # 2. Trusted source claims identity.trusted = True -> preserved as True
        event_trusted = self._sample_event(event_id="evt_trusted_1", source_id="src_trusted")
        headers_trusted = {"Authorization": "Bearer token_trusted_456"}
        async with self.client.post(url, json=event_trusted, headers=headers_trusted) as resp:
            self.assertEqual(resp.status, 202)

        ev2 = self.store.get_event("evt_trusted_1")
        meta2 = json.loads(ev2["metadata_json"])
        self.assertTrue(meta2["identity"]["trusted"])

    async def test_idempotency_and_conflict(self):
        url = self.server.make_url("/v1/events")
        headers = {"Authorization": "Bearer token_untrusted_123"}
        event = self._sample_event(event_id="evt_idem_1")

        # First post: accepted
        async with self.client.post(url, json=event, headers=headers) as resp:
            self.assertEqual(resp.status, 202)
            data = await resp.json()
            self.assertEqual(data["status"], "accepted")
            self.assertEqual(data["event_id"], "evt_idem_1")
            self.assertIn("/v1/events/evt_idem_1", data["status_url"])

        # Second post with identical payload: returns duplicate accepted
        async with self.client.post(url, json=event, headers=headers) as resp:
            self.assertEqual(resp.status, 202)
            data = await resp.json()
            self.assertTrue(data.get("duplicate"))

        # Third post with same event_id but DIFFERENT payload: returns 409 Conflict
        event_conflicted = self._sample_event(event_id="evt_idem_1")
        event_conflicted["payload"]["messages"][0]["content"] = "Tampered message content"
        async with self.client.post(url, json=event_conflicted, headers=headers) as resp:
            self.assertEqual(resp.status, 409)

    async def test_content_integrity_validation(self):
        url = self.server.make_url("/v1/events")
        headers = {"Authorization": "Bearer token_untrusted_123"}

        # Invalid protocol
        bad_protocol = self._sample_event(event_id="evt_bad_proto")
        bad_protocol["protocol"] = "unsupported_llm_proto"
        async with self.client.post(url, json=bad_protocol, headers=headers) as resp:
            self.assertEqual(resp.status, 400)

        # Missing payload when integrity is complete -> 400
        missing_payload = self._sample_event(event_id="evt_bad_payload")
        missing_payload["payload"] = None
        async with self.client.post(url, json=missing_payload, headers=headers) as resp:
            self.assertEqual(resp.status, 400)

        # Allowed missing payload when integrity is missing
        ok_missing = self._sample_event(event_id="evt_ok_missing")
        ok_missing["content_integrity"] = "missing"
        ok_missing["payload"] = None
        async with self.client.post(url, json=ok_missing, headers=headers) as resp:
            self.assertEqual(resp.status, 202)

    async def test_capacity_backpressure_and_limits(self):
        # Configure small disk buffer for testing backpressure
        small_buffer_dir = Path(self.tempdir.name) / "small_buffer"
        small_buffer = DiskBuffer(
            small_buffer_dir,
            evidence_key=self.evidence_key,
            max_event_bytes=800,
            max_buffer_bytes=500,
        )
        small_app = web.Application()
        register_ingress_routes(small_app, self.store, small_buffer, None)
        small_server = TestServer(small_app)
        await small_server.start_server()

        url = small_server.make_url("/v1/events")
        headers = {"Authorization": "Bearer token_untrusted_123"}

        try:
            # 1. Single event exceeding max_event_bytes -> 413 Payload Too Large
            large_event = self._sample_event(event_id="evt_huge")
            large_event["payload"]["messages"][0]["content"] = "x" * 700
            async with self.client.post(url, json=large_event, headers=headers) as resp:
                self.assertEqual(resp.status, 413)

            # 2. Cumulative buffer full -> 507 Insufficient Storage with Retry-After
            ev1 = self._sample_event(event_id="evt_fill_1")
            ev1["payload"]["messages"][0]["content"] = "x" * 100
            async with self.client.post(url, json=ev1, headers=headers) as resp:
                self.assertEqual(resp.status, 202)

            ev2 = self._sample_event(event_id="evt_fill_2")
            ev2["payload"]["messages"][0]["content"] = "x" * 100
            async with self.client.post(url, json=ev2, headers=headers) as resp:
                self.assertEqual(resp.status, 202)

            ev3 = self._sample_event(event_id="evt_fill_3")
            ev3["payload"]["messages"][0]["content"] = "x" * 100
            async with self.client.post(url, json=ev3, headers=headers) as resp:
                self.assertEqual(resp.status, 507)
                self.assertEqual(resp.headers.get("Retry-After"), "5")
        finally:
            await small_server.close()

    async def test_get_event_status_source_isolation(self):
        url_post = self.server.make_url("/v1/events")
        headers_untrusted = {"Authorization": "Bearer token_untrusted_123"}
        headers_trusted = {"Authorization": "Bearer token_trusted_456"}

        event = self._sample_event(event_id="evt_iso_1", source_id="src_untrusted")
        async with self.client.post(url_post, json=event, headers=headers_untrusted) as resp:
            self.assertEqual(resp.status, 202)

        url_get = self.server.make_url("/v1/events/evt_iso_1")

        # Allowed source query
        async with self.client.get(url_get, headers=headers_untrusted) as resp:
            self.assertEqual(resp.status, 200)
            data = await resp.json()
            self.assertEqual(data["event_id"], "evt_iso_1")
            self.assertEqual(data["source_id"], "src_untrusted")
            self.assertIn("processing_status", data)

        # Unauthorized other source query -> 404
        async with self.client.get(url_get, headers=headers_trusted) as resp:
            self.assertEqual(resp.status, 404)


class EventWorkerPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "test_pipeline.db"
        self.evidence_key = os.urandom(32)
        self.store = TraceStore(self.db_path, evidence_key=self.evidence_key)
        self.buffer_dir = Path(self.tempdir.name) / "disk_buffer"
        self.disk_buffer = DiskBuffer(self.buffer_dir, evidence_key=self.evidence_key)
        self.worker = EventWorker(
            self.store,
            self.disk_buffer,
            rule_concurrency=2,
            reviewer_concurrency=2,
        )
        self.store.create_source(
            id="src_agent",
            name="Agent Source",
            token="token_agent",
            allow_trusted_identity=False,
        )
        await self.worker.start()

    async def asyncTearDown(self):
        await self.worker.stop()
        self.tempdir.cleanup()

    async def test_rule_detection_and_reviewer_flow(self):
        # Submit request with sensitive credential keyword
        event_id = "evt_sensitive_1"
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Here is my secret AWS key: AKIAIOSFODNN7EXAMPLE"}
            ],
        }
        raw_bytes = json.dumps(payload).encode("utf-8")
        await self.disk_buffer.async_write(event_id, raw_bytes)
        self.store.record_event(
            event_id=event_id,
            source_id="src_agent",
            call_id="call_sens_1",
            event_type="request",
            protocol="openai_chat_completions",
            capture_stage="model_outbound",
            content_integrity="complete",
            is_realtime=True,
            timestamp="2026-09-09T10:00:00Z",
            payload_hash="hash1",
            disk_buffer_path=str(self.disk_buffer.directory / f"{event_id}.enc"),
        )

        # Enqueue for rule processing
        await self.worker.enqueue_rule(event_id)
        await self.worker.drain()

        # Check event status and alert
        event = self.store.get_event(event_id)
        self.assertEqual(event["rule_status"], "completed")
        self.assertEqual(event["processing_status"], "failed")
        self.assertEqual(event["llm_status"], "failed")

        # Verify rule alert was created in alerts table
        alerts = self.store.alerts(status="open")
        matching = [a for a in alerts if a.get("event_id") == event["id"]]
        self.assertEqual(len(matching), 1)
        alert = matching[0]
        self.assertEqual(alert["channel_source"], "rule")
        self.assertIn(alert["rule_severity"], ("medium", "high", "critical"))

        # An unavailable reviewer must retain the encrypted input for retry.
        self.assertTrue(self.disk_buffer.exists(event_id))

    async def test_orphan_response_handling_and_late_request_reconciliation(self):
        call_id = "call_orphan_99"
        resp_event_id = "evt_resp_orphan"
        resp_payload = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "tc_1",
                                "type": "function",
                                "function": {"name": "query_db", "arguments": "{\"q\": \"select 1\"}"},
                            }
                        ],
                    }
                }
            ]
        }
        await self.disk_buffer.async_write(resp_event_id, json.dumps(resp_payload).encode("utf-8"))
        self.store.record_event(
            event_id=resp_event_id,
            source_id="src_agent",
            call_id=call_id,
            event_type="response",
            protocol="openai_chat_completions",
            capture_stage="model_outbound",
            content_integrity="complete",
            is_realtime=True,
            timestamp="2026-09-09T10:00:00Z",
            payload_hash="hash_resp",
            disk_buffer_path=str(self.disk_buffer.directory / f"{resp_event_id}.enc"),
        )

        # 1. Process orphan response first
        await self.worker.enqueue_rule(resp_event_id)
        await self.worker.drain()

        resp_event = self.store.get_event(resp_event_id)
        # Marked as request_missing without blocking worker
        self.assertEqual(resp_event["processing_status"], "completed")
        self.assertEqual(resp_event["association_status"], "request_missing")
        # Temporary body is freed immediately
        self.assertFalse(self.disk_buffer.exists(resp_event_id))

        # 2. Late arriving request with matching call_id
        req_event_id = "evt_req_late"
        req_payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Please query the database"}],
        }
        await self.disk_buffer.async_write(req_event_id, json.dumps(req_payload).encode("utf-8"))
        self.store.record_event(
            event_id=req_event_id,
            source_id="src_agent",
            call_id=call_id,
            event_type="request",
            protocol="openai_chat_completions",
            capture_stage="model_outbound",
            content_integrity="complete",
            is_realtime=True,
            timestamp="2026-09-09T10:01:00Z",
            payload_hash="hash_req",
            disk_buffer_path=str(self.disk_buffer.directory / f"{req_event_id}.enc"),
        )

        await self.worker.enqueue_rule(req_event_id)
        await self.worker.drain()

        # Check reconciliation: both request and response are now 'associated'
        resp_after = self.store.get_event(resp_event_id)
        req_after = self.store.get_event(req_event_id)
        self.assertEqual(resp_after["association_status"], "associated")
        self.assertEqual(req_after["association_status"], "associated")

    async def test_retry_three_times_and_retain_on_failure(self):
        event_id = "evt_fail_test"
        # Write invalid corrupt JSON to trigger read/parse error
        await self.disk_buffer.async_write(event_id, b"not a json object")
        self.store.record_event(
            event_id=event_id,
            source_id="src_agent",
            call_id="call_fail",
            event_type="request",
            protocol="openai_chat_completions",
            capture_stage="model_outbound",
            content_integrity="complete",
            is_realtime=True,
            timestamp="2026-09-09T10:00:00Z",
            payload_hash="hash_fail",
            disk_buffer_path=str(self.disk_buffer.directory / f"{event_id}.enc"),
        )

        await self.worker.enqueue_rule(event_id)
        await self.worker.drain()

        event = self.store.get_event(event_id)
        self.assertEqual(event["retry_count"], 3)
        self.assertEqual(event["processing_status"], "failed")
        self.assertEqual(event["rule_status"], "failed")
        self.assertIn("failed after 3 attempts", event["error_message"])

        # When failed after 3 attempts, disk buffer payload is retained for admin inspection!
        self.assertTrue(self.disk_buffer.exists(event_id))

    async def test_crash_recovery(self):
        event_id = "evt_crash_recovery"
        payload = {"model": "gpt-4o", "messages": [{"role": "user", "content": "Recover me"}]}
        await self.disk_buffer.async_write(event_id, json.dumps(payload).encode("utf-8"))
        self.store.record_event(
            event_id=event_id,
            source_id="src_agent",
            call_id="call_crash",
            event_type="request",
            protocol="openai_chat_completions",
            capture_stage="model_outbound",
            content_integrity="complete",
            is_realtime=True,
            timestamp="2026-09-09T10:00:00Z",
            payload_hash="hash_crash",
            disk_buffer_path=str(self.disk_buffer.directory / f"{event_id}.enc"),
        )
        # Simulate in-flight crash
        self.store.update_event_status(event_id, processing_status="processing", rule_status="processing")

        # Stop existing worker and start a new one to simulate restart
        await self.worker.stop()

        new_worker = EventWorker(
            self.store,
            self.disk_buffer,
            rule_concurrency=2,
            reviewer_concurrency=2,
        )
        stats = await new_worker.recover()
        self.assertEqual(stats["recovered_rules"], 1)

        await new_worker.start()
        await new_worker.drain()
        await new_worker.stop()

        event = self.store.get_event(event_id)
        self.assertEqual(event["processing_status"], "completed")
        self.assertEqual(event["rule_status"], "completed")


if __name__ == "__main__":
    unittest.main()
