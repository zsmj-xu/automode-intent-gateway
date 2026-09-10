import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from automode_gateway.evidence import generate_key
from automode_gateway.gateway import GATEWAY_KEY, create_app
from automode_gateway.event_ingress import EVENT_WORKER_KEY


class ProxyEventAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_upstream_starts_event_service_and_uses_bounded_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            old_limit = os.environ.get("AUTOMODE_PROXY_BUFFER_EVENTS")
            os.environ["AUTOMODE_PROXY_BUFFER_EVENTS"] = "3"
            try:
                app = create_app(upstream=None, db_path=str(Path(directory) / "events.db"))
                app.freeze()
                await app.startup()
                gateway = app[GATEWAY_KEY]
                self.assertIsNone(gateway.upstream)
                self.assertEqual(gateway.reliability_mode, "standard_event_only")
                self.assertEqual(gateway.proxy_audit_queue.maxsize, 3)
                await app.cleanup()
            finally:
                if old_limit is None:
                    os.environ.pop("AUTOMODE_PROXY_BUFFER_EVENTS", None)
                else:
                    os.environ["AUTOMODE_PROXY_BUFFER_EVENTS"] = old_limit

    async def test_active_proxy_item_counts_toward_event_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            old_limit = os.environ.get("AUTOMODE_PROXY_BUFFER_EVENTS")
            os.environ["AUTOMODE_PROXY_BUFFER_EVENTS"] = "2"
            try:
                app = create_app(upstream="http://127.0.0.1:9", db_path=str(Path(directory) / "events.db"))
                gateway = app[GATEWAY_KEY]
                loop = asyncio.get_running_loop()
                gateway.proxy_audit_active = True
                gateway.proxy_audit_queue.put_nowait(({}, b"x", loop.create_future()))
                gateway.proxy_audit_buffer_bytes = 1
                args = {
                    "trace_id": "trace-cap", "protocol": "openai_chat_completions",
                    "method": "POST", "path": "/v1/chat/completions", "payload": {"model": "m"},
                }
                future = gateway._enqueue_proxy_audit(args, args["payload"], {}, {})
                self.assertIsNone(await future)
                self.assertEqual(gateway.proxy_dropped_count, 1)
                self.assertEqual(gateway.proxy_dropped_by_reason["buffer_full"], 1)
                gateway.proxy_audit_queue.get_nowait()
                gateway.proxy_audit_queue.task_done()
                gateway.proxy_audit_active = False
            finally:
                if old_limit is None:
                    os.environ.pop("AUTOMODE_PROXY_BUFFER_EVENTS", None)
                else:
                    os.environ["AUTOMODE_PROXY_BUFFER_EVENTS"] = old_limit

    async def test_encrypted_adapter_uses_internal_event_id_and_shared_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "evidence.key"
            key_path.write_text(generate_key(), encoding="ascii")
            key_path.chmod(0o600)
            old_key = os.environ.get("AUTOMODE_EVIDENCE_KEY_FILE")
            os.environ["AUTOMODE_EVIDENCE_KEY_FILE"] = str(key_path)
            try:
                app = create_app(upstream=None, db_path=str(Path(directory) / "events.db"))
                app.freeze()
                await app.startup()
                gateway = app[GATEWAY_KEY]
                worker = app[EVENT_WORKER_KEY]
                self.assertIs(worker.engine, gateway.engine)
                payload = {"model": "test-model", "messages": []}
                args = {
                    "trace_id": "trace-proxy-1", "protocol": "openai_chat_completions",
                    "method": "POST", "path": "/v1/chat/completions", "payload": payload,
                    "headers": {}, "session_id": None, "latest_user_text": "",
                    "declared_tool_count": 0,
                }
                future = gateway._enqueue_proxy_audit(args, payload, {}, {})
                self.assertEqual(await future, "proxy_trace-proxy-1_request")
                await asyncio.sleep(0.05)
                event = gateway.store.get_event("proxy_trace-proxy-1_request")
                self.assertIsNotNone(event)
                self.assertNotEqual(event["id"], event["external_event_id"])
                await app.cleanup()
            finally:
                if old_key is None:
                    os.environ.pop("AUTOMODE_EVIDENCE_KEY_FILE", None)
                else:
                    os.environ["AUTOMODE_EVIDENCE_KEY_FILE"] = old_key

    async def test_encrypted_proxy_preserves_trace_and_response_evidence(self):
        async def upstream_handler(request):
            await request.read()
            return web.json_response({
                "id": "chatcmpl-proxy-key",
                "choices": [{"message": {"role": "assistant", "tool_calls": [
                    {"id": "call-1", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"README.md\"}"}}
                ]}}],
            })

        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "evidence.key"
            key_path.write_text(generate_key(), encoding="ascii")
            key_path.chmod(0o600)
            old_key = os.environ.get("AUTOMODE_EVIDENCE_KEY_FILE")
            os.environ["AUTOMODE_EVIDENCE_KEY_FILE"] = str(key_path)
            upstream_app = web.Application()
            upstream_app.router.add_post("/v1/chat/completions", upstream_handler)
            upstream = TestServer(upstream_app)
            await upstream.start_server()
            app = create_app(
                upstream=str(upstream.make_url("/")).rstrip("/"),
                db_path=str(Path(directory) / "events.db"),
            )
            app_server = TestServer(app)
            await app_server.start_server()
            try:
                async with ClientSession() as client:
                    async with client.post(
                        app_server.make_url("/v1/chat/completions"),
                        json={"model": "proxy-key-model", "messages": [{"role": "user", "content": "hello"}]},
                    ) as response:
                        self.assertEqual(response.status, 200)
                        trace_id = response.headers["x-automode-trace-id"]
                        await response.read()
                gateway = app[GATEWAY_KEY]
                for _ in range(100):
                    events = gateway.store.list_events()["data"]
                    trace = gateway.store.get(trace_id)
                    if len(events) >= 2 and all(item.get("processing_status") == "completed" for item in events) and trace and trace.get("response_status") == 200:
                        break
                    await asyncio.sleep(0.02)
                self.assertEqual(len(events), 2)
                request_event = next(item for item in events if item["event_type"] == "request")
                response_event = next(item for item in events if item["event_type"] == "response")
                self.assertNotEqual(request_event["id"], request_event["event_id"])
                self.assertNotEqual(response_event["id"], response_event["event_id"])
                self.assertEqual(request_event["call_id"], response_event["call_id"])
                self.assertEqual(request_event["capture_stage"], response_event["capture_stage"])
                self.assertEqual(trace["response_status"], 200)
                self.assertNotEqual(trace["classification"].get("decision"), "pending")
                self.assertEqual(len(gateway.store.session_detail(trace["session_record_id"])["traces"][0]["tool_actions"]), 1)
            finally:
                await app_server.close()
                await upstream.close()
                if old_key is None:
                    os.environ.pop("AUTOMODE_EVIDENCE_KEY_FILE", None)
                else:
                    os.environ["AUTOMODE_EVIDENCE_KEY_FILE"] = old_key


if __name__ == "__main__":
    unittest.main()
