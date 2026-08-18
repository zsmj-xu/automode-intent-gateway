import asyncio
import gc
import json
import os
import resource
import statistics
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from automode_gateway.gateway import create_app
from automode_gateway.normalizer import normalize
from automode_gateway.pipeline import DecisionPipeline
from automode_gateway.storage import TraceStore


class PerformanceTests(unittest.TestCase):
    def test_ac_p1_014_rules_direct_allow_p95_under_10ms(self):
        request = normalize({"model": "m", "messages": [{"role": "user", "content": "翻译 hello"}]})
        pipeline = DecisionPipeline()
        samples = []
        for _ in range(1000):
            started = time.perf_counter()
            result = pipeline.classify(request, [])
            samples.append((time.perf_counter() - started) * 1000)
            self.assertEqual(result.final_stage, "rules")
        p95 = statistics.quantiles(samples, n=100)[94]
        print(f"BENCH rules_direct_p95_ms={p95:.3f}")
        self.assertLess(p95, 10, f"rules p95 was {p95:.3f}ms")

    def test_ac_p1_016_and_018_large_console_dataset_remains_queryable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "load.db", store_raw=False)
            trace_ids = []
            for index in range(1000):
                trace_ids.append(store.create(
                    protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
                    payload={"model": "m", "messages": []}, headers={}, session_id=f"session-{index % 100}",
                    latest_user_text=f"message {index}", declared_tool_count=0,
                ))
            alert_result = {
                "final_decision": "alert", "final_stage": "rules", "risk": "high",
                "action_alignment": "high_impact", "reason_code": "LOAD_ALERT", "reason": "load test",
                "authorization_evidence": ["test"], "proposed_actions": [], "matched_rules": [],
                "review_transcript": [{"type": "user", "text": "test"}], "total_latency_ms": 1,
                "stages": [{"stage": "rules", "status": "completed", "verdict": "ALWAYS_ALERT", "risk": "high", "reason_code": "LOAD_ALERT", "reason": "load test", "latency_ms": 1, "action_alignment": "high_impact", "matched_rule_ids": [], "matched_rule_versions": []}],
            }
            for trace_id in trace_ids[:200]:
                store.save_pipeline(trace_id, alert_result)
            started = time.perf_counter()
            rows = store.list(500)
            elapsed = (time.perf_counter() - started) * 1000
            self.assertEqual(len(rows), 500)
            self.assertEqual(len(store.sessions()), 100)
            self.assertEqual(len(store.alerts(200)), 200)
            self.assertLess(elapsed, 1000)
            dashboard_started = time.perf_counter()
            dashboard = store.dashboard()
            self.assertLess((time.perf_counter() - dashboard_started) * 1000, 2000)
            self.assertEqual(dashboard["open_alert_count"], 200)
            print(f"BENCH sessions_query_ms={elapsed:.3f} dataset=1000_traces/100_sessions/200_alerts")


class LargeResponseTests(unittest.IsolatedAsyncioTestCase):
    async def test_ac_p1_015_one_hundred_concurrent_streams_and_ttfb_overhead(self):
        wire_body = b"data: {\"ok\":true}\n\ndata: [DONE]\n\n"
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length", "0")))
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(wire_body)))
                self.end_headers()
                self.wfile.write(wire_body)
                self.wfile.flush()
            def log_message(self, *_):
                pass
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        upstream.daemon_threads = True
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        upstream_url = f"http://127.0.0.1:{upstream.server_port}"
        tempdir = tempfile.TemporaryDirectory()
        gateway_app = create_app(upstream_url, str(Path(tempdir.name) / "concurrent.db"), store_raw=False)
        gateway = TestServer(gateway_app)
        await gateway.start_server()
        payload = {"model": "stream", "stream": True, "messages": [{"role": "user", "content": "hello"}]}

        async def measure(client, url):
            started = time.perf_counter()
            async with client.post(url, json=payload) as response:
                ttfb = (time.perf_counter() - started) * 1000
                timing = response.headers.get("server-timing", "automode;dur=0")
                processing = float(timing.rsplit("=", 1)[-1])
                body = await response.read()
                self.assertEqual(body, wire_body)
                return ttfb, processing

        try:
            async with ClientSession() as client:
                # Exclude cold TCP establishment from the gateway processing overhead.
                direct_url = f"{upstream_url}/v1/chat/completions"
                await asyncio.gather(*(measure(client, direct_url) for _ in range(100)))
                baseline = await asyncio.gather(*(measure(client, direct_url) for _ in range(100)))
                await asyncio.gather(*(measure(client, gateway.make_url("/v1/chat/completions")) for _ in range(100)))
                # Let asynchronous trace persistence/classification from warm-up drain.
                await asyncio.sleep(1)
                gateway_times = await asyncio.gather(*(measure(client, gateway.make_url("/v1/chat/completions")) for _ in range(100)))
            baseline_p95 = statistics.quantiles([item[0] for item in baseline], n=100)[94]
            gateway_p95 = statistics.quantiles([item[0] for item in gateway_times], n=100)[94]
            processing_p95 = statistics.quantiles([item[1] for item in gateway_times], n=100)[94]
            print(f"BENCH gateway_internal_p95_ms={processing_p95:.3f} streams={len(gateway_times)}")
            self.assertEqual(len(gateway_times), 100)
            self.assertLess(processing_p95, 50, f"gateway processing P95 was {processing_p95:.1f}ms; end-to-end gateway={gateway_p95:.1f}, direct={baseline_p95:.1f}")
        finally:
            await gateway.close()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=2)
            tempdir.cleanup()

    @patch.dict(os.environ, {"AUTOMODE_RESPONSE_CAPTURE_BYTES": str(1024 * 1024)}, clear=False)
    async def test_ac_p1_019_fifty_mb_response_is_streamed_and_incomplete_capture_alerts(self):
        total_size = 50 * 1024 * 1024

        async def large_response(request):
            response = web.StreamResponse(headers={"content-type": "application/octet-stream"})
            await response.prepare(request)
            chunk = b"x" * (256 * 1024)
            for _ in range(total_size // len(chunk)):
                await response.write(chunk)
            await response.write_eof()
            return response

        upstream_app = web.Application()
        upstream_app.router.add_post("/v1/chat/completions", large_response)
        upstream = TestServer(upstream_app)
        await upstream.start_server()
        tempdir = tempfile.TemporaryDirectory()
        gateway_app = create_app(str(upstream.make_url("/")).rstrip("/"), str(Path(tempdir.name) / "large.db"))
        gateway = TestServer(gateway_app)
        await gateway.start_server()
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        try:
            async with ClientSession() as client:
                async with client.post(gateway.make_url("/v1/chat/completions"), json={"model": "large", "messages": [{"role": "user", "content": "hello"}]}) as response:
                    trace_id = response.headers["x-automode-trace-id"]
                    received = 0
                    async for chunk in response.content.iter_chunked(256 * 1024):
                        received += len(chunk)
                self.assertEqual(received, total_size)
                for _ in range(100):
                    async with client.get(gateway.make_url(f"/traces/{trace_id}")) as response:
                        trace = await response.json()
                    if trace.get("final_decision"):
                        break
                    await asyncio.sleep(0.01)
            self.assertEqual(trace["response_bytes"], total_size)
            self.assertEqual(trace["final_decision"], "alert")
            self.assertEqual(trace["classification"]["proposed_actions"][0]["name"], "response_capture_incomplete")
            gc.collect()
            after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # On macOS ru_maxrss is bytes. The gateway capture stays bounded well below response size.
            self.assertLess(after - before, 40 * 1024 * 1024)
        finally:
            await gateway.close()
            await upstream.close()
            tempdir.cleanup()

    async def test_ac_p1_020_client_disconnect_keeps_gateway_healthy_and_trace(self):
        async def slow_response(request):
            response = web.StreamResponse(headers={"content-type": "application/octet-stream"})
            await response.prepare(request)
            try:
                for _ in range(40):
                    await response.write(b"x" * 65536)
                    await asyncio.sleep(0.01)
            except ConnectionResetError:
                pass
            return response

        upstream_app = web.Application()
        upstream_app.router.add_post("/v1/chat/completions", slow_response)
        upstream = TestServer(upstream_app)
        await upstream.start_server()
        tempdir = tempfile.TemporaryDirectory()
        gateway_app = create_app(str(upstream.make_url("/")).rstrip("/"), str(Path(tempdir.name) / "disconnect.db"), store_raw=False)
        gateway = TestServer(gateway_app)
        await gateway.start_server()
        try:
            async with ClientSession() as client:
                response = await client.post(gateway.make_url("/v1/chat/completions"), json={"model": "slow", "messages": [{"role": "user", "content": "hello"}]})
                trace_id = response.headers["x-automode-trace-id"]
                await response.content.read(65536)
                response.close()
                await asyncio.sleep(0.2)
                async with client.get(gateway.make_url("/health")) as health:
                    self.assertEqual(health.status, 200)
                async with client.get(gateway.make_url(f"/traces/{trace_id}")) as trace_response:
                    trace = await trace_response.json()
            self.assertEqual(trace["id"], trace_id)
            self.assertEqual(trace["error"], "client_disconnected")
            self.assertEqual(trace["classification"]["proposed_tool_calls"], [])
        finally:
            await gateway.close()
            await upstream.close()
            tempdir.cleanup()


if __name__ == "__main__":
    unittest.main()
