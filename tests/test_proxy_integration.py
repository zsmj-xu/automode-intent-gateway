import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, web
from aiohttp.test_utils import TestServer

from automode_gateway.gateway import GATEWAY_KEY, create_app


class ProxyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.received = []

        async def upstream_handler(request: web.Request) -> web.StreamResponse:
            body = await request.read()
            self.received.append(
                {
                    "path": request.path,
                    "body": body,
                    "authorization": request.headers.get("authorization"),
                    "trace_id": request.headers.get("x-automode-trace-id"),
                }
            )
            payload = json.loads(body)
            if payload.get("model") == "upstream-error":
                return web.json_response({"error": "upstream unavailable"}, status=503)
            if str(payload.get("model", "")).startswith("upstream-status-"):
                status = int(payload["model"].rsplit("-", 1)[-1])
                return web.json_response({"error": f"status {status}"}, status=status)
            if payload.get("model") == "upstream-timeout":
                await asyncio.sleep(0.2)
                return web.json_response({"ok": True})
            if payload.get("model") == "claude-tool-test":
                return web.json_response(
                    {
                        "id": "msg-1",
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {"type": "thinking", "thinking": "This must not be reviewed"},
                            {"type": "text", "text": "I will do it"},
                            {
                                "type": "tool_use",
                                "id": "tool-1",
                                "name": "Bash",
                                "input": {"command": "git push origin main"},
                            },
                        ],
                    }
                )
            if payload.get("model") == "multi-tool-test":
                return web.json_response({
                    "id": "chatcmpl-multi", "choices": [{"message": {"role": "assistant", "tool_calls": [
                        {"id": "call-1", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"README.md\"}"}},
                        {"id": "call-2", "type": "function", "function": {"name": "write_file", "arguments": "{\"path\":\"report.md\"}"}},
                        {"id": "call-3", "type": "function", "function": {"name": "git_push", "arguments": "{\"remote\":\"origin\"}"}},
                    ]}}],
                })
            if payload.get("stream"):
                response = web.StreamResponse(headers={"content-type": "text/event-stream"})
                await response.prepare(request)
                await response.write(b"data: first\n\n")
                await response.write(b"data: [DONE]\n\n")
                await response.write_eof()
                return response
            return web.json_response({"ok": True, "path": request.path})

        upstream_app = web.Application()
        for path in ("/v1/messages", "/v1/chat/completions", "/v1/responses"):
            upstream_app.router.add_post(path, upstream_handler)
        self.upstream = TestServer(upstream_app)
        await self.upstream.start_server()

        gateway_app = create_app(
            upstream=str(self.upstream.make_url("/")).rstrip("/"),
            db_path=str(Path(self.tempdir.name) / "traces.db"),
            store_raw=True,
        )
        self.gateway = TestServer(gateway_app)
        await self.gateway.start_server()
        self.client = ClientSession()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.gateway.close()
        await self.upstream.close()
        self.tempdir.cleanup()

    async def test_all_protocols_are_forwarded_without_body_conversion(self) -> None:
        cases = [
            ("/v1/messages", {"model": "claude-test", "messages": [{"role": "user", "content": "hello"}]}),
            (
                "/v1/chat/completions",
                {"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}], "stream": True},
            ),
            ("/v1/responses", {"model": "gpt-test", "input": "hello"}),
        ]
        for path, payload in cases:
            original = json.dumps(payload, separators=(",", ":")).encode()
            async with self.client.post(
                self.gateway.make_url(path),
                data=original,
                headers={
                    "content-type": "application/json",
                    "authorization": "Bearer client-token",
                    "x-session-id": "session-test",
                },
            ) as response:
                response_body = await response.read()
                self.assertEqual(response.status, 200)
                self.assertTrue(response.headers.get("x-automode-trace-id"))
                if payload.get("stream"):
                    self.assertEqual(response_body, b"data: first\n\ndata: [DONE]\n\n")

            received = self.received[-1]
            self.assertEqual(received["path"], path)
            self.assertEqual(received["body"], original)
            self.assertEqual(received["authorization"], "Bearer client-token")
            self.assertTrue(received["trace_id"])

        await asyncio.sleep(0.05)
        async with self.client.get(self.gateway.make_url("/traces?limit=10")) as response:
            traces = (await response.json())["data"]
        self.assertEqual(len(traces), 3)
        self.assertEqual({item["protocol"] for item in traces}, {
            "anthropic_messages",
            "openai_chat_completions",
            "openai_responses",
        })
        self.assertTrue(all(item["decision"] == "allow" for item in traces))
        self.assertTrue(all(item["session_id"] == "session-test" for item in traces))

    async def test_response_tool_call_overwrites_trace_with_alignment_decision(self) -> None:
        payload = {
            "model": "claude-tool-test",
            "messages": [{"role": "user", "content": "检查代码，但不要 push。"}],
        }
        async with self.client.post(
            self.gateway.make_url("/v1/messages"),
            json=payload,
            headers={"x-session-id": "alignment-session"},
        ) as response:
            await response.read()
            trace_id = response.headers["x-automode-trace-id"]

        for _ in range(20):
            async with self.client.get(self.gateway.make_url(f"/traces/{trace_id}")) as response:
                trace = await response.json()
            if trace["classification"]["proposed_tool_calls"]:
                break
            await asyncio.sleep(0.01)

        classification = trace["classification"]
        self.assertEqual(classification["decision"], "deny")
        self.assertEqual(classification["action_alignment"], "contradicted")
        self.assertEqual(classification["proposed_tool_calls"][0]["name"], "Bash")
        serialized = json.dumps(classification, ensure_ascii=False)
        self.assertNotIn("This must not be reviewed", serialized)
        self.assertNotIn("I will do it", serialized)

    async def test_ac_p0_017_upstream_error_is_preserved_and_traced(self) -> None:
        payload = {"model": "upstream-error", "messages": [{"role": "user", "content": "hello"}]}
        async with self.client.post(self.gateway.make_url("/v1/chat/completions"), json=payload) as response:
            trace_id = response.headers["x-automode-trace-id"]
            body = await response.json()
        self.assertEqual(response.status, 503)
        self.assertEqual(body["error"], "upstream unavailable")
        for _ in range(50):
            async with self.client.get(self.gateway.make_url(f"/traces/{trace_id}")) as response:
                trace = await response.json()
            if trace["response_status"] is not None:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(trace["response_status"], 503)
        self.assertGreater(trace["latency_ms"], 0)
        self.assertGreater(trace["response_bytes"], 0)

    async def test_ac_p0_017_preserves_400_401_429_500_and_traces_timeout(self) -> None:
        for status in (400, 401, 429, 500):
            payload = {"model": f"upstream-status-{status}", "messages": [{"role": "user", "content": "hello"}]}
            async with self.client.post(self.gateway.make_url("/v1/chat/completions"), json=payload) as response:
                trace_id = response.headers["x-automode-trace-id"]
                self.assertEqual(response.status, status)
                self.assertEqual((await response.json())["error"], f"status {status}")
            for _ in range(50):
                async with self.client.get(self.gateway.make_url(f"/traces/{trace_id}")) as response:
                    trace = await response.json()
                if trace["response_status"] is not None:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(trace["response_status"], status)
            self.assertEqual(trace["classification"]["proposed_tool_calls"], [])

        gateway = self.gateway.app[GATEWAY_KEY]
        assert gateway.client is not None
        original_timeout = gateway.client._timeout
        gateway.client._timeout = ClientTimeout(total=0.03)
        try:
            async with self.client.post(self.gateway.make_url("/v1/chat/completions"), json={"model": "upstream-timeout", "messages": [{"role": "user", "content": "hello"}]}) as response:
                self.assertEqual(response.status, 502)
        finally:
            gateway.client._timeout = original_timeout
        await asyncio.sleep(0.05)
        async with self.client.get(self.gateway.make_url("/traces?limit=1")) as response:
            timeout_trace = (await response.json())["data"][0]
        self.assertEqual(timeout_trace["error"], "TimeoutError")
        self.assertEqual(timeout_trace["classification"]["proposed_tool_calls"], [])

    async def test_agent_compatible_multi_tool_session_is_observed(self) -> None:
        payload = {
            "model": "multi-tool-test",
            "messages": [{"role": "user", "content": "检查并写报告，但不要 push。"}],
            "tools": [{"type": "function", "function": {"name": "git_push"}}],
        }
        async with self.client.post(
            self.gateway.make_url("/v1/chat/completions"), json=payload,
            headers={"x-session-id": "agent-multi-tool"},
        ) as response:
            self.assertEqual(response.status, 200)
            trace_id = response.headers["x-automode-trace-id"]
            await response.read()
        for _ in range(100):
            async with self.client.get(self.gateway.make_url(f"/traces/{trace_id}")) as response:
                trace = await response.json()
            if len(trace["classification"].get("proposed_actions", [])) == 3:
                break
            await asyncio.sleep(0.01)
        classification = trace["classification"]
        self.assertEqual(len(classification["proposed_actions"]), 3)
        self.assertEqual(classification["decision"], "deny")
        self.assertEqual(classification["action_alignment"], "contradicted")
        self.assertNotEqual(trace["declared_tool_count"], len(classification["proposed_actions"]))

    async def test_conversation_fingerprint_groups_requests_without_session_header(self) -> None:
        opener = {"model": "fp-test", "messages": [{"role": "user", "content": "帮我重构这个模块"}]}
        continued = {"model": "fp-test", "messages": [
            {"role": "user", "content": "帮我重构这个模块"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Edit", "input": {"file_path": "a.py"}}]},
            {"role": "user", "content": "继续"},
        ]}
        for payload in (opener, continued):
            async with self.client.post(
                self.gateway.make_url("/v1/chat/completions"), json=payload,
            ) as response:
                self.assertEqual(response.status, 200)
                await response.read()
        await asyncio.sleep(0.05)
        async with self.client.get(self.gateway.make_url("/api/sessions")) as response:
            sessions = (await response.json())["data"]
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["call_count"], 2)
        self.assertIn("write", sessions[0]["authorization"]["capabilities"])
        self.assertEqual(sessions[0]["external_session_id"], None)

    async def test_conversation_fingerprint_splits_different_openers(self) -> None:
        for content in ("帮我重构这个模块", "写一个部署脚本"):
            payload = {"model": "fp-test", "messages": [{"role": "user", "content": content}]}
            async with self.client.post(
                self.gateway.make_url("/v1/chat/completions"), json=payload,
            ) as response:
                self.assertEqual(response.status, 200)
                await response.read()
        await asyncio.sleep(0.05)
        async with self.client.get(self.gateway.make_url("/api/sessions")) as response:
            sessions = (await response.json())["data"]
        self.assertEqual(len(sessions), 2)


if __name__ == "__main__":
    unittest.main()
