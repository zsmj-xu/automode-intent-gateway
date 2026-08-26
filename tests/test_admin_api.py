import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from automode_gateway.events import EVENT_BROKER_KEY
from automode_gateway.gateway import TRACE_STORE_KEY, create_app


class AdminApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        upstream_app = web.Application()
        self.upstream = TestServer(upstream_app)
        await self.upstream.start_server()
        self.app = create_app(str(self.upstream.make_url("/")).rstrip("/"), str(Path(self.tempdir.name) / "api.db"))
        self.server = TestServer(self.app)
        await self.server.start_server()
        self.client = ClientSession()

    async def asyncTearDown(self):
        await self.client.close()
        await self.server.close()
        await self.upstream.close()
        self.tempdir.cleanup()
        os.environ.pop("AUTOMODE_FAST_API_KEY", None)
        os.environ.pop("AUTOMODE_FAST_MODEL", None)

    async def test_rule_compile_confirm_test_enable_and_version_routes(self):
        async with self.client.post(self.server.make_url("/api/rules/compile"), json={"text": "用户明确说不要 push 时，任何 git push 都告警。"}) as response:
            self.assertEqual(response.status, 200)
            preview = await response.json()
        self.assertTrue(preview["requires_confirmation"])

        async with self.client.post(self.server.make_url("/api/rules"), json={"compiled": preview["compiled"]}) as response:
            self.assertEqual(response.status, 422)
        async with self.client.post(self.server.make_url("/api/rules"), json={"compiled": preview["compiled"], "confirmed": True}) as response:
            self.assertEqual(response.status, 201)
            rule = await response.json()
        self.assertFalse(rule["enabled"])

        test_input = {
            "rule": preview["compiled"], "user_message": "检查，但不要 push",
            "proposed_tool_calls": [{"name": "Bash", "arguments": {"command": "git push origin main"}}],
        }
        async with self.client.post(self.server.make_url("/api/rules/test"), json=test_input) as response:
            result = await response.json()
        self.assertTrue(result["matched"])
        self.assertFalse(result["executed_tools"])
        self.assertFalse(result["forwarded_to_agent"])

        async with self.client.post(self.server.make_url(f"/api/rules/{rule['id']}/enable"), json={}) as response:
            enabled = await response.json()
        self.assertTrue(enabled["enabled"])
        async with self.client.get(self.server.make_url(f"/api/rules/{rule['id']}/versions")) as response:
            versions = (await response.json())["data"]
        self.assertEqual(versions[0]["version"], 1)
        changed = {**preview["compiled"], "reason": "更新后的规则原因"}
        async with self.client.patch(self.server.make_url(f"/api/rules/{rule['id']}"), json={"compiled": changed, "confirmed": True}) as response:
            self.assertEqual(response.status, 200)
            updated = await response.json()
        self.assertEqual(updated["version"], 2)
        async with self.client.get(self.server.make_url(f"/api/rules/{rule['id']}")) as response:
            self.assertEqual((await response.json())["reason"], "更新后的规则原因")
        async with self.client.post(self.server.make_url(f"/api/rules/{rule['id']}/rollback"), json={"version": 1}) as response:
            rolled = await response.json()
        self.assertEqual(rolled["version"], 3)
        async with self.client.post(self.server.make_url(f"/api/rules/{rule['id']}/disable"), json={}) as response:
            self.assertFalse((await response.json())["enabled"])
        async with self.client.delete(self.server.make_url(f"/api/rules/{rule['id']}")) as response:
            self.assertEqual(response.status, 204)
        async with self.client.get(self.server.make_url("/api/rules")) as response:
            self.assertEqual(len((await response.json())["data"]), 1)

        async with self.client.post(self.server.make_url("/api/rules/compile"), json={"text": "模糊处理一下"}) as response:
            self.assertEqual(response.status, 422)
            self.assertEqual((await response.json())["errors"][0]["field"], "conditions")

    async def test_playground_and_settings_never_return_credentials(self):
        body = {
            "protocol": "openai_chat_completions",
            "payload": {"model": "test", "messages": [{"role": "user", "content": "翻译 hello"}]},
            "proposed_tool_calls": [],
        }
        async with self.client.post(self.server.make_url("/api/playground/classify"), json=body) as response:
            self.assertEqual(response.status, 200)
            result = await response.json()
        self.assertEqual(result["final_decision"], "allow")
        self.assertEqual(result["final_stage"], "rules")
        body["stage"] = "rules"
        body["temporary_rule"] = {
            "name": "temporary", "original_text": "发布告警", "scope": {"protocols": ["*"], "models": [], "tools": []},
            "conditions": {"capabilities": ["publish"]}, "effect": "always_alert", "priority": 100,
            "reason_code": "TEMP_PUBLISH", "reason": "临时测试规则",
        }
        body["proposed_tool_calls"] = [{"name": "git_push", "arguments": {}}]
        async with self.client.post(self.server.make_url("/api/playground/classify"), json=body) as response:
            rules_only = await response.json()
        self.assertEqual(rules_only["final_decision"], "alert")
        self.assertEqual(len(rules_only["stages"]), 1)
        async with self.client.get(self.server.make_url("/api/settings")) as response:
            value = await response.json()
        self.assertFalse(any(key.endswith("api_key") for key in value))
        self.assertNotIn("authorization", json.dumps(value).lower())
        secret = "sk-runtime-only-secret"
        async with self.client.patch(self.server.make_url("/api/settings"), json={"fast_api_key": secret}) as response:
            updated = await response.json()
        self.assertNotIn(secret, json.dumps(updated))
        self.assertEqual(updated["fast_api_key_masked"], "••••cret")
        self.assertNotIn(secret.encode(), (Path(self.tempdir.name) / "api.db").read_bytes())
        async with self.client.patch(self.server.make_url("/api/settings"), json={"operating_mode": "observe", "retention_days": 14, "fast_model": "fast-runtime"}) as response:
            configured = await response.json()
        self.assertEqual(configured["retention_days"], 14)
        self.assertEqual(configured["fast_model"], "fast-runtime")
        self.assertIn("fast_url", configured)
        async with self.client.patch(self.server.make_url("/api/settings"), json={"fast_model": "bad-model”"}) as response:
            self.assertEqual(response.status, 400)
        for stage in ("fast", "deep"):
            async with self.client.post(self.server.make_url(f"/api/settings/test-{stage}-model"), json={}) as response:
                self.assertEqual(response.status, 503)

    async def test_alert_lifecycle_dashboard_session_timeline_and_sse(self):
        store = self.app[TRACE_STORE_KEY]
        trace_id = store.create(
            protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
            payload={"model": "m", "messages": [{"role": "user", "content": "不要 push"}]},
            headers={}, session_id="session-api", latest_user_text="不要 push", declared_tool_count=1,
        )
        result = {
            "final_decision": "alert", "final_stage": "deep_llm", "risk": "high",
            "action_alignment": "contradicted", "reason_code": "USER_CONSTRAINT", "reason": "用户明确禁止 push",
            "authorization_evidence": ["不要 push"],
            "proposed_actions": [{"name": "Bash", "arguments": {"command": "git push"}, "capability": "publish", "target": "git push", "side_effect": "external_state_change", "risk": "high"}],
            "matched_rules": ["rule:1"], "review_transcript": [{"type": "user", "text": "不要 push"}],
            "total_latency_ms": 3,
            "stages": [
                {"stage": "rules", "status": "completed", "verdict": "RISKY", "risk": "high", "reason_code": "USER_CONSTRAINT", "reason": "constraint", "latency_ms": 1, "action_alignment": "contradicted", "matched_rule_ids": [], "matched_rule_versions": []},
                {"stage": "fast_llm", "status": "completed", "verdict": "reject", "risk": "high", "reason_code": "FAST_REJECT", "reason": "reject", "latency_ms": 1, "action_alignment": "contradicted", "matched_rule_ids": [], "matched_rule_versions": []},
                {"stage": "deep_llm", "status": "completed", "verdict": "reject", "risk": "high", "reason_code": "USER_CONSTRAINT", "reason": "reject", "latency_ms": 1, "action_alignment": "contradicted", "matched_rule_ids": [], "matched_rule_versions": []},
            ],
        }
        _, alert_id = store.save_pipeline(trace_id, result)
        self.assertIsNotNone(alert_id)

        async with self.client.get(self.server.make_url("/api/dashboard")) as response:
            dashboard = await response.json()
        self.assertEqual(dashboard["open_alert_count"], 1)
        self.assertEqual(set(dashboard["health"]), {"gateway", "upstream", "fast", "deep"})
        self.assertIn("p95", dashboard["classification_latency_ms"])
        async with self.client.get(self.server.make_url("/api/sessions")) as response:
            session = (await response.json())["data"][0]
        self.assertEqual(session["external_session_id"], "session-api")
        self.assertEqual(session["alert_count"], 1)
        async with self.client.get(self.server.make_url("/api/sessions?protocol=openai_chat_completions&model=m&risk=high&decision=alert&capability=publish")) as response:
            self.assertEqual(len((await response.json())["data"]), 1)
        async with self.client.get(self.server.make_url("/api/sessions?protocol=anthropic_messages")) as response:
            self.assertEqual((await response.json())["data"], [])
        async with self.client.get(self.server.make_url(f"/api/sessions/{session['id']}/timeline")) as response:
            timeline = (await response.json())["data"]
        types = [item["type"] for item in timeline]
        self.assertEqual(types[:3], ["user_message", "model_call", "tool_action"])
        self.assertEqual([item["stage"] for item in timeline if item["type"] == "classification_stage"], ["rules", "fast_llm", "deep_llm"])
        deep = [item for item in timeline if item.get("stage") == "deep_llm"][0]
        self.assertEqual(deep["reason_code"], "USER_CONSTRAINT")
        self.assertEqual(deep["latency_ms"], 1)
        async with self.client.get(self.server.make_url(f"/api/sessions/{session['id']}/detail")) as response:
            detail = await response.json()
        self.assertEqual(detail["session"]["external_session_id"], "session-api")
        self.assertEqual(len(detail["traces"]), 1)
        trace_detail = detail["traces"][0]
        self.assertEqual(trace_detail["trace_id"], trace_id)
        self.assertEqual(trace_detail["latest_user_text"], "不要 push")
        self.assertEqual(trace_detail["tool_actions"][0]["tool_name"], "Bash")
        self.assertEqual(trace_detail["tool_actions"][0]["arguments"], {"command": "git push"})
        self.assertEqual(trace_detail["classification"]["final_decision"], "alert")
        self.assertEqual(trace_detail["classification"]["action_alignment"], "contradicted")
        self.assertEqual(trace_detail["classification"]["review_transcript"], [{"type": "user", "text": "不要 push"}])
        self.assertEqual(len(trace_detail["alerts"]), 1)
        self.assertEqual(trace_detail["alerts"][0]["reason_code"], "USER_CONSTRAINT")
        async with self.client.get(self.server.make_url(f"/api/sessions/{session['id']}")) as response:
            self.assertEqual((await response.json())["external_session_id"], "session-api")
        async with self.client.get(self.server.make_url(f"/api/traces/{trace_id}/classification")) as response:
            classification = await response.json()
        self.assertEqual(classification["final_decision"], "alert")
        self.assertEqual(len(classification["stages"]), 3)
        async with self.client.get(self.server.make_url(f"/api/alerts/{alert_id}")) as response:
            self.assertEqual((await response.json())["reason_code"], "USER_CONSTRAINT")

        async with self.client.patch(self.server.make_url(f"/api/alerts/{alert_id}"), json={"status": "acknowledged", "operator_note": "reviewed"}) as response:
            updated = await response.json()
        self.assertEqual(updated["status"], "acknowledged")
        self.assertEqual(updated["operator_note"], "reviewed")
        async with self.client.post(self.server.make_url(f"/api/alerts/{alert_id}/feedback"), json={"feedback": "false_positive", "operator_note": "benchmark"}) as response:
            feedback = await response.json()
        self.assertEqual(feedback["status"], "false_positive")
        async with self.client.post(self.server.make_url(f"/api/playground/replay/{trace_id}"), json={}) as response:
            replayed = await response.json()
        self.assertEqual(replayed["replay_of"], trace_id)

        async with self.client.get(self.server.make_url("/api/events")) as stream:
            first = await asyncio.wait_for(stream.content.readline(), 1)
            self.assertEqual(first, b": connected\n")
            self.app[EVENT_BROKER_KEY].publish("alert.created", {"id": "live-alert"})
            lines = [await asyncio.wait_for(stream.content.readline(), 1) for _ in range(3)]
            self.assertTrue(any(line.startswith(b"event: alert.created") for line in lines))

    async def test_built_console_is_served(self):
        async with self.client.get(self.server.make_url("/")) as response:
            text = await response.text()
        self.assertEqual(response.status, 200)
        self.assertIn("AutoMode Intent Console", text)

    async def test_console_directory_can_be_overridden_by_env(self):
        # Wheel installs live under site-packages, so __file__-relative dist
        # resolution fails; AUTOMODE_WEB_DIST must override the static root.
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / "index.html"
            index.write_text("<title>Custom Console</title>", encoding="utf-8")
            os.environ["AUTOMODE_WEB_DIST"] = directory
            try:
                app = create_app(str(self.upstream.make_url("/")).rstrip("/"), str(Path(self.tempdir.name) / "override.db"))
                server = TestServer(app)
                await server.start_server()
                try:
                    async with ClientSession() as client:
                        async with client.get(server.make_url("/")) as response:
                            text = await response.text()
                finally:
                    await server.close()
            finally:
                os.environ.pop("AUTOMODE_WEB_DIST", None)
        self.assertEqual(response.status, 200)
        self.assertIn("Custom Console", text)


class AdminAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_non_loopback_binding_requires_and_enforces_token(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                create_app("http://127.0.0.1:9", str(Path(directory) / "no.db"), bind_host="0.0.0.0")
            app = create_app("http://127.0.0.1:9", str(Path(directory) / "yes.db"), bind_host="0.0.0.0", admin_token="admin-secret")
            server = TestServer(app)
            await server.start_server()
            async with ClientSession() as client:
                async with client.get(server.make_url("/api/settings")) as response:
                    self.assertEqual(response.status, 401)
                async with client.get(server.make_url("/api/settings"), headers={"x-automode-admin-token": "admin-secret"}) as response:
                    self.assertEqual(response.status, 200)
            await server.close()


if __name__ == "__main__":
    unittest.main()
