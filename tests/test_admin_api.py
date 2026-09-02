import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from automode_gateway.events import EVENT_BROKER_KEY
from automode_gateway.evidence import generate_key
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

    async def test_dlp_destination_policy_compile_test_and_version_routes(self):
        async with self.client.post(self.server.make_url("/api/destinations"), json={
            "name": "Internal Models", "upstream_pattern": "*", "model_pattern": "corp-*", "trust": "trusted", "provider": "internal", "region": "cn",
        }) as response:
            self.assertEqual(response.status, 201)
            target = await response.json()
        async with self.client.get(self.server.make_url("/api/destinations")) as response:
            self.assertEqual((await response.json())["data"][0]["id"], target["id"])

        async with self.client.post(self.server.make_url("/api/dlp-policies/compile"), json={"text": "凭据发往外部模型时告警"}) as response:
            preview = await response.json()
        self.assertTrue(preview["valid"])
        async with self.client.post(self.server.make_url("/api/dlp-policies"), json={"compiled": preview["compiled"], "enabled": True}) as response:
            self.assertEqual(response.status, 201)
            policy = await response.json()
        async with self.client.post(self.server.make_url("/api/dlp-policies/test"), json={
            "payload": {"model": "external-model", "messages": [{"role": "user", "content": "password=hunter2"}]}
        }) as response:
            result = await response.json()
        self.assertEqual(result["policy_decision"], "alert")
        self.assertEqual(result["data_findings"][0]["category"], "credential")
        async with self.client.get(self.server.make_url(f"/api/dlp-policies/{policy['id']}/versions")) as response:
            self.assertEqual(len((await response.json())["data"]), 1)
        async with self.client.post(self.server.make_url(f"/api/dlp-policies/{policy['id']}/disable"), json={}) as response:
            self.assertFalse((await response.json())["enabled"])
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
        self.assertEqual(rules_only["final_decision"], "allow")
        self.assertEqual(rules_only["review_object"], "outbound_request")
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
            "review_object": "tool_action",
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

    async def test_session_intent_risk_excludes_dlp_severity(self):
        store = self.app[TRACE_STORE_KEY]
        trace_id = store.create(
            protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
            payload={"model": "m", "messages": [{"role": "user", "content": "password=hunter2"}]},
            headers={}, session_id="dlp-only-risk", latest_user_text="password=hunter2", declared_tool_count=1,
        )
        dlp_result = {
            "final_decision": "alert", "final_stage": "rules", "risk": "critical",
            "review_object": "outbound_request", "action_alignment": "normal",
            "reason_code": "SENSITIVE_DATA_TO_EXTERNAL", "reason": "Sensitive outbound data.",
            "authorization_evidence": [], "proposed_actions": [{"name": "read_file", "arguments": {}, "capability": "read", "target": "docs", "side_effect": "none", "risk": "low"}],
            "matched_rules": ["builtin-sensitive-external"], "review_transcript": [], "total_latency_ms": 1,
            "data_findings": [{"category": "credential", "path": "$.messages[0].content", "confidence": "high", "fingerprint": "x", "snippet": "[REDACTED:CREDENTIAL]", "detector": "secret_assignment"}],
            "destination": {"trust": "external"}, "policy_decision": "alert",
            "stages": [{"stage": "rules", "status": "completed", "verdict": "ALWAYS_ALERT", "risk": "critical", "reason_code": "SENSITIVE_DATA_TO_EXTERNAL", "reason": "Sensitive outbound data.", "latency_ms": 1, "action_alignment": "normal", "matched_rule_ids": [], "matched_rule_versions": []}],
        }
        store.save_pipeline(trace_id, dlp_result)
        session = next(item for item in store.sessions() if item["external_session_id"] == "dlp-only-risk")
        self.assertEqual(session["max_risk"], "critical")
        self.assertEqual(session["intent_risk"], "low")
        self.assertFalse(session["has_intent_alert"])

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

    async def test_prompts_crud_and_reset(self):
        async with self.client.get(self.server.make_url("/api/prompts")) as response:
            self.assertEqual(response.status, 200)
            data = await response.json()
            self.assertIn("outbound_dlp", data["data"])
            self.assertIn("outbound_dlp", data["defaults"])

        new_prompt = "Custom DLP prompt for testing"
        async with self.client.patch(self.server.make_url("/api/prompts"), json={"prompts": {"outbound_dlp": new_prompt}}) as response:
            self.assertEqual(response.status, 200)
            data = await response.json()
            self.assertEqual(data["data"]["outbound_dlp"], new_prompt)

        async with self.client.post(self.server.make_url("/api/prompts/reset"), json={"name": "outbound_dlp"}) as response:
            self.assertEqual(response.status, 200)
            data = await response.json()
            self.assertEqual(data["data"]["outbound_dlp"], data["defaults"]["outbound_dlp"])

    async def test_detectors_crud_and_toggle(self):
        async with self.client.get(self.server.make_url("/api/detectors")) as response:
            self.assertEqual(response.status, 200)
            data = await response.json()
            self.assertTrue(len(data["data"]) > 0)
            pk = next(d for d in data["data"] if d["id"] == "private_key")
            self.assertTrue(pk["enabled"])

        async with self.client.patch(self.server.make_url("/api/detectors/private_key"), json={"enabled": False}) as response:
            self.assertEqual(response.status, 200)
            data = await response.json()
            self.assertFalse(data["data"]["enabled"])

        async with self.client.patch(self.server.make_url("/api/detectors/private_key"), json={"enabled": True}) as response:
            self.assertEqual(response.status, 200)
            data = await response.json()
            self.assertTrue(data["data"]["enabled"])

        # Create custom detector
        custom_payload = {
            "name": "内部员工工号",
            "category": "credential",
            "description": "检测 HT- 开头的工号",
            "pattern": r"\bHT-\d{6}\b",
        }
        async with self.client.post(self.server.make_url("/api/detectors"), json=custom_payload) as response:
            self.assertEqual(response.status, 201)
            created = await response.json()
            self.assertEqual(created["data"]["name"], "内部员工工号")
            self.assertTrue(created["data"]["custom"])
            det_id = created["data"]["id"]

        # Toggle custom detector
        async with self.client.patch(self.server.make_url(f"/api/detectors/{det_id}"), json={"enabled": False}) as response:
            self.assertEqual(response.status, 200)
            data = await response.json()
            self.assertFalse(data["data"]["enabled"])

        # Delete custom detector
        async with self.client.delete(self.server.make_url(f"/api/detectors/{det_id}")) as response:
            self.assertEqual(response.status, 200)
            data = await response.json()
            self.assertTrue(data["deleted"])


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

    async def test_raw_evidence_requires_admin_token_and_loopback_and_is_audited(self):
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "evidence.key"
            key_path.write_text(generate_key(), encoding="ascii")
            os.chmod(key_path, 0o600)
            os.environ["AUTOMODE_EVIDENCE_KEY_FILE"] = str(key_path)
            try:
                app = create_app("http://127.0.0.1:9", str(Path(directory) / "evidence.db"), bind_host="127.0.0.1", admin_token="admin-secret")
                store = app[TRACE_STORE_KEY]
                payload = {"model": "m", "messages": [{"role": "user", "content": "password=hunter2"}]}
                trace_id = store.create(protocol="openai_chat_completions", method="POST", path="/v1/chat/completions", payload=payload, headers={}, session_id=None, latest_user_text="password=hunter2", declared_tool_count=0)
                from automode_gateway.dlp import scan_payload
                evidence_id = store.store_evidence(trace_id, payload, scan_payload(payload), {"trust": "external"})
                server = TestServer(app)
                await server.start_server()
                async with ClientSession() as client:
                    async with client.get(server.make_url(f"/api/evidence/{evidence_id}/raw")) as response:
                        self.assertEqual(response.status, 401)
                    async with client.get(server.make_url(f"/api/evidence/{evidence_id}/raw"), headers={"x-automode-admin-token": "admin-secret"}) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual((await response.json())["payload"], payload)
                await server.close()
            finally:
                os.environ.pop("AUTOMODE_EVIDENCE_KEY_FILE", None)


if __name__ == "__main__":
    unittest.main()
