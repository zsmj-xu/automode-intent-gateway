import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from automode_gateway.rule_compiler import RuleCompileError, compile_preview, compile_rule
from automode_gateway.normalizer import normalize
from automode_gateway.policy import evaluate_rules
from automode_gateway.review_context import normalize_tool_call
from automode_gateway.storage import TRACE_COLUMNS, TraceStore, validate_rule


class RuleTests(unittest.TestCase):
    def test_ac_p0_018_compile_push_rule_to_restricted_schema(self):
        preview = compile_preview("用户明确说不要 push 时，任何 git push 都告警。")
        compiled = preview["compiled"]
        self.assertTrue(preview["valid"])
        self.assertEqual(compiled["effect"], "always_alert")
        self.assertIn("publish", compiled["conditions"]["capabilities"])
        self.assertRegex(compiled["reason_code"], r"^[A-Z][A-Z0-9_]+$")
        validate_rule(compiled)

    def test_ac_p0_023_illegal_rules_are_rejected(self):
        valid = compile_rule("所有生产部署都告警")
        cases = [
            {**valid, "unknown": True},
            {**valid, "effect": "execute_python"},
            {**valid, "reason_code": ""},
            {**valid, "scope": {**valid["scope"], "protocols": ["magic"]}},
            {**valid, "reason": "```python\nimport os\n```"},
        ]
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_rule(value)

    def test_unrecognized_natural_language_has_field_error(self):
        with self.assertRaises(RuleCompileError) as caught:
            compile_rule("如果觉得合适就处理一下")
        self.assertEqual(caught.exception.field, "conditions")

    def test_compiler_supports_external_data_fetch_alert_rule(self):
        preview = compile_preview("不信任任何外部数据，只要获取外部数据就告警")
        compiled = preview["compiled"]
        self.assertEqual(compiled["effect"], "always_alert")
        self.assertEqual(compiled["conditions"]["capabilities"], ["read"])
        self.assertIn("https://", compiled["conditions"]["target_contains"])
        request = normalize(
            {"model": "m", "messages": [{"role": "user", "content": "获取外部数据"}]},
            source_format_override="openai_chat_completions",
        )
        stage, _ = evaluate_rules(request, [{"name": "fetch_url", "arguments": {"url": "https://example.test/data"}}], [{**compiled, "id": "external", "version": 1}])
        self.assertEqual((stage.verdict, stage.matched_rule_ids), ("ALWAYS_ALERT", ["external"]))
        curl = normalize_tool_call(
            {"name": "Bash", "arguments": {"command": "curl https://example.test/data"}},
            source="response",
        )
        self.assertEqual((curl.capability, curl.target), ("read", "curl https://example.test/data"))

    def test_compiler_supports_safe_read_escalate_delete_and_size_errors(self):
        safe = compile_rule("所有查看操作都安全允许")
        self.assertEqual((safe["effect"], safe["conditions"]["capabilities"]), ("safe", ["read"]))
        escalate = compile_rule("删除资源时需要复核")
        self.assertEqual((escalate["effect"], escalate["conditions"]["capabilities"]), ("escalate", ["delete"]))
        with self.assertRaises(RuleCompileError) as caught:
            compile_rule("x" * 2001)
        self.assertEqual(caught.exception.field, "original_text")

    def test_policy_custom_safe_escalate_and_scope_filters(self):
        request = normalize({"model": "m", "messages": [{"role": "user", "content": "读取文件"}]}, source_format_override="openai_chat_completions")
        action = [{"name": "read_file", "arguments": {"path": "docs/readme.md"}}]
        base = {
            "id": "r", "version": 1, "name": "rule", "priority": 50,
            "scope": {"protocols": ["openai_chat_completions"], "models": ["m"], "tools": ["read_file"]},
            "conditions": {"capabilities": ["read"], "target_environment": [], "target_contains": ["docs/"]},
            "reason_code": "CUSTOM_READ", "reason": "custom",
        }
        stage, _ = evaluate_rules(request, action, [{**base, "effect": "safe"}])
        self.assertEqual((stage.verdict, stage.matched_rule_ids), ("SAFE", ["r"]))
        stage, _ = evaluate_rules(request, action, [{**base, "effect": "escalate"}])
        self.assertEqual(stage.verdict, "RISKY")
        mismatch = {**base, "effect": "always_alert", "scope": {**base["scope"], "models": ["other"]}}
        stage, _ = evaluate_rules(request, action, [mismatch])
        self.assertEqual(stage.verdict, "SAFE")

    def test_unknown_tool_has_unknown_stage_verdict(self):
        request = normalize({"model": "m", "messages": [{"role": "user", "content": "处理一下"}]})
        stage, _ = evaluate_rules(request, [{"name": "mystery", "arguments": {"value": 1}}])
        self.assertEqual(stage.verdict, "UNKNOWN")


class StorageLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "test.db"
        self.store = TraceStore(self.path)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_ac_p0_019_022_rule_confirmation_enable_versions_rollback(self):
        compiled = compile_rule("任何 git push 都告警")
        with self.assertRaises(ValueError):
            self.store.create_rule(compiled)
        first = self.store.create_rule(compiled, confirmed=True)
        self.assertFalse(first["enabled"])
        enabled = self.store.set_rule_enabled(first["id"], True)
        self.assertTrue(enabled["enabled"])
        changed = {**compiled, "reason": "updated reason"}
        second = self.store.update_rule(first["id"], changed, confirmed=True)
        self.assertEqual(second["version"], 2)
        versions = self.store.rule_versions(first["id"])
        self.assertEqual([row["version"] for row in versions], [2, 1])
        rolled = self.store.rollback_rule(first["id"], 1)
        self.assertEqual(rolled["version"], 3)
        with sqlite3.connect(self.path) as connection:
            actions = [row[0] for row in connection.execute("SELECT action FROM audit_log")]
        self.assertIn("rule.rolled_back", actions)

    def test_ac_p0_024_027_credentials_and_reasoning_never_persist(self):
        secret = "sk-test-ultra-secret-value"
        trace_id = self.store.create(
            protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
            payload={"model": "m", "api_key": secret, "messages": [{"role": "user", "content": "hello"}]},
            headers={"authorization": f"Bearer {secret}", "cookie": f"auth={secret}", "x-api-key": secret},
            session_id="security-session", latest_user_text="hello", declared_tool_count=0,
        )
        result = {
            "final_decision": "alert", "final_stage": "deep_llm", "risk": "high",
            "action_alignment": "ambiguous", "reason_code": "DEEP_REJECT", "reason": f"token={secret}",
            "authorization_evidence": ["hello"], "proposed_actions": [], "matched_rules": [],
            "review_transcript": [{"type": "user", "text": "hello"}], "total_latency_ms": 1,
            "stages": [{"stage": "deep_llm", "status": "completed", "model": "m", "input_hash": "h", "verdict": "reject", "risk": "high", "reason_code": "DEEP_REJECT", "reason": "rejected", "matched_rule_ids": [], "matched_rule_versions": [], "latency_ms": 1, "reasoning": "private chain", "thinking": "private"}],
        }
        self.store.save_pipeline(trace_id, result)
        raw = self.path.read_bytes()
        self.assertNotIn(secret.encode(), raw)
        self.assertNotIn(b"private chain", raw)
        self.assertNotIn(b'"thinking"', raw)

    @patch.dict(os.environ, {"AUTOMODE_FAST_API_KEY": "sk-do-not-return-this", "AUTOMODE_FAST_MODEL": "fast-test"}, clear=False)
    def test_ac_p0_025_settings_only_return_masked_key(self):
        value = self.store.settings()
        serialized = json.dumps(value)
        self.assertNotIn("sk-do-not-return-this", serialized)
        self.assertTrue(value["fast_api_key_configured"])
        self.assertEqual(value["fast_api_key_masked"], "••••this")

    def test_ac_p1_017_migrates_legacy_trace_table(self):
        legacy = Path(self.tempdir.name) / "legacy.db"
        with sqlite3.connect(legacy) as connection:
            connection.execute("CREATE TABLE traces (id TEXT PRIMARY KEY, created_at TEXT, protocol TEXT, method TEXT, path TEXT, model TEXT, session_id TEXT, is_stream INTEGER, latest_user_text TEXT, declared_tool_count INTEGER, request_headers_json TEXT, request_body_json TEXT, response_status INTEGER, response_bytes INTEGER, latency_ms REAL, intent TEXT, speech_act TEXT, risk TEXT, decision TEXT, classification_json TEXT, error TEXT)")
            connection.execute("INSERT INTO traces VALUES ('old','now','p','POST','/','m',NULL,0,'',0,'{}',NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL)")
        migrated = TraceStore(legacy)
        self.assertEqual(migrated.get("old")["id"], "old")
        self.assertTrue(Path(f"{legacy}.pre-automode-migration.bak").exists())
        legacy_classification = migrated.classification("old")
        self.assertTrue(legacy_classification["legacy"])
        self.assertEqual(legacy_classification["stages"][0]["verdict"], "旧记录无数据")
        with sqlite3.connect(legacy) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(traces)")}
        self.assertIn("final_decision", columns)

    def test_ac_p1_017_failed_migration_restores_backup(self):
        legacy = Path(self.tempdir.name) / "failed-migration.db"
        with sqlite3.connect(legacy) as connection:
            connection.execute("CREATE TABLE traces (id TEXT PRIMARY KEY, created_at TEXT, protocol TEXT, method TEXT, path TEXT, model TEXT, session_id TEXT, is_stream INTEGER, latest_user_text TEXT, declared_tool_count INTEGER, request_headers_json TEXT, request_body_json TEXT, response_status INTEGER, response_bytes INTEGER, latency_ms REAL, intent TEXT, speech_act TEXT, risk TEXT, decision TEXT, classification_json TEXT, error TEXT)")
            connection.execute("INSERT INTO traces VALUES ('recover-me','now','p','POST','/','m',NULL,0,'',0,'{}',NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL)")
        with patch.dict(TRACE_COLUMNS, {"broken_column": "TEXT INVALID ("}):
            with self.assertRaises(sqlite3.Error):
                TraceStore(legacy)
        with sqlite3.connect(legacy) as connection:
            self.assertEqual(connection.execute("SELECT id FROM traces").fetchone()[0], "recover-me")
            columns = {row[1] for row in connection.execute("PRAGMA table_info(traces)")}
        self.assertNotIn("session_record_id", columns)


if __name__ == "__main__":
    unittest.main()
