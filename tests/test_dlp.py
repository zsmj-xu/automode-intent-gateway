import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from automode_gateway.dlp import evaluate_dlp, redact_payload, scan_payload, trusted_identity
from automode_gateway.dlp_rule_compiler import compile_dlp_policy
from automode_gateway.evidence import generate_key, load_key
from automode_gateway.storage import TraceStore


class DLPDetectorTests(unittest.TestCase):
    def test_credentials_pii_source_and_keywords_are_detected_and_redacted(self):
        policy = {"id": "kw", "conditions": {"keywords": ["Project Nebula"]}}
        payload = {
            "messages": [
                {"role": "system", "content": "Project Nebula password=hunter2"},
                {"role": "user", "content": "联系 13812345678 或 user@example.com"},
                {"role": "tool", "content": "```python\ndef deploy():\n    return True\n```"},
            ]
        }
        findings = scan_payload(payload, [policy])
        self.assertEqual({item["category"] for item in findings}, {"credential", "pii", "source_code", "admin_keyword"})
        redacted = json.dumps(redact_payload(payload, findings), ensure_ascii=False)
        for secret in ("hunter2", "13812345678", "user@example.com", "def deploy", "Project Nebula"):
            self.assertNotIn(secret, redacted)
        source = next(item for item in findings if item["category"] == "source_code")
        self.assertEqual(source["snippet"], "[SOURCE_CODE_REDACTED]")

    def test_negative_plain_text_does_not_match(self):
        self.assertEqual(scan_payload({"messages": [{"role": "user", "content": "总结公开新闻"}]}), [])

    def test_identity_headers_only_apply_to_trusted_peer(self):
        headers = {"x-automode-user-id": "u1", "x-automode-department": "security", "x-automode-roles": "admin, reviewer"}
        trusted = trusted_identity(headers, "127.0.0.1", "127.0.0.0/8")
        spoofed = trusted_identity(headers, "10.0.0.7", "127.0.0.0/8")
        self.assertEqual(trusted["user_id"], "u1")
        self.assertEqual(trusted["roles"], ["admin", "reviewer"])
        self.assertFalse(spoofed["trusted"])
        self.assertIsNone(spoofed["user_id"])

    def test_unknown_target_is_external_and_trusted_target_allows_same_data(self):
        payload = {"model": "internal-gpt", "messages": [{"role": "user", "content": "password=hunter2"}]}
        external = evaluate_dlp(payload, protocol="openai_chat_completions", upstream="https://proxy", identity={}, targets=[])
        trusted = evaluate_dlp(payload, protocol="openai_chat_completions", upstream="https://proxy", identity={}, targets=[{
            "id": "t1", "name": "Internal", "upstream_pattern": "*", "model_pattern": "internal-*", "trust": "trusted", "enabled": True,
        }])
        self.assertEqual((external["destination_trust"], external["policy_decision"]), ("external", "alert"))
        self.assertEqual((trusted["destination_trust"], trusted["policy_decision"]), ("trusted", "allow"))

    def test_hard_external_alert_cannot_be_downgraded_by_review_policy(self):
        payload = {"model": "m", "messages": [{"role": "user", "content": "sk-abcdefghijklmnop"}]}
        policy = {
            "id": "review", "version": 1, "enabled": True, "effect": "review",
            "conditions": {"data_categories": ["credential"], "destination_trust": ["external"]},
        }
        result = evaluate_dlp(payload, protocol="openai_chat_completions", upstream="https://proxy", identity={}, policies=[policy])
        self.assertEqual(result["policy_decision"], "alert")
        self.assertIn("builtin-sensitive-external", result["matched_policies"])

    @patch.dict(os.environ, {
        "AUTOMODE_FAST_URL": "http://fast.test/v1/chat/completions", "AUTOMODE_FAST_MODEL": "fast",
        "AUTOMODE_DEEP_URL": "http://deep.test/v1/chat/completions", "AUTOMODE_DEEP_MODEL": "deep",
    }, clear=False)
    def test_review_policy_uses_only_redacted_signals_and_fails_through_to_deep(self):
        captured = {}
        payload = {"model": "corp-m", "messages": [{"role": "user", "content": "password=hunter2"}]}
        policy = {
            "id": "review", "version": 1, "enabled": True, "effect": "review",
            "conditions": {"data_categories": ["credential"], "destination_trust": ["trusted"]},
        }
        target = {"id": "t", "name": "Corp", "upstream_pattern": "*", "model_pattern": "corp-*", "trust": "trusted", "enabled": True}
        def fast(settings, value):
            captured.update(value)
            return {"decision": "uncertain", "risk": "medium", "policy_assessment": "ambiguous", "reason_code": "FAST_UNCERTAIN", "reason": "Needs deeper review"}
        def deep(settings, value):
            return {"decision": "allow", "risk": "medium", "policy_assessment": "safe", "reason_code": "REDACTED_CONTEXT_SAFE", "reason": "Redacted context is acceptable"}
        result = evaluate_dlp(payload, protocol="openai_chat_completions", upstream="https://proxy", identity={}, targets=[target], policies=[policy], fast_transport=fast, deep_transport=deep)
        self.assertEqual((result["policy_decision"], result["semantic_status"], result["final_stage"]), ("allow", "resolved", "deep_llm"))
        serialized = json.dumps(captured, ensure_ascii=False)
        self.assertNotIn("hunter2", serialized)
        self.assertIn("REDACTED:CREDENTIAL", serialized)

    def test_natural_language_policy_compiles_to_restricted_schema(self):
        value = compile_dlp_policy("部门 security、角色 reviewer、Agent agent-x 的凭据或源码发往外部模型 external-* 时告警，关键词“Project Nebula”")
        self.assertEqual(value["effect"], "alert")
        self.assertEqual(value["conditions"]["destination_trust"], ["external"])
        self.assertIn("credential", value["conditions"]["data_categories"])
        self.assertEqual(value["conditions"]["keywords"], ["Project Nebula"])
        self.assertEqual(value["conditions"]["departments"], ["security"])
        self.assertEqual(value["conditions"]["roles"], ["reviewer"])
        self.assertEqual(value["conditions"]["agent_ids"], ["agent-x"])
        self.assertEqual(value["conditions"]["models"], ["external-*"])


class DLPStorageTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Path(self.tempdir.name) / "dlp.db"
        self.key = bytes(range(32))
        self.store = TraceStore(self.db, evidence_key=self.key)

    def tearDown(self):
        self.tempdir.cleanup()

    def _trace(self, payload):
        return self.store.create(
            protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
            payload=payload, headers={}, session_id=None, latest_user_text=payload["messages"][-1]["content"], declared_tool_count=0,
        )

    def test_trace_is_redacted_and_evidence_is_aes_gcm_encrypted_and_audited(self):
        payload = {"model": "m", "messages": [{"role": "user", "content": "password=hunter2"}]}
        trace_id = self._trace(payload)
        findings = scan_payload(payload)
        evidence_id = self.store.store_evidence(trace_id, payload, findings, {"trust": "external"})
        raw_db = self.db.read_bytes()
        self.assertNotIn(b"hunter2", raw_db)
        self.assertNotIn("hunter2", json.dumps(self.store.get(trace_id), ensure_ascii=False))
        evidence = self.store.evidence(evidence_id, actor="tester", purpose="unit test", source="loopback")
        self.assertEqual(evidence["payload"], payload)
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM evidence_access_log").fetchone()[0], 1)

    def test_wrong_key_cannot_decrypt(self):
        payload = {"model": "m", "messages": [{"role": "user", "content": "password=hunter2"}]}
        trace_id = self._trace(payload)
        evidence_id = self.store.store_evidence(trace_id, payload, scan_payload(payload), {"trust": "external"})
        wrong = TraceStore(self.db, evidence_key=b"x" * 32)
        with self.assertRaises(InvalidTag):
            wrong.evidence(evidence_id, actor="x", purpose="x", source="loopback")

    def test_key_file_permissions_and_expired_evidence_purge(self):
        key_path = Path(self.tempdir.name) / "key"
        key_path.write_text(generate_key(), encoding="ascii")
        key_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "0600"):
            load_key(str(key_path))
        key_path.chmod(0o600)
        self.assertEqual(len(load_key(str(key_path))), 32)

        payload = {"model": "m", "messages": [{"role": "user", "content": "password=hunter2"}]}
        trace_id = self._trace(payload)
        evidence_id = self.store.store_evidence(trace_id, payload, scan_payload(payload), {"trust": "external"})
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE encrypted_evidence SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (evidence_id,))
            connection.commit()
        self.assertEqual(self.store.purge_expired_evidence(), 1)
        with self.assertRaises(KeyError):
            self.store.evidence(evidence_id, actor="x", purpose="x", source="loopback")

    def test_target_policy_versions_and_legacy_migration(self):
        target = self.store.create_destination({"name": "Internal", "upstream_pattern": "*", "model_pattern": "corp-*", "trust": "trusted"})
        self.assertEqual(self.store.list_destinations()[0]["id"], target["id"])
        compiled = compile_dlp_policy("凭据发往外部模型时告警")
        policy = self.store.create_dlp_policy(compiled, enabled=True)
        updated = self.store.update_dlp_policy(policy["id"], {**compiled, "name": "v2"})
        self.assertEqual(updated["version"], 2)
        self.assertEqual(len(self.store.dlp_policy_versions(policy["id"])), 2)
        legacy = {"model": "m", "messages": [{"role": "user", "content": "```python\ndef secret():\n return 1\n```"}]}
        trace_id = self._trace(legacy)
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE traces SET request_body_json=? WHERE id=?", (json.dumps(legacy), trace_id))
            connection.commit()
        stats = self.store.migrate_legacy_evidence()
        self.assertEqual(stats["migrated"], 1)
        self.assertIn("REDACTED", json.dumps(self.store.get(trace_id), ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
