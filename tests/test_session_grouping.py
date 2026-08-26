import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from automode_gateway.classifier import authorization_signals
from automode_gateway.normalizer import normalize
from automode_gateway.policy import evaluate_rules
from automode_gateway.session_fingerprint import conversation_fingerprint, messages_are_continuation
from automode_gateway.storage import SESSION_COLUMNS, TraceStore


def _chat(messages):
    return {"model": "m", "messages": messages}


class ConversationFingerprintTests(unittest.TestCase):
    def test_fingerprint_is_stable_across_turns(self) -> None:
        opener = [{"role": "user", "content": "帮我重构这个模块"}]
        first = conversation_fingerprint(opener)
        self.assertIsNotNone(first)
        continued = conversation_fingerprint([
            *opener,
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Edit", "input": {"file_path": "a.py"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "done"}]},
            {"role": "user", "content": "继续"},
        ])
        self.assertEqual(continued, first)

    def test_fingerprint_distinguishes_different_openers(self) -> None:
        a = conversation_fingerprint([{"role": "user", "content": "帮我重构这个模块"}])
        b = conversation_fingerprint([{"role": "user", "content": "写一个部署脚本"}])
        self.assertNotEqual(a, b)

    def test_fingerprint_none_without_user_text(self) -> None:
        self.assertIsNone(conversation_fingerprint([]))
        self.assertIsNone(conversation_fingerprint([{"role": "system", "content": "be nice"}]))

    def test_continuation_prefix_holds(self) -> None:
        previous = [{"role": "user", "content": "帮我重构"}]
        incoming = [*previous, {"role": "assistant", "content": "ok"}, {"role": "user", "content": "继续"}]
        self.assertTrue(messages_are_continuation(previous, incoming))

    def test_continuation_rejects_divergent_history(self) -> None:
        previous = [{"role": "user", "content": "帮我重构"}, {"role": "assistant", "content": "a"}, {"role": "user", "content": "改这里"}]
        incoming = [{"role": "user", "content": "帮我重构"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "改那里"}]
        self.assertFalse(messages_are_continuation(previous, incoming))

    def test_continuation_ignores_ids_and_cache_fields(self) -> None:
        previous = [{"role": "user", "content": "帮我重构", "id": "u-1"}]
        incoming = [{"role": "user", "content": "帮我重构", "id": "u-2"}, {"role": "assistant", "content": "ok"}]
        self.assertTrue(messages_are_continuation(previous, incoming))


class SessionGroupingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = TraceStore(Path(self.tempdir.name) / "grouping.db")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _create(self, messages, **kwargs):
        return self.store.create(
            protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
            payload=_chat(messages), headers={}, session_id=kwargs.pop("session_id", None),
            latest_user_text="", declared_tool_count=0, **kwargs,
        )

    def test_fingerprint_groups_consecutive_requests_without_session_header(self) -> None:
        opener = [{"role": "user", "content": "帮我重构这个模块"}]
        continued = [
            *opener,
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Edit", "input": {"file_path": "a.py"}}]},
            {"role": "user", "content": "继续"},
        ]
        first = self._create(opener)
        second = self._create(continued)
        first_session = self.store.get(first)["session_record_id"]
        second_session = self.store.get(second)["session_record_id"]
        self.assertEqual(first_session, second_session)
        self.assertEqual(self.store.session(first_session)["call_count"], 2)

    def test_fingerprint_splits_different_openers(self) -> None:
        a = self._create([{"role": "user", "content": "帮我重构这个模块"}])
        b = self._create([{"role": "user", "content": "写一个部署脚本"}])
        self.assertNotEqual(
            self.store.get(a)["session_record_id"],
            self.store.get(b)["session_record_id"],
        )

    def test_fingerprint_splits_same_opener_with_divergent_history(self) -> None:
        opener = [{"role": "user", "content": "帮我重构"}]
        a = self._create([*opener, {"role": "assistant", "content": "a"}, {"role": "user", "content": "改这里"}])
        b = self._create([*opener, {"role": "assistant", "content": "b"}, {"role": "user", "content": "改那里"}])
        self.assertNotEqual(
            self.store.get(a)["session_record_id"],
            self.store.get(b)["session_record_id"],
        )

    def test_explicit_session_id_takes_precedence_over_fingerprint(self) -> None:
        a = self._create([{"role": "user", "content": "帮我重构这个模块"}], session_id="explicit-1")
        b = self._create([{"role": "user", "content": "写一个部署脚本"}], session_id="explicit-1")
        self.assertEqual(
            self.store.get(a)["session_record_id"],
            self.store.get(b)["session_record_id"],
        )

    def test_no_fingerprint_falls_back_to_trace_session(self) -> None:
        a = self._create([])
        b = self._create([])
        self.assertNotEqual(
            self.store.get(a)["session_record_id"],
            self.store.get(b)["session_record_id"],
        )


class SessionBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = TraceStore(Path(self.tempdir.name) / "baseline.db")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_baseline_accumulates_and_deduplicates_statements(self) -> None:
        signals = {
            "capabilities": ["write", "execute"],
            "forbidden_capabilities": ["publish"],
            "statements": [{"text": "不要 push", "capabilities": [], "forbidden_capabilities": ["publish"]}],
        }
        a = self.store.create(
            protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
            payload=_chat([{"role": "user", "content": "不要 push"}]),
            headers={}, session_id="baseline-session", latest_user_text="不要 push",
            declared_tool_count=0, session_signals=signals,
        )
        b = self.store.create(
            protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
            payload=_chat([{"role": "user", "content": "继续"}]),
            headers={}, session_id="baseline-session", latest_user_text="继续",
            declared_tool_count=0,
            session_signals={"capabilities": ["read"], "forbidden_capabilities": [], "statements": [{"text": "不要 push", "capabilities": [], "forbidden_capabilities": ["publish"]}]},
        )
        baseline = self.store.session_baseline_for_trace(b)
        self.assertEqual(baseline["capabilities"], ["write", "execute", "read"])
        self.assertEqual(baseline["forbidden_capabilities"], ["publish"])
        self.assertEqual(len(baseline["statements"]), 1)
        self.assertEqual(self.store.session_baseline_for_trace(a), baseline)

    def test_authorization_signals_infer_capabilities_from_intent(self) -> None:
        signals = authorization_signals(["帮我重构这个模块"])
        self.assertIn("write", signals["capabilities"])
        self.assertIn("read", signals["capabilities"])
        self.assertEqual(signals["statements"][0]["text"], "帮我重构这个模块")

    def test_session_scope_makes_later_action_aligned(self) -> None:
        request = normalize({"model": "m", "messages": [{"role": "user", "content": "继续"}]})
        action = [{"name": "edit_file", "arguments": {"path": "app.py"}}]
        baseline = {
            "capabilities": ["write"],
            "forbidden_capabilities": [],
            "statements": [{"text": "帮我重构这个模块", "capabilities": ["write"], "forbidden_capabilities": []}],
        }
        with_baseline, _ = evaluate_rules(request, action, [], session_baseline=baseline)
        self.assertEqual(with_baseline.verdict, "SAFE")
        self.assertEqual(with_baseline.action_alignment, "aligned")
        without, _ = evaluate_rules(request, action, [])
        self.assertEqual(without.verdict, "RISKY")
        self.assertEqual(without.action_alignment, "out_of_scope")

    def test_session_constraint_denies_later_action(self) -> None:
        request = normalize({"model": "m", "messages": [{"role": "user", "content": "继续"}]})
        action = [{"name": "Bash", "arguments": {"command": "git push origin main"}}]
        baseline = {
            "capabilities": ["read"],
            "forbidden_capabilities": ["publish"],
            "statements": [{"text": "检查代码，但不要 push", "capabilities": ["read"], "forbidden_capabilities": ["publish"]}],
        }
        stage, _ = evaluate_rules(request, action, [], session_baseline=baseline)
        self.assertEqual(stage.verdict, "RISKY")
        self.assertEqual(stage.action_alignment, "contradicted")
        self.assertIn("ACTION_CONTRADICTS_USER_CONSTRAINT", stage.reason_code)


class SessionMigrationTests(unittest.TestCase):
    def test_legacy_sessions_table_gets_new_columns_with_backup(self) -> None:
        directory = tempfile.TemporaryDirectory()
        legacy = Path(directory.name) / "legacy.db"
        with sqlite3.connect(legacy) as connection:
            connection.execute(
                """CREATE TABLE sessions (
                    id TEXT PRIMARY KEY, external_session_id TEXT UNIQUE, created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL, client_type TEXT, protocols_json TEXT NOT NULL DEFAULT '[]',
                    models_json TEXT NOT NULL DEFAULT '[]', call_count INTEGER NOT NULL DEFAULT 0,
                    tool_call_count INTEGER NOT NULL DEFAULT 0, allow_count INTEGER NOT NULL DEFAULT 0,
                    alert_count INTEGER NOT NULL DEFAULT 0, max_risk TEXT NOT NULL DEFAULT 'low'
                )"""
            )
            connection.execute(
                "INSERT INTO sessions VALUES ('s1', NULL, 'now', 'now', NULL, '[]', '[]', 1, 0, 0, 0, 'low')"
            )
        store = TraceStore(legacy)
        with sqlite3.connect(legacy) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(sessions)")}
        self.assertLess(set(SESSION_COLUMNS), columns)
        self.assertTrue(Path(f"{legacy}.pre-automode-migration.bak").exists())
        self.assertEqual(store.session("s1")["call_count"], 1)
        self.assertEqual(store.session("s1")["authorization"], {})
        directory.cleanup()


class BackfillTests(unittest.TestCase):
    """Regrouping of legacy trace-per-session data into conversation sessions."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "backfill.db"
        self.store = TraceStore(self.path)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _create(self, messages, session_id=None):
        return self.store.create(
            protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
            payload={"model": "m", "messages": messages}, headers={}, session_id=session_id,
            latest_user_text="", declared_tool_count=0,
        )

    def _force_legacy_state(self, trace_id: str) -> None:
        """Simulate a pre-fingerprint database: every trace in its own trace-fallback session."""
        with sqlite3.connect(self.path) as connection:
            session_id = str(uuid.uuid4())
            connection.execute(
                """INSERT INTO sessions (id, external_session_id, created_at, last_seen_at,
                   protocols_json, models_json, call_count) VALUES (?, ?, 'now', 'now', '[]', '[]', 1)""",
                (session_id, f"trace:{trace_id}"),
            )
            connection.execute("UPDATE traces SET session_record_id=? WHERE id=?", (session_id, trace_id))

    def test_backfill_regroups_legacy_trace_per_session(self) -> None:
        opener = [{"role": "user", "content": "帮我重构这个模块"}]
        continued = [*opener, {"role": "assistant", "content": "ok"}, {"role": "user", "content": "继续"}]
        t1 = self._create(opener)
        t2 = self._create(continued)
        self._force_legacy_state(t1)
        self._force_legacy_state(t2)
        self.assertNotEqual(self.store.get(t1)["session_record_id"], self.store.get(t2)["session_record_id"])

        stats = self.store.backfill_sessions()
        self.assertEqual(stats["regrouped_traces"], 2)
        self.assertEqual(stats["orphan_sessions_deleted"], 2)
        self.assertEqual(stats["sessions_after"], 1)
        session_id = self.store.get(t1)["session_record_id"]
        self.assertEqual(self.store.get(t2)["session_record_id"], session_id)
        session = self.store.session(session_id)
        self.assertEqual(session["call_count"], 2)
        self.assertIn("write", session["authorization"]["capabilities"])
        self.assertEqual(len(session["authorization"]["statements"]), 1)
        self.assertIsNotNone(session["conversation_fingerprint"])

    def test_backfill_preserves_explicit_sessions_and_splits_openers(self) -> None:
        t1 = self._create([{"role": "user", "content": "帮我重构这个模块"}], session_id="explicit-S")
        t2 = self._create([{"role": "user", "content": "写一个部署脚本"}], session_id="explicit-S")
        t3 = self._create([{"role": "user", "content": "检查配置"}])
        for trace_id in (t1, t2, t3):
            self._force_legacy_state(trace_id)

        stats = self.store.backfill_sessions()
        self.assertEqual(stats["sessions_after"], 2)
        self.assertEqual(stats["regrouped_traces"], 3)
        self.assertEqual(
            self.store.get(t1)["session_record_id"],
            self.store.get(t2)["session_record_id"],
        )
        self.assertEqual(self.store.session(self.store.get(t1)["session_record_id"])["external_session_id"], "explicit-S")
        self.assertNotEqual(
            self.store.get(t3)["session_record_id"],
            self.store.get(t1)["session_record_id"],
        )

    def test_backfill_is_idempotent(self) -> None:
        opener = [{"role": "user", "content": "帮我重构这个模块"}]
        continued = [*opener, {"role": "user", "content": "继续"}]
        t1 = self._create(opener)
        t2 = self._create(continued)
        self._force_legacy_state(t1)
        self._force_legacy_state(t2)
        self.store.backfill_sessions()
        first_session = self.store.get(t1)["session_record_id"]
        second = self.store.backfill_sessions()
        self.assertEqual(second["regrouped_traces"], 0)
        self.assertEqual(self.store.get(t1)["session_record_id"], first_session)
        self.assertEqual(self.store.session(first_session)["call_count"], 2)


if __name__ == "__main__":
    unittest.main()
