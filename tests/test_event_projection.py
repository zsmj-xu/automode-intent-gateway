import json
import os
import tempfile
import unittest
from pathlib import Path

from automode_gateway.storage import TraceStore


class EventProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TraceStore(Path(self.tmp.name) / "projection.db", evidence_key=os.urandom(32))
        self.store.create_source("proxy-adapter", "Proxy adapter", "proxy-token")
        self.trace_id = "trace-projection-1"
        self.store.create(
            trace_id=self.trace_id,
            protocol="openai_chat_completions",
            method="POST",
            path="/v1/chat/completions",
            payload={"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]},
            headers={},
            session_id="session-projection-1",
            latest_user_text="hello",
            declared_tool_count=0,
        )
        self.session_record_id = self.store.get(self.trace_id)["session_record_id"]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _event(self):
        return self.store.record_event(
            event_id="proxy-event-1",
            source_id="proxy-adapter",
            call_id="proxy-call-1",
            event_type="request",
            protocol="openai_chat_completions",
            capture_stage="model_outbound",
            content_integrity="complete",
            timestamp="2026-09-09T00:00:00Z",
            payload_hash="proxy-hash-1",
            metadata={"source_metadata": {"trace_id": self.trace_id}, "secret": "sk-1234567890"},
        )

    @staticmethod
    def _result(llm_status="pending"):
        return {
            "final_decision": "alert" if llm_status == "completed" else "review",
            "final_stage": "fast_llm" if llm_status == "completed" else "rules",
            "risk": "high" if llm_status == "completed" else "medium",
            "decision": "alert" if llm_status == "completed" else "review",
            "reason_code": "DLP_TEST",
            "reason": "synthetic result",
            "action_alignment": "normal",
            "request_safety": "harmful" if llm_status == "completed" else "ambiguous",
            "review_object": "outbound_request",
            "semantic_status": "resolved" if llm_status == "completed" else "pending",
            "data_findings": [{"category": "credential", "snippet": "[REDACTED:TOKEN]"}],
            "destination": {"trust": "external", "model": "gpt-test"},
            "rule_severity": "medium",
            "llm_severity": "high" if llm_status == "completed" else None,
            "llm_status": llm_status,
            "review_status": "resolved" if llm_status == "completed" else "pending",
            "divergence": False,
            "hit_source": "dual" if llm_status == "completed" else "rule_only",
            "stages": [{
                "stage": "rules", "status": "completed", "verdict": "alert", "risk": "medium",
                "reason_code": "DLP_TEST", "reason": "synthetic", "matched_rule_ids": ["rule-1"],
                "evidence": [], "messages": [{"role": "user", "content": "must not persist"}],
            }],
        }

    def test_projection_is_idempotent_and_links_event_alert(self):
        event = self._event()
        alert_id = self.store.create_event_alert(
            event_id=event["id"], severity="medium", rule_severity="medium",
            reason_code="DLP_TEST", title="test", reason="test", evidence_id="ev-1",
        )
        with self.store._connect() as connection:
            connection.execute("UPDATE alerts SET status='acknowledged', operator_note='keep me' WHERE id=?", (alert_id,))

        before = self.store.session(self.session_record_id)
        first = self.store.project_event_analysis(event["id"], self._result())
        second = self.store.project_event_analysis(event["id"], self._result("completed"))
        self.assertEqual(first["run_id"], second["run_id"])

        with self.store._connect() as connection:
            runs = connection.execute("SELECT * FROM classification_runs WHERE trace_id=?", (self.trace_id,)).fetchall()
            stages = connection.execute("SELECT * FROM classification_stages WHERE run_id=?", (second["run_id"],)).fetchall()
            alert = connection.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            trace = connection.execute("SELECT pipeline_status, final_decision, classification_json FROM traces WHERE id=?", (self.trace_id,)).fetchone()
        self.assertEqual(len(runs), 1)
        self.assertEqual(len(stages), 1)
        self.assertEqual(trace["pipeline_status"], "completed")
        self.assertEqual(trace["final_decision"], "alert")
        self.assertEqual(alert["trace_id"], self.trace_id)
        self.assertEqual(alert["classification_run_id"], second["run_id"])
        self.assertEqual(alert["status"], "acknowledged")
        self.assertEqual(alert["operator_note"], "keep me")
        self.assertEqual(self.store.session(self.session_record_id)["call_count"], before["call_count"])
        self.assertEqual(self.store.session(self.session_record_id)["alert_count"], before["alert_count"] + 1)
        summary = json.loads(trace["classification_json"])
        self.assertNotIn("messages", json.dumps(summary))
        self.assertNotIn("sk-1234567890", json.dumps(summary))

        detail = self.store.session_detail(self.session_record_id)
        self.assertEqual(detail["traces"][0]["classification"]["id"], second["run_id"])
        self.assertEqual(detail["traces"][0]["alerts"][0]["id"], alert_id)

    def test_projection_only_accepts_proxy_adapter_and_existing_trace(self):
        event = self._event()
        with self.store._connect() as connection:
            connection.execute("UPDATE events SET source_id='other-source' WHERE id=?", (event["id"],))
        with self.assertRaises(ValueError):
            self.store.project_event_analysis(event["id"], self._result())


if __name__ == "__main__":
    unittest.main()
