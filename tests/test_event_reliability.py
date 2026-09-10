import json
import os
import tempfile
import unittest
from pathlib import Path

from automode_gateway.disk_buffer import DiskBuffer
from automode_gateway.event_ingress import canonical_event_hash, validate_event_data
from automode_gateway.storage import TraceStore


class EventReliabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.key = os.urandom(32)
        self.store = TraceStore(root / "events.db", evidence_key=self.key)
        self.buffer = DiskBuffer(root / "buffer", self.key)
        self.store.create_source("source-a", "A", "token-a")
        self.store.create_source("source-b", "B", "token-b")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _reserve(self, source: str, external: str, **kwargs):
        return self.store.reserve_event(
            external_event_id=external,
            source_id=source,
            call_id=kwargs.pop("call_id", "call-1"),
            event_type=kwargs.pop("event_type", "request"),
            protocol="openai_chat_completions",
            capture_stage=kwargs.pop("capture_stage", "model_outbound"),
            content_integrity="complete",
            timestamp="2026-09-09T00:00:00Z",
            payload_hash=kwargs.pop("payload_hash", f"hash-{source}-{external}"),
            body_hash=kwargs.pop("body_hash", "body-1"),
            metadata=kwargs.pop("metadata", {}),
            **kwargs,
        )

    def test_external_ids_are_source_scoped_and_buffer_keys_are_internal(self):
        first = self._reserve("source-a", "same-id")
        second = self._reserve("source-b", "same-id")
        self.assertEqual(first["status"], "reserved")
        self.assertEqual(second["status"], "reserved")
        self.assertNotEqual(first["internal_id"], second["internal_id"])

        path_a = self.buffer.write(first["internal_id"], b"a")
        path_b = self.buffer.write(second["internal_id"], b"b")
        self.store.finalize_event_storage(first["internal_id"], path_a)
        self.store.finalize_event_storage(second["internal_id"], path_b)
        self.assertNotEqual(path_a, path_b)
        self.assertEqual(self.store.get_event_by_source_and_id("source-a", "same-id")["id"], first["internal_id"])
        self.assertIsNone(self.store.get_event("same-id"))

    def test_pending_reservation_and_hash_conflict_are_explicit(self):
        first = self._reserve("source-a", "event-1", payload_hash="hash-1")
        pending = self._reserve("source-a", "event-1", payload_hash="hash-1")
        conflict = self._reserve("source-a", "event-1", payload_hash="hash-2")
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(conflict["status"], "conflict")
        self.assertTrue(self.store.remove_event_reservation(first["internal_id"]))

    def test_event_hash_covers_identity_destination_and_type(self):
        source = {"id": "source-a", "allow_trusted_identity": True}
        base = {
            "version": "1", "event_id": "hash-event", "source_id": "source-a", "call_id": "call-hash",
            "event_type": "request", "protocol": "openai_chat_completions", "capture_stage": "model_outbound",
            "content_integrity": "complete", "timestamp": "2026-09-09T00:00:00Z", "payload": {"x": 1},
            "identity": {"trusted": True}, "model_destination": {"id": "target-a"},
        }
        first = validate_event_data(base, source)
        changed = dict(base, identity={"trusted": False})
        changed_event = validate_event_data(changed, source)
        self.assertNotEqual(canonical_event_hash(first), canonical_event_hash(changed_event))
        changed_type = validate_event_data(dict(base, event_type="full_call"), source)
        self.assertNotEqual(canonical_event_hash(first), canonical_event_hash(changed_type))

    def test_metadata_is_redacted_and_alert_id_is_stable(self):
        event = self._reserve(
            "source-a",
            "event-2",
            metadata={"authorization": "Bearer very-secret-value", "nested": {"token": "sk-1234567890"}},
        )
        row = self.store.get_event(event["internal_id"])
        metadata = json.loads(row["metadata_json"])
        self.assertNotIn("very-secret-value", json.dumps(metadata))
        self.assertNotIn("sk-1234567890", json.dumps(metadata))
        alert_one = self.store.create_event_alert(
            event_id=event["internal_id"], severity="high", rule_severity="high",
            reason_code="DLP_RULE_HIT", title="hit", reason="redacted",
        )
        alert_two = self.store.create_event_alert(
            event_id=event["internal_id"], severity="high", rule_severity="high",
            reason_code="DLP_RULE_HIT", title="hit", reason="redacted",
        )
        self.assertEqual(alert_one, alert_two)

    def test_correlation_requires_matching_attempt_stage_and_realtime(self):
        base = self._reserve("source-a", "request-1", call_id="call-2")
        self.store.finalize_event_storage(base["internal_id"], self.buffer.write(base["internal_id"], b"{}"))
        response = self._reserve(
            "source-a", "response-1", call_id="call-2", event_type="response",
            capture_stage="model_outbound",
        )
        self.store.finalize_event_storage(response["internal_id"], self.buffer.write(response["internal_id"], b"{}"))
        matches = self.store.find_correlated_events(
            "source-a", "call-2", None, "request", "model_outbound", True,
        )
        self.assertEqual([item["id"] for item in matches], [base["internal_id"]])
        self.assertEqual(self.store.find_correlated_events(
            "source-a", "call-2", None, "request", "inbound_request", True,
        ), [])


if __name__ == "__main__":
    unittest.main()
