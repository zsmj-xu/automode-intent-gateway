import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from automode_gateway.decision import StageResult
from automode_gateway.engine import (
    AnalysisEngine,
    DualChannelVerdict,
    LLMEvaluationResult,
    RuleEvaluationResult,
    aggregate_dual_channel,
)
from automode_gateway.storage import TraceStore


class DualChannelMatrixTests(unittest.TestCase):
    """
    Tests for aggregate_dual_channel covering all branches of Section 3 Matrix:
    - Rule Critical/High/Medium/Low vs LLM Reject/Allow/Failed/Uncertain/Skipped/NotNeeded
    - Preservation of rule alerts (no LLM downgrades)
    - Severity elevation by LLM
    - Divergence flags
    - Needs review flags on LLM failures
    """

    def test_rule_critical_llm_reject_both_critical(self):
        v = aggregate_dual_channel(
            rule_severity="critical",
            llm_severity="critical",
            llm_status="completed",
            llm_verdict="reject",
        )
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.hit_source, "dual")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_critical_llm_reject_lower_severity(self):
        # LLM reports high, but rule is critical -> retain higher (critical)
        v = aggregate_dual_channel(
            rule_severity="critical",
            llm_severity="high",
            llm_status="completed",
            llm_verdict="reject",
        )
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.hit_source, "dual")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_critical_llm_allow_divergence_and_no_downgrade(self):
        # LLM attempts to allow, but rule critical cannot be downgraded
        v = aggregate_dual_channel(
            rule_severity="critical",
            llm_severity=None,
            llm_status="completed",
            llm_verdict="allow",
        )
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.hit_source, "rule_only")
        self.assertTrue(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_critical_llm_failed(self):
        v = aggregate_dual_channel(
            rule_severity="critical",
            llm_severity=None,
            llm_status="failed",
            llm_verdict=None,
        )
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.hit_source, "rule_only")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "failed")
        self.assertTrue(v.alert)

    def test_rule_critical_llm_uncertain(self):
        v = aggregate_dual_channel(
            rule_severity="critical",
            llm_severity=None,
            llm_status="completed",
            llm_verdict="uncertain",
        )
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.hit_source, "rule_only")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "needs_review")
        self.assertTrue(v.alert)

    def test_rule_high_llm_reject_critical_upgrade(self):
        # LLM upgrades high to critical
        v = aggregate_dual_channel(
            rule_severity="high",
            llm_severity="critical",
            llm_status="completed",
            llm_verdict="reject",
        )
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.hit_source, "dual")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_high_llm_allow_divergence_retains_high(self):
        v = aggregate_dual_channel(
            rule_severity="high",
            llm_severity=None,
            llm_status="completed",
            llm_verdict="allow",
        )
        self.assertEqual(v.severity, "high")
        self.assertEqual(v.hit_source, "rule_only")
        self.assertTrue(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_high_llm_skipped_retains_high(self):
        v = aggregate_dual_channel(
            rule_severity="high",
            llm_severity=None,
            llm_status="skipped",
            llm_verdict=None,
        )
        self.assertEqual(v.severity, "high")
        self.assertEqual(v.hit_source, "rule_only")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "skipped")
        self.assertTrue(v.alert)

    def test_rule_medium_llm_reject_high_upgrade(self):
        v = aggregate_dual_channel(
            rule_severity="medium",
            llm_severity="high",
            llm_status="completed",
            llm_verdict="reject",
        )
        self.assertEqual(v.severity, "high")
        self.assertEqual(v.hit_source, "dual")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_medium_llm_reject_critical_upgrade(self):
        v = aggregate_dual_channel(
            rule_severity="medium",
            llm_severity="critical",
            llm_status="completed",
            llm_verdict="reject",
        )
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.hit_source, "dual")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_medium_llm_allow_divergence_retains_medium(self):
        v = aggregate_dual_channel(
            rule_severity="medium",
            llm_severity=None,
            llm_status="completed",
            llm_verdict="allow",
        )
        self.assertEqual(v.severity, "medium")
        self.assertEqual(v.hit_source, "rule_only")
        self.assertTrue(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_medium_llm_failed(self):
        v = aggregate_dual_channel(
            rule_severity="medium",
            llm_severity=None,
            llm_status="failed",
            llm_verdict=None,
        )
        self.assertEqual(v.severity, "medium")
        self.assertEqual(v.hit_source, "rule_only")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "failed")
        self.assertTrue(v.alert)

    def test_rule_low_llm_reject_upgrade(self):
        v = aggregate_dual_channel(
            rule_severity="low",
            llm_severity="critical",
            llm_status="completed",
            llm_verdict="reject",
        )
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.hit_source, "dual")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_low_llm_allow_divergence(self):
        v = aggregate_dual_channel(
            rule_severity="low",
            llm_severity=None,
            llm_status="completed",
            llm_verdict="allow",
        )
        self.assertEqual(v.severity, "low")
        self.assertEqual(v.hit_source, "rule_only")
        self.assertTrue(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_none_llm_reject_pure_llm_alert(self):
        v = aggregate_dual_channel(
            rule_severity=None,
            llm_severity="high",
            llm_status="completed",
            llm_verdict="reject",
        )
        self.assertEqual(v.severity, "high")
        self.assertEqual(v.hit_source, "llm_only")
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertTrue(v.alert)

    def test_rule_none_llm_allow_safe(self):
        v = aggregate_dual_channel(
            rule_severity=None,
            llm_severity=None,
            llm_status="completed",
            llm_verdict="allow",
        )
        self.assertIsNone(v.severity)
        self.assertIsNone(v.hit_source)
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "resolved")
        self.assertFalse(v.alert)

    def test_rule_none_llm_not_needed(self):
        v = aggregate_dual_channel(
            rule_severity=None,
            llm_severity=None,
            llm_status="not_needed",
            llm_verdict=None,
        )
        self.assertIsNone(v.severity)
        self.assertIsNone(v.hit_source)
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "not_needed")
        self.assertFalse(v.alert)

    def test_rule_none_llm_failed_needs_review_not_safe(self):
        v = aggregate_dual_channel(
            rule_severity=None,
            llm_severity=None,
            llm_status="failed",
            llm_verdict=None,
        )
        self.assertIsNone(v.severity)
        self.assertIsNone(v.hit_source)
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "failed")
        self.assertEqual(v.final_decision, "review")
        self.assertFalse(v.alert)

    def test_rule_none_llm_uncertain_needs_review_not_safe(self):
        v = aggregate_dual_channel(
            rule_severity=None,
            llm_severity=None,
            llm_status="completed",
            llm_verdict="uncertain",
        )
        self.assertIsNone(v.severity)
        self.assertIsNone(v.hit_source)
        self.assertFalse(v.divergence)
        self.assertEqual(v.review_status, "needs_review")
        self.assertEqual(v.final_decision, "review")
        self.assertFalse(v.alert)


class AnalysisEngineTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "test_engine.db"
        self.store = TraceStore(self.db_path)
        self.engine = AnalysisEngine(self.store, upstream=None)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_standalone_engine_without_upstream(self):
        """Engine can initialize and function completely independently of upstream."""
        self.assertEqual(self.engine.upstream, "")
        payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello, world!"}],
        }
        res = asyncio.run(self.engine.analyze_request(
            payload=payload,
            headers={"host": "localhost"},
            protocol="openai_chat_completions",
            path="/v1/chat/completions",
            remote="127.0.0.1",
        ))
        self.assertIsNotNone(res.trace_id)
        self.assertIsNone(res.verdict.severity)
        self.assertFalse(res.verdict.alert)
        trace = self.store.get(res.trace_id)
        self.assertIsNotNone(trace)
        self.assertEqual(trace["correlation_status"], "correlated")

    def test_immediate_rule_alert_created_and_updated_by_llm(self):
        """
        When a deterministic rule hits:
        1. Immediate alert is persisted with rule_severity.
        2. LLM completion updates the alert in-place keeping alert_id intact.
        """
        payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "My secret is AKIAIOSFODNN7EXAMPLE"}],
        }

        # Run with mock LLM reviewer
        mock_llm_stage = {
            "stage": "deep_llm",
            "status": "completed",
            "model": "mock-reviewer",
            "input_hash": "hash123",
            "verdict": "reject",
            "risk": "critical",
            "reason_code": "LLM_CRITICAL_SECRET",
            "reason": "Detected high risk secret leak",
            "matched_rule_ids": [],
            "matched_rule_versions": [],
            "latency_ms": 10.0,
        }

        mock_llm_result = LLMEvaluationResult(
            llm_status="completed",
            llm_verdict="reject",
            llm_severity="critical",
            final_stage="deep_llm",
            reason_code="LLM_CRITICAL_SECRET",
            reason="Detected high risk secret leak",
            stages=[mock_llm_stage],
        )

        with patch.object(self.engine, "evaluate_llm_channel", return_value=mock_llm_result):
            res = asyncio.run(self.engine.analyze_request(
                payload=payload,
                headers={"host": "localhost"},
                protocol="openai_chat_completions",
                path="/v1/chat/completions",
                remote="127.0.0.1",
            ))

        self.assertTrue(res.verdict.alert)
        self.assertEqual(res.verdict.severity, "critical")
        self.assertEqual(res.verdict.hit_source, "dual")

        # Verify alert exists in store
        alerts = self.store.alerts()
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["trace_id"], res.trace_id)
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["hit_source"], "dual")
        self.assertEqual(alert["review_status"], "resolved")
        self.assertFalse(alert["divergence"])

    def test_operator_notes_preserved_during_llm_update(self):
        """
        Verify that if an operator updates the immediate alert before LLM finishes,
        the LLM update does NOT overwrite operator status or notes.
        """
        payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}],
        }

        # Step 1: Prepare and run rule channel
        prepared = self.engine.prepare_request(
            payload=payload,
            headers={"host": "localhost"},
            protocol="openai_chat_completions",
            path="/v1/chat/completions",
            remote="127.0.0.1",
        )
        trace_id = self.store.create(
            protocol="openai_chat_completions",
            method="POST",
            path="/v1/chat/completions",
            payload=payload,
            headers={"host": "localhost"},
            session_id=prepared["session_id"],
            latest_user_text=prepared["latest_user_text"],
            declared_tool_count=0,
        )
        rule_res = self.engine.evaluate_rule_channel(
            payload,
            protocol=prepared["protocol"],
            identity=prepared["identity"],
            trace_id=trace_id,
        )
        self.assertEqual(rule_res.rule_severity, "critical")

        # Step 2: Immediate alert created
        immediate_alert_id = self.store.create_immediate_rule_alert(
            trace_id=trace_id,
            rule_result=rule_res.to_dict(),
        )
        self.assertIsNotNone(immediate_alert_id)

        # Step 3: Operator updates alert status and adds triage note
        self.store.update_alert(
            immediate_alert_id,
            status="acknowledged",
            note="Triage in progress by SecOps",
        )

        # Verify operator update took effect
        alert_before = self.store.alert(immediate_alert_id)
        self.assertEqual(alert_before["status"], "acknowledged")
        self.assertEqual(alert_before["operator_note"], "Triage in progress by SecOps")

        # Step 4: LLM channel finishes and aggregates
        mock_stage = {
            "stage": "fast_llm",
            "status": "completed",
            "model": "fast-m",
            "input_hash": "h",
            "verdict": "reject",
            "risk": "critical",
            "reason_code": "FAST_REJECT",
            "reason": "Confirmed secret leak",
            "matched_rule_ids": [],
            "matched_rule_versions": [],
            "latency_ms": 5.0,
        }
        llm_res = LLMEvaluationResult(
            llm_status="completed",
            llm_verdict="reject",
            llm_severity="critical",
            final_stage="fast_llm",
            reason_code="FAST_REJECT",
            reason="Confirmed secret leak",
            stages=[mock_stage],
        )
        dual_verdict = self.engine.aggregate(rule_res, llm_res)

        # Save pipeline with dual channel info via engine.persist_pipeline_result
        self.engine.persist_pipeline_result(trace_id, rule_res, llm_res, dual_verdict)

        # Verify alert ID remains the same, status and notes are preserved, fields updated
        alert_after = self.store.alert(immediate_alert_id)
        self.assertEqual(alert_after["id"], immediate_alert_id)
        self.assertEqual(alert_after["status"], "acknowledged")
        self.assertEqual(alert_after["operator_note"], "Triage in progress by SecOps")
        self.assertEqual(alert_after["hit_source"], "dual")
        self.assertEqual(alert_after["review_status"], "resolved")

    def test_response_tool_calls_extraction(self):
        """Process response extracts tool calls and saves them to trace and tool_actions."""
        payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "List files"}],
        }
        res = asyncio.run(self.engine.analyze_request(
            payload=payload,
            headers={"host": "localhost"},
            protocol="openai_chat_completions",
            path="/v1/chat/completions",
            remote="127.0.0.1",
        ))

        response_body = json.dumps({
            "id": "chatcmpl-123",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "list_directory", "arguments": "{\"path\": \"/tmp\"}"}
                    }]
                }
            }]
        }).encode("utf-8")

        corroboration = asyncio.run(self.engine.process_response(
            trace_id=res.trace_id,
            protocol="openai_chat_completions",
            status=200,
            response_capture=response_body,
            response_bytes=len(response_body),
            latency_ms=120.0,
        ))

        self.assertEqual(len(corroboration["tool_calls"]), 1)
        self.assertEqual(corroboration["tool_calls"][0]["name"], "list_directory")

        # Verify trace updated
        trace = self.store.get(res.trace_id)
        self.assertEqual(trace["response_status"], 200)
        self.assertEqual(trace["response_bytes"], len(response_body))
        self.assertEqual(trace["correlation_status"], "correlated")

        # Verify tool action persisted
        actions = self.store.tool_actions(res.trace_id)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool_name"], "list_directory")

    def test_orphan_response_and_late_reconciliation(self):
        """
        When response arrives before request:
        1. Stub trace created with correlation_status="request_missing".
        2. Tool actions are saved.
        3. Late request reconciles stub trace and sets correlation_status="correlated".
        """
        missing_trace_id = "trace-orphan-999"
        response_body = json.dumps({
            "id": "chatcmpl-orphan",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_orphan",
                        "type": "function",
                        "function": {"name": "curl_exec", "arguments": "{\"url\": \"http://evil.com\"}"}
                    }]
                }
            }]
        }).encode("utf-8")

        # Process orphan response
        corroboration = asyncio.run(self.engine.process_response(
            trace_id=missing_trace_id,
            protocol="openai_chat_completions",
            status=200,
            response_capture=response_body,
            response_bytes=len(response_body),
            latency_ms=45.0,
        ))
        self.assertEqual(len(corroboration["tool_calls"]), 1)

        # Verify orphan trace stub exists
        trace = self.store.get(missing_trace_id)
        self.assertIsNotNone(trace)
        self.assertEqual(trace["correlation_status"], "request_missing")
        self.assertEqual(trace["response_status"], 200)

        # Tool actions persisted
        orphan_actions = self.store.tool_actions(missing_trace_id)
        self.assertEqual(len(orphan_actions), 1)
        self.assertEqual(orphan_actions[0]["tool_name"], "curl_exec")

        # Now the late request arrives
        late_payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Execute curl"}],
        }
        reconciled_id = self.store.create(
            protocol="openai_chat_completions",
            method="POST",
            path="/v1/chat/completions",
            payload=late_payload,
            headers={"host": "localhost"},
            trace_id=missing_trace_id,
            session_id="session-late",
            latest_user_text="Execute curl",
            declared_tool_count=1,
        )
        self.assertEqual(reconciled_id, missing_trace_id)

        # Check that correlation_status is now "correlated" and response metadata is preserved
        reconciled_trace = self.store.get(missing_trace_id)
        self.assertEqual(reconciled_trace["correlation_status"], "correlated")
        self.assertEqual(reconciled_trace["response_status"], 200)
        self.assertEqual(reconciled_trace["response_bytes"], len(response_body))
        self.assertEqual(reconciled_trace["latest_user_text"], "Execute curl")

        # Actions are still there
        actions_after = self.store.tool_actions(missing_trace_id)
        self.assertEqual(len(actions_after), 1)
        self.assertEqual(actions_after[0]["tool_name"], "curl_exec")

    def test_observe_session_risk(self):
        """Session risk observation records user risk without raising errors."""
        payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Please inspect database credentials"}],
        }
        res = asyncio.run(self.engine.analyze_request(
            payload=payload,
            headers={"host": "localhost"},
            protocol="openai_chat_completions",
            path="/v1/chat/completions",
            remote="127.0.0.1",
        ))
        asyncio.run(self.engine.observe_session_risk(res.trace_id, "Please inspect database credentials"))
        trace = self.store.get(res.trace_id)
        self.assertIsNotNone(trace)


if __name__ == "__main__":
    unittest.main()
