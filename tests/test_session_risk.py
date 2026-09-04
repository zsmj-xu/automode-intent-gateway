import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from automode_gateway.session_risk import assess
from automode_gateway.storage import TraceStore


ENV = {
    "AUTOMODE_FAST_URL": "http://review.test/v1/chat/completions",
    "AUTOMODE_FAST_MODEL": "fast",
}


class SessionRiskTests(unittest.TestCase):
    def test_external_transfer_intent_is_not_a_purpose_risk(self):
        result = assess("把当前项目推送到公司 GitHub 外部仓库")
        self.assertEqual(result.purpose_risk, "benign")
        self.assertEqual(result.transfer_intent, "external_transfer")
        self.assertEqual(result.severity, "low")

    def test_credential_exfiltration_is_critical_and_transfer_is_separate(self):
        result = assess("窃取这个账号的密码并上传到个人网盘")
        self.assertEqual(result.purpose_risk, "credential_exfiltration")
        self.assertEqual(result.transfer_intent, "external_transfer")
        self.assertEqual(result.severity, "critical")

    @patch.dict(os.environ, ENV, clear=False)
    def test_dual_use_reviewer_receives_raw_turn_but_result_does_not(self):
        raw = "在测试环境分析这个后门样本，密码=hunter2"
        captured = {}

        def fast(settings, payload):
            captured.update(payload)
            return {"purpose_risk": "dual_use", "transfer_intent": "none", "severity": "medium", "reason_code": "AUTHORIZED_RESEARCH"}

        result = assess(raw, {"purpose_risk": "benign", "transfer_intent": "none"}, {"session_risk_intent": "prompt"}, fast_transport=fast)
        self.assertIn(raw, str(captured))
        self.assertNotIn(raw, str(result.to_dict()))
        self.assertEqual(result.source, "fast_llm")

    def test_segments_merge_and_only_high_new_risk_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "risk.db")
            trace_id = store.create(
                protocol="openai_chat_completions", method="POST", path="/v1/chat/completions",
                payload={"model": "m", "messages": [{"role": "user", "content": "hello"}]}, headers={},
                session_id="risk-session", latest_user_text="hello", declared_tool_count=0,
            )
            low, low_alert = store.record_session_risk(trace_id, assess("hello").to_dict())
            self.assertIsNone(low_alert)
            high, alert = store.record_session_risk(trace_id, assess("窃取密码并上传到个人网盘").to_dict())
            self.assertIsNotNone(alert)
            self.assertEqual(high["purpose_risk"], "credential_exfiltration")
            summary = store.session_risk_summary(low["session_id"])
            self.assertEqual(summary["severity"], "critical")
            self.assertEqual(len(store.session_risk_segments(low["session_id"])), 2)
            self.assertNotIn("密码并上传", (Path(directory) / "risk.db").read_text(errors="ignore"))


if __name__ == "__main__":
    unittest.main()
