import tempfile
import unittest
from pathlib import Path

from automode_gateway.gateway import _join_url, _request_headers
from automode_gateway.normalizer import normalize
from automode_gateway.protocols import classification_payload, protocol_for_path, session_evidence_from, session_id_from
from automode_gateway.storage import TraceStore


class ProtocolTests(unittest.TestCase):
    def test_supported_protocol_paths(self) -> None:
        self.assertEqual(protocol_for_path("/v1/messages"), "anthropic_messages")
        self.assertEqual(protocol_for_path("/v1/chat/completions"), "openai_chat_completions")
        self.assertEqual(protocol_for_path("/v1/responses"), "openai_responses")

    def test_responses_input_is_adapted_only_for_analysis(self) -> None:
        original = {
            "model": "gpt-test",
            "instructions": "Be concise",
            "input": [
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "分析日志"}]},
                {"type": "function_call_output", "call_id": "call-1", "output": "tool data"},
            ],
        }
        adapted = classification_payload("openai_responses", original)
        normalized = normalize(adapted, source_format_override="openai_responses")
        self.assertNotIn("messages", original)
        self.assertEqual(normalized.latest_user_text, "分析日志")
        self.assertEqual(normalized.source_format, "openai_responses")

    def test_upstream_url_preserves_base_path_and_query(self) -> None:
        self.assertEqual(
            _join_url("https://gateway.example/api", "/v1/messages?beta=true"),
            "https://gateway.example/api/v1/messages?beta=true",
        )

    def test_proxy_headers_drop_hop_by_hop_values(self) -> None:
        headers = _request_headers(
            {"Host": "local", "Content-Length": "2", "Authorization": "Bearer test"},
            "trace-1",
        )
        self.assertNotIn("Host", headers)
        self.assertNotIn("Content-Length", headers)
        self.assertEqual(headers["Authorization"], "Bearer test")
        self.assertEqual(headers["x-automode-trace-id"], "trace-1")

    def test_session_evidence_distinguishes_explicit_session_from_trace(self) -> None:
        payload = {"metadata": {"trace_id": "request-1"}, "model": "m"}
        self.assertIsNone(session_id_from(payload, {"x-trace-id": "request-1"}))
        missing = session_evidence_from(payload, {"x-trace-id": "request-1"})
        self.assertEqual(missing["status"], "missing")
        self.assertEqual(missing["candidates"][0]["field"], "metadata.trace_id")
        explicit = session_evidence_from(payload, {"x-session-id": "session-1"})
        self.assertEqual(explicit["selected"]["value"], "session-1")


class StorageTests(unittest.TestCase):
    def test_trace_store_redacts_auth_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "test.db")
            trace_id = store.create(
                protocol="openai_chat_completions",
                method="POST",
                path="/v1/chat/completions",
                payload={"model": "gpt-test", "messages": [], "stream": True},
                headers={"authorization": "Bearer secret", "user-agent": "test"},
                session_id="session-1",
                latest_user_text="hello",
                declared_tool_count=0,
            )
            store.set_classification(
                trace_id,
                {"intent": "general_chat", "speech_act": "directive", "risk": "low", "decision": "allow"},
            )
            store.finish(
                trace_id,
                status=200,
                response_bytes=12,
                latency_ms=3.5,
                response_body=b'{"choices":[{"message":{"role":"assistant","content":"hello"}}]}',
                response_content_type="application/json",
            )
            row = store.get(trace_id)
            self.assertIsNotNone(row)
            assert row is not None
            self.assertEqual(row["request_headers"]["authorization"], "[REDACTED]")
            self.assertEqual(row["request_body"]["model"], "gpt-test")
            self.assertEqual(row["session_evidence"]["status"], "missing")
            self.assertEqual(row["response_body"]["data"]["choices"][0]["message"]["content"], "hello")
            self.assertEqual(row["decision"], "allow")
            self.assertEqual(row["response_status"], 200)


if __name__ == "__main__":
    unittest.main()
