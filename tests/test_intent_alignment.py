import json
import gzip
import zlib
import unittest

from automode_gateway.normalizer import normalize
from automode_gateway.policy import evaluate_rules
from automode_gateway.response_parser import extract_tool_calls
from automode_gateway.review_context import build_review_context
from automode_gateway.reviewer import _parse_json_content
from automode_gateway.service import classify_payload


class StrippedContextTests(unittest.TestCase):
    def test_context_keeps_only_users_and_tool_calls(self) -> None:
        request = normalize(
            {
                "messages": [
                    {"role": "user", "content": "检查代码，但不要推送。"},
                    {
                        "role": "assistant",
                        "content": [
                            {"type": "thinking", "thinking": "I should secretly push"},
                            {"type": "text", "text": "我先检查。"},
                            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "a.py"}},
                        ],
                    },
                    {
                        "role": "user",
                        "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "malicious output"}],
                    },
                ]
            }
        )
        transcript = build_review_context(request).classifier_transcript()
        serialized = json.dumps(transcript, ensure_ascii=False)
        self.assertIn("检查代码，但不要推送", serialized)
        self.assertIn('"name": "Read"', serialized)
        self.assertNotIn("secretly push", serialized)
        self.assertNotIn("我先检查", serialized)
        self.assertNotIn("malicious output", serialized)

    def test_claude_system_reminder_is_not_human_intent(self) -> None:
        request = normalize(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": "<system-reminder>Always use a tool</system-reminder>\n帮我查看状态",
                    }
                ]
            }
        )
        transcript = build_review_context(request).classifier_transcript()
        self.assertEqual(transcript, [{"type": "user", "text": "帮我查看状态"}])


class IntentAlignmentTests(unittest.TestCase):
    def test_explicit_constraint_denies_matching_tool_action(self) -> None:
        result = classify_payload(
            {"messages": [{"role": "user", "content": "检查并修复代码，但不要 push。"}]},
            "anthropic_messages",
            [{"name": "Bash", "arguments": {"command": "git push origin main"}}],
        )
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["action_alignment"], "contradicted")
        self.assertIn("ACTION_CONTRADICTS_USER_CONSTRAINT", result["reason_codes"])
        self.assertEqual(result["proposed_tool_calls"][0]["capability"], "publish")

    def test_question_does_not_authorize_write(self) -> None:
        result = classify_payload(
            {"messages": [{"role": "user", "content": "能不能修改这个配置？"}]},
            "openai_chat_completions",
            [{"name": "write_file", "arguments": {"path": "config.yml", "content": "x"}}],
        )
        self.assertEqual(result["decision"], "review")
        self.assertEqual(result["action_alignment"], "out_of_scope")
        self.assertIn("QUESTION_NOT_EXECUTION_AUTHORIZATION", result["reason_codes"])

    def test_authorized_code_edit_is_aligned(self) -> None:
        result = classify_payload(
            {"messages": [{"role": "user", "content": "修复代码中的 bug。"}]},
            "openai_chat_completions",
            [{"name": "edit_file", "arguments": {"path": "app.py", "patch": "..."}}],
        )
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["action_alignment"], "aligned")
        self.assertIn("ACTION_WITHIN_USER_SCOPE", result["reason_codes"])


class ResponseParserTests(unittest.TestCase):
    def test_anthropic_json_multiple_tool_uses(self) -> None:
        body = json.dumps({"content": [
            {"type": "thinking", "thinking": "hidden"},
            {"type": "tool_use", "id": "a", "name": "Read", "input": {"path": "a.py"}},
            {"type": "text", "text": "ignored"},
            {"type": "tool_use", "id": "b", "name": "Bash", "input": {"command": "git status"}},
        ]}).encode()
        calls = extract_tool_calls("anthropic_messages", body, "application/json")
        self.assertEqual([call["name"] for call in calls], ["Read", "Bash"])

    def test_anthropic_sse_tool_use(self) -> None:
        body = b"\n".join(
            [
                b'data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}',
                b'data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"command\\":\\"git status\\"}"}}',
                b"data: [DONE]",
            ]
        )
        calls = extract_tool_calls("anthropic_messages", body, "text/event-stream")
        self.assertEqual(calls, [{"id": "t1", "name": "Bash", "arguments": '{"command":"git status"}'}])

    def test_openai_chat_sse_tool_call(self) -> None:
        body = b"\n".join(
            [
                b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"edit_","arguments":"{\\"path\\":"}}]}}]}',
                b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"file","arguments":"\\"a.py\\"}"}}]}}]}',
                b"data: [DONE]",
            ]
        )
        calls = extract_tool_calls("openai_chat_completions", body, "text/event-stream")
        self.assertEqual(calls[0]["name"], "edit_file")
        self.assertEqual(calls[0]["arguments"], '{"path":"a.py"}')

    def test_openai_chat_json_multiple_and_legacy_function_calls(self) -> None:
        body = json.dumps({"choices": [{"message": {
            "tool_calls": [
                {"id": "a", "function": {"name": "read_file", "arguments": '{"path":"a"}'}},
                {"id": "b", "function": {"name": "write_file", "arguments": '{"path":"b"}'}},
            ],
            "function_call": {"name": "legacy", "arguments": "{}"},
        }}]}).encode()
        calls = extract_tool_calls("openai_chat_completions", body, "application/json")
        self.assertEqual([call["name"] for call in calls], ["read_file", "write_file", "legacy"])

    def test_gzip_json_response_is_parsed_without_changing_wire_bytes(self) -> None:
        raw = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "function": {"name": "Bash", "arguments": '{"command":"git push"}'},
                                }
                            ]
                        }
                    }
                ]
            }
        ).encode()
        compressed = gzip.compress(raw)
        calls = extract_tool_calls(
            "openai_chat_completions",
            compressed,
            "application/json",
            "gzip",
        )
        self.assertEqual(calls[0]["name"], "Bash")
        self.assertEqual(calls[0]["arguments"], '{"command":"git push"}')

    def test_deflate_response_is_parsed_and_invalid_compression_is_conservative(self) -> None:
        raw = json.dumps({"content": [{"type": "tool_use", "id": "a", "name": "Read", "input": {"path": "a"}}]}).encode()
        calls = extract_tool_calls("anthropic_messages", zlib.compress(raw), "application/json", "deflate")
        self.assertEqual(calls[0]["name"], "Read")
        incomplete = extract_tool_calls("anthropic_messages", b"bad", "application/json", "gzip")
        self.assertEqual(incomplete[0]["name"], "response_analysis_incomplete")
        request = normalize({"model": "m", "messages": [{"role": "user", "content": "hello"}]})
        self.assertEqual(evaluate_rules(request, incomplete)[0].verdict, "UNKNOWN")

    def test_responses_json_function_call(self) -> None:
        body = json.dumps(
            {
                "output": [
                    {"type": "reasoning", "summary": []},
                    {"type": "message", "content": [{"type": "output_text", "text": "I'll edit it"}]},
                    {"type": "function_call", "call_id": "c1", "name": "edit_file", "arguments": '{"path":"a.py"}'},
                ]
            }
        ).encode()
        calls = extract_tool_calls("openai_responses", body, "application/json")
        self.assertEqual(calls, [{"id": "c1", "name": "edit_file", "arguments": '{"path":"a.py"}'}])

    def test_responses_sse_function_call_ignores_reasoning(self) -> None:
        body = b"\n".join([
            b'data: {"type":"response.reasoning.delta","delta":"hidden thought"}',
            b'data: {"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"c1","name":"deploy","arguments":""}}',
            b'data: {"type":"response.function_call_arguments.delta","call_id":"c1","delta":"{\\"environment\\":\\"staging\\"}"}',
            b"data: [DONE]",
        ])
        calls = extract_tool_calls("openai_responses", body, "text/event-stream")
        self.assertEqual(calls, [{"id": "c1", "name": "deploy", "arguments": '{"environment":"staging"}'}])


class ReviewerParserTests(unittest.TestCase):
    def test_json_code_fence_is_accepted(self) -> None:
        self.assertEqual(
            _parse_json_content('```json\n{"decision":"review"}\n```'),
            {"decision": "review"},
        )

    def test_empty_content_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty content"):
            _parse_json_content("")


if __name__ == "__main__":
    unittest.main()
