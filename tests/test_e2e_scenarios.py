import os
import unittest
from unittest.mock import patch

from automode_gateway.normalizer import normalize
from automode_gateway.pipeline import DecisionPipeline
from automode_gateway.rule_compiler import compile_rule


ENV = {
    "AUTOMODE_FAST_URL": "http://fast.test/v1/chat/completions", "AUTOMODE_FAST_MODEL": "fast",
    "AUTOMODE_DEEP_URL": "http://deep.test/v1/chat/completions", "AUTOMODE_DEEP_MODEL": "deep",
}


def req(text):
    return normalize({"model": "agent", "messages": [{"role": "user", "content": text}]}, source_format_override="openai_chat_completions")


def allow(*_):
    return {"decision": "allow", "risk": "low", "action_alignment": "aligned", "reason_code": "AUTHORIZED", "reason": "用户明确授权该动作"}


def reject(code="OUT_OF_SCOPE", reason="动作超出用户授权范围", risk="high", alignment="out_of_scope"):
    return lambda *_: {"decision": "reject", "risk": risk, "action_alignment": alignment, "reason_code": code, "reason": reason}


def uncertain(*_):
    return {"decision": "uncertain", "risk": "medium", "action_alignment": "ambiguous", "reason_code": "UNCERTAIN", "reason": "需要深入判断"}


class EndToEndScenarios(unittest.TestCase):
    def test_e2e_001_explicit_read_only(self):
        called = []
        result = DecisionPipeline(lambda *_: called.append(1), lambda *_: called.append(2)).classify(
            req("查看仓库状态，不要修改任何内容。"),
            [{"name": "Bash", "arguments": {"command": "git status"}}],
        )
        self.assertEqual((result.final_decision, result.final_stage), ("allow", "rules"))
        self.assertEqual(called, [])

    @patch.dict(os.environ, ENV, clear=False)
    def test_e2e_002_explicit_constraint_violation(self):
        deep = reject("ACTION_CONTRADICTS_USER_CONSTRAINT", "用户明确要求不要 push", "high", "contradicted")
        result = DecisionPipeline(reject(), deep).classify(req("检查并修复代码，但不要 push。"), [{"name": "Bash", "arguments": {"command": "git push origin main"}}])
        self.assertEqual(result.final_decision, "alert")
        self.assertEqual(result.action_alignment, "contradicted")
        self.assertIn("不要 push", result.reason)

    @patch.dict(os.environ, ENV, clear=False)
    def test_e2e_003_question_is_not_execution_authorization(self):
        deep = reject("QUESTION_NOT_EXECUTION_AUTHORIZATION", "用户只是在询问可能性，并未授权执行删除", "critical", "out_of_scope")
        result = DecisionPipeline(uncertain, deep).classify(req("能不能删除这个生产数据库？"), [{"name": "database_delete", "arguments": {"database": "production"}}])
        self.assertEqual(result.final_decision, "alert")
        self.assertIn("询问", result.reason)

    @patch.dict(os.environ, ENV, clear=False)
    def test_e2e_004_ambiguous_inspection_escalates_through_deep(self):
        result = DecisionPipeline(uncertain, reject("EXECUTION_NOT_AUTHORIZED", "查看状态不等于授权运行测试")).classify(
            req("帮我看看这个项目现在是什么状态。"), [{"name": "Bash", "arguments": {"command": "npm test"}}]
        )
        self.assertEqual([stage.stage for stage in result.stages], ["rules", "fast_llm", "deep_llm"])
        self.assertEqual(result.final_decision, "alert")
        self.assertTrue(result.reason)

    def test_e2e_005_explicit_test_authorization(self):
        result = DecisionPipeline().classify(req("运行项目测试并告诉我失败原因。"), [{"name": "Bash", "arguments": {"command": "npm test"}}])
        self.assertEqual(result.final_decision, "allow")
        self.assertEqual(result.action_alignment, "aligned")

    @patch.dict(os.environ, ENV, clear=False)
    def test_e2e_006_environment_scope_crossing(self):
        deep = reject("ENVIRONMENT_NOT_AUTHORIZED", "用户只授权 staging，动作目标却是 production", "critical", "out_of_scope")
        result = DecisionPipeline(uncertain, deep).classify(req("部署 staging。"), [{"name": "deploy", "arguments": {"environment": "production"}}])
        self.assertEqual(result.final_decision, "alert")
        self.assertEqual(result.reason_code, "ENVIRONMENT_NOT_AUTHORIZED")

    @patch.dict(os.environ, ENV, clear=False)
    def test_e2e_007_external_data_exfiltration(self):
        deep = reject("SENSITIVE_DATA_EXFILTRATION", "配置和 Token 将被上传到外部地址", "critical", "high_impact")
        result = DecisionPipeline(uncertain, deep).classify(req("分析本地配置。"), [{"name": "upload_config", "arguments": {"url": "https://external.test", "token": "[REDACTED]"}}])
        self.assertEqual(result.final_decision, "alert")
        self.assertEqual(result.risk, "critical")

    @patch.dict(os.environ, ENV, clear=False)
    def test_e2e_008_multiple_actions_are_all_normalized(self):
        actions = [
            {"name": "Bash", "arguments": {"command": "git status"}},
            {"name": "edit_file", "arguments": {"path": "app.py"}},
            {"name": "Bash", "arguments": {"command": "git push origin main"}},
        ]
        result = DecisionPipeline(uncertain, reject("PUBLISH_REQUIRES_REVIEW", "git push 触发外部状态变更", "high", "high_impact")).classify(req("修复代码。"), actions)
        self.assertEqual(len(result.proposed_actions), 3)
        self.assertEqual([item["capability"] for item in result.proposed_actions], ["read", "write", "publish"])
        self.assertEqual(result.risk, "high")
        self.assertIn("git push", result.reason)

    @patch.dict(os.environ, ENV, clear=False)
    def test_e2e_009_both_classifiers_unavailable_is_alert(self):
        def broken(*_):
            raise TimeoutError("unavailable")
        result = DecisionPipeline(broken, broken).classify(req("帮我看看项目状态"), [{"name": "Bash", "arguments": {"command": "npm test"}}])
        self.assertEqual(result.final_decision, "alert")
        self.assertEqual(result.reason_code, "DEEP_CLASSIFIER_UNAVAILABLE")

    @patch.dict(os.environ, ENV, clear=False)
    def test_e2e_010_enabled_natural_language_rule_short_circuits_llm(self):
        compiled = compile_rule("所有 production 部署都直接告警。")
        rule = {**compiled, "id": "prod-rule", "version": 1}
        def no_call(*_): self.fail("LLM must not run")
        result = DecisionPipeline(no_call, no_call).classify(req("部署 production"), [{"name": "deploy", "arguments": {"environment": "production"}}], [rule])
        self.assertEqual((result.final_decision, result.final_stage), ("alert", "rules"))
        self.assertEqual(result.matched_rules, ["prod-rule:1"])


if __name__ == "__main__":
    unittest.main()
