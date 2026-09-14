import json
import unittest
from unittest.mock import Mock, patch

from scanops.core import java_semantic as semantic
from scripts import api_rebuild as api


class JavaSemanticTests(unittest.TestCase):
    def finding(self, **changes):
        return {"cwe": "CWE-798", "line": 1, "confidence": "high",
                "reason": "Embedded credential", **changes}

    def test_prompt_is_target_blind(self):
        call = Mock(return_value='{"findings":[]}')
        result = semantic.review("class Demo {}", call)
        self.assertEqual("DONE", result["status"])
        self.assertEqual({"source": "class Demo {}"}, json.loads(call.call_args.args[1]))

    def test_invalid_responses_are_partial(self):
        for raw in ('{}', '{"findings":[null]}', 'not json',
                    json.dumps({"findings": [self.finding(line=True)]}),
                    json.dumps({"findings": [self.finding(line=2)]})):
            with self.subTest(raw=raw):
                self.assertEqual("PARTIAL", semantic.review("one line", Mock(return_value=raw))["status"])

    def test_large_input_is_not_silently_truncated(self):
        call = Mock(return_value='{"findings":[]}')
        result = semantic.review("abcdefghij", call, max_chars=4)
        self.assertEqual("DONE", result["status"])
        self.assertGreater(call.call_count, 1)
        self.assertEqual(0, result["windows"][0]["start_offset"])
        self.assertEqual(10, result["windows"][-1]["end_offset"])

    def test_window_lines_are_original_and_failures_are_partial(self):
        call = Mock(side_effect=['{"findings":[]}', 'invalid',
                               '{"findings":[]}'])
        result = semantic.review("abc\ndef\nghi\n", call, max_chars=5)
        self.assertEqual("PARTIAL", result["status"])
        self.assertEqual(len("abc\ndef\nghi\n"), result["windows"][-1]["end_offset"])

    def test_gate_and_duplicate_provenance(self):
        parsed = semantic.review("code", Mock(return_value=json.dumps({"findings": [
            self.finding(), self.finding(cwe="CWE-89", confidence="low")]})))
        result = semantic.merge([{"cwe": "CWE-798", "line": 1, "source": "cpg"}], parsed["findings"])
        self.assertEqual(1, len(result))
        self.assertEqual(["cpg", "qwen-semantic"], result[0]["contributors"])

    def test_api_semantics_runs_even_after_cpg_detection(self):
        joern = {"verdict": "vuln", "categories": ["CWE-78"],
                 "path": [{"line": 1, "role": "sink"}]}
        with patch.object(api, "JAVA_ENGINE", "cpg-qwen38-ensemble"), \
             patch.object(api, "META_ENABLED", False), \
             patch.object(api.graph_spec_prod, "qwen_runtime_ready", return_value=True), \
             patch.object(api.graph_spec_prod, "call_rulegen", return_value=json.dumps(
                 {"findings": [self.finding()]})) as call:
            result = api._analyze_one("Java", "code", "Demo.java", joern_override=joern)
        self.assertEqual("DONE", result.status)
        self.assertEqual(2, len(result.findings))
        self.assertEqual("CWE-78", result.vulnerability)
        call.assert_called_once()

    def test_semantic_positive_with_cpg_failure_is_still_partial(self):
        with patch.object(api, "JAVA_ENGINE", "cpg-qwen38-ensemble"), \
             patch.object(api, "META_ENABLED", False), \
             patch.object(api.graph_spec_prod, "qwen_runtime_ready", return_value=True), \
             patch.object(api.graph_spec_prod, "call_rulegen", return_value=json.dumps(
                 {"findings": [self.finding()]})):
            result = api._analyze_one("Java", "code", "Demo.java")
        self.assertTrue(result.detected)
        self.assertEqual("PARTIAL", result.status)
        self.assertEqual("semantic-review", result.findings[0]["evidence_level"])

    def test_pr_preserves_multiple_findings(self):
        request = api.PrScanRequest(repo="demo/repo", pr_number=1, files=[
            api.PrFile(filename="Demo.java", content="class Demo {}")])
        cpg = {"file": "Demo.java", "cwe": "CWE-78",
               "path": [{"line": 1, "role": "sink"}]}
        with patch.object(api, "JAVA_ENGINE", "cpg-qwen38-ensemble"), \
             patch.object(api, "META_ENABLED", False), \
             patch.object(api.graph_spec_prod, "analyze_repo", return_value=[cpg]), \
             patch.object(api.graph_spec_prod, "qwen_runtime_ready", return_value=True), \
             patch.object(api.graph_spec_prod, "call_rulegen", return_value=json.dumps(
                 {"findings": [self.finding()]})):
            result = api.analyze_pr(request, None)
        self.assertEqual(2, result.vulnerable_count)
        self.assertEqual({"CWE-78", "CWE-798"}, {r.vulnerability for r in result.findings})

    def test_pr_semantic_failure_is_not_clean(self):
        request = api.PrScanRequest(repo="demo/repo", pr_number=1, files=[
            api.PrFile(filename="Demo.java", content="class Demo {}")])
        with patch.object(api, "JAVA_ENGINE", "cpg-qwen38-ensemble"), \
             patch.object(api.graph_spec_prod, "analyze_repo", return_value=[]), \
             patch.object(api.graph_spec_prod, "qwen_runtime_ready", return_value=False):
            with self.assertRaises(api.HTTPException) as caught:
                api.analyze_pr(request, None)
        self.assertEqual(503, caught.exception.status_code)


if __name__ == "__main__":
    unittest.main()
