import unittest
from unittest.mock import patch

try:
    from scripts import api_rebuild as api
except ModuleNotFoundError as exc:
    if exc.name != "fastapi":
        raise
    api = None


@unittest.skipIf(api is None, "FastAPI is not installed in this test environment")
class JavaCpgPrimaryApiTests(unittest.TestCase):
    def test_java_cpg_verdict_does_not_call_legacy_classifier(self):
        joern = {
            "verdict": "vuln", "categories": ["CWE-78"],
            "path": [{"line": 4, "code": "cmd", "role": "source"},
                     {"line": 8, "code": "Runtime.exec(cmd)", "role": "sink"}],
        }
        with patch.object(api, "JAVA_ENGINE", "cpg-qwen38"), \
             patch.object(api, "_detect", side_effect=AssertionError("legacy LLM called")):
            result = api._analyze_one("Java", "class Demo {}", "Demo.java",
                                      joern_override=joern)
        self.assertTrue(result.detected)
        self.assertEqual("CWE-78", result.vulnerability)
        self.assertEqual("cpg+qwen3.8-max", result.source)
        self.assertEqual({"cpg_qwen38": True}, result.votes)

    def test_unavailable_java_cpg_is_partial_not_legacy_fallback(self):
        with patch.object(api, "JAVA_ENGINE", "cpg-qwen38"), \
             patch.object(api, "_detect", side_effect=AssertionError("legacy LLM called")):
            result = api._analyze_one("Java", "class Demo {}", "Demo.java")
        self.assertFalse(result.detected)
        self.assertEqual("PARTIAL", result.status)
        self.assertEqual("cpg+qwen3.8-max", result.source)

    def test_stop_on_first_batch_still_runs_java_repository_cpg(self):
        request = api.BatchRequest(files=[
            api.AnalyzeRequest(language="Java", code="class Demo {}", file_path="Demo.java")
        ], stop_on_first=True)
        finding = {"file": "Demo.java", "cwe": "CWE-78", "category": "cmdi",
                   "path": [{"line": 1, "role": "sink", "code": "exec(x)"}]}
        with patch.object(api, "JAVA_ENGINE", "cpg-qwen38"), \
             patch.object(api.graph_spec_prod, "analyze_repo", return_value=[finding]) as graph, \
             patch.object(api, "_detect", side_effect=AssertionError("legacy LLM called")):
            result = api.analyze_batch(request, None)
        graph.assert_called_once()
        self.assertEqual(1, result.detected_count)
        self.assertEqual("CWE-78", result.results[0].vulnerability)

    def test_java_pr_cpg_failure_is_not_reported_as_clean(self):
        request = api.PrScanRequest(repo="demo/repo", pr_number=1, files=[
            api.PrFile(filename="Demo.java", content="class Demo {}")
        ])
        with patch.object(api, "JAVA_ENGINE", "cpg-qwen38"), \
             patch.object(api.graph_spec_prod, "analyze_repo",
                          side_effect=RuntimeError("unavailable")):
            with self.assertRaises(api.HTTPException) as raised:
                api.analyze_pr(request, None)
        self.assertEqual(503, raised.exception.status_code)


if __name__ == "__main__":
    unittest.main()
