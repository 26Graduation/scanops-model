"""Offline deployment boundaries: all analysis and external clients are mocked."""
import unittest
from threading import BoundedSemaphore
from unittest.mock import patch

from fastapi.testclient import TestClient
from scripts import api_rebuild as api


class DeploymentGuardsTests(unittest.TestCase):
    def setUp(self):
        self.stack = []
        for name, value in (("JAVA_ONLY", True), ("_API_KEY", "test-key"),
                            ("JAVA_ENGINE", "cpg-qwen38-ensemble"),
                            ("_ANALYSIS_SLOTS", BoundedSemaphore(1))):
            p = patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.client = TestClient(api.app)
        self.headers = {"X-API-Key": "test-key"}
        self.file = {"language": "Java", "code": "class Demo {}", "file_path": "Demo.java"}
        self.requests = [('/analyze', self.file),
                         ('/analyze/batch', {"files": [self.file]}),
                         ('/analyze/pr', {"repo": "demo", "pr_number": 1,
                                          "files": [{"filename": "Demo.java", "content": "class Demo {}"}]})]

    def test_wrong_missing_and_unconfigured_keys_fail_closed(self):
        for path, body in self.requests:
            for headers in ({}, {"X-API-Key": "wrong"}):
                self.assertEqual(401, self.client.post(path, json=body, headers=headers).status_code)
        with patch.object(api, "_API_KEY", ""):
            self.assertEqual(503, self.client.post('/analyze', json=self.file).status_code)
        with patch.object(api, "JAVA_ONLY", False), patch.object(api, "_API_KEY", ""):
            api._require_api_key(None)  # preserve explicitly unconfigured legacy service

    def test_all_endpoints_share_busy_limit(self):
        api._ANALYSIS_SLOTS.acquire()
        try:
            for path, body in self.requests:
                response = self.client.post(path, json=body, headers=self.headers)
                self.assertEqual(429, response.status_code, response.text)
        finally:
            api._ANALYSIS_SLOTS.release()

    def test_limits_reject_before_analysis(self):
        with patch.object(api, '_analyze_one', side_effect=AssertionError('must not analyze')), \
             patch.object(api, 'MAX_FILE_CHARS', 5):
            for path, body in self.requests:
                self.assertEqual(413, self.client.post(path, json=body, headers=self.headers).status_code)
        with patch.object(api, 'MAX_REQUEST_FILES', 1):
            self.assertEqual(413, self.client.post('/analyze/batch', json={'files': [self.file] * 2}, headers=self.headers).status_code)
        with patch.object(api, 'MAX_TOTAL_CHARS', 20):
            self.assertEqual(413, self.client.post('/analyze/batch', json={'files': [self.file] * 2}, headers=self.headers).status_code)

    def test_non_java_rejected_before_calls(self):
        with patch.object(api, '_analyze_one', side_effect=AssertionError('must not analyze')):
            self.assertEqual(422, self.client.post('/analyze', json={**self.file, 'language': 'Python'}, headers=self.headers).status_code)
            self.assertEqual(422, self.client.post('/analyze/pr', json={'repo': 'demo', 'pr_number': 1, 'files': [{'filename': 'demo.py', 'content': 'print(1)'}]}, headers=self.headers).status_code)

    def test_file_failures_are_not_clean_and_release_slot(self):
        with patch.object(api.graph_spec_prod, 'analyze_repo', return_value=[]), \
             patch.object(api, '_analyze_one', side_effect=RuntimeError('failed')):
            for path, body in self.requests:
                response = self.client.post(path, json=body, headers=self.headers)
                self.assertIn(response.status_code, (502, 503))
                self.assertTrue(api._ANALYSIS_SLOTS.acquire(blocking=False))
                api._ANALYSIS_SLOTS.release()

    def test_single_request_receives_complete_original_source(self):
        code = 'class Demo {\n' + '// retained\n' * 1000 + '}\n'
        result = api.AnalyzeResponse(language='Java', file_path='Demo.java', detected=False,
                                     vulnerability='NONE', severity='NONE', elapsed=0)
        with patch.object(api.graph_spec_prod, 'analyze_repo', return_value=[]) as graph, \
             patch.object(api, '_analyze_one', return_value=result) as analyze:
            response = self.client.post('/analyze', json={**self.file, 'code': code}, headers=self.headers)
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(code, graph.call_args.args[0][0]['content'])
        self.assertEqual(code, analyze.call_args.args[1])


if __name__ == '__main__':
    unittest.main()
