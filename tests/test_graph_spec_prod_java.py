import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scanops.core import graph_spec_prod as g


class GraphSpecJavaTests(unittest.TestCase):
    def test_language_context_is_not_jsts_for_java(self):
        self.assertEqual(("JAVASRC", "Java"), g.language_context("Java Spring Boot"))
        self.assertEqual(("JSSRC", "TypeScript/JavaScript"), g.language_context("Node.js / Express"))
        self.assertEqual("calls", g.source_mode("JAVASRC"))
        self.assertEqual("params", g.source_mode("JSSRC"))

    def test_java_uses_java_base_spec_not_jsts_hand_rules(self):
        spec = g.base_spec_text("JAVASRC")
        self.assertIn("ProcessBuilder\\.<init>", spec)
        self.assertIn("\tCWE-327\targ_literal\t^getInstance$\t(?i)DES|DESede", spec)
        self.assertIn("sink\txss\tCWE-79\tcode", spec)
        self.assertNotIn("sink\tsensitive\tCWE-319\tname\tprintln", spec)
        self.assertNotIn("sink\tinfoexpose\tCWE-526\tname\tprintln", spec)
        self.assertNotIn("dangerouslySetInnerHTML", spec)
        self.assertEqual([], g.hand_rules("JAVASRC"))
        sanitizers = g.sanitizer_spec_text("JAVASRC")
        self.assertIn("pathtraver,pathtraversal", sanitizers)

    def test_multi_cwe_category_preserves_valid_specific_cwe(self):
        rule = {"role": "sink", "cat": "weakcrypto", "cwe": "CWE-338",
                "match": "exists", "pattern": "^random$"}
        good = g.validate([rule], set())
        self.assertEqual("CWE-338", good[0]["cwe"])
        self.assertIn("weakcrypto\tCWE-338", g.to_tsv(good))

    def test_invalid_category_cwe_pair_is_rejected(self):
        rule = {"role": "sink", "cat": "weakcrypto", "cwe": "CWE-89",
                "match": "exists", "pattern": "^random$"}
        self.assertEqual([], g.validate([rule], set()))

    def test_arg_count_reaches_sixth_tsv_column(self):
        rule = {"role": "sink", "cat": "obsolete", "cwe": "CWE-477",
                "match": "arg_count", "pattern": "^encode$", "arg_count": 1}
        good = g.validate([rule], set())
        self.assertEqual(1, good[0]["arg_count"])
        self.assertIn("arg_count\t^encode$\t1", g.to_tsv(good))

    def test_cache_isolated_by_frontend(self):
        rule = {"role": "sink", "cat": "sqli", "cwe": "CWE-89",
                "match": "name", "pattern": "^execute$",
                "_candidate": {"kind": "call", "name": "execute", "n": 1}}
        with tempfile.TemporaryDirectory() as td:
            cache_path = Path(td) / "cache.json"
            with patch.object(g, "API_CACHE_PATH", cache_path):
                g.update_api_cache([rule], "test", "JAVASRC")
                cache = json.loads(cache_path.read_text())
        self.assertIn("JAVASRC:call:execute", cache)
        self.assertNotIn("JSSRC:call:execute", cache)

    def test_none_role_is_valid_and_cached_but_not_emitted(self):
        rule = {"role": "none", "match": "name", "pattern": "^getWriter$",
                "_candidate": {"kind": "call", "name": "getWriter", "n": 1}}
        good = g.validate([rule], set())
        self.assertEqual(1, len(good))
        self.assertEqual("\n", g.to_tsv(good))
        with tempfile.TemporaryDirectory() as td:
            cache_path = Path(td) / "cache.json"
            with patch.object(g, "API_CACHE_PATH", cache_path):
                g.update_api_cache(good, "test", "JAVASRC")
                cache = json.loads(cache_path.read_text())
        self.assertEqual("none", cache["JAVASRC:call:getWriter"]["role"])

    def test_qwen38_dashscope_payload(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"choices": [{"message": {"content": "[]"}}]}
        with patch.object(g, "DASHSCOPE_API_KEY", "test-key"), \
             patch.object(g.requests, "post", return_value=response) as post:
            self.assertEqual("[]", g.call_rulegen("system", "user", 100))
        payload = post.call_args.kwargs["json"]
        self.assertEqual("qwen3.8-max", payload["model"])
        self.assertEqual("system", payload["messages"][0]["content"])
        self.assertEqual("user", payload["messages"][1]["content"])


if __name__ == "__main__":
    unittest.main()
