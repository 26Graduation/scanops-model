import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scanops.core import graph_spec_prod as g


class GraphSpecJavaTests(unittest.TestCase):
    def test_fresh_candidate_default_is_unlimited(self):
        self.assertEqual(0, g.MAX_FRESH_ITEMS)

    def test_rulegen_default_uses_g1_verified_batch_size(self):
        self.assertEqual(20, g.RULEGEN_BATCH)
        self.assertEqual(600, g.RULEGEN_TIMEOUT)

    def test_unpromoted_dynamic_rules_are_shadow_only(self):
        rule = {"role": "sink", "cat": "cmdi", "cwe": "CWE-78",
                "match": "name", "pattern": "^danger$"}
        with patch.object(g, "DYNAMIC_RULE_MODE", "shadow"):
            shadow = g.compose_spec_text("JAVASRC", [rule])
        with patch.object(g, "DYNAMIC_RULE_MODE", "enforce"):
            enforced = g.compose_spec_text("JAVASRC", [rule])
        self.assertNotIn("^danger$", shadow)
        self.assertIn("^danger$", enforced)

    def test_partial_rulegen_response_retries_only_missing_ids(self):
        items = [
            {"id": 0, "kind": "call", "name": "first", "fulls": [], "n": 1,
             "snippets": []},
            {"id": 1, "kind": "call", "name": "second", "fulls": [], "n": 1,
             "snippets": []},
        ]
        responses = [
            '[{"id":0,"role":"none","match":"name","pattern":"^first$"}]',
            '[{"id":1,"role":"none","match":"name","pattern":"^second$"}]',
        ]
        with patch.object(g, "RULEGEN_BATCH", 20), \
             patch.object(g, "LLM_MAX_WORKERS", 1), \
             patch.object(g, "call_rulegen", side_effect=responses) as call:
            result = g.label_items(items, "Java")
        self.assertEqual({0, 1}, {x["id"] for x in result})
        self.assertEqual(2, call.call_count)
        self.assertIn('"id": 1', call.call_args.args[1])
        self.assertNotIn('"id": 0', call.call_args.args[1])

    def test_java_rulegen_drops_property_writes_and_resolved_local_calls(self):
        candidates = {
            "calls": [
                {"name": "localRun", "n": 1,
                 "fulls": [{"full": "demo.Service.localRun:void()", "n": 1}],
                 "codes": ["service.localRun()"]},
                {"name": "exec", "n": 1,
                 "fulls": [{"full": "java.lang.Runtime.exec:java.lang.Process(java.lang.String)",
                             "n": 1}], "codes": ["runtime.exec(cmd)"]},
                {"name": "mystery", "n": 1,
                 "fulls": [{"full": "<unresolvedNamespace>.mystery:ANY()", "n": 1}],
                 "codes": ["mystery(value)"]},
            ],
            "assigns": [{"field": "body", "n": 1, "codes": ["this.body = body"]}],
        }
        files = [{"path": "Service.java", "content": "package demo; class Service {}"}]
        java_items = g.build_items(candidates, "JAVASRC", files)
        self.assertEqual({"exec", "mystery"}, {item["name"] for item in java_items})
        js_items = g.build_items(candidates, "JSSRC", files)
        self.assertEqual(4, len(js_items))

    def test_v2_candidates_split_exact_fqn_and_keep_endpoint_context(self):
        files = [{"path": "src/demo/Web.java", "content": (
            "package demo;\nclass Web {\n  void x(String cmd) {\n"
            "    Runtime.getRuntime().exec(cmd);\n  }\n}\n")}]
        candidates = {"calls": [{
            "name": "exec", "method_full_name":
                "java.lang.Runtime.exec:java.lang.Process(java.lang.String)",
            "signature": "java.lang.Process(java.lang.String)",
            "return_type": "java.lang.Process", "resolved": True, "occurrences": 1,
            "sites": [{"file": "src/demo/Web.java", "line": 4,
                       "code": "Runtime.getRuntime().exec(cmd)",
                       "arguments": [{"index": 1, "type": "", "code": "cmd"}],
                       "enclosing_method": "x"}],
        }], "internal_methods": []}
        items = g.build_items_v2(candidates, files)
        self.assertEqual(1, len(items))
        self.assertEqual("call_v2", items[0]["kind"])
        self.assertTrue(items[0]["resolved"])
        self.assertIn("4:     Runtime", items[0]["sites"][0]["context"])
        rendered = json.loads(g.fmt_item_v2(items[0]))
        self.assertEqual(
            "^java\\.lang\\.Runtime\\.exec:java\\.lang\\.Process\\(java\\.lang\\.String\\)$",
            rendered["required_exact_pattern"])

    def test_v2_exact_high_confidence_endpoint_is_enforce_eligible(self):
        full = "java.lang.Runtime.exec:java.lang.Process(java.lang.String)"
        rule = {"role": "sink", "cat": "cmdi", "cwe": "CWE-78",
                "match": "full", "pattern": g._exact_pattern(full),
                "endpoint": "arg:1", "confidence": "high",
                "_candidate": {"kind": "call_v2", "name": full, "n": 1,
                               "resolved": True, "method_full_name": full}}
        good = g.validate([rule], set())
        self.assertTrue(good[0]["_enforce_eligible"])
        row = g.to_tsv(good)
        self.assertIn("\t\targ:1\tqwen38.", row)

    def test_v2_unresolved_or_widened_rule_is_shadow_only(self):
        full = "<unresolvedNamespace>.exec:<unresolvedSignature>(1)"
        rule = {"role": "sink", "cat": "cmdi", "cwe": "CWE-78",
                "match": "full", "pattern": "^.*exec.*$", "endpoint": "arg:1",
                "confidence": "high", "_candidate": {"kind": "call_v2",
                "name": full, "n": 1, "resolved": False, "method_full_name": full}}
        good = g.validate([rule], set())
        self.assertFalse(good[0]["_enforce_eligible"])
        with patch.object(g, "DYNAMIC_RULE_MODE", "enforce"):
            self.assertNotIn("^.*exec.*$", g.compose_spec_text("JAVASRC", good))

    def test_v2_sanitizer_and_propagation_are_separate_serializers(self):
        common = {"match": "full", "pattern": "^lib\\.Codec\\.clean:.*$",
                  "_candidate": {"resolved": True}, "_enforce_eligible": True,
                  "rule_id": "r1"}
        sanitizer = {**common, "role": "sanitizer", "applies_to": ["xss"]}
        propagator = {**common, "role": "propagator",
                      "propagation": [{"from": 1, "to": "return"}]}
        self.assertEqual("dynamic.r1\txss\t^lib\\.Codec\\.clean:.*$\n",
                         g.to_sanitizer_tsv([sanitizer]))
        self.assertEqual("^lib\\.Codec\\.clean:.*$\t1,return\n",
                         g.to_propagation_tsv([propagator]))

    def test_language_context_is_not_jsts_for_java(self):
        self.assertEqual(("JAVASRC", "Java"), g.language_context("Java Spring Boot"))
        self.assertEqual(("JSSRC", "TypeScript/JavaScript"), g.language_context("Node.js / Express"))
        self.assertEqual("java", g.source_mode("JAVASRC"))
        self.assertEqual("params", g.source_mode("JSSRC"))

    def test_java_uses_java_base_spec_not_jsts_hand_rules(self):
        spec = g.base_spec_text("JAVASRC")
        self.assertIn("ProcessBuilder\\.<init>", spec)
        self.assertIn("ClassLoader|Class", spec)
        self.assertIn("buildConstraintViolationWithTemplate", spec)
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
        self.assertIs(payload["enable_thinking"], False)
        self.assertEqual("system", payload["messages"][0]["content"])
        self.assertEqual("user", payload["messages"][1]["content"])

    def test_strict_mode_exposes_unavailable_runtime(self):
        files = [{"path": "Demo.java", "content": "class Demo {}"}]
        with patch.object(g, "ENABLED", True), \
             patch.object(g, "JOERN_HTTP_URL", ""), \
             patch.object(g, "RUNPOD_API_KEY", ""), \
             patch.object(g, "JOERN_ENDPOINT_ID", ""), \
             patch.object(g, "DASHSCOPE_API_KEY", ""):
            self.assertEqual([], g.analyze_repo(files, "Java"))
            with self.assertRaisesRegex(RuntimeError, "CPG runtime is not ready"):
                g.analyze_repo(files, "Java", strict=True)

    def test_shadow_fixed_java_runs_without_dashscope_or_candidate_pass(self):
        files = [{"path": "Demo.java", "content": "class Demo {}"}]
        taint_result = {"data": {"findings": [{
            "file": "Demo.java", "line": 1, "category": "cmdi", "cwe": "CWE-78",
            "sink": "exec(input)", "source": "input", "source_line": 1,
            "source_file": "Demo.java", "path": [],
        }]}}
        with patch.object(g, "ENABLED", True), \
             patch.object(g, "JOERN_HTTP_URL", "http://joern.test"), \
             patch.object(g, "DASHSCOPE_API_KEY", ""), \
             patch.object(g, "RULEGEN_ENABLED", True), \
             patch.object(g, "CRITIC_ENABLED", False), \
             patch.object(g, "DYNAMIC_RULE_MODE", "shadow"), \
             patch.object(g, "call_joern_repo", return_value=taint_result) as joern:
            findings = g.analyze_repo(files, "Java", strict=True)
        self.assertEqual(1, len(findings))
        self.assertEqual("taint", joern.call_args.args[0])
        self.assertEqual(1, joern.call_count)
        self.assertIn("ProcessBuilder\\.<init>", joern.call_args.kwargs["spec_text"])

    def test_rulegen_and_critic_have_independent_effective_flags(self):
        with patch.object(g, "DASHSCOPE_API_KEY", "key"), \
             patch.object(g, "LLM_MODEL", "qwen3.8-max"), \
             patch.object(g, "RULEGEN_ENABLED", False), \
             patch.object(g, "CRITIC_ENABLED", True):
            meta = g.runtime_metadata()
        self.assertFalse(meta["fixed_rules_require_qwen"])
        self.assertFalse(meta["rulegen"]["effective"])
        self.assertTrue(meta["critic"]["effective"])

    def test_enforce_can_use_cache_only_with_rulegen_disabled(self):
        files = [{"path": "Demo.java", "content": "class Demo {}"}]
        candidate_result = {"data": {"calls": [{
            "name": "danger", "n": 1, "fulls": [], "codes": ["danger(value)"],
        }], "assigns": []}}
        taint_result = {"data": {"findings": []}}
        cached = {"JAVASRC:call:danger": {
            "role": "sink", "cat": "cmdi", "cwe": "CWE-78",
            "match": "name", "pattern": "^danger$",
        }}
        with patch.object(g, "ENABLED", True), \
             patch.object(g, "JOERN_HTTP_URL", "http://joern.test"), \
             patch.object(g, "DASHSCOPE_API_KEY", ""), \
             patch.object(g, "RULEGEN_ENABLED", False), \
             patch.object(g, "CRITIC_ENABLED", False), \
             patch.object(g, "DYNAMIC_RULE_MODE", "enforce"), \
             patch.object(g, "load_api_cache", return_value=cached), \
             patch.object(g, "call_rulegen") as qwen, \
             patch.object(g, "call_joern_repo", side_effect=[candidate_result, taint_result]) as joern:
            self.assertEqual([], g.analyze_repo(files, "Java", strict=True))
        qwen.assert_not_called()
        self.assertEqual(["candidates", "taint"], [c.args[0] for c in joern.call_args_list])
        self.assertIn("^danger$", joern.call_args_list[1].kwargs["spec_text"])

    def test_enabled_critic_without_qwen_is_fail_open_in_non_strict_mode(self):
        files = [{"path": "Demo.java", "content": "class Demo {}"}]
        taint_result = {"data": {"findings": [{
            "file": "Demo.java", "line": 1, "category": "cmdi", "cwe": "CWE-78",
            "sink": "exec(input)", "source": "input", "source_line": 1,
            "source_file": "Demo.java", "path": [],
        }]}}
        with patch.object(g, "ENABLED", True), \
             patch.object(g, "JOERN_HTTP_URL", "http://joern.test"), \
             patch.object(g, "DASHSCOPE_API_KEY", ""), \
             patch.object(g, "RULEGEN_ENABLED", False), \
             patch.object(g, "CRITIC_ENABLED", True), \
             patch.object(g, "DYNAMIC_RULE_MODE", "shadow"), \
             patch.object(g, "call_rulegen") as qwen, \
             patch.object(g, "call_joern_repo", return_value=taint_result):
            findings = g.analyze_repo(files, "Java")
        self.assertEqual(1, len(findings))
        qwen.assert_not_called()

    def test_candidate_transport_failure_does_not_block_non_strict_fixed_taint(self):
        files = [{"path": "Demo.java", "content": "class Demo {}"}]
        taint_result = {"data": {"findings": []}}
        with patch.object(g, "ENABLED", True), \
             patch.object(g, "JOERN_HTTP_URL", "http://joern.test"), \
             patch.object(g, "DASHSCOPE_API_KEY", "key"), \
             patch.object(g, "RULEGEN_ENABLED", True), \
             patch.object(g, "CRITIC_ENABLED", False), \
             patch.object(g, "DYNAMIC_RULE_MODE", "shadow"), \
             patch.object(g, "call_joern_repo", side_effect=[OSError("offline"), taint_result]) as joern:
            self.assertEqual([], g.analyze_repo(files, "Java"))
        self.assertEqual(["candidates", "taint"], [c.args[0] for c in joern.call_args_list])

    def test_critic_false_requires_high_confidence_shown_basis_line(self):
        finding = {"line": 20, "source_line": 5}
        self.assertTrue(g._critic_false_is_grounded(finding, {
            "verdict": "FALSE", "confidence": "high", "basis_line": 18,
            "reason": "allow-list check rejects unsafe input",
        }))
        self.assertFalse(g._critic_false_is_grounded(finding, {
            "verdict": "FALSE", "confidence": "med", "basis_line": 18,
            "reason": "allow-list check rejects unsafe input",
        }))
        self.assertFalse(g._critic_false_is_grounded(finding, {
            "verdict": "FALSE", "confidence": "high", "basis_line": 100,
            "reason": "line was not in the supplied evidence",
        }))

    def test_critic_v2_keeps_both_ends_and_rule_endpoint(self):
        path = [{"role": "source" if i == 0 else "sink" if i == 19 else "intermediate",
                 "file": "Demo.java", "line": i + 1, "code": f"step{i}()"}
                for i in range(20)]
        finding = {"_uid": 7, "_dup_count": 1, "category": "cmdi", "cwe": "CWE-78",
                   "file": "Demo.java", "line": 20, "sink": "exec(cmd)",
                   "source_file": "Demo.java", "source_line": 1, "source": "cmd",
                   "source_kind": "internal_parameter", "path": path,
                   "rule_id": "qwen38.test", "rule_pattern": "^Runtime.exec$",
                   "rule_field": "full", "rule_endpoint": "arg:1"}
        rendered = g._fmt_finding(finding, {"Demo.java": "\n".join("x" for _ in range(25))})
        obj = json.loads(rendered.split("\n", 1)[0])
        self.assertEqual(10, len(obj["flow"]))
        self.assertEqual(1, obj["flow"][0]["line"])
        self.assertEqual(20, obj["flow"][-1]["line"])
        self.assertEqual("arg:1", obj["rule"]["endpoint"])
        self.assertEqual("OS command injection", obj["cwe_description"])


if __name__ == "__main__":
    unittest.main()
