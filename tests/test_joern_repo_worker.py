import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from joern import handler_joern as h


class _Proc:
    pid = 12345
    returncode = 0

    def communicate(self, timeout=None):
        return ("ok", None)

    def kill(self):
        pass


class JoernRepoWorkerTests(unittest.TestCase):
    def test_request_propagation_is_written_and_passed_to_joern(self):
        captured = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            prop_arg = next(x for x in cmd if x.startswith("propFile="))
            captured["prop_text"] = Path(prop_arg.split("=", 1)[1]).read_text()
            return _Proc()

        with tempfile.TemporaryDirectory() as td, \
             patch.object(h, "WORK_ROOT", Path(td)), \
             patch.object(h, "JOERN_BIN", "joern-test"), \
             patch.object(h.subprocess, "Popen", side_effect=fake_popen), \
             patch.object(h, "_peak_rss_mb"), \
             patch.object(h.shutil, "rmtree"):
            result = h.run_repo_script(
                "prop-text-test", "taint", "Java",
                [{"path": "Example.java", "content": "class Example {}"}],
                spec_text="source\t-\t-\tname\t^input$\n",
                prop_text="^lib\\.copy:.*$\t1,return\n",
            )

        self.assertEqual(0, result["rc"])
        self.assertEqual("^lib\\.copy:.*$\t1,return\n", captured["prop_text"])

    def test_candidate_v2_selects_exact_fqn_script(self):
        captured = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            return _Proc()

        with tempfile.TemporaryDirectory() as td, \
             patch.object(h, "WORK_ROOT", Path(td)), \
             patch.object(h, "JOERN_BIN", "joern-test"), \
             patch.object(h, "CANDIDATES_V2_SCRIPT", "/queries/dump_candidates_v2.sc"), \
             patch.object(h.subprocess, "Popen", side_effect=fake_popen), \
             patch.object(h, "_peak_rss_mb"), \
             patch.object(h.shutil, "rmtree"):
            result = h.run_repo_script(
                "cand-v2-test", "candidates", "Java",
                [{"path": "Example.java", "content": "class Example {}"}],
                candidate_schema="v2",
            )

        self.assertEqual(0, result["rc"])
        self.assertIn("/queries/dump_candidates_v2.sc", captured["cmd"])

    def test_request_sanitizers_are_written_and_passed_to_joern(self):
        captured = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            san_arg = next(x for x in cmd if x.startswith("sanFile="))
            captured["san_text"] = Path(san_arg.split("=", 1)[1]).read_text()
            return _Proc()

        with tempfile.TemporaryDirectory() as td, \
             patch.object(h, "WORK_ROOT", Path(td)), \
             patch.object(h, "JOERN_BIN", "joern-test"), \
             patch.object(h.subprocess, "Popen", side_effect=fake_popen), \
             patch.object(h, "_peak_rss_mb"), \
             patch.object(h.shutil, "rmtree"):
            result = h.run_repo_script(
                "san-text-test", "taint", "Java",
                [{"path": "Example.java", "content": "class Example {}"}],
                spec_text="source\t-\t-\tname\t^getParameter$\n",
                san_text="encode\txss\n",
            )

        self.assertEqual(0, result["rc"])
        self.assertEqual("encode\txss\n", captured["san_text"])
        self.assertTrue(any(x.startswith("sanFile=") for x in captured["cmd"]))


if __name__ == "__main__":
    unittest.main()
