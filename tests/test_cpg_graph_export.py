"""Opt-in integration test: SCANOPS_TEST_JOERN=1 python -m unittest tests.test_cpg_graph_export.
Runs the real analyzer; no LLM, network service, or inferred graph edges.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.getenv('SCANOPS_TEST_JOERN') == '1', 'requires local Joern')
class CpgGraphExportTest(unittest.TestCase):
    def test_real_cpg_direct_nested_input_and_callsite(self):
        code = '''import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
class Demo {
 void render(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  resp.getWriter().println(req.getParameter("q"));
 }
 void dangerous() { System.loadLibrary("unsafe"); }
}'''
        with tempfile.TemporaryDirectory(prefix='scanops-cpg-test-') as directory:
            work = Path(directory)
            (work / 'input').mkdir()
            (work / 'input' / 'Demo.java').write_text(code)
            spec = work / 'rules.tsv'
            spec.write_text('source\t-\t-\tname\tgetParameter\n'
                            'sink\txss\tCWE-79\tname\tprintln\n'
                            'sink\tunsafe\tCWE-114\texists\tloadLibrary\n')
            output = work / 'result.json'
            result = subprocess.run([
                os.getenv('JOERN_BIN', 'joern'), '--script', str(ROOT / 'joern/queries/taint_spec.sc'),
                '--param', f'inDir={work / "input"}', '--param', 'lang=JAVASRC',
                '--param', f'outFile={output}', '--param', f'specFile={spec}',
                '--param', 'srcMode=calls',
            ], cwd=work, capture_output=True, text=True, timeout=180)
            self.assertEqual(0, result.returncode, result.stdout[-5000:] + result.stderr[-5000:])
            data = json.loads(output.read_text())
            self.assertEqual([], data['rule_errors'])
            self.assertEqual({'CWE-79', 'CWE-114'}, {f['cwe'] for f in data['findings']})
            for finding in data['findings']:
                graph = finding['cpg_graph']
                self.assertEqual(2, graph['version'])
                self.assertLessEqual(len(graph['nodes']), 64)
                self.assertLessEqual(len(graph['edges']), 256)
                ids = {n['id'] for n in graph['nodes']}
                self.assertEqual(len(ids), len(graph['nodes']))
                for edge in graph['edges']:
                    self.assertIn(edge['source'], ids)
                    self.assertIn(edge['target'], ids)
                    self.assertIn(edge['kind'], {'AST', 'CFG', 'REACHING_DEF'})
                for node in graph['nodes']:
                    self.assertEqual('Demo.java', node['file'])
                    self.assertTrue(0 < node['line'] <= len(code.splitlines()))
                if finding['cwe'] == 'CWE-79':
                    source = next(n for n in graph['nodes'] if n['role'] == 'source')
                    sink = next(n for n in graph['nodes'] if n['role'] == 'sink')
                    self.assertNotEqual(source['id'], sink['id'])
                    self.assertIn({'source': source['id'], 'target': sink['id'], 'kind': 'REACHING_DEF'}, graph['edges'])
                    self.assertIn({'source': sink['id'], 'target': source['id'], 'kind': 'AST'}, graph['edges'])
                else:
                    self.assertFalse(any(n['role'] == 'source' for n in graph['nodes']))
                    self.assertTrue(any(n['role'] == 'sink' for n in graph['nodes']))

    def test_semantic_context_uses_real_nodes_without_claiming_taint(self):
        from joern.handler_joern import run_repo_script
        code = """import java.security.MessageDigest;
class HashDemo {

    // Password hashing example
    String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return new String(md.digest(password.getBytes()));
    }
}"""
        result = run_repo_script('context-integration', 'context', 'Java',
            [{'path':'HashDemo.java','content':code}], targets=[
              {'id':'blank','file':'HashDemo.java','line':3},
              {'id':'exact','file':'HashDemo.java','line':7},
              {'id':'missing','file':'HashDemo.java','line':100}])
        self.assertEqual(0, result['rc'], result.get('stdout_tail'))
        contexts = {c['id']:c['graph'] for c in result['data']['contexts']}
        self.assertIsNone(contexts['missing'])
        self.assertEqual(6, contexts['blank']['anchorLine'])
        self.assertEqual(7, contexts['exact']['anchorLine'])
        for graph in (contexts['blank'], contexts['exact']):
            self.assertEqual('joern', graph['origin'])
            self.assertEqual('code-context', graph['evidence'])
            self.assertGreater(len(graph['nodes']), 1)
            self.assertGreater(len(graph['edges']), 0)
            self.assertEqual({'intermediate'}, {n['role'] for n in graph['nodes']})
            ids = {n['id'] for n in graph['nodes']}
            self.assertTrue(all(e['source'] in ids and e['target'] in ids for e in graph['edges']))
