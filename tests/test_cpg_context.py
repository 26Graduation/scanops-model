import unittest
from types import SimpleNamespace
from scanops.core.cpg_context import attach

class ContextTest(unittest.TestCase):
    def test_ai_source_preserved_and_real_context_attached(self):
        finding = {'source':'qwen-semantic','line':3,'cwe':'CWE-328'}
        cpg = {'source':'cpg','line':7,'cpg_graph':{'existing':True}}
        graph = {'origin':'joern','evidence':'code-context','nodes':[{'id':'1'}]}
        def worker(mode, language, files, targets):
            self.assertEqual('context', mode)
            self.assertEqual([{'id':'0','file':'Hash.java','line':3}], targets)
            return {'data':{'contexts':[{'id':'0','graph':graph}]}}
        attach([{'path':'Hash.java','content':'code'}], [SimpleNamespace(file_path='Hash.java',findings=[finding,cpg])], worker)
        self.assertEqual('qwen-semantic', finding['source'])
        self.assertIs(graph, finding['cpg_graph'])
        self.assertEqual(3, finding['line'])
        self.assertEqual({'existing':True},cpg['cpg_graph'])
    def test_failure_preserves_finding_without_fabricated_graph(self):
        f={'source':'qwen-semantic','line':3}
        def worker(*args,**kwargs): raise TimeoutError()
        attach([{'path':'A.java'}],[SimpleNamespace(file_path='A.java',findings=[f])],worker)
        self.assertNotIn('cpg_graph',f)
        self.assertEqual('export-unavailable',f['cpg_graph_status'])
    def test_does_not_accept_unattributed_graph(self):
        f={'source':'qwen-semantic','line':3}
        attach([{'path':'A.java'}],[SimpleNamespace(file_path='A.java',findings=[f])],lambda *a,**k:{'data':{'contexts':[{'id':'0','graph':{'nodes':[1]}}]}})
        self.assertNotIn('cpg_graph', f)
