import json
import unittest
from unittest.mock import Mock, patch
from scanops.core import java_resource_context as rc
from scripts import api_rebuild as api

class ResourceContextTests(unittest.TestCase):
    def files(self, isolated=False, cleanup=False):
        expr='root.child(s.getKey())' if isolated else 'root.child("shared")'
        return [{'path':'Flow.java','content':'''class Flow {
 void run(SCM s, FilePath root) {
  SCMStep worker = new GenericSCMStep(s);
  FilePath dir = Paths.destination(root, s);
  '''+('dir.deleteRecursive();' if cleanup else '')+'''
  worker.checkout(build, dir, listener, launcher);
 }
}'''}, {'path':'Paths.java','content':'class Paths { static FilePath destination(FilePath root, SCM s) { return '+expr+'; } }'}]

    def test_cross_file_complete_methods_and_original_lines(self):
        c=rc.collect(self.files()); self.assertEqual('DONE',c['status']);x=c['candidates'][0]
        self.assertEqual(6,x['line']);self.assertEqual('s',x['resource_identity']);self.assertEqual('dir',x['workspace'])
        self.assertEqual({'Flow.java','Paths.java'},{m['file'] for m in x['methods']})
        self.assertEqual([], c.get('findings',[])) # collection never claims a vulnerability

    def test_isolation_and_cleanup_are_preserved_not_blindly_suppressed(self):
        for isolated,cleanup in [(True,False),(False,True)]:
            c=rc.collect(self.files(isolated,cleanup))['candidates'][0]
            source='\n'.join(m['source'] for m in c['methods'])
            self.assertIn('getKey()' if isolated else 'deleteRecursive()',source)

    def test_comments_and_unmodeled_checkout_do_not_create_candidates(self):
        for source in ['class A { /* x.checkout(a,b,c,d); */ }',
                       'class A { void f(){ something.checkout(a,b,c,d); } }']:
            self.assertEqual([],rc.collect([{'path':'A.java','content':source}])['candidates'])

    def test_parse_failure_and_context_limit_are_visible(self):
        self.assertEqual('PARTIAL',rc.collect([{'path':'Bad.java','content':'class {'}])['status'])
        self.assertEqual('PARTIAL',rc.collect(self.files(),max_chars=10)['candidates'][0]['context_status'])

    def test_json_fences_are_accepted_but_surrounding_prose_is_not(self):
        for raw in ['```json\n{"findings":[]}\n```','```\n{"findings":[]}\n```']:
            self.assertEqual('DONE',rc.review(self.files(),Mock(return_value=raw))['status'])
        self.assertEqual('PARTIAL',rc.review(self.files(),Mock(return_value='Here: {"findings":[]}'))['status'])

    def test_invalid_evidence_is_not_accepted(self):
        f={'cwe':'CWE-706','file':'Flow.java','line':6,'confidence':'high','reason':'Shared destination',
           'evidence':[{'file':'elsewhere.java','line':1}]}
        r=rc.review(self.files(),Mock(return_value=json.dumps({'findings':[f]})))
        self.assertEqual('PARTIAL',r['status']);self.assertEqual([],r['findings'])

    def test_context_review_can_reject_and_preserves_evidence(self):
        call=Mock(return_value='{"findings":[]}');r=rc.review(self.files(True),call)
        self.assertEqual('DONE',r['status']);self.assertEqual([],r['findings'])
        f={'cwe':'CWE-706','file':'Flow.java','line':6,'confidence':'medium','reason':'Requires attacker-controlled SCM',
           'evidence':[{'file':'Paths.java','line':1}]}
        r=rc.review(self.files(),Mock(return_value=json.dumps({'findings':[f]})))
        self.assertFalse(r['findings'][0]['accepted'])

    def test_api_context_finding_keeps_source_line_and_cross_file_evidence(self):
        finding={'file':'Flow.java','line':6,'cwe':'CWE-706','confidence':'high',
                 'reason':'Candidate requires external configuration review', 'accepted':True,
                 'source':'qwen-resource-context','evidence_level':'semantic-review',
                 'path':[{'file':'Paths.java','line':1,'role':'evidence'}]}
        with patch.object(api,'JAVA_ENGINE','cpg-qwen38-context'), patch.object(api.graph_spec_prod,'qwen_runtime_ready',return_value=True), patch.object(rc,'review',return_value={'status':'DONE','findings':[finding],'errors':[],'reviews':[]}):
            overrides=api._repo_overrides(self.files(),[],'Java')
            with patch.object(api.java_semantic,'review',return_value={'status':'DONE','findings':[],'error':None}):
                r=api._analyze_one('Java',self.files()[0]['content'],'Flow.java',joern_override=overrides['Flow.java'])
            self.assertTrue(r.detected)
            self.assertEqual('DONE',r.status)
            self.assertEqual('cpg-qwen38-context',r.source)
            self.assertEqual(6,r.findings[0]['line'])
            self.assertEqual('qwen-resource-context',r.findings[0]['source'])
            self.assertEqual('Paths.java',r.findings[0]['path'][0]['file'])

    def test_api_new_policy_preserves_failure_and_existing_policy_has_no_new_calls(self):
        with patch.object(api,'JAVA_ENGINE','cpg-qwen38-ensemble'),patch.object(rc,'review') as review:
            api._repo_overrides(self.files(),[],'Java'); review.assert_not_called()
        with patch.object(api,'JAVA_ENGINE','cpg-qwen38-context'),patch.object(api.graph_spec_prod,'qwen_runtime_ready',return_value=True),patch.object(rc,'review',return_value={'status':'PARTIAL','findings':[],'errors':['parse'],'reviews':[]}):
            overrides=api._repo_overrides(self.files(),[],'Java')
            with patch.object(api.java_semantic,'review',return_value={'status':'DONE','findings':[],'error':None}):
                r=api._analyze_one('Java',self.files()[0]['content'],'Flow.java',joern_override=overrides['Flow.java'])
            self.assertEqual('PARTIAL',r.status)

if __name__=='__main__':unittest.main()
