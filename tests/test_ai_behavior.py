import json
import tempfile
import unittest
from pathlib import Path
from cyberlab.ai_behavior import run,detail,propose

class AIGuidedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.project=self.base/'demo'
        route=self.project/'app/api/orders/[id]/route.ts'
        route.parent.mkdir(parents=True)
        route.write_text('export async function GET() {}')
        self.db=str(self.base/'db.sqlite')

    def test_ai_selects_route_and_records_unverified_hypothesis(self):
        def planner(routes,reviewed):
            if reviewed:return {'action':'finish'}
            return {'action':'inspect_route','route':'/api/orders/[id]',
                    'hypothesis':'Check record ownership','reason':'dynamic identifier'}
        rid=run(self.db,str(self.project),str(self.base),planner)
        check,events=detail(self.db,rid)
        self.assertEqual(check['status'],'completed')
        self.assertIn('zero vulnerabilities verified',check['summary'])
        self.assertIn('hypothesis',[e['kind'] for e in events])
        self.assertEqual(json.loads(next(e['payload'] for e in events if e['kind']=='hypothesis'))['status'],'unverified')

    def test_rejects_unapproved_tool(self):
        def planner(routes,reviewed):return {'action':'shell','route':'/api/orders/[id]','hypothesis':'','reason':''}
        rid=run(self.db,str(self.project),str(self.base),planner)
        _,events=detail(self.db,rid)
        self.assertEqual(len([e for e in events if e['kind']=='policy_denied']),5)
        self.assertFalse(any(e['kind']=='tool_observation' for e in events))

    def test_rejects_unknown_route(self):
        def planner(routes,reviewed):return {'action':'inspect_route','route':'/api/nonexistent','hypothesis':'','reason':''}
        rid=run(self.db,str(self.project),str(self.base),planner)
        _,events=detail(self.db,rid)
        self.assertTrue(any(e['kind']=='policy_denied' for e in events))

    def test_model_proposal_parsing(self):
        def fake(payload):
            self.assertIn('candidates',payload['messages'][1]['content'])
            return {'message':{'content':json.dumps({'action':'inspect_route','route':'/api/orders/[id]',
                'hypothesis':'Check ownership','reason':'dynamic'})}}
        result=propose([{'route':'/api/orders/[id]','dynamic':True,'sensitive':True,'evidence':'filename'}],set(),transport=fake)
        self.assertEqual(result['action'],'inspect_route')

if __name__=='__main__':unittest.main()
