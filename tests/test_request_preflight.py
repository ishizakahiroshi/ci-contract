"""Independent preflight decisions and exact request byte boundaries."""
import copy
import unittest
from ci_contract import cjson, request
from ci_contract.hashing import canonical_hash
from ci_contract.errors import InputError
from synthetic_verify import documents, make_plan
from synthetic_request import fixed_model
from test_request import mutant

class PreflightPredicates(unittest.TestCase):
    def context(self):
        selection, inputs = fixed_model()
        plan=make_plan(); projection=inputs['target_projection']
        plan['qualityProjectionSha256']=canonical_hash(projection)
        return plan,projection

    def check(self,plan,target,projection,expected,before,after):
        self.assertEqual(request.preflight(plan,target,quality_projection=projection)['exitCode'],expected)
        broken=mutant(before,after)
        with self.assertRaises(AssertionError):
            self.assertEqual(broken.preflight(plan,target,quality_projection=projection)['exitCode'],expected)

    def test_snapshot_guard(self):
        p,q=self.context();p['source'].update(mode='snapshot',targetCommit=None,tree=None,comparison='snapshot')
        self.check(p,'github',q,4,"if plan['source']['mode'] == 'snapshot' and target == 'github':","if False:")
    def test_local_allowed_guard(self):
        p,q=self.context();p['repository']['localAllowed']=False
        self.check(p,'local',q,4,"not plan['repository']['localAllowed']","False")
    def test_projection_missing_guard(self):
        p,q=self.context()
        broken=mutant('if quality_projection is None:','if False:')
        self.assertEqual(request.preflight(p,'github',quality_projection=None)['exitCode'],4)
        with self.assertRaises(TypeError):broken.preflight(p,'github',quality_projection=None)
    def test_projection_identity_guard(self):
        p,q=self.context();q['repositoryId']='synthetic-other';p['qualityProjectionSha256']=canonical_hash(q)
        self.check(p,'github',q,5,"quality_projection['repositoryId'] != plan['repository']['id']","False")
    def test_projection_digest_guard(self):
        p,q=self.context();p['qualityProjectionSha256']='0'*64
        self.check(p,'github',q,5,"canonical_hash(quality_projection) != plan['qualityProjectionSha256']","False")
    def test_target_shape_guard(self):
        p,q=self.context()
        self.check(p,'unknown',q,3,"if target not in ('local','github'):","if False:")
    def test_projection_kind_guard(self):
        p,q=self.context()
        broken=mutant("if quality_projection['kind'] != 'quality-projection':","if False:")
        self.assertEqual(request.preflight(p,'github',quality_projection=p)['exitCode'],3)
        with self.assertRaises(KeyError):broken.preflight(p,'github',quality_projection=p)
    def test_wrong_plan_kind_and_surrogate_are_invalid(self):
        execution=documents()[1]
        self.assertEqual(request.preflight(execution,'github',quality_projection=None)['exitCode'],3)
        with self.assertRaises(InputError):request.dispatch_inputs(execution,'synthetic-request','f'*40)
        data=request.dispatch_inputs(make_plan(),'synthetic-request','f'*40);data['selection_json']='\ud800'
        with self.assertRaises(InputError):request.restore_dispatch(data)
    def test_exact_byte_limit(self):
        sel,inputs=fixed_model()
        sel['requestedCheckIds']=['x'+str(i).zfill(3)+'a'*80 for i in range(170)]
        remaining=16384-len(cjson.dumps(sel))
        self.assertGreater(remaining,0)
        # Add separate valid identifiers without exceeding each identifier's cap.
        number=0
        while remaining>100:
            sel['requestedCheckIds'].append('y'+str(number).zfill(3)+'b'*80);number+=1
            remaining=16384-len(cjson.dumps(sel))
        if remaining<7:
            sel['requestedCheckIds'][-1]=sel['requestedCheckIds'][-1][:-10];remaining+=10
        sel['requestedCheckIds'].append('z'*(remaining-3))
        self.assertEqual(len(cjson.dumps(sel)),16384)
        self.assertEqual(len(cjson.dumps(request.read_selection(sel))),16384)
        sel['requestedCheckIds'][-1]+='z'
        with self.assertRaises(InputError):request.read_selection(sel)
    def test_projection_duplicate_shape_precedes_admission(self):
        p,q=self.context();duplicate=copy.deepcopy(q['requirements'][0]);duplicate['purpose']+=' duplicate';q['requirements'].append(duplicate)
        p['source'].update(mode='snapshot',targetCommit=None,tree=None,comparison='snapshot')
        self.check(p,'github',q,3,'            normalize(quality_projection)','            pass')
    def test_plan_kind_guard_is_removed_at_each_boundary(self):
        from test_request_predicates import remove_guard
        execution=documents()[1]
        self.assertEqual(request.preflight(execution,'github',quality_projection=None)['exitCode'],3)
        broken=remove_guard('wrong plan kind',function='preflight')
        with self.assertRaises(KeyError):broken.preflight(execution,'github',quality_projection=None)
        with self.assertRaises(InputError):request.dispatch_inputs(execution,'synthetic-request','f'*40)
        broken=remove_guard('wrong plan kind',function='dispatch_inputs')
        with self.assertRaises(KeyError):broken.dispatch_inputs(execution,'synthetic-request','f'*40)
    def test_cli_stale_route_retains_exact_code(self):
        import inspect
        import io
        import tempfile
        import types
        from pathlib import Path
        from unittest.mock import patch
        from ci_contract import cli
        source=inspect.getsource(cli)
        needle='if isinstance(error, StaleError):'
        self.assertEqual(source.count(needle),1)
        broken=types.ModuleType('ci_contract.synthetic_cli_route');broken.__package__='ci_contract'
        exec(compile(source.replace(needle,'if False:'),'<synthetic-cli-route>','exec'),broken.__dict__)
        class Stream:
            def __init__(self):self.buffer=io.BytesIO()
        with tempfile.TemporaryDirectory(prefix='synthetic-cli-route-') as temp:
            selection=Path(temp)/'selection.json';selection.write_bytes(b'{}')
            out=Path(temp)/'plan.json'
            args=['plan','--repo','synthetic','--repo-path',temp,'--target','a'*40,'--profile','change','--selection',str(selection),'--out',str(out)]
            def invoke(module):
                with patch.object(request,'build_request_from_git',side_effect=request.StaleError('synthetic-stale')),patch('sys.stdout',Stream()) as stdout,patch('sys.stderr',Stream()) as stderr:
                    code=module.main(args)
                self.assertEqual(stdout.buffer.getvalue(),b'');self.assertFalse(out.exists())
                return code,stderr.buffer.getvalue()
            self.assertEqual(invoke(cli),(5,b'ci-contract: stale\n'))
            self.assertEqual(invoke(broken),(4,b'ci-contract: blocked\n'))
