"""M6 pure request parsing, fixed inputs, selection and preflight regressions."""
import copy
import inspect
import io
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from ci_contract import cjson, cli, request
from ci_contract.arrays import normalize
from ci_contract.errors import InputError, BlockedError
from ci_contract.hashing import canonical_hash, domain_hash, raw_hash
from ci_contract.plan import build_plan, plan_bytes, _compile, variant_id
from ci_contract.schema import validate
from synthetic_verify import make_plan
from test_plan import synthetic_history

ROOT = Path(__file__).resolve().parents[1]
CASES = {c['id']:c for c in cjson.loads((ROOT/'tests/fixtures/request-cases.json').read_bytes())['cases']}


def mutant(before, after):
    source = inspect.getsource(request)
    if source.count(before) != 1:
        raise AssertionError('fault location changed')
    module = types.ModuleType('ci_contract.synthetic_request_fault')
    module.__package__ = 'ci_contract'
    exec(compile(source.replace(before,after), '<synthetic-request-fault>', 'exec'),module.__dict__)
    return module


class RequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='synthetic-request-')
        cls.git, cls.anchor, cls.base, cls.target, *rest = synthetic_history(Path(cls.temp.name)/'objects')
        cls.old = build_plan(cls.git.path, 'synthetic', cls.base, cls.target)
        cls.inputs = request.fixed_inputs_from_git(cls.git.path,'synthetic',cls.base,cls.target)
        cls.selection = copy.deepcopy(cls.old['selectionRequest'])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def build(self, selection=None, profile='change', inputs=None, module=request):
        return module.build_selection_plan(copy.deepcopy(selection or self.selection),profile,
                                           **copy.deepcopy(inputs or self.inputs))

    def test_changed_is_byte_identical_to_existing_planner(self):
        self.assertEqual(plan_bytes(self.build()),plan_bytes(self.old))

    def test_explicit_check_and_case_keep_guards_and_native_argv(self):
        sel=copy.deepcopy(self.selection);sel.update(mode='explicit',requestedCheckIds=[])
        checks=self.old['checks']; test=next(c for c in checks if c['kind']=='test')
        sel['cases']=[{'checkId':test['logicalCheckId'],'caseIds':[test['proofPolicy']['expectedCaseIds'][0]]}]
        plan=self.build(sel,'case')
        expected={c['id'] for c in checks if c['always'] or c['logicalCheckId']==test['logicalCheckId']}
        self.assertEqual(set(plan['selectionEvidence']['selectedInstanceIds']),expected)
        for check in plan['checks']:
            self.assertEqual(check['argv'],next(c['argv'] for c in checks if c['id']==check['id']))

    def test_full_contains_only_trusted_base_all_os_and_defers_target(self):
        sel=copy.deepcopy(self.selection);sel['mode']='full'
        inputs=copy.deepcopy(self.inputs); tm=inputs['target_manifest']
        first=tm['checks'][0];first['argv']=['synthetic-target-replacement']
        extra_variant=copy.deepcopy(first['variants'][0]);extra_variant['features']=['synthetic-extra']
        first['variants'].append(extra_variant)
        for rule in tm['selectionModel']['inputRules'] + tm['selectionModel']['checkMappings']:
            rule['condition']['variantIds'].append(variant_id(extra_variant))
        additional=copy.deepcopy(first);additional['id']='synthetic-added';additional['argv']=['synthetic-added']
        additional['dependsOn']=[];additional['always']=True
        additional['alwaysScope']={'scope':'repo','componentIds':[],'profiles':['change']}
        tm['checks'].append(additional)
        for requirement in tm['requirements']:
            if requirement['id'] in additional['requirementIds']: requirement['checkIds'].append('synthetic-added')
        for requirement in inputs['target_projection']['requirements']:
            if requirement['id'] in additional['requirementIds']: requirement['checkIds'].append('synthetic-added')
        for mapping in inputs['target_projection']['mappings']:
            if mapping['requirementId'] in additional['requirementIds']: mapping['logicalCheckIds'].append('synthetic-added')
        plan=self.build(sel,inputs=inputs)
        base_expanded=_compile(cjson.loads(inputs['trusted_inputs']['manifest']['bytes']),'change')[1]
        self.assertEqual({c['id'] for c in plan['checks']},set(base_expanded))
        self.assertIn('target-only-check:synthetic-added',plan['omissionReasons'])
        self.assertIn('target-only-variant:'+first['id']+':'+variant_id(extra_variant),plan['omissionReasons'])
        self.assertNotIn(['synthetic-added'],[c['argv'] for c in plan['checks']])
        for check in plan['checks']:
            self.assertEqual(check,base_expanded[check['id']])
        self.assertEqual({c['variant']['os'] for c in plan['checks']},{'linux','windows'})

    def test_full_base_null_with_separate_trusted_inputs(self):
        for mode in ('explicit', 'full'):
            with self.subTest(mode=mode):
                sel=copy.deepcopy(self.selection);sel.update(mode=mode,baseCommit=None)
                if mode == 'explicit': sel['requestedCheckIds']=[self.old['checks'][0]['logicalCheckId']]
                inputs=copy.deepcopy(self.inputs);inputs['source']['baseCommit']=None
                self.assertGreater(len(self.build(sel,inputs=inputs)['checks']),0)

    def test_cli_base_null_blocks_without_trusted_anchor(self):
        sel=copy.deepcopy(self.selection);sel.update(mode='full',baseCommit=None)
        with patch('ci_contract.gitsource.GitSource') as git:
            with self.assertRaises(BlockedError):request.build_request_from_git('synthetic','synthetic',sel,self.target)
            git.assert_not_called()

    def test_all_four_missing_and_stale_pins(self):
        for name in request.PIN_PATHS:
            with self.subTest(pin=name):
                missing=copy.deepcopy(self.inputs);missing['trusted_inputs'].pop(name)
                with self.assertRaises(BlockedError) as err:self.build(inputs=missing)
                self.assertNotIsInstance(err.exception,request.StaleError)
                stale=copy.deepcopy(self.selection);stale['expectedPins'][name]['sha256']='0'*64
                with self.assertRaises(request.StaleError):self.build(stale)
                other=copy.deepcopy(self.selection);other['expectedPins'][name]['commit']='0'*40
                with self.assertRaises(BlockedError) as err:self.build(other)
                self.assertNotIsInstance(err.exception,request.StaleError)

    def test_shape_precedes_bad_pin_or_unsupported_profile(self):
        sel=copy.deepcopy(self.selection);sel['expectedPins']['policy']['sha256']='0'*64
        invalids=[]
        s=copy.deepcopy(sel);s['extra']=True;invalids.append(s)
        s=copy.deepcopy(sel);s['requestedCheckIds']=['x']*257;invalids.append(s)
        s=copy.deepcopy(sel);s['expectedPins']['manifest']['path']='../bad';invalids.append(s)
        s=copy.deepcopy(sel);s['repositoryId']+='\n';invalids.append(s)
        s=copy.deepcopy(sel);s['cases']=[{'checkId':'x','caseIds':['a']},{'checkId':'x','caseIds':['b']}];invalids.append(s)
        for s in invalids:
            with self.subTest(selection=s):
                with self.assertRaises(InputError):self.build(s,'release')
        broken=copy.deepcopy(self.inputs);doc=cjson.loads(broken['trusted_inputs']['manifest']['bytes']);doc['unknown']=True
        broken['trusted_inputs']['manifest']['bytes']=cjson.dumps(doc)
        with self.assertRaises(InputError):self.build(sel,inputs=broken)

    def test_size_and_count_boundaries_no_truncation(self):
        sel=copy.deepcopy(self.selection)
        sel['requestedCheckIds']=['c'+str(i) for i in range(256)]
        self.assertEqual(len(request.read_selection(sel)['requestedCheckIds']),256)
        sel['requestedCheckIds'].append('c256')
        with self.assertRaises(InputError):request.read_selection(sel)
        sel=copy.deepcopy(self.selection);sel['cases']=[{'checkId':'c'+str(i),'caseIds':['x']} for i in range(257)]
        with self.assertRaises(InputError):request.read_selection(sel)
        sel=copy.deepcopy(self.selection);sel['requestedCheckIds']=['x'*90+str(i) for i in range(200)]
        with self.assertRaises(InputError):request.read_selection(sel)
        with self.assertRaises(InputError):request.read_selection(b'\xff')

    def test_unknown_check_or_case_invalid_before_stale(self):
        sel=copy.deepcopy(self.selection);sel['expectedPins']['policy']['sha256']='0'*64
        sel['requestedCheckIds']=['synthetic-unknown']
        with self.assertRaises(InputError):self.build(sel)
        sel['requestedCheckIds']=[];check=next(c for c in self.old['checks'] if c['kind']=='test')
        sel['cases']=[{'checkId':check['logicalCheckId'],'caseIds':['synthetic-unknown']}]
        with self.assertRaises(InputError):self.build(sel)

    def test_unsupported_valid_profiles_block(self):
        for profile in ('integration','release','operations'):
            with self.assertRaises(BlockedError):self.build(profile=profile)

    def test_dispatch_roundtrip_and_each_overlap(self):
        plan=self.build();inputs=request.dispatch_inputs(plan,'synthetic-request','f'*40)
        restored=request.reconstruct_dispatch(inputs,**copy.deepcopy(self.inputs))
        self.assertEqual(plan_bytes(plan),plan_bytes(restored))
        for field,value in [('target_sha','a'*40),('plan_sha256','0'*64),('profile','case')]:
            bad=dict(inputs);bad[field]=value
            with self.assertRaises(BlockedError):request.reconstruct_dispatch(bad,**copy.deepcopy(self.inputs))
        bad=dict(inputs);bad['extra']='x'
        with self.assertRaises(InputError):request.restore_dispatch(bad)

    def test_r02_lost_addition_blocks_reconstruction(self):
        sel=copy.deepcopy(self.selection);sel.update(mode='explicit',requestedCheckIds=[self.old['checks'][0]['logicalCheckId']])
        plan=self.build(sel,'case');inputs=request.dispatch_inputs(plan,'synthetic-request','f'*40)
        dropped=copy.deepcopy(sel);dropped.update(mode='changed',requestedCheckIds=[])
        inputs['selection_json']=cjson.dumps(dropped).decode()
        with self.assertRaises(BlockedError):request.reconstruct_dispatch(inputs,**copy.deepcopy(self.inputs))
        self.assertEqual((CASES['r02']['expected']['status'],CASES['r02']['expected']['exitCode']),('blocked',4))

    def test_cli_selection_and_base_exclusive_and_output(self):
        directory=Path(self.temp.name)
        selection=directory/'selection.json';selection.write_bytes(cjson.dumps(self.selection))
        output=directory/'selection-plan.json'
        class Stream:
            def __init__(self):self.buffer=io.BytesIO()
        args=['plan','--repo','synthetic','--repo-path',str(self.git.path),'--target',self.target,
              '--profile','change','--selection',str(selection),'--out',str(output)]
        with patch('sys.stdout',Stream()) as stdout,patch('sys.stderr',Stream()) as stderr:
            self.assertEqual(cli.main(args),0)
            self.assertEqual(stdout.buffer.getvalue(),(domain_hash('plan',self.old)+'\n').encode())
            self.assertEqual(stderr.buffer.getvalue(),b'')
        self.assertEqual(output.read_bytes(),plan_bytes(self.old))
        output.unlink()
        with patch('sys.stdout',Stream()) as stdout,patch('sys.stderr',Stream()) as stderr:
            self.assertEqual(cli.main(args+['--base',self.base]),3)
            self.assertEqual(stdout.buffer.getvalue(),b'')
            self.assertEqual(stderr.buffer.getvalue(),b'ci-contract: invalid input\n')
        self.assertFalse(output.exists())
        for mode in ('explicit', 'full'):
            with self.subTest(mode=mode, base='present'):
                selected=copy.deepcopy(self.selection);selected['mode']=mode
                if mode == 'explicit': selected['requestedCheckIds']=[self.old['checks'][0]['logicalCheckId']]
                selection.write_bytes(cjson.dumps(selected))
                expected=self.build(selected)
                with patch('sys.stdout',Stream()) as stdout,patch('sys.stderr',Stream()) as stderr:
                    self.assertEqual(cli.main(args),0)
                    self.assertEqual(stdout.buffer.getvalue(),(domain_hash('plan',expected)+'\n').encode())
                    self.assertEqual(stderr.buffer.getvalue(),b'')
                self.assertEqual(output.read_bytes(),plan_bytes(expected))
                output.unlink()
            with self.subTest(mode=mode, base='absent'):
                selected['baseCommit']=None
                selection.write_bytes(cjson.dumps(selected))
                with patch('ci_contract.gitsource.GitSource') as git,patch('sys.stdout',Stream()) as stdout,patch('sys.stderr',Stream()) as stderr:
                    self.assertEqual(cli.main(args),4)
                    self.assertEqual(stdout.buffer.getvalue(),b'')
                    self.assertEqual(stderr.buffer.getvalue(),b'ci-contract: blocked\n')
                    git.assert_not_called()
                self.assertFalse(output.exists())


class PreflightTests(unittest.TestCase):
    def test_four_preflight_acceptance_cases_do_not_start_processes(self):
        for identifier in ('c11','c13','r36','r04'):
            plan=make_plan();plan['profile']='case'
            projection=cjson.loads((ROOT/'tests/fixtures/synthetic-quality-projection.json').read_bytes())
            if identifier=='c11':
                plan['source'].update(mode='snapshot',targetCommit=None,tree=None,comparison='snapshot')
                target='github'
            elif identifier in ('c13','r36'):
                plan['repository'].update(product='github-only',localAllowed=False,defaultTarget='github')
                target='local'
            else:target='github';projection=None
            with patch('subprocess.run') as run,patch('subprocess.Popen') as popen:
                verdict=request.preflight(plan,target,quality_projection=projection)
                run.assert_not_called();popen.assert_not_called()
            self.assertEqual(verdict,{'status':CASES[identifier]['expected']['status'],'exitCode':CASES[identifier]['expected']['exitCode']})
            self.assertNotIn('execution',verdict)
