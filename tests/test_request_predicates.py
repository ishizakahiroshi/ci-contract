"""Every request decision is exercised with an isolated guard-removal fault."""
import ast
import copy
import inspect
import types
import unittest
from unittest.mock import patch
from ci_contract import cjson, request
from ci_contract.errors import InputError, BlockedError
from ci_contract.hashing import raw_hash, canonical_hash, domain_hash
from synthetic_verify import documents
import test_request as request_tests
ROOT = request_tests.ROOT


def remove_guard(reason, function=None):
    tree=ast.parse(inspect.getsource(request));found=[]
    roots = [tree] if function is None else [node for node in tree.body
                                            if isinstance(node, ast.FunctionDef) and node.name == function]
    for node in (node for root in roots for node in ast.walk(root)):
        if isinstance(node,ast.If):
            for statement in node.body:
                if isinstance(statement,ast.Raise) and isinstance(statement.exc,ast.Call):
                    args=statement.exc.args
                    if args and isinstance(args[0],ast.Constant) and args[0].value==reason:
                        node.test=ast.Constant(value=False);found.append(node)
    if len(found)!=1:raise AssertionError('fault location changed: '+reason)
    module=types.ModuleType('ci_contract.synthetic_removed_request_guard');module.__package__='ci_contract'
    exec(compile(ast.fix_missing_locations(tree),'<synthetic-removed-request-guard>','exec'),module.__dict__)
    # Preserve exception identity: otherwise an unrelated stale result is misread
    # as blocked and can falsely appear to kill a removed stale guard.
    module.StaleError = request.StaleError
    return module


def exit_code(call):
    try:
        result=call()
        return result.get('exitCode',0) if isinstance(result,dict) else 0
    except request.StaleError:return 5
    except InputError:return 3
    except BlockedError:return 4
    except (KeyError,TypeError,AttributeError,ValueError):return 9


class RequestPredicateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        request_tests.RequestTests.setUpClass();cls.inputs=request_tests.RequestTests.inputs;cls.selection=request_tests.RequestTests.selection;cls.old=request_tests.RequestTests.old
    @classmethod
    def tearDownClass(cls):request_tests.RequestTests.tearDownClass()

    def test_mutants_preserve_stale_exception_identity(self):
        mutant = remove_guard('invalid request structure')
        self.assertIs(mutant.StaleError, request.StaleError)
        selection = copy.deepcopy(self.selection)
        selection['expectedPins']['policy']['sha256'] = '0' * 64
        self.assertEqual(exit_code(lambda: mutant.match_pins(selection, self.inputs['trusted_inputs'])), 5)

    def test_full_trusted_only_boundary_mutation_is_detected(self):
        sel=copy.deepcopy(self.selection);sel.update(mode='full')
        inputs=copy.deepcopy(self.inputs)
        added=copy.deepcopy(inputs['target_manifest']['checks'][0])
        added.update(id='synthetic-added',argv=['synthetic-added'],dependsOn=[],always=True,
                     alwaysScope={'scope':'repo','componentIds':[],'profiles':['change']})
        inputs['target_manifest']['checks'].append(added)
        for requirement in inputs['target_manifest']['requirements']:
            if requirement['id'] in added['requirementIds']: requirement['checkIds'].append('synthetic-added')
        for requirement in inputs['target_projection']['requirements']:
            if requirement['id'] in added['requirementIds']: requirement['checkIds'].append('synthetic-added')
        for mapping in inputs['target_projection']['mappings']:
            if mapping['requirementId'] in added['requirementIds']: mapping['logicalCheckIds'].append('synthetic-added')
        plan=request.build_selection_plan(sel,'change',**inputs)
        self.assertNotIn('synthetic-added',{check['logicalCheckId'] for check in plan['checks']})
        self.assertIn('target-only-check:synthetic-added',plan['omissionReasons'])
        broken=request_tests.mutant('        target_compact = compact',
            '        full_compact, target_expanded, _, _ = _compile(target_manifest, compile_profile)\n        target_compact = full_compact\n        expanded = dict(target_expanded, **expanded)\n        broad_instances = sorted(expanded)')
        bad=broken.build_selection_plan(sel,'change',**inputs)
        self.assertIn('synthetic-added',{check['logicalCheckId'] for check in bad['checks']})
        missing=request_tests.mutant("+ deferred,", "+ [],")
        omitted=missing.build_selection_plan(sel,'change',**inputs)
        self.assertNotIn('target-only-check:synthetic-added',omitted['omissionReasons'])

    def test_case_profile_gate_branch_removal_is_detected(self):
        sel=copy.deepcopy(self.selection);sel.update(mode='explicit')
        test=next(check for check in self.old['checks'] if check['kind']=='test')
        sel['requestedCheckIds']=[test['logicalCheckId']]
        plan=request.build_selection_plan(sel,'case',**copy.deepcopy(self.inputs))
        self.assertIn(test['logicalCheckId'],{check['logicalCheckId'] for check in plan['checks']})
        broken=request_tests.mutant("    if profile == 'case':\n        compact = copy.deepcopy(compact)","    if False:\n        compact = copy.deepcopy(compact)")
        with self.assertRaises(BlockedError): broken.build_selection_plan(sel,'case',**copy.deepcopy(self.inputs))

    def test_case_compile_profile_branch_removal_is_detected(self):
        from synthetic_request import fixed_model
        sel,inputs=fixed_model()
        manifest=cjson.loads(inputs['trusted_inputs']['manifest']['bytes'])
        for mapping in manifest['selectionModel']['checkMappings']:
            mapping['condition']['profiles']=['case']
        item=inputs['trusted_inputs']['manifest'];item['bytes']=cjson.dumps(manifest)
        item['ref']['sha256']=raw_hash(item['bytes']);sel['expectedPins']['manifest']=copy.deepcopy(item['ref'])
        inputs['target_manifest']=copy.deepcopy(manifest)
        plan=request.build_selection_plan(sel,'case',**inputs)
        self.assertIn('auth.unit',{check['logicalCheckId'] for check in plan['checks']})
        broken=request_tests.mutant("compile_profile = profile if profile in ('change','case') else 'change'","compile_profile = 'change'")
        altered=broken.build_selection_plan(sel,'case',**inputs)
        self.assertNotIn('auth.unit',{check['logicalCheckId'] for check in altered['checks']})

    def scenario(self, reason, module):
        inputs=copy.deepcopy(self.inputs);sel=copy.deepcopy(self.selection);profile='change'
        def rehash(name, doc):
            item=inputs['trusted_inputs'][name];item['bytes']=cjson.dumps(doc)
            item['ref']['sha256']=raw_hash(item['bytes']);sel['expectedPins'][name]['sha256']=item['ref']['sha256']
        if reason=='invalid request structure':
            sel['unexpected']=True
            return lambda:module.read_selection(sel),3
        if reason=='selection request too large':
            sel['requestedCheckIds']=['x'*90+str(i) for i in range(200)]
            return lambda:module.read_selection(sel),3
        if reason=='invalid request profile':
            return lambda:module._profile('unknown'),3
        elif reason=='invalid trusted input registry':
            inputs['trusted_inputs']['unknown']=copy.deepcopy(inputs['trusted_inputs']['manifest'])
            return lambda:module._controls(inputs['trusted_inputs']),3
        elif reason=='invalid trusted input':
            inputs['trusted_inputs']['policy']['unknown']=True
            return lambda:module._controls(inputs['trusted_inputs']),3
        elif reason=='unsupported policy structure':
            policy=cjson.loads(inputs['trusted_inputs']['policy']['bytes']);policy['version']=2;rehash('policy',policy)
        elif reason=='wrong trusted input kind':
            inputs['trusted_inputs']['engineLock']['bytes']=inputs['trusted_inputs']['manifest']['bytes']
            return lambda:module._controls(inputs['trusted_inputs']),3
        elif reason=='fixed-reference-unavailable':
            sel['expectedPins']['policy']['commit']='0'*40
            return lambda:module.match_pins(sel,inputs['trusted_inputs']),4
        elif reason=='fixed-reference-stale':
            sel['expectedPins']['policy']['sha256']='0'*64
            return lambda:module.match_pins(sel,inputs['trusted_inputs']),5
        elif reason=='wrong target control kind':inputs['target_projection']=copy.deepcopy(inputs['target_manifest'])
        elif reason=='invalid changes':
            # The root-list and per-entry predicates have separate positions.
            inputs['changes']=tuple(inputs['changes']);sel['mode']='full'
        elif reason=='invalid change':
            inputs['changes']=[{'status':'modify','path':'src/main.txt','unknown':True}];sel['mode']='full'
        elif reason=='duplicate change':
            inputs['changes']*=2;profile='release'  # Invalid shape must precede unsupported-profile admission.
        elif reason=='undeclared requested check':sel['requestedCheckIds']=['unknown']
        elif reason=='undeclared requested case':
            check=next(c for c in self.old['checks'] if c['kind']=='test')
            sel['cases']=[{'checkId':check['logicalCheckId'],'caseIds':['unknown']}]
        elif reason=='request-source-mismatch':inputs['source']['comparison']='merge'
        elif reason=='engine-pin-mismatch':
            lock=cjson.loads(inputs['trusted_inputs']['engineLock']['bytes']);lock['engine']['bundleSha256']='0'*64;rehash('engineLock',lock)
        elif reason=='control-pin-mismatch':
            m=cjson.loads(inputs['trusted_inputs']['manifest']['bytes']);m['policySha256']='0'*64;rehash('manifest',m)
        elif reason=='source-inventory-mismatch':inputs['source']['digest']='0'*64
        elif reason=='undeclared-source-input':
            inputs['source']['inputs'].append({'path':'unknown.txt','kind':'file','mode':'100644','size':0,'bytesSha256':raw_hash(b''),'role':'source'})
            from ci_contract.inventory import source_digest,normalize_inventory
            inputs['source']['digest']=source_digest(normalize_inventory(inputs['source']['inputs']))
        elif reason in ('invalid selection model','selected-not-ready'):
            code=3 if reason=='invalid selection model' else 4
            def call():
                with patch.object(module,'select',return_value={'exitCode':code,'reasonCode':'synthetic-denied'}):
                    return module.build_selection_plan(sel,profile,**inputs)
            return call,code
        elif reason=='wrong plan kind':
            return lambda:module.dispatch_inputs(documents()[1],'synthetic-request','f'*40),3
        elif reason=='snapshot-dispatch-unsupported':
            plan=copy.deepcopy(self.old);plan['source'].update(mode='snapshot',targetCommit=None,tree=None,comparison='snapshot')
            return lambda:module.dispatch_inputs(plan,'synthetic-request','f'*40),4
        elif reason=='selection-binding-mismatch':
            plan=copy.deepcopy(self.old);plan['selectionRequestSha256']='0'*64
            return lambda:module.dispatch_inputs(plan,'synthetic-request','f'*40),4
        elif reason=='invalid dispatch fields':
            dispatch=request.dispatch_inputs(self.old,'synthetic-request','f'*40);dispatch['unknown']='x'
            return lambda:module.restore_dispatch(dispatch),3
        elif reason=='invalid selection encoding':
            dispatch=request.dispatch_inputs(self.old,'synthetic-request','f'*40);dispatch['selection_json']={}
            return lambda:module.restore_dispatch(dispatch),3
        elif reason in ('dispatch-target-mismatch','reconstructed-plan-mismatch'):
            dispatch=request.dispatch_inputs(self.old,'synthetic-request','f'*40)
            dispatch['target_sha' if reason=='dispatch-target-mismatch' else 'plan_sha256']='a'*40 if reason=='dispatch-target-mismatch' else '0'*64
            return lambda:module.reconstruct_dispatch(dispatch,**inputs),4
        elif reason=='trusted-base-anchor-required':
            sel.update(mode='full',baseCommit=None)
            def call():
                with patch.object(module,'fixed_inputs_from_git',return_value=inputs),patch.object(module,'build_selection_plan',return_value={}):
                    return module.build_request_from_git('synthetic','synthetic',sel,'a'*40)
            return call,4
        return lambda:module.build_selection_plan(sel,profile,**inputs),3 if reason in (
            'invalid request profile','unsupported policy structure','wrong target control kind','invalid changes','invalid change',
            'duplicate change','undeclared requested check','undeclared requested case') else 5 if reason in (
            'engine-pin-mismatch','control-pin-mismatch','source-inventory-mismatch') else 4

    def assert_guard(self, reason, module):
        call,expected=self.scenario(reason,module)
        self.assertEqual(exit_code(call),expected)


REASONS = ['invalid request structure','selection request too large','invalid request profile',
           'invalid trusted input registry','invalid trusted input','unsupported policy structure','wrong trusted input kind',
           'fixed-reference-unavailable','fixed-reference-stale','wrong target control kind','invalid changes','invalid change',
           'duplicate change','undeclared requested check','undeclared requested case','request-source-mismatch',
           'engine-pin-mismatch','control-pin-mismatch',
           'source-inventory-mismatch','undeclared-source-input','snapshot-dispatch-unsupported','selection-binding-mismatch',
           'invalid dispatch fields','invalid selection encoding','dispatch-target-mismatch','reconstructed-plan-mismatch',
           'trusted-base-anchor-required']


def make_test(reason):
    def test(self):
        self.assert_guard(reason,request)
        broken=remove_guard(reason)
        with self.assertRaises(AssertionError):self.assert_guard(reason,broken)
    return test
for number,reason in enumerate(REASONS):
    setattr(RequestPredicateTests,'test_guard_'+str(number).zfill(2)+'_'+reason.replace('-','_').replace(' ','_'),make_test(reason))
