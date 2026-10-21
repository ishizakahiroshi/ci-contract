"""Single-condition request faults use synthetic inputs and exact exit codes."""
import copy
import inspect
import io
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from ci_contract import cjson, cli, request, request_binding
from ci_contract.errors import InputError, BlockedError
from ci_contract.hashing import raw_hash
from ci_contract.inventory import normalize_inventory, source_digest
from synthetic_request import fixed_model
from test_plan import synthetic_history


def fault(module, before, after):
    source = inspect.getsource(module)
    if source.count(before) != 1:
        raise AssertionError('single fault location changed: ' + before)
    result = types.ModuleType('ci_contract.synthetic_condition_fault')
    result.__package__ = 'ci_contract'
    exec(compile(source.replace(before, after, 1), '<synthetic-condition-fault>', 'exec'), result.__dict__)
    if module is request:
        result.StaleError = request.StaleError
    return result


def code(call):
    try:
        value = call()
        return value.get('exitCode', 0) if isinstance(value, dict) else (value if type(value) is int else 0)
    except request.StaleError:
        return 5
    except InputError:
        return 3
    except BlockedError:
        return 4
    except (TypeError, KeyError, AttributeError, ValueError):
        return 9


class RequestCorrectionConditions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selection, cls.inputs = fixed_model()
        cls.plan = request.build_selection_plan(cls.selection, 'change', **cls.inputs)

    def compare(self, invoke, broken, real_code, fault_code):
        self.assertNotEqual(real_code, fault_code)
        self.assertEqual(code(lambda: invoke(request)), real_code)
        observed_fault = code(lambda: invoke(broken))
        self.assertEqual(observed_fault, fault_code)
        # The same assertion that guards the real input must fail on the fault.
        with self.assertRaises(AssertionError):
            self.assertEqual(observed_fault, real_code)

    def test_pin_path_validation_each_lexical_form(self):
        broken = fault(request, "        validate_path(pin['path'])", '        pass')
        for path in ('synthetic:pin.json', 'CON', 'synthetic.json '):
            with self.subTest(path=path):
                selection = copy.deepcopy(self.selection)
                selection['expectedPins']['policy']['path'] = path
                self.compare(lambda m: m.match_pins(selection, self.inputs['trusted_inputs']), broken, 3, 4)

    def test_trusted_reference_path_validation(self):
        inputs = copy.deepcopy(self.inputs['trusted_inputs'])
        inputs['policy']['ref']['path'] = 'synthetic:pin.json'
        broken = fault(request, "        validate_path(item['ref']['path'])", '        pass')
        self.compare(lambda m: m.match_pins(self.selection, inputs), broken, 3, 4)

    def test_undeclared_target_input_is_independent(self):
        inputs = copy.deepcopy(self.inputs)
        inputs['source']['inputs'].append({'path':'synthetic-unknown.txt','kind':'file','mode':'100644',
                                          'size':0,'bytesSha256':raw_hash(b''),'role':'source'})
        inputs['source']['digest'] = source_digest(normalize_inventory(inputs['source']['inputs']))
        term = "any(entry['kind'] == 'file' and entry['path'] not in target_roles for entry in source['inputs'])"
        self.compare(lambda m: m.build_selection_plan(self.selection, 'change', **inputs),
                     fault(request, term, 'False'), 4, 0)

    def test_undeclared_base_input_is_independent(self):
        inputs = copy.deepcopy(self.inputs)
        inputs['base_source']['inputs'].append({'path':'synthetic-unknown.txt','kind':'file','mode':'100644',
                                               'size':0,'bytesSha256':raw_hash(b''),'role':'source'})
        inputs['base_source']['digest'] = source_digest(normalize_inventory(inputs['base_source']['inputs']))
        term = "any(entry['kind'] == 'file' and entry['path'] not in base_roles for entry in base_source['inputs'])"
        self.compare(lambda m: m.build_selection_plan(self.selection, 'change', **inputs),
                     fault(request, term, 'False'), 4, 0)

    def test_github_only_group_mapping(self):
        selection, inputs = copy.deepcopy((self.selection, self.inputs))
        manifest = cjson.loads(inputs['trusted_inputs']['manifest']['bytes'])
        manifest['repository']['product'] = 'github-only'
        manifest['repository']['localAllowed'] = False
        inputs['target_manifest'] = copy.deepcopy(manifest)
        item = inputs['trusted_inputs']['manifest']; item['bytes'] = cjson.dumps(manifest)
        item['ref']['sha256'] = raw_hash(item['bytes']); selection['expectedPins']['manifest'] = copy.deepcopy(item['ref'])
        broken = fault(request, "group = 'github-only' if repository['product'] == 'github-only' else repository['group']",
                       "group = repository['group']")
        self.compare(lambda m: m.build_selection_plan(selection, 'change', repository_group='github-only', **inputs), broken, 0, 4)

    def test_dispatch_request_id_shape(self):
        broken = fault(request, "    _shape(request_id, 'id')", '    pass')
        self.compare(lambda m: m.dispatch_inputs(self.plan, '', 'f'*40), broken, 3, 0)

    def test_dispatch_workflow_shape(self):
        broken = fault(request, "    _shape(workflow_commit, 'git')", '    pass')
        self.compare(lambda m: m.dispatch_inputs(self.plan, 'synthetic-request', 'invalid'), broken, 3, 0)

    def test_restore_root_type_condition(self):
        class SyntheticFields(dict):
            pass
        inputs = SyntheticFields(request.dispatch_inputs(self.plan, 'synthetic-request', 'f'*40))
        broken = fault(request, 'type(inputs) is not dict', 'False')
        self.compare(lambda m: m.restore_dispatch(inputs), broken, 3, 0)

    def test_restore_closed_fields_condition(self):
        inputs = request.dispatch_inputs(self.plan, 'synthetic-request', 'f'*40)
        inputs['syntheticUnknown'] = 'synthetic'
        term = "set(inputs) != {'plan_sha256','target_sha','profile','request_id','expected_workflow_sha','selection_json'}"
        broken = fault(request, term, 'False')
        self.compare(lambda m: m.restore_dispatch(inputs), broken, 3, 0)

    def test_restore_profile_shape(self):
        inputs = request.dispatch_inputs(self.plan, 'synthetic-request', 'f'*40); inputs['profile'] = 'synthetic-unknown'
        broken = fault(request, "    _profile(inputs['profile'])", '    pass')
        self.compare(lambda m: m.restore_dispatch(inputs), broken, 3, 0)

    def test_request_repository_shape_before_missing_anchor(self):
        selection = copy.deepcopy(self.selection); selection.update(mode='full', baseCommit=None)
        before = "    if selection['repositoryId'] != repository_id:"
        broken = fault(request, before, '    if False:')
        self.compare(lambda m: m.build_request_from_git('synthetic', 'synthetic-other', selection, 'c'*40), broken, 3, 4)

    def test_preflight_projection_schema_before_digest(self):
        projection = copy.deepcopy(self.inputs['target_projection']); projection['syntheticUnknown'] = True
        broken = fault(request, '            validate(quality_projection)', '            pass')
        self.compare(lambda m: m.preflight(self.plan, 'github', quality_projection=projection), broken, 3, 5)

    def test_target_projection_schema(self):
        inputs = copy.deepcopy(self.inputs); inputs['target_projection']['syntheticUnknown'] = True
        broken = fault(request, '    validate(target_projection)', '    pass')
        self.compare(lambda m: m.build_selection_plan(self.selection, 'change', **inputs), broken, 3, 0)

    def test_target_quality_not_reduced(self):
        inputs = copy.deepcopy(self.inputs)
        removed = inputs['target_projection']['requirements'][0]['checkIds'].pop()
        inputs['target_projection']['mappings'][0]['logicalCheckIds'].remove(removed)
        broken = fault(request, '    _quality_not_reduced(projection, target_projection)', '    pass')
        self.compare(lambda m: m.build_selection_plan(self.selection, 'change', **inputs), broken, 4, 0)

    def test_selector_invalid_code_propagation(self):
        broken = fault(request, "    if selected['exitCode'] == 3:", '    if False:')
        def invoke(module):
            with patch.object(module, 'select', return_value={'exitCode':3, 'reasonCode':'synthetic-invalid'}):
                return module.build_selection_plan(self.selection, 'change', **self.inputs)
        self.compare(invoke, broken, 3, 4)

    def test_cli_selection_read_error_code(self):
        broken = fault(cli, "                    raise InputError('selection unavailable') from None", '                    raise')
        class Stream:
            def __init__(self): self.buffer = io.BytesIO()
        with tempfile.TemporaryDirectory(prefix='synthetic-selection-read-') as directory:
            missing = Path(directory)/'missing.json'; output = Path(directory)/'plan.json'
            args = ['plan','--repo','synthetic','--repo-path',directory,'--target','c'*40,
                    '--profile','change','--selection',str(missing),'--out',str(output)]
            for module, expected in ((cli,3),(broken,9)):
                with self.subTest(expected=expected),patch('sys.stdout',Stream()) as out,patch('sys.stderr',Stream()) as err:
                    self.assertEqual(module.main(args), expected)
                    self.assertEqual(out.buffer.getvalue(), b'')
                    self.assertEqual(err.buffer.getvalue(), b'ci-contract: invalid input\n' if expected==3 else b'ci-contract: internal error\n')
                self.assertFalse(output.exists())

    def test_binding_final_validation(self):
        broken = fault(request_binding, '    validate_request_binding(binding)\n    return binding', '    return binding')
        kwargs = dict(request_id='synthetic-request',authority_id='synthetic-authority',target='synthetic-unknown',
                      trust='trusted', workflow_commit='f'*40, created_at='2026-01-01T00:00:00Z',
                      expires_at='2026-01-01T01:00:00Z',authority_kind='local-single-supervisor-v1')
        self.assertEqual(code(lambda: request_binding.make_request_binding(self.plan, **kwargs)),3)
        self.assertEqual(code(lambda: broken.make_request_binding(self.plan, **kwargs)),0)


POLICY_TERMS = {
    'root_type': ("type(value) is not dict", ['kind','version','repositoryId','profiles','repoFullProfileApproved'], 9),
    'closed_keys': ("set(value) != {'kind','version','repositoryId','profiles','repoFullProfileApproved'}", ('syntheticUnknown',True), 0),
    'kind': ("value['kind'] != 'synthetic-plan-policy'", ('kind','synthetic-other'), 0),
    'version_type': ("type(value['version']) is not int", ('version',True), 0),
    'version_value': ("value['version'] != 1", ('version',2), 0),
    'repository_type': ("type(value['repositoryId']) is not str", ('repositoryId',5), 0),
    'profiles': ("value['profiles'] != ['change']", ('profiles',['case']), 0),
    'full_approval': ("value['repoFullProfileApproved'] is not False", ('repoFullProfileApproved',True), 0),
}


def policy_test(name):
    def test(self):
        term, change, expected = POLICY_TERMS[name]
        inputs = copy.deepcopy(self.inputs['trusted_inputs'])
        policy = cjson.loads(inputs['policy']['bytes'])
        if name == 'root_type': policy = change
        else: policy[change[0]] = change[1]
        inputs['policy']['bytes'] = cjson.dumps(policy)
        broken = fault(request, term, 'False')
        if name in ('profiles', 'full_approval'):
            selection, fixed = copy.deepcopy((self.selection, self.inputs))
            fixed['trusted_inputs'] = inputs
            item = inputs['policy']; item['ref']['sha256'] = raw_hash(item['bytes'])
            selection['expectedPins']['policy'] = copy.deepcopy(item['ref'])
            manifest = cjson.loads(inputs['manifest']['bytes'])
            manifest['policySha256'] = item['ref']['sha256']
            item = inputs['manifest']; item['bytes'] = cjson.dumps(manifest)
            item['ref']['sha256'] = raw_hash(item['bytes'])
            selection['expectedPins']['manifest'] = copy.deepcopy(item['ref'])
            fixed['target_manifest'] = copy.deepcopy(manifest)
            self.compare(lambda m: m.build_selection_plan(selection, 'change', **fixed), broken, 3, expected)
        else:
            self.compare(lambda m: m._controls(inputs), broken, 3, expected)
    return test
for name in POLICY_TERMS:
    setattr(RequestCorrectionConditions, 'test_policy_term_'+name, policy_test(name))


def restore_field_test(field):
    def test(self):
        inputs = request.dispatch_inputs(self.plan, 'synthetic-request', 'f'*40)
        inputs[field] = '' if field == 'request_id' else 'invalid'
        broken = fault(request, '        _shape(inputs[field], definition)',
                       "        if field != '"+field+"': _shape(inputs[field], definition)")
        if field in ('request_id','expected_workflow_sha'):
            self.compare(lambda m: m.restore_dispatch(inputs), broken, 3, 0)
        else:
            self.compare(lambda m: m.reconstruct_dispatch(inputs, **self.inputs), broken, 3, 4)
    return test
for field in ('request_id','expected_workflow_sha','target_sha','plan_sha256'):
    setattr(RequestCorrectionConditions, 'test_restore_shape_'+field, restore_field_test(field))


class RequestAnchorCondition(unittest.TestCase):
    def test_nonancestor_anchor_has_equal_bytes(self):
        from ci_contract.plan import MANIFEST, PROJECTION
        broken = fault(request, "    git.require_ancestor(anchor['commit'], base)", '    pass')
        with tempfile.TemporaryDirectory(prefix='synthetic-anchor-condition-') as directory:
            git, anchor, base, target, mode, manifest, base_files, target_files = synthetic_history(Path(directory)/'objects')
            sibling = git.commit({PROJECTION:base_files[PROJECTION]},message='synthetic independent anchor')
            self.assertNotEqual(sibling, anchor)
            manifest['qualityProjectionRef']['commit'] = sibling
            base_files[MANIFEST] = ('100644', cjson.dumps(manifest))
            new_base = git.commit(base_files, parents=(anchor,), message='synthetic nonancestor reference')
            target_files[MANIFEST] = base_files[MANIFEST]
            new_target = git.commit(target_files, parents=(new_base,), message='synthetic target')
            self.assertEqual(code(lambda: request.fixed_inputs_from_git(git.path, 'synthetic', new_base, new_target)),4)
            self.assertEqual(code(lambda: broken.fixed_inputs_from_git(git.path, 'synthetic', new_base, new_target)),0)
