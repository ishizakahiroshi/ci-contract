"""Dispatch fields are bound to an independently constructed synthetic request."""
import copy
import unittest
from ci_contract import cjson, request
from ci_contract.errors import BlockedError, InputError
from ci_contract.request_binding import make_request_binding
from ci_contract.plan import plan_bytes
from synthetic_request import fixed_model
from test_request import mutant


class DispatchBindingCorrections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selection, cls.fixed = fixed_model()
        cls.plan = request.build_selection_plan(cls.selection, 'change', **cls.fixed)
        cls.binding = make_request_binding(
            cls.plan, request_id='synthetic-request', authority_id='synthetic-authority',
            target='github', trust='trusted', workflow_commit='f'*40,
            created_at='2026-01-01T00:00:00Z', expires_at='2026-01-01T01:00:00Z',
            authority_kind='local-single-supervisor-v1')
        cls.inputs = request.dispatch_inputs(cls.plan, 'synthetic-request', 'f'*40)

    def test_six_dispatch_fields_are_bound(self):
        result=request.reconstruct_bound_dispatch(self.inputs,self.binding,**self.fixed)
        self.assertEqual(plan_bytes(result),plan_bytes(self.plan))
        selection=copy.deepcopy(self.selection);selection['mode']='full'
        changes={'request_id':'synthetic-other','expected_workflow_sha':'e'*40,
                 'plan_sha256':'0'*64,'target_sha':'a'*40,'profile':'case',
                 'selection_json':cjson.dumps(selection).decode()}
        for field,value in changes.items():
            with self.subTest(field=field):
                bad=dict(self.inputs);bad[field]=value
                with self.assertRaises(BlockedError):
                    request.reconstruct_bound_dispatch(bad,self.binding,**self.fixed)

    def test_each_new_binding_comparison_has_removal_control(self):
        for field,binding_key,value,reason in (
            ('request_id','requestId','synthetic-other','request'),
            ('expected_workflow_sha','workflowCommit','e'*40,'workflow'),
            ('plan_sha256','planSha256','0'*64,'binding-plan')):
            with self.subTest(field=field):
                # Change only the independently supplied binding field. This
                # isolates each new comparison from the existing plan rehash.
                binding=copy.deepcopy(self.binding);binding[binding_key]=value
                with self.assertRaises(BlockedError):
                    request.reconstruct_bound_dispatch(self.inputs,binding,**self.fixed)
                broken=mutant(f"    if inputs['{field}'] != binding['{binding_key}']:\n        raise BlockedError('dispatch-{reason}-mismatch')",'    pass')
                actual=broken.reconstruct_bound_dispatch(self.inputs,binding,**self.fixed)
                self.assertEqual(plan_bytes(actual),plan_bytes(self.plan))

    def test_noncanonical_selection_is_invalid_and_removal_detected(self):
        for suffix in (' ', ' '*17000):
            with self.subTest(bytes=len(suffix)):
                bad=dict(self.inputs);bad['selection_json']+=suffix
                with self.assertRaises(InputError):request.restore_dispatch(bad)
                broken=mutant("    if inputs['selection_json'].encode('utf-8') != cjson.dumps(selection):\n        raise InputError('noncanonical selection encoding')",'    pass')
                self.assertEqual(broken.restore_dispatch(bad),self.selection)

    def test_binding_shape_validation_has_removal_control(self):
        binding=copy.deepcopy(self.binding);binding['unexpected']=True
        with self.assertRaises(InputError):request.reconstruct_bound_dispatch(self.inputs,binding,**self.fixed)
        broken=mutant('    validate_request_binding(binding)','    pass')
        self.assertEqual(plan_bytes(broken.reconstruct_bound_dispatch(self.inputs,binding,**self.fixed)),plan_bytes(self.plan))

    def test_fixed_input_shape_precedes_binding_mismatch(self):
        fixed=copy.deepcopy(self.fixed);fixed['target_projection']['unexpected']=True
        binding=copy.deepcopy(self.binding);binding['requestId']='synthetic-other'
        with self.assertRaises(InputError):
            request.reconstruct_bound_dispatch(self.inputs,binding,**fixed)
        broken=mutant('    plan = reconstruct_dispatch(inputs, **fixed_inputs)',
            '    plan = None')
        with self.assertRaises(BlockedError):
            broken.reconstruct_bound_dispatch(self.inputs,binding,**fixed)

    def test_github_target_is_required_with_removal_control(self):
        binding=copy.deepcopy(self.binding);binding['target']='local'
        with self.assertRaises(BlockedError):
            request.reconstruct_bound_dispatch(self.inputs,binding,**self.fixed)
        broken=mutant("    if binding['target'] != 'github':\n        raise BlockedError('dispatch-binding-target-mismatch')",'    pass')
        self.assertEqual(plan_bytes(broken.reconstruct_bound_dispatch(self.inputs,binding,**self.fixed)),plan_bytes(self.plan))

    def test_each_plan_derived_binding_field_has_removal_control(self):
        for key,value in {'repositoryId':'synthetic-other','sourceDigest':'1'*64,
                          'selectionRequestSha256':'2'*64,'engineLockSha256':'3'*64,
                          'profile':'case'}.items():
            with self.subTest(field=key):
                binding=copy.deepcopy(self.binding);binding[key]=value
                with self.assertRaises(BlockedError):
                    request.reconstruct_bound_dispatch(self.inputs,binding,**self.fixed)
                broken=mutant('binding[key] != value for key, value in plan_binding_fields(plan).items()',
                    'binding[key] != value for key, value in plan_binding_fields(plan).items() if key != '+repr(key))
                self.assertEqual(plan_bytes(broken.reconstruct_bound_dispatch(self.inputs,binding,**self.fixed)),plan_bytes(self.plan))

    def test_shape_precedes_new_plan_binding_mismatch(self):
        fixed=copy.deepcopy(self.fixed);fixed['target_projection']['unexpected']=True
        for field,value in [('target','local'),('repositoryId','synthetic-other')]:
            with self.subTest(field=field):
                binding=copy.deepcopy(self.binding);binding[field]=value
                with self.assertRaises(InputError):
                    request.reconstruct_bound_dispatch(self.inputs,binding,**fixed)
