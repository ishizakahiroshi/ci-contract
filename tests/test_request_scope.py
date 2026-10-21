"""Explicit repository boundaries and profile-specific mandatory checks."""
import copy
import unittest
from ci_contract import cjson, request
from ci_contract.errors import InputError, BlockedError
from ci_contract.hashing import raw_hash
from synthetic_request import fixed_model
from test_request import mutant

class RequestScopeTests(unittest.TestCase):
    def build(self,group=None,profile='change',module=request):
        sel,inputs=fixed_model();sel['mode']='full'
        return module.build_selection_plan(sel,profile,repository_group=group,**inputs)
    def test_excluded_blocks_and_malformed_group_invalid(self):
        with self.assertRaises(BlockedError):self.build('excluded')
        with self.assertRaises(InputError):self.build('unknown')
        broken=mutant("if repository_group is not None and repository_group not in ('public','private','github-only','excluded'):","if False:")
        with self.assertRaises(BlockedError):self.build('unknown',module=broken)
    def test_excluded_priority_before_stale(self):
        sel,inputs=fixed_model();sel['mode']='full';inputs['source']['digest']='0'*64
        with self.assertRaises(BlockedError) as e:request.build_selection_plan(sel,'change',repository_group='excluded',**inputs)
        self.assertNotIsInstance(e.exception,request.StaleError)
        broken=mutant("if repository_group == 'excluded':","if False:");broken.StaleError=request.StaleError
        with self.assertRaises(request.StaleError):broken.build_selection_plan(sel,'change',repository_group='excluded',**inputs)
    def test_scope_mismatch_guard(self):
        sel,inputs=fixed_model();actual=inputs['target_manifest']['repository']['group'];other='private' if actual=='public' else 'public'
        with self.assertRaises(BlockedError):self.build(other)
        broken=mutant('if repository_group is not None and repository_group != group:','if False:')
        self.assertGreater(len(self.build(other,module=broken)['checks']),0)
    def test_case_only_guard_survives_explicit_selection(self):
        sel,inputs=fixed_model();sel.update(mode='explicit',requestedCheckIds=['auth.unit'])
        item=inputs['trusted_inputs']['manifest'];manifest=cjson.loads(item['bytes'])
        guard=next(c for c in manifest['checks'] if c['id']=='guard.type')
        guard['alwaysScope']['profiles']=['case']
        item['bytes']=cjson.dumps(manifest);item['ref']['sha256']=raw_hash(item['bytes']);sel['expectedPins']['manifest']=copy.deepcopy(item['ref'])
        inputs['target_manifest']=copy.deepcopy(manifest)
        plan=request.build_selection_plan(sel,'case',**inputs)
        self.assertIn('guard.type',{c['logicalCheckId'] for c in plan['checks']})
    def test_full_defers_unknown_target_only_quality_reference(self):
        sel,inputs=fixed_model();sel['mode']='full'
        new=copy.deepcopy(inputs['target_manifest']['checks'][0]);new['id']='synthetic-target-only';new['requirementIds']=['synthetic-unknown']
        inputs['target_manifest']['checks'].append(new)
        accepted=request.build_selection_plan(sel,'change',**inputs)
        self.assertNotIn('synthetic-unknown',accepted['requirements'])
        self.assertNotIn('synthetic-target-only',{c['logicalCheckId'] for c in accepted['checks']})
        self.assertIn('target-only-check:synthetic-target-only',accepted['omissionReasons'])
        self.assertEqual(accepted['requirements'],['synthetic.requirement'])
        broken=mutant('    _quality_not_reduced(projection, target_projection)',
            "    _quality_not_reduced(projection, target_projection)\n    if selection['mode'] == 'full':\n        _quality(target_manifest, target_projection)")
        with self.assertRaisesRegex(BlockedError,'quality-check-unmapped'):
            broken.build_selection_plan(sel,'change',**inputs)
