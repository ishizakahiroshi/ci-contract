"""Acceptance reconstruction uses given additions, never expected IDs as inputs."""
import copy
import inspect
from pathlib import Path
import unittest
from unittest.mock import patch
from ci_contract import cjson
from ci_contract.errors import BlockedError
from ci_contract.hashing import domain_hash
import ci_contract.request as request
import synthetic_request
from synthetic_verify import make_plan, MODEL

DATA = cjson.loads((Path(__file__).parent / 'fixtures/request-cases.json').read_bytes())
CASES = {case['id']: case for case in DATA['cases']}
ALIASES = {entry['instanceId']: entry for entry in DATA['fixtureModels'][0]['instanceAliases'].values()}


class RequestReconstructionAcceptanceTests(unittest.TestCase):
    def test_r02_explicit_addition_survives_reconstruction_or_blocks(self):
        case = CASES['r02']
        given = case['given']
        # Extend the declared synthetic model using the given addition, not expected IDs.
        ids = sorted(set(MODEL['requiredGate']['requiredInstanceIds']) | set(given['explicit_addition']))
        with patch.object(synthetic_request, 'make_plan', return_value=make_plan(ids)):
            selection, inputs = synthetic_request.fixed_model()
        selection['mode'] = 'explicit'
        selection['requestedCheckIds'] = [ALIASES[i]['logicalCheckId']
                                         for i in given['base_selection'] + given['explicit_addition']]
        plan = request.build_selection_plan(selection, given['profile'], **inputs)
        required = case['expected']['observations'][0]['required_if_restored']
        self.assertEqual(set(plan['selectionEvidence']['selectedInstanceIds']), set(required))
        dispatch = request.dispatch_inputs(plan, 'synthetic-addition-request', 'c' * 40)
        restored = request.reconstruct_dispatch(dispatch, **inputs)
        self.assertEqual(cjson.dumps(restored), cjson.dumps(plan))
        self.assertFalse(given['addition_available_to_remote'])
        reduced = copy.deepcopy(selection)
        reduced['requestedCheckIds'] = [ALIASES[i]['logicalCheckId'] for i in given['base_selection']]
        dispatch['selection_json'] = cjson.dumps(reduced).decode('utf-8')
        with self.assertRaises(BlockedError):
            request.reconstruct_dispatch(dispatch, **inputs)
        # Omitting the reconstruction comparison accepts the same lost-addition input.
        source = inspect.getsource(request)
        guard = "if domain_hash('plan', plan) != inputs['plan_sha256']:"
        self.assertEqual(source.count(guard), 1)
        namespace = {'__name__': 'ci_contract.synthetic_reconstruction_mutant', '__package__': 'ci_contract'}
        exec(compile(source.replace(guard, 'if False:', 1), '<synthetic-reconstruction-mutant>', 'exec'), namespace)
        mutant_plan = namespace['reconstruct_dispatch'](dispatch, **inputs)
        self.assertNotEqual(domain_hash('plan', mutant_plan), domain_hash('plan', plan))
        with self.assertRaises(AssertionError):
            with self.assertRaises(BlockedError):
                namespace['reconstruct_dispatch'](dispatch, **inputs)

    def test_c11_snapshot_preflight_preserves_selected_plan(self):
        case = CASES['c11']
        selection, inputs = synthetic_request.fixed_model()
        plan = request.build_selection_plan(selection, 'change', **inputs)
        plan['source']['mode'] = case['given']['sourceMode']
        plan['source']['targetCommit'] = None
        plan['source']['tree'] = None
        plan['source']['comparison'] = 'snapshot'
        before = cjson.dumps(plan)
        with patch('subprocess.Popen') as process:
            verdict = request.preflight(plan, case['given']['target'], quality_projection=inputs['target_projection'])
        self.assertEqual(verdict, {key: case['expected'][key] for key in ('status', 'exitCode')})
        process.assert_not_called()
        self.assertEqual(cjson.dumps(plan), before)
        self.assertEqual(set(plan['selectionEvidence']['selectedInstanceIds']),
                         set(case['expected']['selectedInstanceIds']))
