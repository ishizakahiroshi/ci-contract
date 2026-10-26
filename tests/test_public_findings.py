"""Findings F1, F2, F3 and F6 of the independent review of the public copy (4de838a).

Each fix has a test that fails on 2389943 and passes on the fixed source, except
F2, which is a documented contract: its tests pin the behavior that stays.
All data is synthetic.
"""
import copy
import io
import json
import unittest
from unittest.mock import patch

import synthetic_verify
from ci_contract import cjson, cli, request, selection
from ci_contract.errors import InputError
from ci_contract.hashing import canonical_hash
from ci_contract.inventory import normalize_inventory, source_digest, validate_paths
from ci_contract.plan import plan_bytes
from ci_contract.verify import verify
from synthetic_request import fixed_model
from synthetic_verify import documents


class SelectionRequestHash(unittest.TestCase):
    """F1: selectionRequestSha256 is the hash of the normalized request in the plan."""

    @classmethod
    def setUpClass(cls):
        cls.selection, cls.fixed = fixed_model()
        base = request.build_selection_plan(cls.selection, 'change', **copy.deepcopy(cls.fixed))
        cls.logical = sorted({check['logicalCheckId'] for check in base['checks']})
        assert len(cls.logical) >= 2

    def unsorted(self):
        value = copy.deepcopy(self.selection)
        value['mode'] = 'explicit'
        value['requestedCheckIds'] = list(reversed(self.logical))
        return value

    def build(self, value):
        return request.build_selection_plan(copy.deepcopy(value), 'change', **copy.deepcopy(self.fixed))

    def test_premise_the_plan_kind_sorts_the_request_but_the_request_kind_does_not(self):
        value = self.unsorted()
        self.assertNotEqual(value['requestedCheckIds'], sorted(value['requestedCheckIds']))
        self.assertEqual(request.read_selection(value)['requestedCheckIds'], value['requestedCheckIds'])
        self.assertEqual(self.build(value)['selectionRequest']['requestedCheckIds'], self.logical)

    def test_hash_is_that_of_the_normalized_request_stored_in_the_plan(self):
        plan = self.build(self.unsorted())
        self.assertEqual(plan['selectionRequestSha256'],
                         canonical_hash(plan['selectionRequest'], 'selection-request'))

    def test_dispatch_inputs_accepts_the_built_plan(self):
        plan = self.build(self.unsorted())
        inputs = request.dispatch_inputs(plan, 'synthetic-request', 'f' * 40)
        self.assertEqual(inputs['profile'], 'change')
        self.assertEqual(json.loads(inputs['selection_json'])['requestedCheckIds'], self.logical)

    def test_dispatch_round_trip_reconstructs_the_same_plan(self):
        plan = self.build(self.unsorted())
        inputs = request.dispatch_inputs(plan, 'synthetic-request', 'f' * 40)
        again = request.reconstruct_dispatch(inputs, **copy.deepcopy(self.fixed))
        self.assertEqual(plan_bytes(again), plan_bytes(plan))

    def test_a_request_that_is_already_sorted_keeps_its_hash(self):
        value = self.unsorted()
        value['requestedCheckIds'] = list(self.logical)
        plan = self.build(value)
        self.assertEqual(plan['selectionRequestSha256'], canonical_hash(value, 'selection-request'))
        request.dispatch_inputs(plan, 'synthetic-request', 'f' * 40)


class ChangesAreTheCallersDeclaration(unittest.TestCase):
    """F2 (documented, no behavior change): build_selection_plan does not compare
    `changes` with the difference of the two inventories. The inventories and the
    changes come from the same trusted caller (README, typed selection requests);
    the Git adapter derives both from the same two commits.
    """

    @classmethod
    def setUpClass(cls):
        cls.selection, cls.fixed = fixed_model()

    def test_identical_inventories_with_a_declared_modification_are_accepted(self):
        fixed = copy.deepcopy(self.fixed)
        self.assertEqual(fixed['source']['digest'], fixed['base_source']['digest'])
        self.assertEqual(fixed['changes'], [{'status': 'modify', 'path': 'src/auth.ts'}])
        plan = request.build_selection_plan(copy.deepcopy(self.selection), 'change', **fixed)
        self.assertEqual(plan['selectionEvidence']['changes'],
                         [{'status': 'modified', 'oldPath': 'src/auth.ts', 'newPath': 'src/auth.ts'}])

    def test_an_inventory_difference_without_a_declared_change_is_accepted_as_declared(self):
        fixed = copy.deepcopy(self.fixed)
        base = fixed['base_source']
        base['inputs'] = [entry for entry in base['inputs'] if entry['path'] != 'src/auth.ts']
        base['digest'] = source_digest(normalize_inventory(base['inputs']))
        fixed['changes'] = []
        plan = request.build_selection_plan(copy.deepcopy(self.selection), 'change', **fixed)
        self.assertEqual(plan['selectionEvidence']['changes'], [])
        self.assertNotEqual(plan['selectionEvidence']['baseInventorySha256'],
                            plan['selectionEvidence']['targetInventorySha256'])


class UncoveredRequirement(unittest.TestCase):
    """F3: a plan requirement that no planned check covers is never accepted."""

    def run_documents(self, uncovered):
        original = synthetic_verify.make_plan

        def make_plan(ids=None, overrides=None):
            plan = original(ids, overrides)
            if uncovered:
                plan['requirements'] = sorted(plan['requirements'] + ['synthetic.uncovered'])
            return plan

        with patch.object(synthetic_verify, 'make_plan', make_plan):
            plan, execution, result, ledger = documents()
        covered = {r for check in plan['checks'] for r in check['requirementIds']}
        self.assertEqual(set(plan['requirements']) - covered, {'synthetic.uncovered'} if uncovered else set())
        return verify(plan, execution, result, synthetic_collector_ledger=ledger)

    def test_covered_requirements_are_accepted(self):
        self.assertEqual(self.run_documents(False), {'status': 'accepted', 'exitCode': 0})

    def test_an_uncovered_requirement_is_blocked(self):
        # Every other binding (hashes, proofs, ledger) is consistent, so only
        # the requirement coverage can decide this verdict.
        self.assertEqual(self.run_documents(True), {'status': 'blocked', 'exitCode': 4})


def explain_input(**overrides):
    value = {'model': {'components': ['lib'], 'literalInputOwners': {'src/a.py': 'lib'},
                       'componentInstances': {'lib': ['lib-test']}, 'guardInstanceIds': ['guard']},
             'scope': {'repositoryGroup': 'public'}}
    value.update(overrides)
    return value


def put_path(location, path):
    """An explain input that declares `path` in the named place."""
    if location == 'changedPaths':
        return explain_input(changedPaths=[path])
    if location == 'change':
        return explain_input(changes=[{'status': 'modify', 'path': path}])
    if location == 'rename-old':
        return explain_input(changes=[{'status': 'rename', 'old': path, 'new': 'src/b.py'}])
    if location == 'rename-new':
        return explain_input(changes=[{'status': 'rename', 'old': 'src/b.py', 'new': path}])
    value = explain_input(changedPaths=[])
    model = value['model']
    if location == 'owner':
        model['literalInputOwners'] = {path: 'lib'}
    elif location == 'path-instances':
        model['pathInstanceIds'] = {path: ['lib-test']}
    elif location == 'base-owner':
        value['baseModel'] = copy.deepcopy(model)
        value['baseModel']['literalInputOwners'] = {path: 'lib'}
    return value


LOCATIONS = ('changedPaths', 'change', 'rename-old', 'rename-new', 'owner', 'path-instances', 'base-owner')
INVALID = selection.select({})
# Refused by inventory.validate_path and also by selection's own (weaker) rule.
REFUSED_BY_BOTH = ('..', 'src/../a.py', '/abs/a.py', 'src\\a.py', 'src/a\x00.py', 'src/con.txt', 'src/NUL', 'src/a.py ')
# Refused by inventory.validate_path only: the weaker selection grammar accepts them.
REFUSED_ONLY_BY_INVENTORY = ('.git/config', 'src/.GIT/x', 'src/git~1/x', 'src/conin$', 'conout$.txt',
                             'src/.g‌it/x', 'a/' + 'b' * 600)


class ExplainPathRule(unittest.TestCase):
    """F6: explain holds every declared path to the inventory's path rule."""

    def run_cli(self, value):
        stdin = io.TextIOWrapper(io.BytesIO(cjson.dumps(value)), encoding='utf-8')
        out, err = io.BytesIO(), io.BytesIO()
        stdout = io.TextIOWrapper(out, encoding='utf-8', newline='\r\n')
        stderr = io.TextIOWrapper(err, encoding='utf-8', newline='\r\n')
        with patch('sys.stdin', stdin), patch('sys.stdout', stdout), patch('sys.stderr', stderr):
            code = cli.main(['explain', '-'])
            stdout.flush(), stderr.flush()
        return code, out.getvalue(), err.getvalue()

    def test_premise_the_two_rules_differ(self):
        for path in REFUSED_ONLY_BY_INVENTORY:
            with self.subTest(path=path[:24]):
                with self.assertRaises(InputError):
                    validate_paths([path])
                # Not invalid input: ready or (unowned path) blocked.
                self.assertIn(selection.select(put_path('changedPaths', path))['exitCode'], (0, 4))

    def test_paths_the_inventory_refuses_are_invalid_input_in_every_place(self):
        for location in LOCATIONS:
            for path in REFUSED_BY_BOTH + REFUSED_ONLY_BY_INVENTORY:
                with self.subTest(location=location, path=path[:24]):
                    try:
                        value = put_path(location, path)
                        cjson.dumps(value)
                    except InputError:
                        continue  # NUL and the like cannot even be an explain input
                    self.assertEqual(self.run_cli(value), (3, cjson.dumps(INVALID), b''))

    def test_a_path_the_inventory_accepts_gives_the_unchanged_selection_result(self):
        for location in LOCATIONS:
            with self.subTest(location=location):
                path = 'src/a.py' if location != 'owner' else 'src/other/a.py'
                value = put_path(location, path)
                expected = selection.select(value)
                self.assertIn(expected['exitCode'], (0, 4))
                self.assertEqual(self.run_cli(value), (expected['exitCode'], cjson.dumps(expected), b''))

    def test_a_blocked_result_is_kept_for_valid_paths(self):
        value = explain_input(changedPaths=['unknown/file'])
        self.assertEqual(self.run_cli(value), (4, cjson.dumps(selection.select(value)), b''))

    def test_changed_paths_are_checked_before_scope_admission_but_the_model_is_not(self):
        excluded = {'scope': {'repositoryGroup': 'excluded'}}
        value = put_path('changedPaths', '.git/config')
        value.update(excluded)
        self.assertEqual(self.run_cli(value), (3, cjson.dumps(INVALID), b''))
        value = put_path('owner', '.git/config')
        value.update(excluded)
        self.assertEqual(selection.select(value)['reasonCode'], 'excluded-scope')
        self.assertEqual(self.run_cli(value), (4, cjson.dumps(selection.select(value)), b''))

    def test_collision_rule_of_the_inventory_applies_to_the_declared_set(self):
        # Parent directories collide by case in an inventory; select alone only
        # compares whole paths.
        value = explain_input(changedPaths=['Src/a.py', 'src/b.py'])
        value['model']['literalInputOwners'] = {'lib/x.py': 'lib'}
        self.assertIn(selection.select(value)['exitCode'], (0, 4))
        self.assertEqual(self.run_cli(value), (3, cjson.dumps(INVALID), b''))


if __name__ == '__main__':
    unittest.main()
