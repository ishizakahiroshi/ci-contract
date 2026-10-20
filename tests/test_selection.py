"""M3 selection projections, not end-to-end acceptance of the contract.

Ten unchanged design-case projections use the approved comparison: selected IDs
are an exact set, while not-selected IDs are declared, forbidden examples. All
ID lists reject duplicates. Two input-incomplete cases remain UNEXECUTED, and
r05 belongs to plan tests. The adapter reads only fixture/given inputs, never
expected. Fault controls use deliberately wrong synthetic inputs; they are not
a claim of exhaustive production-code mutation testing.
"""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from ci_contract import cjson, cli, selection
from publication_source import transformed_source

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / 'tests/fixtures/planning-cases.json'
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding='utf-8'))
MODEL = FIXTURE['fixtureModels'][0]
CASES = {case['id']: case for case in FIXTURE['cases']}
EXECUTED = ('c01', 'c03', 'c04', 'c07', 'c14', 'r06', 'r07', 'r09', 'r10', 'r37')
UNEXECUTED = ('c05', 'r08')
PLAN_CASES = ('r05',)
SOURCE_SHA256 = '98c356bf50e6f872f5d61aa47341fb6009d592bc7650b5b2640c8404bea30f37'


def source_input(case_id):
    """Translate explicit fixture/given inputs only; no expected-derived data."""
    if case_id not in EXECUTED:
        raise ValueError('source case is outside the executed selection projections')
    case = CASES[case_id]
    given = case['given']
    model = {key: copy.deepcopy(MODEL[key]) for key in (
        'components', 'literalInputOwners', 'componentInstances',
        'guardInstanceIds', 'impactEdges')}
    model['prepareEdges'] = []
    if 'checks_by_component' in given:
        # This explicit mapping is a replacement, not an overlay. All declared
        # components/owners remain; absent components have no declared checks.
        model['componentInstances'] = copy.deepcopy(given['checks_by_component'])
    for field in ('impact_edges', 'impactEdges'):
        if field in given:
            model['impactEdges'] = copy.deepcopy(given[field])
    if 'guards' in given:
        model['guardInstanceIds'] = list(given['guards'])
    if 'prepare_edges' in given:
        # Abstract nodes need no invented instance aliases to prove a cycle.
        # The selector validates the global cycle before endpoint references.
        model['prepareEdges'] = copy.deepcopy(given['prepare_edges'])
    result = {'model': model, 'scope': {'repositoryGroup': MODEL['repository']['group']}}
    if given.get('repository', {}).get('product') == 'github-only':
        result['scope']['repositoryGroup'] = 'github-only'
    for field in ('changed_paths', 'changedPaths'):
        if field in given:
            result['changedPaths'] = list(given[field])
    for field in ('baseAvailable', 'repoFullProfileApproved'):
        if field in given:
            result[field] = given[field]
    if 'input_owner' in given:
        for path in given['changed_paths']:
            model['literalInputOwners'][path] = given['input_owner']
    if 'package_rule' in given:
        if given['package_rule'] != 'schema changes require package.verify.linux':
            raise ValueError('unmapped source package rule')
        instance = MODEL['instanceAliases']['package.verify.linux']['instanceId']
        model['pathInstanceIds'] = {path: [instance] for path in given['changed_paths']}
    if 'approved_repo_full_profile' in given:
        if given['approved_repo_full_profile'] is not None:
            raise ValueError('unmapped source full-profile approval')
        result['repoFullProfileApproved'] = False
    for group_field, alias_field in (('canonical_repository_group', 'requested_alias'),
                                     ('canonicalScope', 'requestedAlias')):
        if group_field not in given:
            continue
        group = given[group_field]
        alias = given[alias_field]
        result['scope'] = {'repositoryGroup': group, 'requestedAlias': alias,
                           'aliases': {alias: group}}
    return result


def simple_input():
    """Independent, explicitly declared unit fixture; not a source-case repair."""
    return {
        'model': {
            'components': ['auth', 'api', 'web', 'unused'],
            'literalInputOwners': {'src/auth.ts': 'auth', 'src/api.ts': 'api',
                                   'web/view.ts': 'web', 'unused/data': 'unused'},
            'componentInstances': {'auth': ['auth-linux'], 'api': ['api-linux'],
                                   'web': ['web-linux', 'web-windows'],
                                   'unused': ['unused-linux']},
            'guardInstanceIds': ['type', 'static', 'secrets'],
            'impactEdges': [['auth', 'api'], ['api', 'web']],
            'prepareEdges': [],
        },
        'changedPaths': ['src/auth.ts'],
        'scope': {'repositoryGroup': 'public'},
    }


def declared_universe(value):
    """Collect declarations independently of selector output or expectations."""
    universe = set()
    for field in ('model', 'baseModel'):
        if field not in value:
            continue
        model = value[field]
        universe.update(model['guardInstanceIds'])
        for instances in model['componentInstances'].values():
            universe.update(instances)
        for instances in model.get('pathInstanceIds', {}).values():
            universe.update(instances)
    return universe


def assert_projection(test, result, expected, value):
    test.assertEqual(result['status'], expected['status'])
    test.assertEqual(result['exitCode'], expected['exitCode'])
    universe = declared_universe(value)
    for label, projection in (('actual', result), ('expected', expected)):
        for field in ('selectedInstanceIds', 'notSelectedInstanceIds'):
            ids = projection[field]
            test.assertEqual(len(ids), len(set(ids)), (label, field, 'duplicates'))
            test.assertTrue(set(ids) <= universe, (label, field, 'undeclared instance'))
        test.assertTrue(set(projection['selectedInstanceIds']).isdisjoint(
            projection['notSelectedInstanceIds']), (label, 'selected forbidden instance'))
    test.assertEqual(set(result['selectedInstanceIds']), set(expected['selectedInstanceIds']))
    # Expected exclusions are examples, including when rejection leaves no
    # actual partition. Do not demand an exhaustive complement or truncate it.
    test.assertTrue(set(expected['notSelectedInstanceIds']).isdisjoint(result['selectedInstanceIds']))


def assert_empty_rejection(test, result, status, code, reason=None):
    test.assertEqual((result['status'], result['exitCode']), (status, code))
    test.assertEqual(result['selectedInstanceIds'], [])
    test.assertEqual(result['notSelectedInstanceIds'], [])
    test.assertEqual(result['notSelectedReasons'], [])
    if reason is not None:
        test.assertEqual(result['reasonCode'], reason)


class SelectionProvenanceTests(unittest.TestCase):
    def test_exact_source_case_inventory_and_unchanged_design_execution_labels(self):
        self.assertEqual(FIXTURE['sourceSha256'], SOURCE_SHA256)
        self.assertEqual(list(CASES), ['c01', 'c03', 'c04', 'c05', 'c07', 'c14',
                                      'r05', 'r06', 'r07', 'r08', 'r09', 'r10', 'r37'])
        self.assertEqual(len(FIXTURE['fixtureModels']), 1)
        self.assertTrue(all(c['execution'] == 'not-run' for c in CASES.values()))
        self.assertTrue(all(c['fixtureId'] == MODEL['id'] for c in CASES.values()))

    def test_planning_fixture_is_pinned_and_m1_source_list_is_untouched(self):
        manifest = json.loads((ROOT / 'src/ci_contract/data/SOURCES.json').read_text())
        self.assertEqual(len(manifest['files']), 6)
        self.assertEqual(len(manifest['planningFiles']), 1)
        asset = manifest['planningFiles'][0]
        self.assertEqual(asset['path'], 'tests/fixtures/planning-cases.json')
        self.assertEqual(asset['sourceSha256'], SOURCE_SHA256)
        self.assertEqual(asset['bytes'], len(FIXTURE_PATH.read_bytes()))
        self.assertEqual(asset['sha256'], hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest())
        self.assertEqual(asset['jsonPointers'][0], '/fixtureModels')
        self.assertEqual(len(asset['jsonPointers']), 14)

    def test_fixed_case_extractions_match_original_when_local_input_is_available(self):
        # Portable runs validate the pinned extraction above. The implementation
        # workspace also proves value-for-value equality against read-only input.
        original = json.loads(transformed_source(self, 'acceptance-cases.json', SOURCE_SHA256))
        self.assertEqual(cjson.dumps(FIXTURE['fixtureModels']), cjson.dumps(original['fixtureModels']))
        self.assertEqual(cjson.dumps(FIXTURE['cases']),
                         cjson.dumps([c for c in original['cases'] if c['id'] in CASES]))

    def test_coverage_explicitly_accounts_for_all_thirteen_and_does_not_claim_e2e(self):
        report = json.loads((ROOT / 'tests/acceptance-coverage.json').read_text())
        self.assertEqual(report['fullAcceptanceCasesPassed'], 0)
        section = report['selectionCore']
        self.assertEqual(section['caseCount'], 13)
        self.assertEqual(section['selectionProjectionPassedCount'], 10)
        self.assertEqual(section['unexecutedCount'], 2)
        self.assertEqual(section['delegatedToPlanCount'], 1)
        self.assertEqual({c['id'] for c in section['cases']}, set(CASES))
        self.assertEqual({c['id'] for c in section['cases'] if c['status'] == 'UNEXECUTED'}, set(UNEXECUTED))
        self.assertEqual({c['id'] for c in section['cases']
                          if c['status'] == 'delegated-to-plan-tests'}, set(PLAN_CASES))
        self.assertEqual({c['id'] for c in section['cases']
                          if c['status'] == 'selection-projection-passed'}, set(EXECUTED))
        for case in section['cases']:
            self.assertFalse(case['expectedModified'])
            if case['status'] == 'UNEXECUTED':
                self.assertTrue(case['reason'])

    def test_adapter_does_not_consume_expected(self):
        for case_id in EXECUTED:
            with self.subTest(case=case_id):
                original = source_input(case_id)
                corrupted_case = copy.deepcopy(CASES[case_id])
                corrupted_case['expected'] = {'invalid': 'SHOULD NEVER BE READ'}
                with patch.dict(CASES, {case_id: corrupted_case}):
                    self.assertEqual(source_input(case_id), original)

    def test_unexecuted_cases_cannot_be_silently_adapted(self):
        for case_id in UNEXECUTED + PLAN_CASES:
            with self.subTest(case=case_id), self.assertRaises(ValueError):
                source_input(case_id)


class UnexecutedFixedCaseTests(unittest.TestCase):
    """Visible skips, never replaced expected values or synthetic false passes."""


def unexecuted_case_test(case_id, reason):
    def test(self):
        self.skipTest(reason)
    test.__name__ = 'test_' + case_id + '_UNEXECUTED'
    return test


for _entry in json.loads((ROOT / 'tests/acceptance-coverage.json').read_text())['selectionCore']['cases']:
    if _entry['status'] == 'UNEXECUTED':
        setattr(UnexecutedFixedCaseTests, 'test_' + _entry['id'] + '_UNEXECUTED',
                unexecuted_case_test(_entry['id'], _entry['reason']))


class FixedPlanningProjectionTests(unittest.TestCase):
    def test_c01_leaf_selects_consumers_and_guards_with_forbidden_examples(self):
        value = source_input('c01')
        result = selection.select(value)
        assert_projection(self, result, CASES['c01']['expected'], value)
        self.assertEqual(result['evidence']['reachedComponents'], ['auth', 'api', 'web'])
        self.assertGreater(len(result['notSelectedInstanceIds']),
                           len(CASES['c01']['expected']['notSelectedInstanceIds']))

    def test_c03_shared_auth_reaches_all_declared_consumers(self):
        value = source_input('c03')
        self.assertEqual(value['scope']['repositoryGroup'], 'github-only')
        result = selection.select(value)
        assert_projection(self, result, CASES['c03']['expected'], value)
        self.assertEqual(result['evidence']['reachedComponents'],
                         ['auth', 'userdata', 'family', 'mutation'])

    def test_c04_nonimport_input_keeps_generator_package_and_both_os_variants(self):
        value = source_input('c04')
        result = selection.select(value)
        assert_projection(self, result, CASES['c04']['expected'], value)
        for alias in ('assets.generate.linux', 'package.verify.linux',
                      'cli.contract.linux', 'cli.contract.windows'):
            self.assertIn(MODEL['instanceAliases'][alias]['instanceId'], result['selectedInstanceIds'])

    def test_c07_unknown_path_and_unavailable_base_block_without_partial_partition(self):
        value = source_input('c07')
        self.assertFalse(value['baseAvailable'])
        self.assertFalse(value['repoFullProfileApproved'])
        result = selection.select(value)
        assert_projection(self, result, CASES['c07']['expected'], value)
        assert_empty_rejection(self, result, 'blocked', 4, 'unknown-path')

    def test_c14_canonical_excluded_scope_blocks_despite_nonexcluded_alias(self):
        value = source_input('c14')
        result = selection.select(value)
        assert_projection(self, result, CASES['c14']['expected'], value)
        assert_empty_rejection(self, result, 'blocked', 4, 'excluded-scope')

    def test_r06_auth_leaf_exact_membership(self):
        result = selection.select(source_input('r06'))
        assert_projection(self, result, CASES['r06']['expected'], source_input('r06'))
        self.assertEqual(result['evidence']['reachedComponents'], ['auth', 'api', 'web'])
        self.assertEqual(result['evidence']['fallback'], 'none')

    def test_r07_nonimport_schema_consumers_and_package_exact_membership(self):
        result = selection.select(source_input('r07'))
        assert_projection(self, result, CASES['r07']['expected'], source_input('r07'))
        self.assertIn(MODEL['instanceAliases']['cli.contract.windows']['instanceId'], result['selectedInstanceIds'])
        self.assertIn(MODEL['instanceAliases']['package.verify.linux']['instanceId'], result['selectedInstanceIds'])

    def test_r09_unknown_root_blocked_with_no_partial_partition(self):
        result = selection.select(source_input('r09'))
        assert_projection(self, result, CASES['r09']['expected'], source_input('r09'))
        self.assertEqual(result['reasonCode'], 'unknown-path')

    def test_r10_global_prepare_cycle_is_invalid_before_endpoint_resolution(self):
        result = selection.select(source_input('r10'))
        assert_projection(self, result, CASES['r10']['expected'], source_input('r10'))
        self.assertEqual(result['reasonCode'], 'prepare-cycle')

    def test_r37_excluded_alias_resolves_before_selection(self):
        result = selection.select(source_input('r37'))
        assert_projection(self, result, CASES['r37']['expected'], source_input('r37'))
        self.assertEqual(result['reasonCode'], 'excluded-scope')


class ProjectionOracleTests(unittest.TestCase):
    """Sensitivity checks for the approved comparison, never source rewrites."""

    def test_set_comparison_ignores_only_array_order(self):
        value = source_input('c01')
        result = selection.select(value)
        result['selectedInstanceIds'].reverse()
        result['notSelectedInstanceIds'].reverse()
        assert_projection(self, result, CASES['c01']['expected'], value)

    def test_missing_or_extra_actual_selected_instance_is_rejected(self):
        value = source_input('c01')
        for change in ('missing', 'extra'):
            result = selection.select(value)
            if change == 'missing':
                result['selectedInstanceIds'].pop()
            else:
                result['selectedInstanceIds'].append(result['notSelectedInstanceIds'].pop())
            with self.subTest(change=change), self.assertRaises(AssertionError):
                assert_projection(self, result, CASES['c01']['expected'], value)

    def test_duplicate_actual_or_expected_ids_are_rejected(self):
        value = source_input('c01')
        for label in ('actual', 'expected'):
            for field in ('selectedInstanceIds', 'notSelectedInstanceIds'):
                result = selection.select(value)
                expected = copy.deepcopy(CASES['c01']['expected'])
                projection = result if label == 'actual' else expected
                projection[field].append(projection[field][0])
                with self.subTest(label=label, field=field), self.assertRaises(AssertionError):
                    assert_projection(self, result, expected, value)

    def test_unknown_forbidden_example_is_rejected_even_for_blocked_result(self):
        value = source_input('c07')
        expected = copy.deepcopy(CASES['c07']['expected'])
        expected['notSelectedInstanceIds'].append('synthetic-undeclared-instance')
        with self.assertRaises(AssertionError):
            assert_projection(self, selection.select(value), expected, value)

    def test_forbidden_example_universe_comes_from_input_not_output(self):
        value = source_input('c07')
        value['model']['componentInstances']['unused'] = []
        with self.assertRaises(AssertionError):
            assert_projection(self, selection.select(value), CASES['c07']['expected'], value)

    def test_selected_forbidden_example_is_rejected(self):
        value = source_input('c01')
        expected = copy.deepcopy(CASES['c01']['expected'])
        expected['notSelectedInstanceIds'].append(expected['selectedInstanceIds'][0])
        with self.assertRaises(AssertionError):
            assert_projection(self, selection.select(value), expected, value)

    def test_expected_examples_need_not_exhaust_actual_omissions(self):
        value = source_input('c01')
        result = selection.select(value)
        self.assertLess(set(CASES['c01']['expected']['notSelectedInstanceIds']),
                        set(result['notSelectedInstanceIds']))
        assert_projection(self, result, CASES['c01']['expected'], value)

    def test_blocked_result_need_not_emit_a_partial_omitted_partition(self):
        for case_id in ('c07', 'c14'):
            value = source_input(case_id)
            result = selection.select(value)
            with self.subTest(case=case_id):
                self.assertEqual(result['notSelectedInstanceIds'], [])
                self.assertTrue(CASES[case_id]['expected']['notSelectedInstanceIds'])
                assert_projection(self, result, CASES[case_id]['expected'], value)


class SelectionGraphTests(unittest.TestCase):
    def test_transitive_consumers_guards_and_declared_order(self):
        result = selection.select(simple_input())
        self.assertEqual(result['selectedInstanceIds'], ['type', 'static', 'secrets',
                         'auth-linux', 'api-linux', 'web-linux', 'web-windows'])
        self.assertEqual(result['notSelectedInstanceIds'], ['unused-linux'])
        self.assertEqual(result['notSelectedReasons'], [
            {'instanceId': 'unused-linux', 'reasonCode': 'not-reached-or-required'}])
        self.assertEqual(result['evidence'], {'reachedComponents': ['auth', 'api', 'web'],
                         'changedPaths': ['src/auth.ts'], 'fallback': 'none'})
        self.assertEqual((result['status'], result['exitCode']), ('plan-ready', 0))
        self.assertNotIn('accepted', result.values())

    def test_impact_direction_does_not_select_producers(self):
        value = simple_input(); value['changedPaths'] = ['web/view.ts']
        result = selection.select(value)
        self.assertEqual(result['selectedInstanceIds'], ['type', 'static', 'secrets', 'web-linux', 'web-windows'])
        self.assertEqual(result['notSelectedInstanceIds'], ['auth-linux', 'api-linux', 'unused-linux'])

    def test_impact_cycle_and_self_loop_converge(self):
        value = simple_input(); value['model']['impactEdges'] += [['web', 'auth'], ['api', 'api']]
        result = selection.select(value)
        self.assertEqual(result['status'], 'plan-ready')
        self.assertEqual(result['evidence']['reachedComponents'], ['auth', 'api', 'web'])
        self.assertEqual(len(result['selectedInstanceIds']), 7)

    def test_prepare_transitive_closure_is_separate_from_impact(self):
        value = simple_input(); value['changedPaths'] = ['web/view.ts']
        value['model']['prepareEdges'] = [['web-linux', 'api-linux'], ['api-linux', 'auth-linux']]
        result = selection.select(value)
        self.assertEqual(result['evidence']['reachedComponents'], ['web'])
        self.assertEqual(result['selectedInstanceIds'], ['type', 'static', 'secrets',
                         'web-linux', 'web-windows', 'api-linux', 'auth-linux'])

    def test_prepare_direction_does_not_select_dependents(self):
        value = simple_input(); value['changedPaths'] = ['src/auth.ts']; value['model']['impactEdges'] = []
        value['model']['prepareEdges'] = [['web-linux', 'auth-linux']]
        self.assertEqual(selection.select(value)['selectedInstanceIds'], ['type', 'static', 'secrets', 'auth-linux'])

    def test_unreached_prepare_cycle_is_still_invalid(self):
        value = simple_input(); value['changedPaths'] = ['src/auth.ts']; value['model']['impactEdges'] = []
        value['model']['prepareEdges'] = [['web-linux', 'unused-linux'], ['unused-linux', 'web-linux']]
        assert_empty_rejection(self, selection.select(value), 'invalid-input', 3, 'prepare-cycle')

    def test_prepare_self_cycle_is_invalid(self):
        value = simple_input(); value['model']['prepareEdges'] = [['auth-linux', 'auth-linux']]
        assert_empty_rejection(self, selection.select(value), 'invalid-input', 3, 'prepare-cycle')

    def test_base_target_union_can_introduce_prepare_cycle(self):
        value = simple_input(); value['baseModel'] = copy.deepcopy(value['model'])
        value['baseModel']['prepareEdges'] = [['auth-linux', 'api-linux']]
        value['model']['prepareEdges'] = [['api-linux', 'auth-linux']]
        assert_empty_rejection(self, selection.select(value), 'invalid-input', 3, 'prepare-cycle')

    def test_two_variants_remain_selected_on_any_host(self):
        value = simple_input(); value['changedPaths'] = ['web/view.ts']
        with patch('platform.system', return_value='Linux'), patch('os.name', 'posix'):
            result = selection.select(value)
        self.assertIn('web-linux', result['selectedInstanceIds'])
        self.assertIn('web-windows', result['selectedInstanceIds'])

    def test_no_changes_keeps_all_guards(self):
        value = simple_input(); value['changedPaths'] = []
        result = selection.select(value)
        self.assertEqual(result['selectedInstanceIds'], ['type', 'static', 'secrets'])
        self.assertEqual(result['evidence']['reachedComponents'], [])

    def test_empty_selection_is_never_ready(self):
        value = simple_input(); value['changedPaths'] = []; value['model']['guardInstanceIds'] = []
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'empty-selection')

    def test_profile_and_required_instances_add_without_removing_guards(self):
        value = simple_input(); value['changedPaths'] = ['src/auth.ts']; value['model']['impactEdges'] = []
        value['model']['profileInstanceIds'] = {'integration': ['web-windows']}
        value['profile'] = 'integration'; value['requiredInstanceIds'] = ['unused-linux']
        result = selection.select(value)
        self.assertEqual(result['selectedInstanceIds'], ['type', 'static', 'secrets',
                         'auth-linux', 'web-windows', 'unused-linux'])

    def test_path_rule_is_literal_and_adds_declared_instance(self):
        value = simple_input(); value['model']['pathInstanceIds'] = {'src/auth.ts': ['package-check'], 'src': ['literal-root-check']}
        result = selection.select(value)
        self.assertIn('package-check', result['selectedInstanceIds'])
        self.assertIn('literal-root-check', result['notSelectedInstanceIds'])
        self.assertNotIn('literal-root-check', result['selectedInstanceIds'])

    def test_selection_is_fresh_deterministic_and_input_is_unchanged(self):
        value = simple_input(); original = copy.deepcopy(value)
        a = selection.select(value); b = selection.select(value)
        self.assertEqual(a, b); self.assertEqual(value, original)
        a['selectedInstanceIds'].append('tamper'); a['evidence']['changedPaths'].append('tamper')
        self.assertEqual(selection.select(value), b); self.assertEqual(value, original)

    def test_library_function_has_no_files_network_or_process_effects(self):
        with patch('builtins.open', side_effect=AssertionError('filesystem forbidden')) as opened, \
             patch('pathlib.Path.read_bytes', side_effect=AssertionError('filesystem forbidden')) as read, \
             patch('socket.socket', side_effect=AssertionError('network forbidden')) as network, \
             patch('subprocess.Popen', side_effect=AssertionError('process forbidden')) as process:
            self.assertEqual(selection.select(simple_input())['exitCode'], 0)
        opened.assert_not_called(); read.assert_not_called(); network.assert_not_called(); process.assert_not_called()

    def test_long_impact_chain_is_iterative(self):
        size = 1100
        model = {'components': [f'c{i}' for i in range(size)],
                 'literalInputOwners': {'one/file': 'c0'},
                 'componentInstances': {f'c{i}': [f'check{i}'] for i in range(size)},
                 'guardInstanceIds': ['guard'],
                 'impactEdges': [[f'c{i}', f'c{i+1}'] for i in range(size-1)]}
        result = selection.select({'model': model, 'scope': {'repositoryGroup': 'private'}, 'changedPaths': ['one/file']})
        self.assertEqual(result['exitCode'], 0)
        self.assertEqual(len(result['selectedInstanceIds']), size + 1)

    def test_long_prepare_chain_is_iterative(self):
        size = 1100
        model = {'components': ['all'], 'literalInputOwners': {},
                 'componentInstances': {'all': [f'check{i}' for i in range(size)]},
                 'guardInstanceIds': ['guard'],
                 'prepareEdges': [['guard', 'check0']] + [[f'check{i}', f'check{i+1}'] for i in range(size-1)]}
        result = selection.select({'model': model, 'scope': {'repositoryGroup': 'private'}, 'changedPaths': []})
        self.assertEqual(result['exitCode'], 0)
        self.assertEqual(len(result['selectedInstanceIds']), size + 1)


class BaseAndFallbackTests(unittest.TestCase):
    def test_rename_keeps_old_and_new_owners_consumers_and_instances(self):
        value = simple_input(); del value['changedPaths']
        value['baseModel'] = copy.deepcopy(value['model'])
        value['baseModel']['literalInputOwners']['old/schema.json'] = 'auth'
        value['baseModel']['componentInstances']['auth'] = ['old-auth']
        value['baseModel']['impactEdges'] = [['auth', 'api']]
        value['model']['literalInputOwners']['new/schema.json'] = 'web'
        value['model']['impactEdges'] = []
        value['changes'] = [{'status': 'rename', 'old': 'old/schema.json', 'new': 'new/schema.json'}]
        result = selection.select(value)
        self.assertEqual(result['selectedInstanceIds'], ['type', 'static', 'secrets', 'old-auth',
                         'auth-linux', 'api-linux', 'web-linux', 'web-windows'])
        self.assertEqual(result['evidence']['changedPaths'], ['old/schema.json', 'new/schema.json'])

    def test_delete_keeps_base_reverse_dependencies_and_old_quality_instances(self):
        value = simple_input(); del value['changedPaths']
        value['baseModel'] = copy.deepcopy(value['model'])
        value['baseModel']['componentInstances']['auth'] = ['old-required-auth']
        del value['model']['literalInputOwners']['src/auth.ts']
        value['model']['impactEdges'] = []; value['model']['componentInstances']['auth'] = []
        value['changes'] = [{'status': 'delete', 'path': 'src/auth.ts'}]
        result = selection.select(value)
        self.assertEqual(result['evidence']['reachedComponents'], ['auth', 'api', 'web'])
        self.assertIn('old-required-auth', result['selectedInstanceIds'])
        self.assertIn('api-linux', result['selectedInstanceIds'])

    def test_add_and_modify_use_both_declared_graphs(self):
        for status in ('add', 'modify'):
            value = simple_input(); del value['changedPaths']
            value['baseModel'] = copy.deepcopy(value['model'])
            value['model']['impactEdges'] = [['auth', 'unused']]
            value['changes'] = [{'status': status, 'path': 'src/auth.ts'}]
            with self.subTest(status=status):
                self.assertEqual(selection.select(value)['evidence']['reachedComponents'], ['auth', 'api', 'web', 'unused'])

    def test_unknown_path_blocks_without_scope_expansion(self):
        value = simple_input(); value['changedPaths'] = ['unknown/file']
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'unknown-path')

    def test_missing_base_blocks_without_explicit_full_approval(self):
        value = simple_input(); value['baseAvailable'] = False
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'base-unavailable')

    def test_full_approval_alone_does_not_invent_full_profile(self):
        value = simple_input(); value['baseAvailable'] = False; value['repoFullProfileApproved'] = True
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'undeclared-full-profile')

    def test_incomplete_full_profile_blocks(self):
        value = simple_input(); value['baseAvailable'] = False; value['repoFullProfileApproved'] = True
        value['model']['profileInstanceIds'] = {'full': ['auth-linux']}
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'incomplete-full-profile')

    def test_approved_declared_complete_full_fallback_selects_only_current_repo(self):
        for missing_base in (False, True):
            value = simple_input(); value['repoFullProfileApproved'] = True
            value['baseAvailable'] = not missing_base
            if not missing_base: value['changedPaths'] = ['unknown/file']
            model = value['model']
            full = model['guardInstanceIds'] + [i for ids in model['componentInstances'].values() for i in ids]
            model['profileInstanceIds'] = {'full': full}
            with self.subTest(base_missing=missing_base):
                result = selection.select(value)
                self.assertEqual(result['selectedInstanceIds'], full)
                self.assertEqual(result['notSelectedInstanceIds'], [])
                self.assertEqual(result['evidence']['fallback'], 'approved-repository-full')

    def test_profile_declaration_does_not_grant_approval(self):
        value = simple_input(); value['baseAvailable'] = False
        value['model']['profileInstanceIds'] = {'full': ['auth-linux']}
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'base-unavailable')

    def test_excluded_scope_blocked_even_with_full_approval(self):
        value = simple_input(); value['scope']['repositoryGroup'] = 'excluded'; value['repoFullProfileApproved'] = True
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'excluded-scope')

    def test_alias_must_agree_with_canonical_registry_group(self):
        value = simple_input(); value['scope'].update(requestedAlias='learning-copy', aliases={'learning-copy': 'excluded'})
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'scope-registry-conflict')

    def test_unknown_alias_and_group_block(self):
        value = simple_input(); value['scope']['requestedAlias'] = 'unknown'
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'unknown-scope-alias')
        value = simple_input(); value['scope']['repositoryGroup'] = 'other-repository'
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'unknown-repository-group')

    def test_declared_public_alias_is_allowed(self):
        value = simple_input(); value['scope'].update(requestedAlias='public-copy', aliases={'public-copy': 'public'})
        self.assertEqual(selection.select(value)['status'], 'plan-ready')

    def test_undeclared_profile_blocks_without_guard_only_success(self):
        value = simple_input(); value['profile'] = 'release'
        assert_empty_rejection(self, selection.select(value), 'blocked', 4, 'undeclared-profile')


class SelectionInputValidationTests(unittest.TestCase):
    def test_noncanonical_paths_are_rejected_without_normalization(self):
        for path in ('/absolute', '../parent', 'a/../parent', './same', 'a//b', 'a/',
                     r'a\b', 'C:/windows', 'a\x00b', 'e\u0301/file', '\ud800',
                     'aux.txt', 'dir/file.', 'dir/file ', 'a\x7fb', 'a\x80b',
                     'COM¹.txt', 'dir/file?', 'dir/file*', 'dir/a|b'):
            value = simple_input(); value['changedPaths'] = [path]
            with self.subTest(path=repr(path)):
                assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)

    def test_nfc_nonascii_path_is_accepted_when_declared(self):
        value = simple_input(); value['changedPaths'] = ['é/資料.txt']
        value['model']['literalInputOwners']['é/資料.txt'] = 'auth'
        self.assertEqual(selection.select(value)['status'], 'plan-ready')

    def test_case_collisions_across_revisions_and_changed_paths_are_rejected(self):
        for kind in ('change', 'base', 'path-rule'):
            value = simple_input()
            if kind == 'change': value['changedPaths'] = ['SRC/auth.ts']
            elif kind == 'base':
                value['baseModel'] = copy.deepcopy(value['model'])
                value['baseModel']['literalInputOwners']['SRC/auth.ts'] = 'auth'
            else: value['model']['pathInstanceIds'] = {'SRC/auth.ts': ['another']}
            with self.subTest(kind=kind):
                assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)

    def test_unknown_fields_at_each_input_boundary_rejected(self):
        for location in ('root', 'model', 'baseModel', 'scope', 'change'):
            value = simple_input()
            if location == 'root': target = value
            elif location == 'baseModel': value['baseModel'] = copy.deepcopy(value['model']); target = value['baseModel']
            elif location == 'change':
                del value['changedPaths']; value['changes'] = [{'status': 'modify', 'path': 'src/auth.ts'}]; target = value['changes'][0]
            else: target = value[location]
            target['UNEXPECTED_SECRET_SENTINEL'] = True
            with self.subTest(location=location):
                result = selection.select(value)
                assert_empty_rejection(self, result, 'invalid-input', 3)
                self.assertNotIn('UNEXPECTED_SECRET_SENTINEL', json.dumps(result))

    def test_duplicate_identifiers_and_edges_are_rejected(self):
        for field in ('components', 'guardInstanceIds', 'changedPaths', 'impactEdges', 'prepareEdges', 'componentInstances'):
            value = simple_input()
            if field == 'changedPaths': value[field] *= 2
            elif field == 'prepareEdges': value['model'][field] = [['api-linux', 'auth-linux']] * 2
            elif field == 'componentInstances': value['model'][field]['auth'] *= 2
            else: value['model'][field] *= 2
            with self.subTest(field=field):
                assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)

    def test_missing_required_fields_are_rejected(self):
        for field in ('model', 'scope', 'components', 'literalInputOwners', 'componentInstances', 'guardInstanceIds'):
            value = simple_input()
            del (value if field in ('model', 'scope') else value['model'])[field]
            with self.subTest(field=field):
                assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)

    def test_invalid_types_rejected_without_python_exceptions(self):
        for value in (None, [], 1, True, '', {'model': []}, {'model': {}, 'scope': None}):
            with self.subTest(value=repr(value)):
                assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)
        for field in ('baseAvailable', 'repoFullProfileApproved'):
            for bad in (1, 'true', None, []):
                value = simple_input(); value[field] = bad
                with self.subTest(field=field, bad=repr(bad)):
                    assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)

    def test_other_repository_expansion_is_not_an_accepted_input(self):
        value = source_input('r09')
        value['otherRepositories'] = CASES['r09']['given']['other_repositories']
        assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)

    def test_unknown_references_and_profile_are_rejected(self):
        for kind in ('owner', 'mapping', 'impact', 'prepare', 'required', 'profile-ref', 'profile'):
            value = simple_input(); model = value['model']
            if kind == 'owner': model['literalInputOwners']['some/path'] = 'missing'
            elif kind == 'mapping': model['componentInstances']['missing'] = ['other']
            elif kind == 'impact': model['impactEdges'] = [['auth', 'missing']]
            elif kind == 'prepare': model['prepareEdges'] = [['auth-linux', 'missing']]
            elif kind == 'required': value['requiredInstanceIds'] = ['missing']
            elif kind == 'profile-ref': model['profileInstanceIds'] = {'release': ['missing']}
            else: value['profile'] = 'unknown-profile'
            with self.subTest(kind=kind):
                assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)

    def test_malformed_changes_and_ambiguous_forms_are_rejected(self):
        bad_changes = [None, {}, [{}], [{'status': 'rename', 'old': 'src/auth.ts'}],
                       [{'status': 'rename', 'old': 'src/auth.ts', 'new': 'web/view.ts', 'path': 'extra'}],
                       [{'status': 'copy', 'path': 'src/auth.ts'}], [{'status': 'delete'}],
                       [{'status': 'modify', 'path': 1}]]
        for changes in bad_changes:
            value = simple_input(); del value['changedPaths']; value['changes'] = changes
            with self.subTest(changes=repr(changes)):
                assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)
        value = simple_input(); value['changes'] = []
        assert_empty_rejection(self, selection.select(value), 'invalid-input', 3)


class SelectionNegativeControlTests(unittest.TestCase):
    def assert_source_fault_detected(self, case_id, mutation):
        original = source_input(case_id)
        self.assertTrue(CASES[case_id]['negativeControl']['mustBeDetected'])
        assert_projection(self, selection.select(original), CASES[case_id]['expected'], original)
        value = copy.deepcopy(original)
        mutation(value)
        result = selection.select(value)
        # The wrong model simulates an implementation fault. Keep both the
        # original expectation and original declared universe as the oracle.
        with self.assertRaises(AssertionError):
            assert_projection(self, result, CASES[case_id]['expected'], original)

    def test_c01_negative_control_ignores_required_guard_at_selection_boundary(self):
        self.assert_source_fault_detected('c01', lambda v: v['model']['guardInstanceIds'].pop())

    def test_c03_negative_control_ignores_required_auth_consumer(self):
        self.assert_source_fault_detected('c03', lambda v: v['model']['impactEdges'].remove(['auth', 'family']))

    def test_c04_negative_control_ignores_required_generator_instance(self):
        instance = MODEL['instanceAliases']['assets.generate.linux']['instanceId']
        self.assert_source_fault_detected('c04', lambda v: v['model']['componentInstances']['assets'].remove(instance))

    def test_c07_negative_control_bypasses_explicit_full_profile_approval(self):
        def bypass(value):
            # Wrong input represents the source policy-boundary fault: granting
            # a complete full fallback despite the case's explicit disapproval.
            value['model']['profileInstanceIds'] = {'full': sorted(declared_universe(value))}
            value['repoFullProfileApproved'] = True
        self.assert_source_fault_detected('c07', bypass)

    def test_c14_negative_control_ignores_canonical_excluded_scope(self):
        def bypass(value):
            value['scope'] = {'repositoryGroup': 'public'}
        self.assert_source_fault_detected('c14', bypass)

    def test_fault_drops_api_consumer(self):
        self.assert_source_fault_detected('r06', lambda v: v['model']['impactEdges'].remove(['auth', 'api']))

    def test_fault_always_adds_unused_component(self):
        self.assert_source_fault_detected('r06', lambda v: v['model']['impactEdges'].append(['auth', 'unused']))

    def test_fault_omits_required_guard(self):
        self.assert_source_fault_detected('r06', lambda v: v['model']['guardInstanceIds'].pop())

    def test_fault_uses_import_only_model_and_omits_nonimport_owner(self):
        self.assert_source_fault_detected('r07', lambda v: v['model']['literalInputOwners'].pop('fixtures/schema.json'))

    def test_fault_omits_declared_package_rule(self):
        self.assert_source_fault_detected('r07', lambda v: v['model'].pop('pathInstanceIds'))

    def test_fault_drops_windows_variant(self):
        self.assert_source_fault_detected('r07', lambda v: v['model']['componentInstances']['cli'].pop())

    def test_fault_alias_name_bypasses_canonical_excluded_scope(self):
        def bypass(value): value['scope'] = {'repositoryGroup': 'public'}
        self.assert_source_fault_detected('r37', bypass)

    def test_fault_suppresses_prepare_cycle_edge_changes_rejection_cause(self):
        value = source_input('r10'); value['model']['prepareEdges'].pop()
        result = selection.select(value)
        self.assertNotEqual(result['reasonCode'], 'prepare-cycle')
        # Endpoint labels remain undeclared in this source fixture, so this
        # mutant is still invalid. A synthetic declared graph below separately
        # demonstrates that dropping a cycle edge can incorrectly reach ready.
        self.assertEqual(result['reasonCode'], 'invalid-selection-input')

    def test_fault_drops_cycle_edge_in_declared_graph_would_allow_ready(self):
        value = simple_input(); value['model']['prepareEdges'] = [
            ['auth-linux', 'api-linux'], ['api-linux', 'auth-linux']]
        self.assertEqual(selection.select(value)['reasonCode'], 'prepare-cycle')
        value['model']['prepareEdges'].pop()
        self.assertEqual(selection.select(value)['status'], 'plan-ready')

    def test_fault_target_only_delete_loses_old_quality_obligations(self):
        value = simple_input(); del value['changedPaths']
        value['baseModel'] = copy.deepcopy(value['model'])
        value['model']['literalInputOwners'].pop('src/auth.ts')
        value['model']['impactEdges'] = []; value['model']['componentInstances']['auth'] = []
        value['changes'] = [{'status': 'delete', 'path': 'src/auth.ts'}]
        correct = selection.select(value)
        self.assertIn('auth-linux', correct['selectedInstanceIds'])
        value.pop('baseModel')
        self.assertNotEqual(selection.select(value)['selectedInstanceIds'], correct['selectedInstanceIds'])


class SelectionCliTests(unittest.TestCase):
    def run_cli(self, args, data):
        stdin = io.TextIOWrapper(io.BytesIO(data), encoding='utf-8')
        out = io.BytesIO(); err = io.BytesIO()
        stdout = io.TextIOWrapper(out, encoding='utf-8', newline='\r\n')
        stderr = io.TextIOWrapper(err, encoding='utf-8', newline='\r\n')
        with patch('sys.stdin', stdin), patch('sys.stdout', stdout), patch('sys.stderr', stderr):
            code = cli.main(args)
            stdout.flush(); stderr.flush()
            return code, out.getvalue(), err.getvalue()

    def test_explain_stdout_is_canonical_bytes_without_lf(self):
        value = simple_input()
        code, output, error = self.run_cli(['explain', '-'], json.dumps(value).encode())
        self.assertEqual((code, output, error), (0, cjson.dumps(selection.select(value)), b''))
        self.assertFalse(output.endswith(b'\n')); self.assertFalse(output.startswith(b'\xef\xbb\xbf'))

    def test_explain_blocked_is_structured_and_exit_four(self):
        value = simple_input(); value['changedPaths'] = ['unknown/file']
        code, output, error = self.run_cli(['explain'], cjson.dumps(value))
        self.assertEqual((code, output, error), (4, cjson.dumps(selection.select(value)), b''))

    def test_explain_invalid_semantic_input_is_structured_exit_three(self):
        value = simple_input(); value['model']['prepareEdges'] = [['auth-linux', 'auth-linux']]
        code, output, error = self.run_cli(['explain'], cjson.dumps(value))
        self.assertEqual((code, output, error), (3, cjson.dumps(selection.select(value)), b''))

    def test_explain_malformed_json_has_fixed_safe_stderr(self):
        for data in (b'{"SECRET_SENTINEL": NaN}', b'{"a":1,"a":2}', b'\xef\xbb\xbf{}'):
            with self.subTest(data=data):
                self.assertEqual(self.run_cli(['explain'], data), (3, b'', b'ci-contract: invalid input\n'))

    def test_explain_internal_error_has_fixed_safe_stderr(self):
        with patch('ci_contract.selection.select', side_effect=RuntimeError('SECRET_SENTINEL')):
            self.assertEqual(self.run_cli(['explain'], cjson.dumps(simple_input())),
                             (9, b'', b'ci-contract: internal error\n'))

    def test_explain_subprocess_entrypoint_returns_exact_bytes(self):
        value = source_input('r06')
        result = subprocess.run([sys.executable, '-m', 'ci_contract', 'explain', '-'],
                                input=cjson.dumps(value), capture_output=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, cjson.dumps(selection.select(value)), b''))


if __name__ == '__main__':
    unittest.main()
