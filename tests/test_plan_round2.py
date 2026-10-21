"""Second owner review: unknown-path trust boundaries and precise evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci_contract import cjson, plan as planner
from ci_contract.errors import BlockedError
from ci_contract.hashing import canonical_hash
from ci_contract.arrays import normalize
from test_plan import canonical, synthetic_history, ROOT


class SecondPlanReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-round-two-')
        cls.directory = Path(cls.temp.name)
        (cls.git, cls.anchor, cls.base, cls.target, cls.mode, cls.manifest,
         cls.base_files, cls.target_files) = synthetic_history(cls.directory / 'synthetic.git')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def build(self, base=None, target=None):
        return planner.build_plan(self.git.path, 'synthetic', base or self.base, target or self.target)

    def plugin_history(self, *, bridge=None, unrelated=False, base=None, files=None):
        files = copy.deepcopy(files or self.base_files)
        manifest = cjson.loads(files[planner.MANIFEST][1])
        graph = manifest['selectionModel']
        extra = copy.deepcopy(next(c for c in manifest['checks'] if c['id'] == 'app.test'))
        extra.update(id='synthetic.plugin-only', argv=['synthetic-plugin-do-not-execute'])
        manifest['checks'].append(extra)
        graph['components'].append({'id': 'plugin', 'broadLogicalCheckIds': [extra['id']]})
        graph['completeness']['scopeComponentIds'].append('plugin')
        condition = copy.deepcopy(graph['inputRules'][0]['condition'])
        graph['inputRules'].append({'id': 'synthetic-plugin-rule', 'path': 'src/plugin.txt',
            'role': 'source', 'componentIds': ['plugin'], 'sides': 'base-and-target',
            'condition': condition})
        graph['checkMappings'].append({'componentIds': ['plugin'],
            'logicalCheckIds': [extra['id']], 'condition': copy.deepcopy(condition)})
        if bridge:
            graph['impactEdges'].append({'id': 'synthetic-plugin-bridge',
                'producerComponentId': 'plugin', 'consumerComponentId': bridge,
                'reason': 'shared-contract', 'condition': copy.deepcopy(condition)})
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        files['src/plugin.txt'] = ('100644', b'synthetic new plugin\n')
        if unrelated:
            files['src/main.txt'] = self.target_files['src/main.txt']
        target = self.git.commit(files, parents=(base or self.base,), message='synthetic unknown plugin')
        return target

    def test_target_only_component_cannot_succeed_with_global_guards(self):
        target = self.plugin_history()
        with self.assertRaisesRegex(BlockedError, 'unknown-target-owner-no-approved-fallback'):
            self.build(target=target)

    def test_unrelated_known_change_cannot_hide_unknown_target_component(self):
        target = self.plugin_history(unrelated=True)
        with self.assertRaisesRegex(BlockedError, 'unknown-target-owner-no-approved-fallback'):
            self.build(target=target)

    def test_unknown_path_bridge_to_global_guard_component_is_not_coverage(self):
        target = self.plugin_history(bridge='controls')
        with self.assertRaisesRegex(BlockedError, 'unknown-path-no-trusted-broad-checks'):
            self.build(target=target)

    def test_inapplicable_component_guard_is_not_broad_coverage(self):
        for components, profiles in ((['docs'], ['change']), (['app'], ['release'])):
            with self.subTest(components=components, profiles=profiles):
                manifest = copy.deepcopy(self.manifest)
                next(c for c in manifest['selectionModel']['components'] if c['id'] == 'app')['broadLogicalCheckIds'] = ['docs.lint']
                check = next(c for c in manifest['checks'] if c['id'] == 'docs.lint')
                check.update(always=True, alwaysScope={'scope': 'component',
                    'componentIds': components, 'profiles': profiles})
                files = copy.deepcopy(self.base_files)
                files[planner.MANIFEST] = ('100644', canonical(manifest))
                base = self.git.commit(files, parents=(self.anchor,), message='synthetic inapplicable broad guard')
                target = self.plugin_history(bridge='app', base=base, files=files)
                with self.assertRaisesRegex(BlockedError, 'unknown-path-no-trusted-broad-checks'):
                    self.build(base, target)

    def test_inactive_non_guard_is_not_broad_coverage(self):
        manifest = copy.deepcopy(self.manifest)
        next(c for c in manifest['selectionModel']['components'] if c['id'] == 'app')['broadLogicalCheckIds'] = ['docs.lint']
        for mapping in manifest['selectionModel']['checkMappings']:
            if 'docs.lint' in mapping['logicalCheckIds']:
                mapping['condition']['profiles'] = ['release']
        files = copy.deepcopy(self.base_files)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic inactive broad check')
        target = self.plugin_history(bridge='app', base=base, files=files)
        with self.assertRaisesRegex(BlockedError, 'unknown-path-no-trusted-broad-checks'):
            self.build(base, target)

    def test_guard_only_fault_in_actual_fallback_is_detected(self):
        with patch.object(planner, '_unknown_path_fallback', return_value=([],
                {'scope': 'none', 'componentIds': [], 'reasons': []})) as fault:
            with self.assertRaises(AssertionError):
                self.test_target_only_component_cannot_succeed_with_global_guards()
        self.assertTrue(fault.called)

    def test_target_only_component_bridge_uses_trusted_component_broad_fallback(self):
        result = self.build(target=self.plugin_history(bridge='app'))
        self.assertEqual(result['selectionEvidence']['fallback'], {
            'scope': 'component-broad', 'componentIds': ['app'],
            'reasons': ['unknown-path-to-trusted-component']})
        self.assertEqual({c['variant']['os'] for c in result['checks']
                          if c['logicalCheckId'] == 'app.test'}, {'linux', 'windows'})
        self.assertFalse(any(c['logicalCheckId'] == 'synthetic.plugin-only' for c in result['checks']))

    def test_new_literal_owned_by_known_component_requires_all_base_broad_checks(self):
        manifest = copy.deepcopy(self.manifest)
        next(c for c in manifest['selectionModel']['components'] if c['id'] == 'app')['broadLogicalCheckIds'].append('docs.lint')
        files = copy.deepcopy(self.base_files)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic trusted broad component')
        rule = copy.deepcopy(next(r for r in manifest['selectionModel']['inputRules'] if r['path'] == 'src/main.txt'))
        rule.update(id='synthetic-new-known-owner', path='src/extra.txt')
        manifest['selectionModel']['inputRules'].append(rule)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        files['src/extra.txt'] = ('100644', b'synthetic extra source\n')
        target = self.git.commit(files, parents=(base,), message='synthetic known owner new path')
        result = self.build(base, target)
        self.assertEqual(result['selectionEvidence']['fallback']['scope'], 'component-broad')
        self.assertTrue({'app.test', 'docs.lint'} <= {c['logicalCheckId'] for c in result['checks']})

    def test_undeclared_path_has_distinct_unknown_path_reason(self):
        files = copy.deepcopy(self.target_files)
        files['src/undeclared.txt'] = ('100644', b'synthetic undeclared\n')
        target = self.git.commit(files, parents=(self.base,), message='synthetic undeclared path')
        with self.assertRaisesRegex(BlockedError, 'unknown-path-no-approved-fallback'):
            self.build(target=target)

    def test_target_only_variant_is_recorded_without_executable_identity(self):
        manifest = copy.deepcopy(self.manifest)
        check = next(c for c in manifest['checks'] if c['id'] == 'app.test')
        variant = copy.deepcopy(check['variants'][0])
        variant.update(os='macos', arch='aarch64', features=['synthetic-target-only'])
        check['variants'].append(variant)
        vid = planner.variant_id(variant)
        for rule in manifest['selectionModel']['inputRules']:
            rule['condition']['variantIds'].append(vid)
        for mapping in manifest['selectionModel']['checkMappings']:
            mapping['condition']['variantIds'].append(vid)
        files = copy.deepcopy(self.target_files)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        target = self.git.commit(files, parents=(self.base,), message='synthetic target-only variant')
        result = self.build(target=target)
        iid = planner.instance_id('app.test', variant)
        self.assertNotIn(iid, result['selectionEvidence']['selectedInstanceIds'])
        self.assertFalse(any(c['variant'] == variant for c in result['checks']))
        self.assertIn('target-only-variant:app.test:' + vid, result['omissionReasons'])
        self.assertEqual(result['selectionEvidence']['targetModelSha256'],
                         canonical_hash(normalize(manifest)['selectionModel']))

    def test_ancestor_without_projection_has_distinct_reason(self):
        anchor = self.git.commit({'placeholder.txt': ('100644', b'synthetic empty anchor')},
                                 message='synthetic ancestor without projection')
        manifest = copy.deepcopy(self.manifest)
        manifest['qualityProjectionRef']['commit'] = anchor
        files = copy.deepcopy(self.base_files)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(anchor,), message='synthetic base missing anchor projection')
        with self.assertRaisesRegex(BlockedError, 'projection-anchor-projection-unavailable'):
            self.build(base, base)

    def test_target_missing_controls_have_side_specific_reasons(self):
        for path, reason in ((planner.MANIFEST, 'target-manifest-unavailable'),
                             (planner.PROJECTION, 'target-quality-projection-unavailable')):
            with self.subTest(path=path):
                files = copy.deepcopy(self.target_files)
                files.pop(path)
                target = self.git.commit(files, parents=(self.base,), message='synthetic target missing control')
                with self.assertRaisesRegex(BlockedError, reason):
                    self.build(target=target)


class SecondReportTests(unittest.TestCase):
    def test_exact_original_observation_quote_and_coverage_naming(self):
        quote = ('Expected at the stated observation point; empty means '
                 'pre-plan/canonical/compatibility stage, not an accepted zero-check run.')
        sources = cjson.loads((ROOT / 'src/ci_contract/data/SOURCES.json').read_bytes())
        self.assertEqual(sources['planInterpretation']['value'], quote)
        self.assertEqual(sources['planInterpretation']['jsonPointer'], '/interpretation/selectedInstances')
        coverage = cjson.loads((ROOT / 'tests/acceptance-coverage.json').read_bytes())
        self.assertNotIn('stageProjectionPassedCount', coverage['planCore'])
        self.assertEqual(coverage['planCore']['stageObservationPassedCount'], 3)
        for case in coverage['planCore']['cases']:
            self.assertEqual(case['selectedInstancesSourceQuote'], quote)
        r05 = next(c for c in coverage['planCore']['cases'] if c['id'] == 'r05')
        self.assertNotIn('executionStarted', r05)
        self.assertFalse(r05['executionSideEffectsObserved'])
