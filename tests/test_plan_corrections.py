"""Owner-review regressions built only from independent synthetic variants.

Frozen acceptance inputs and the default six-commit fixture are not modified.
These tests exercise planner output and inject faults into implementation seams,
never into expected values or the comparison-side observations.
"""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci_contract import cjson, plan as planner
from ci_contract.arrays import normalize
from ci_contract.errors import BlockedError
from ci_contract.gitsource import GitSource
from ci_contract.hashing import canonical_hash, raw_hash
from ci_contract.schema import validate
from test_plan import canonical, fixture, synthetic_history


class PlanCorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-corrections-')
        cls.directory = Path(cls.temp.name)
        (cls.git, cls.anchor, cls.base, cls.target, cls.mode, cls.manifest,
         cls.base_files, cls.target_files) = synthetic_history(cls.directory / 'synthetic.git')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def build(self, base=None, target=None):
        return planner.build_plan(self.git.path, 'synthetic', base or self.base, target or self.target)

    def target_with(self, transform, *, base=None, files=None):
        values = copy.deepcopy(self.target_files if files is None else files)
        transform(values)
        return self.git.commit(values, parents=(base or self.base,), message='synthetic correction target')

    def target_manifest(self, transform, *, base=None, files=None):
        def update(values):
            manifest = cjson.loads(values[planner.MANIFEST][1])
            transform(manifest)
            values[planner.MANIFEST] = ('100644', canonical(manifest))
        return self.target_with(update, base=base, files=files)

    def edge(self, producer='app', consumer='docs'):
        return {'id': 'synthetic-extra-impact', 'producerComponentId': producer,
                'consumerComponentId': consumer, 'reason': 'shared-contract',
                'condition': copy.deepcopy(self.manifest['selectionModel']['inputRules'][0]['condition'])}

    def logical_checks(self, plan):
        return {check['logicalCheckId'] for check in plan['checks']}

    def assert_trusted_controls(self, result, base=None):
        reference = self.build(base=base, target=base or self.base)
        for field in ('manifestSha256', 'policySha256', 'engine',
                      'qualityProjectionRef', 'qualityProjectionSha256'):
            self.assertEqual(result[field], reference[field])
        manifest = cjson.loads(GitSource(self.git.path).read_blob(
            base or self.base, planner.MANIFEST, side='base'))
        _, trusted, _, _ = planner._compile(manifest, 'change')
        for check in result['checks']:
            expected = normalize({'kind': 'plan', 'checks': [trusted[check['id']]]})['checks'][0]
            self.assertEqual(check, expected)

    def test_target_new_literal_owner_selects_trusted_base_check(self):
        target_manifest = copy.deepcopy(self.manifest)
        rule = copy.deepcopy(next(r for r in target_manifest['selectionModel']['inputRules']
                                  if r['path'] == 'src/main.txt'))
        rule.update(id='synthetic-added-file', path='src/added.txt')
        target_manifest['selectionModel']['inputRules'].append(rule)
        def update(files):
            files['src/main.txt'] = self.base_files['src/main.txt']
            files['src/added.txt'] = ('100644', b'synthetic newly declared source\n')
            files[planner.MANIFEST] = ('100644', canonical(target_manifest))
        target = self.target_with(update)
        result = self.build(target=target)
        self.assertIn('app.test', self.logical_checks(result))
        self.assertNotIn('docs.lint', self.logical_checks(result))
        self.assertIn('app', result['selectionEvidence']['impactedComponentIds'])
        self.assert_trusted_controls(result)
        self.assertEqual(result['selectionEvidence']['targetModelSha256'],
                         canonical_hash(normalize(target_manifest)['selectionModel']))
        self.assertNotEqual(result['selectionEvidence']['targetModelSha256'],
                            result['selectionEvidence']['baseModelSha256'])

    def test_target_reassigned_literal_owner_preserves_both_graph_owners(self):
        def reassign(manifest):
            rule = next(r for r in manifest['selectionModel']['inputRules'] if r['path'] == 'src/main.txt')
            rule['componentIds'] = ['docs']
        result = self.build(target=self.target_manifest(reassign))
        self.assertTrue({'app.test', 'docs.lint'} <= self.logical_checks(result))
        self.assertTrue({'app', 'docs'} <= set(result['selectionEvidence']['impactedComponentIds']))
        self.assert_trusted_controls(result)

    def test_target_added_impact_edge_broadens_base_check_selection(self):
        target_manifest = copy.deepcopy(self.manifest)
        target_manifest['selectionModel']['impactEdges'].append(self.edge())
        target = self.target_with(lambda files: files.update({
            planner.MANIFEST: ('100644', canonical(target_manifest))}))
        result = self.build(target=target)
        self.assertEqual(self.logical_checks(result),
                         {'app.test', 'docs.lint', 'guard.type', 'guard.static', 'guard.secrets'})
        self.assertIn('docs', result['selectionEvidence']['impactedComponentIds'])
        self.assertEqual(result['selectionEvidence']['targetModelSha256'],
                         canonical_hash(normalize(target_manifest)['selectionModel']))
        self.assert_trusted_controls(result)

    def test_target_new_component_can_bridge_to_a_trusted_check(self):
        manifest = copy.deepcopy(self.manifest)
        graph = manifest['selectionModel']
        graph['components'].append({'id': 'synthetic-bridge', 'broadLogicalCheckIds': ['docs.lint']})
        graph['completeness']['scopeComponentIds'].append('synthetic-bridge')
        rule = copy.deepcopy(graph['inputRules'][0])
        rule.update(id='synthetic-bridge-rule', path='src/new-bridge.txt', componentIds=['synthetic-bridge'])
        graph['inputRules'].append(rule)
        graph['impactEdges'].append(self.edge('synthetic-bridge', 'docs'))
        target = self.target_with(lambda files: files.update({
            'src/new-bridge.txt': ('100644', b'synthetic bridge\n'),
            planner.MANIFEST: ('100644', canonical(manifest))}))
        result = self.build(target=target)
        self.assertIn('docs.lint', self.logical_checks(result))
        self.assertIn('synthetic-bridge', result['selectionEvidence']['impactedComponentIds'])

    def test_target_deleting_edges_and_ownership_cannot_narrow_base(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['selectionModel']['impactEdges'].append(self.edge())
        files = copy.deepcopy(self.base_files)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic base with impact')
        target_files = copy.deepcopy(files)
        target_files['src/main.txt'] = self.target_files['src/main.txt']
        def reduce(target_manifest):
            graph = target_manifest['selectionModel']
            graph['impactEdges'] = []
            graph['inputRules'] = [r for r in graph['inputRules'] if r['path'] != 'src/main.txt']
        target = self.target_manifest(reduce, base=base, files=target_files)
        result = self.build(base, target)
        self.assertIn('docs.lint', self.logical_checks(result))
        self.assertIn('app.test', self.logical_checks(result))
        self.assertEqual(result['selectionEvidence']['baseModelSha256'],
                         canonical_hash(normalize(manifest)['selectionModel']))

    def test_target_only_check_is_recorded_but_never_executed(self):
        manifest = copy.deepcopy(self.manifest)
        extra = copy.deepcopy(next(check for check in manifest['checks'] if check['id'] == 'app.test'))
        extra.update(id='synthetic.target-only', argv=['synthetic-target-only-do-not-execute'])
        manifest['checks'].append(extra)
        manifest['selectionModel']['checkMappings'].append({
            'componentIds': ['app'], 'logicalCheckIds': [extra['id']],
            'condition': copy.deepcopy(manifest['selectionModel']['checkMappings'][0]['condition'])})
        target = self.target_with(lambda files: files.update({
            planner.MANIFEST: ('100644', canonical(manifest))}))
        result = self.build(target=target)
        self.assertNotIn(extra['id'], self.logical_checks(result))
        self.assertTrue(any(extra['id'] in reason for reason in result['omissionReasons']))
        self.assertIn('app.test', self.logical_checks(result))
        self.assertEqual(result['selectionEvidence']['targetModelSha256'],
                         canonical_hash(normalize(manifest)['selectionModel']))

    def test_target_check_definition_cannot_replace_base_execution_fields(self):
        def poison(manifest):
            check = next(c for c in manifest['checks'] if c['id'] == 'app.test')
            check.update(argv=['synthetic-target-definition-do-not-execute'], timeoutSeconds=7200,
                         adapter='synthetic-untrusted-adapter', adapterSha256='0' * 64,
                         network='synthetic-service', dependsOn=['docs.lint'])
        result = self.build(target=self.target_manifest(poison))
        self.assertIn('app.test', self.logical_checks(result))
        self.assertNotIn('docs.lint', self.logical_checks(result))
        self.assert_trusted_controls(result)

    def test_directory_literal_role_is_preserved_in_source_inventory(self):
        manifest = copy.deepcopy(self.manifest)
        rule = copy.deepcopy(next(r for r in manifest['selectionModel']['inputRules']
                                  if r['path'] == 'src/main.txt'))
        rule.update(id='synthetic-directory-role', path='src', role='generated')
        manifest['selectionModel']['inputRules'].append(rule)
        files = copy.deepcopy(self.base_files)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic declared directory role')
        files['src/main.txt'] = self.target_files['src/main.txt']
        target = self.git.commit(files, parents=(base,), message='synthetic directory-role target')
        result = self.build(base, target)
        directory = next(entry for entry in result['source']['inputs'] if entry['path'] == 'src')
        self.assertEqual((directory['kind'], directory['role']), ('directory', 'generated'))

    def quality_target(self, transform, *, base=None, files=None):
        def update(values):
            projection = cjson.loads(values[planner.PROJECTION][1])
            transform(projection)
            values[planner.PROJECTION] = ('100644', canonical(projection))
        return self.target_with(update, base=base, files=files)

    def rich_quality_base(self):
        """A valid stronger base permits schema-valid removals in regressions."""
        projection = fixture('synthetic-quality-projection.json')
        requirement = projection['requirements'][0]
        requirement['checkIds'].append('docs.lint')
        requirement['origins'].append('synthetic-extra-origin')
        requirement['externalReferences'].append('SYNTHETIC-extra-reference')
        requirement['releaseRequired'] = True
        mapping = projection['mappings'][0]
        mapping['logicalCheckIds'].append('docs.lint')
        mapping['applicability'] = 'all'
        extra_mapping = copy.deepcopy(mapping)
        extra_mapping['externalReference'] = 'SYNTHETIC-extra-reference'
        projection['mappings'].append(extra_mapping)
        raw = canonical(projection)
        anchor = self.git.commit({planner.PROJECTION: ('100644', raw)},
                                 parents=(self.anchor,), message='synthetic strengthened quality anchor')
        manifest = copy.deepcopy(self.manifest)
        manifest['requirements'] = copy.deepcopy(projection['requirements'])
        next(c for c in manifest['checks'] if c['id'] == 'docs.lint')['requirementIds'].append(requirement['id'])
        manifest['qualityProjectionRef'].update(commit=anchor, sha256=raw_hash(raw))
        files = copy.deepcopy(self.base_files)
        files[planner.PROJECTION] = ('100644', raw)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(anchor,), message='synthetic strengthened quality base')
        files['src/main.txt'] = self.target_files['src/main.txt']
        return base, files

    def test_quality_descriptive_edits_and_strengthening_are_allowed(self):
        def purpose(projection):
            projection['requirements'][0]['purpose'] = 'Synthetic corrected explanatory text'
            projection['mappings'][0]['purpose'] = 'Synthetic corrected mapping text'
        def release(projection):
            projection['requirements'][0]['releaseRequired'] = True
        def provenance(projection):
            projection['requirements'][0]['origins'].append('synthetic-additional-origin')
        def checks(projection):
            projection['requirements'][0]['checkIds'].append('docs.lint')
            projection['mappings'][0]['logicalCheckIds'].append('docs.lint')
        def reference(projection):
            projection['requirements'][0]['externalReferences'].append('SYNTHETIC-new-reference')
            mapping = copy.deepcopy(projection['mappings'][0])
            mapping['externalReference'] = 'SYNTHETIC-new-reference'
            projection['mappings'].append(mapping)
        def scope(projection):
            projection['mappings'][0]['applicability'] = 'all'
        def labels(projection):
            projection['requirements'][0]['coverage'] = 'inherited'
            projection['mappings'][0]['classification'] = 'inherited'
            projection['revision'] = 'synthetic-v2'
            projection['approvalRef'] = 'synthetic-new-approval'
        for name, transform in [('purpose', purpose), ('releaseRequired', release),
                                ('origins', provenance), ('checkIds', checks),
                                ('externalReferences', reference), ('applicability', scope),
                                ('descriptive labels', labels)]:
            with self.subTest(field=name):
                target = self.quality_target(transform)
                result = self.build(target=target)
                self.assertIn('app.test', self.logical_checks(result))
                self.assert_trusted_controls(result)

    def test_quality_requirement_set_removals_and_release_weakening_are_blocked(self):
        base, files = self.rich_quality_base()
        for field, value in [('checkIds', ['app.test']),
                             ('origins', ['synthetic-fixture']),
                             ('externalReferences', ['SYNTHETIC-app.test']),
                             ('releaseRequired', False)]:
            with self.subTest(field=field):
                target = self.quality_target(lambda p: p['requirements'][0].update({field: value}),
                                             base=base, files=files)
                with self.assertRaisesRegex(BlockedError, 'quality-obligations-reduced'):
                    self.build(base, target)

    def test_quality_mapping_weakening_and_removal_are_blocked(self):
        base, files = self.rich_quality_base()
        for field, value in [('logicalCheckIds', ['app.test']), ('applicability', 'change'),
                             ('requirementId', 'req.docs.lint'),
                             ('exceptionIds', ['synthetic-new-exception'])]:
            with self.subTest(field=field):
                target = self.quality_target(lambda p: p['mappings'][0].update({field: value}),
                                             base=base, files=files)
                with self.assertRaisesRegex(BlockedError, 'quality-obligations-reduced'):
                    self.build(base, target)
        target = self.quality_target(lambda p: p['mappings'].pop(0), base=base, files=files)
        with self.assertRaisesRegex(BlockedError, 'quality-obligations-reduced'):
            self.build(base, target)

    def test_quality_profile_replacement_and_new_exemptions_are_blocked(self):
        for name, transform in [
                ('disjoint profile', lambda p: p['mappings'][0].update(applicability='release')),
                ('projection exemption', lambda p: p['exceptionIds'].append('synthetic-exemption')),
                ('mapping exemption', lambda p: p['mappings'][0]['exceptionIds'].append('synthetic-exemption'))]:
            with self.subTest(field=name):
                target = self.quality_target(transform)
                with self.assertRaisesRegex(BlockedError, 'quality-obligations-reduced'):
                    self.build(target=target)

    def test_quality_added_reference_without_mapping_is_blocked(self):
        target = self.quality_target(lambda p: p['requirements'][0]['externalReferences'].append('SYNTHETIC-unmapped'))
        with self.assertRaises(BlockedError):
            self.build(target=target)

    def guard_only_history(self, *, remove=False):
        """Guards are selected solely by alwaysScope, never component mappings."""
        manifest = copy.deepcopy(self.manifest)
        guards = {check['id'] for check in manifest['checks'] if check['always']}
        graph = manifest['selectionModel']
        for component in graph['components']:
            component['broadLogicalCheckIds'] = [lid for lid in component['broadLogicalCheckIds'] if lid not in guards] or ['app.test']
        graph['checkMappings'] = [mapping for mapping in graph['checkMappings']
                                  if not guards.intersection(mapping['logicalCheckIds'])]
        files = copy.deepcopy(self.base_files)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic guards only always base')
        target_manifest = copy.deepcopy(manifest)
        if remove:
            target_manifest['checks'] = [check for check in target_manifest['checks'] if check['id'] not in guards]
        else:
            for check in target_manifest['checks']:
                if check['id'] in guards:
                    check.update(always=False, alwaysScope=None)
            # A target replacement remains structurally compilable, but its
            # now-optional guards are dormant for the change profile.
            dormant = copy.deepcopy(self.manifest['selectionModel']['checkMappings'][1])
            dormant['condition']['profiles'] = ['release']
            target_manifest['selectionModel']['checkMappings'].append(dormant)
        target_files = copy.deepcopy(files)
        target_files['src/main.txt'] = self.target_files['src/main.txt']
        target_files[planner.MANIFEST] = ('100644', canonical(target_manifest))
        target = self.git.commit(target_files, parents=(base,), message='synthetic target drops always guards')
        compact, _, _, _ = planner._compile(manifest, 'change')
        guard_instances = set(compact['guardInstanceIds'])
        self.assertEqual(len(guard_instances), 3)
        self.assertTrue(all(guard_instances.isdisjoint(ids) for ids in compact['componentInstances'].values()))
        return base, target, guards

    def assert_guard_observation(self, base, target, guards):
        result = self.build(base, target)
        selected_guards = {check['logicalCheckId'] for check in result['checks'] if check['always']}
        self.assertEqual(selected_guards, guards)
        self.assertTrue(guards <= self.logical_checks(result))
        return result

    def test_target_removed_guards_remain_selected_from_base_always_scope(self):
        self.assert_guard_observation(*self.guard_only_history(remove=True))

    def test_target_always_false_guards_remain_selected_from_base_always_scope(self):
        self.assert_guard_observation(*self.guard_only_history())

    def test_clearing_implementation_guards_is_detected_without_component_mapping(self):
        base, target, guards = self.guard_only_history()
        real_compile = planner._compile
        def clear_guards(*args, **kwargs):
            compact, expanded, roles, nodes = real_compile(*args, **kwargs)
            compact['guardInstanceIds'] = []
            return compact, expanded, roles, nodes
        with patch.object(planner, '_compile', side_effect=clear_guards) as fault:
            with self.assertRaises(AssertionError):
                self.assert_guard_observation(base, target, guards)
        self.assertGreater(fault.call_count, 0)

    def test_substituting_target_manifest_in_implementation_is_detected(self):
        base, target, guards = self.guard_only_history()
        real_document = planner._document
        def substitute(git, commit, path, kind, *args, **kwargs):
            if commit == base and path == planner.MANIFEST:
                commit = target
            return real_document(git, commit, path, kind, *args, **kwargs)
        with patch.object(planner, '_document', side_effect=substitute) as fault:
            with self.assertRaises(AssertionError):
                self.assert_guard_observation(base, target, guards)
        self.assertTrue(any(call.args[1:3] == (base, planner.MANIFEST) for call in fault.call_args_list))

    def projection_reference_history(self, anchor):
        manifest = copy.deepcopy(self.manifest)
        manifest['qualityProjectionRef']['commit'] = anchor
        files = copy.deepcopy(self.base_files)
        files[planner.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic projection reference base')
        files['src/main.txt'] = self.target_files['src/main.txt']
        target = self.git.commit(files, parents=(base,), message='synthetic projection reference target')
        return base, target

    def test_projection_missing_anchor_has_distinct_reason(self):
        with self.assertRaisesRegex(BlockedError, 'projection-anchor-not-recoverable'):
            self.build(*self.projection_reference_history('0' * 40))

    def test_projection_unrelated_anchor_is_blocked_even_with_identical_bytes(self):
        unrelated = self.git.commit({planner.PROJECTION: self.base_files[planner.PROJECTION]},
                                    message='synthetic unrelated root identical projection')
        with self.assertRaisesRegex(BlockedError, 'projection-anchor-not-ancestor'):
            self.build(*self.projection_reference_history(unrelated))

    def test_projection_real_ancestor_is_accepted(self):
        result = self.build(*self.projection_reference_history(self.anchor))
        self.assertEqual(result['qualityProjectionRef']['commit'], self.anchor)
        self.assertIn('app.test', self.logical_checks(result))

    def test_selection_request_hash_matches_normalized_embedded_explicit_request(self):
        real_normalize = planner.normalize
        injected = []
        def unsorted_request(value, document_kind=None):
            if document_kind == 'selection-request':
                value = copy.deepcopy(value)
                value.update(mode='explicit', requestedCheckIds=['guard.type', 'app.test'],
                             cases=[{'checkId': 'guard.type', 'caseIds': ['synthetic-z', 'synthetic-a']},
                                    {'checkId': 'app.test', 'caseIds': ['synthetic-b', 'synthetic-a']}])
                injected.append(copy.deepcopy(value))
            return real_normalize(value, document_kind)
        with patch.object(planner, 'normalize', side_effect=unsorted_request):
            result = self.build()
        self.assertEqual(len(injected), 1)
        request = result['selectionRequest']
        self.assertEqual(request['requestedCheckIds'], ['app.test', 'guard.type'])
        self.assertEqual([case['checkId'] for case in request['cases']], ['app.test', 'guard.type'])
        self.assertTrue(all(case['caseIds'] == sorted(case['caseIds']) for case in request['cases']))
        self.assertNotEqual(request, injected[0])
        self.assertEqual(result['selectionRequestSha256'], canonical_hash(request))
        validate(result)


if __name__ == '__main__':
    unittest.main()
