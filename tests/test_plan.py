"""Synthetic M3 planning tests; no execution or provider connection."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ci_contract import cjson, cli
from ci_contract.arrays import normalize
from ci_contract.errors import InputError, BlockedError
from ci_contract.gitsource import GitSource
from ci_contract.hashing import canonical_hash, domain_hash, raw_hash
from ci_contract.plan import (build_plan, plan_bytes, plan_digest, variant_id, instance_id,
                              MANIFEST, PROJECTION, POLICY, ENGINE_LOCK)
from ci_contract.schema import validate
from synthetic_git import SyntheticGit
from publication_source import transformed_source

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures'
CASE_FILE = FIXTURES / 'plan-cases.json'
CASES = {c['id']: c for c in json.loads(CASE_FILE.read_bytes())['cases']}


def fixture(name):
    return cjson.loads((FIXTURES / name).read_bytes())


def canonical(value):
    return cjson.dumps(normalize(value))


def synthetic_history(directory):
    """Deterministic bytes and plumbing; no checkout, git add or OS mode read."""
    git = SyntheticGit(directory)
    quality = (FIXTURES / 'synthetic-quality-projection.json').read_bytes()
    anchor = git.commit({PROJECTION: ('100644', quality)}, message='synthetic quality anchor')
    manifest = fixture('synthetic-manifest-template.json')
    manifest['qualityProjectionRef']['commit'] = anchor
    files = {MANIFEST: ('100644', canonical(manifest)), PROJECTION: ('100644', quality),
             POLICY: ('100644', (FIXTURES / 'synthetic-policy.json').read_bytes()),
             ENGINE_LOCK: ('100644', (FIXTURES / 'synthetic-engine-lock.json').read_bytes()),
             'src/main.txt': ('100644', b'synthetic base\n'),
             'docs/readme.md': ('100644', b'synthetic docs\n'),
             'bin/helper': ('100644', b'synthetic helper\n')}
    base_files = copy.deepcopy(files)
    base = git.commit(files, parents=(anchor,), message='synthetic base')
    files['src/main.txt'] = ('100644', b'synthetic target\n')
    target = git.commit(files, parents=(base,), message='synthetic target')
    mode_files = copy.deepcopy(files)
    mode_files['bin/helper'] = ('100755', mode_files['bin/helper'][1])
    mode = git.commit(mode_files, parents=(target,), message='synthetic mode only')
    return git, anchor, base, target, mode, manifest, base_files, files


class PlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-plan-')
        cls.directory = Path(cls.temp.name)
        (cls.git, cls.anchor, cls.base, cls.target, cls.mode, cls.manifest,
         cls.base_files, cls.target_files) = synthetic_history(cls.directory / 'synthetic.git')
        cls.plan = build_plan(cls.git.path, 'synthetic', cls.base, cls.target)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def changed_base(self, transform, *, anchor=None):
        files = copy.deepcopy(self.base_files)
        transform(files)
        commit = self.git.commit(files, parents=(anchor or self.anchor,), message='synthetic changed base')
        target = copy.deepcopy(files)
        target['src/main.txt'] = ('100644', b'synthetic target\n')
        head = self.git.commit(target, parents=(commit,), message='synthetic changed target')
        return commit, head

    def build(self, base=None, target=None):
        return build_plan(self.git.path, 'synthetic', base or self.base, target or self.target)

    def test_schema_valid_canonical_nonempty_plan(self):
        validate(self.plan)
        data = plan_bytes(self.plan)
        self.assertEqual(data, canonical(self.plan))
        self.assertFalse(data.endswith(b'\n'))
        self.assertEqual(plan_digest(self.plan), domain_hash('plan', self.plan))
        self.assertEqual(len(self.plan['checks']), 5)
        self.assertEqual({c['variant']['os'] for c in self.plan['checks']}, {'linux', 'windows'})
        self.assertNotIn('accepted', self.plan.values())

    def test_fixed_synthetic_commit_identities(self):
        self.assertEqual(self.anchor, 'f7089354cfb0d09385b6f4ee1dc5a8c9bb02735b')
        # The transformed schema has a new digest; both synthetic engine pins
        # bind it, so descendant fixture commits change. Check identities do not.
        self.assertEqual(self.base, 'f0421bfc8ca810532e6c827bea9fe06a53a75bb5')
        self.assertEqual(self.target, '51948293d8f974e79c21c4581c5a30a7744191da')
        self.assertEqual(self.mode, 'd92e23e9794992112918392770df9e694dde57bd')
        with tempfile.TemporaryDirectory(prefix='ci-contract-repeat-') as temp:
            other = synthetic_history(Path(temp) / 'synthetic.git')
            self.assertEqual(other[1:5], (self.anchor, self.base, self.target, self.mode))

    def test_base_target_profile_and_request_pins_are_bound(self):
        request = self.plan['selectionRequest']
        self.assertEqual(request['baseCommit'], self.base)
        self.assertEqual(request['mode'], 'changed')
        self.assertEqual(self.plan['source']['targetCommit'], self.target)
        self.assertEqual(self.plan['selectionRequestSha256'], canonical_hash(request))
        pins = request['expectedPins']
        for key, path in [('manifest', MANIFEST), ('policy', POLICY), ('engineLock', ENGINE_LOCK)]:
            self.assertEqual(pins[key]['commit'], self.base)
            self.assertEqual(pins[key]['sha256'], raw_hash(self.base_files[path][1]))
        self.assertEqual(pins['qualityProjection'], self.manifest['qualityProjectionRef'])
        self.assertEqual(self.plan['qualityProjectionRef'], pins['qualityProjection'])
        self.assertEqual(self.plan['qualityProjectionSha256'], pins['qualityProjection']['sha256'])

    def test_plan_has_no_execution_destination_run_clock_or_authority(self):
        forbidden = {'execution', 'executionId', 'runId', 'run_id', 'runAttempt', 'target',
                     'startedAt', 'createdAt', 'deadlineAt', 'authority', 'authorityId', 'fence', 'claim'}
        def visit(value):
            if isinstance(value, dict):
                self.assertTrue(forbidden.isdisjoint(value))
                for item in value.values(): visit(item)
            elif isinstance(value, list):
                for item in value: visit(item)
        visit(self.plan)
        # Schema requires this repository preference; it is not a chosen execution.
        self.assertEqual(self.plan['repository']['defaultTarget'], 'github')

    def test_plan_determinism_and_source_bytes_independent_of_location(self):
        again = self.build()
        self.assertEqual(plan_bytes(again), plan_bytes(self.plan))
        self.assertEqual(plan_digest(again), plan_digest(self.plan))
        with tempfile.TemporaryDirectory(prefix='ci-contract-repeat-') as temp:
            other = synthetic_history(Path(temp) / 'synthetic.git')
            rebuilt = build_plan(other[0].path, 'synthetic', other[2], other[3])
            self.assertEqual(plan_bytes(rebuilt), plan_bytes(self.plan))
        self.assertEqual(self.plan['source']['digest'], self.plan['selectionEvidence']['targetInventorySha256'])
        self.assertFalse(self.plan['selectionEvidence']['completenessVerified'])

    def test_changed_base_changes_selected_set(self):
        files = copy.deepcopy(self.target_files)
        files['docs/readme.md'] = ('100644', b'synthetic changed docs\n')
        different_base = self.git.commit(files, parents=(self.anchor,), message='synthetic docs base')
        result = self.build(different_base, self.target)
        self.assertIn('docs.lint', {c['logicalCheckId'] for c in result['checks']})
        self.assertNotEqual(self.plan['selectionEvidence']['selectedInstanceIds'], result['selectionEvidence']['selectedInstanceIds'])

    def test_untrusted_target_cannot_remove_guards_policy_or_engine(self):
        files = copy.deepcopy(self.target_files)
        manifest = copy.deepcopy(self.manifest)
        manifest['checks'] = [c for c in manifest['checks'] if not c['always']]
        files[MANIFEST] = ('100644', canonical(manifest))
        files[POLICY] = ('100644', b'{"kind":"untrusted-target-policy"}')
        files[ENGINE_LOCK] = ('100644', b'{"kind":"untrusted-target-lock"}')
        target = self.git.commit(files, parents=(self.base,), message='synthetic untrusted controls')
        result = self.build(target=target)
        self.assertEqual({c['logicalCheckId'] for c in result['checks'] if c['always']},
                         {'guard.type', 'guard.static', 'guard.secrets'})
        self.assertEqual(result['manifestSha256'], self.plan['manifestSha256'])
        self.assertEqual(result['policySha256'], self.plan['policySha256'])
        self.assertEqual(result['engine'], self.plan['engine'])

    def test_target_unknown_paths_do_not_take_target_graph_authority(self):
        files = copy.deepcopy(self.target_files)
        files['unknown/synthetic.txt'] = ('100644', b'synthetic')
        target = self.git.commit(files, parents=(self.base,), message='synthetic unknown input')
        with self.assertRaisesRegex(BlockedError, 'unknown-path-no-approved-fallback'):
            self.build(target=target)

    def test_target_quality_obligation_removal_is_blocked(self):
        files = copy.deepcopy(self.target_files)
        quality = fixture('synthetic-quality-projection.json')
        quality['requirements'].pop()
        files[PROJECTION] = ('100644', canonical(quality))
        target = self.git.commit(files, parents=(self.base,), message='synthetic reduced obligations')
        with self.assertRaisesRegex(BlockedError, 'quality-obligations-reduced'):
            self.build(target=target)

    def test_missing_manifest_is_blocked(self):
        base, target = self.changed_base(lambda files: files.pop(MANIFEST))
        with self.assertRaisesRegex(BlockedError, 'manifest-unavailable'):
            self.build(base, target)

    def test_invalid_manifest_is_invalid_input(self):
        for data in [b'{}', b'{"kind":"manifest","kind":"manifest"}', b'{"kind":"manifest"}']:
            with self.subTest(data=data):
                base, target = self.changed_base(lambda files: files.update({MANIFEST: ('100644', data)}))
                with self.assertRaises(InputError): self.build(base, target)

    def test_missing_policy_lock_projection_are_blocked(self):
        for path, reason in [(POLICY, 'policy-unavailable'), (ENGINE_LOCK, 'engine-lock-unavailable'),
                             (PROJECTION, 'quality-projection-unavailable')]:
            with self.subTest(path=path):
                base, target = self.changed_base(lambda files: files.pop(path))
                with self.assertRaisesRegex(BlockedError, reason): self.build(base, target)

    def test_policy_pin_mismatch_and_unknown_policy_fail_closed(self):
        def corrupt(files): files[POLICY] = ('100644', b'{}')
        base, target = self.changed_base(corrupt)
        with self.assertRaises(InputError): self.build(base, target)
        def unknown(files):
            value = {'kind': 'unknown-synthetic-policy'}
            raw = cjson.dumps(value)
            manifest = cjson.loads(files[MANIFEST][1]); manifest['policySha256'] = raw_hash(raw)
            files[POLICY] = ('100644', raw); files[MANIFEST] = ('100644', canonical(manifest))
        base, target = self.changed_base(unknown)
        with self.assertRaisesRegex(BlockedError, 'unsupported-policy'): self.build(base, target)

    def test_requirement_check_mapping_must_be_bidirectional(self):
        # A new obligation may not vanish from the plan merely because the
        # associated logical check forgot to reference it in the reverse map.
        manifest = copy.deepcopy(self.manifest)
        quality = fixture('synthetic-quality-projection.json')
        requirement = copy.deepcopy(manifest['requirements'][0])
        requirement.update(id='req.synthetic.extra', externalReferences=['SYNTHETIC-EXTRA'], checkIds=['app.test'])
        manifest['requirements'].append(requirement)
        quality['requirements'].append(copy.deepcopy(requirement))
        quality['mappings'].append({'externalReference': 'SYNTHETIC-EXTRA',
            'requirementId': requirement['id'], 'logicalCheckIds': ['app.test'],
            'purpose': 'Synthetic extra requirement', 'applicability': 'change',
            'classification': 'new-gap', 'exceptionIds': []})
        raw = canonical(quality)
        anchor = self.git.commit({PROJECTION: ('100644', raw)}, message='synthetic extra quality anchor')
        manifest['qualityProjectionRef'].update(commit=anchor, sha256=raw_hash(raw))
        def change(files):
            files[PROJECTION] = ('100644', raw)
            files[MANIFEST] = ('100644', canonical(manifest))
        base, target = self.changed_base(change, anchor=anchor)
        with self.assertRaisesRegex(BlockedError, 'quality-check-unmapped'): self.build(base, target)

    def test_engine_pin_mismatch_is_invalid(self):
        def corrupt(files):
            value = cjson.loads(files[ENGINE_LOCK][1]); value['engine']['version'] = '0.0.1-synthetic'
            files[ENGINE_LOCK] = ('100644', canonical(value))
        base, target = self.changed_base(corrupt)
        with self.assertRaises(InputError): self.build(base, target)

    def test_matching_manifest_lock_cannot_substitute_the_bundled_schema(self):
        def corrupt(files):
            manifest = cjson.loads(files[MANIFEST][1])
            lock = cjson.loads(files[ENGINE_LOCK][1])
            manifest['engine']['schemaSha256'] = '0' * 64
            lock['engine']['schemaSha256'] = '0' * 64
            files[MANIFEST] = ('100644', canonical(manifest))
            files[ENGINE_LOCK] = ('100644', canonical(lock))
        base, target = self.changed_base(corrupt)
        with self.assertRaises(InputError): self.build(base, target)

    def test_declared_release_only_instance_is_omitted_for_change(self):
        def change(files):
            manifest = cjson.loads(files[MANIFEST][1])
            for mapping in manifest['selectionModel']['checkMappings']:
                if mapping['componentIds'] == ['docs']:
                    mapping['condition']['profiles'] = ['release']
            files[MANIFEST] = ('100644', canonical(manifest))
        base, target = self.changed_base(change)
        result = self.build(base, target)
        self.assertNotIn('docs.lint', {c['logicalCheckId'] for c in result['checks']})
        omitted_id = instance_id('docs.lint', fixture('synthetic-manifest-template.json')['checks'][-1]['variants'][0])
        self.assertTrue(any(omitted_id in reason for reason in result['omissionReasons']))

    def test_prepare_dependencies_keep_complete_definitions_and_closure(self):
        def change(files):
            manifest = cjson.loads(files[MANIFEST][1])
            for check in manifest['checks']:
                if check['id'] == 'app.test': check['dependsOn'] = ['docs.lint']
            files[MANIFEST] = ('100644', canonical(manifest))
        base, target = self.changed_base(change)
        result = self.build(base, target)
        docs = next(c for c in result['checks'] if c['logicalCheckId'] == 'docs.lint')
        for check in result['checks']:
            if check['logicalCheckId'] == 'app.test': self.assertEqual(check['dependsOn'], [docs['id']])

    def test_multi_owner_literal_reaches_both_components(self):
        def change(files):
            manifest = cjson.loads(files[MANIFEST][1])
            for rule in manifest['selectionModel']['inputRules']:
                if rule['path'] == 'src/main.txt': rule['componentIds'] = ['app', 'docs']
            files[MANIFEST] = ('100644', canonical(manifest))
        base, target = self.changed_base(change)
        result = self.build(base, target)
        self.assertEqual(result['selectionEvidence']['impactedComponentIds'], ['app', 'docs'])
        self.assertIn('docs.lint', {c['logicalCheckId'] for c in result['checks']})

    def test_synthetic_rename_reaches_old_and_new_owners_without_case_repair(self):
        # Independent synthetic graph. This does not supply missing r08 inputs.
        manifest = copy.deepcopy(self.manifest)
        rule = copy.deepcopy(next(r for r in manifest['selectionModel']['inputRules'] if r['path'] == 'src/main.txt'))
        rule.update(id='synthetic-new-path-rule', path='docs/moved.txt', componentIds=['docs'])
        manifest['selectionModel']['inputRules'].append(rule)
        files = copy.deepcopy(self.base_files)
        files[MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic rename base')
        files['docs/moved.txt'] = files.pop('src/main.txt')
        target = self.git.commit(files, parents=(base,), message='synthetic rename target')
        result = self.build(base, target)
        self.assertEqual(result['selectionEvidence']['impactedComponentIds'], ['app', 'docs'])
        self.assertEqual(result['selectionEvidence']['changes'], [
            {'status': 'added', 'oldPath': None, 'newPath': 'docs/moved.txt'},
            {'status': 'deleted', 'oldPath': 'src/main.txt', 'newPath': None}])
        self.assertIn('app.test', {c['logicalCheckId'] for c in result['checks']})
        self.assertIn('docs.lint', {c['logicalCheckId'] for c in result['checks']})

    def test_prepare_cycle_is_invalid_in_full_manifest(self):
        def change(files):
            manifest = cjson.loads(files[MANIFEST][1])
            for check in manifest['checks']:
                if check['id'] == 'app.test': check['dependsOn'] = ['docs.lint']
                if check['id'] == 'docs.lint': check['dependsOn'] = ['app.test']
            files[MANIFEST] = ('100644', canonical(manifest))
        base, target = self.changed_base(change)
        with self.assertRaises(InputError): self.build(base, target)

    def test_projection_reference_rejects_wrong_repository_path_or_hash(self):
        for key, value in [('repositoryId', 'synthetic-other'), ('path', 'wrong/path'), ('sha256', '0' * 64)]:
            with self.subTest(key=key):
                def corrupt(files):
                    manifest = cjson.loads(files[MANIFEST][1]); manifest['qualityProjectionRef'][key] = value
                    files[MANIFEST] = ('100644', canonical(manifest))
                base, target = self.changed_base(corrupt)
                with self.assertRaises(InputError): self.build(base, target)

    def test_projection_noncanonical_bytes_are_not_raw_hash_confused(self):
        quality = fixture('synthetic-quality-projection.json')
        raw = json.dumps(quality, indent=2).encode()
        anchor = self.git.commit({PROJECTION: ('100644', raw)}, message='synthetic pretty projection')
        def corrupt(files):
            manifest = cjson.loads(files[MANIFEST][1])
            manifest['qualityProjectionRef'].update(commit=anchor, sha256=raw_hash(raw))
            files[MANIFEST] = ('100644', canonical(manifest)); files[PROJECTION] = ('100644', raw)
        base, target = self.changed_base(corrupt, anchor=anchor)
        with self.assertRaises(InputError): self.build(base, target)

    def test_incomplete_or_unmapped_selection_model_is_blocked(self):
        for field, value in [('status', 'unknown'), ('unmappedPaths', ['src/main.txt']),
                             ('scopeComponentIds', ['app'])]:
            with self.subTest(field=field):
                def corrupt(files):
                    manifest = cjson.loads(files[MANIFEST][1])
                    manifest['selectionModel']['completeness'][field] = value
                    files[MANIFEST] = ('100644', canonical(manifest))
                base, target = self.changed_base(corrupt)
                with self.assertRaisesRegex(BlockedError, 'incomplete-selection-model'): self.build(base, target)

    def test_schema_and_semantic_graph_duplicates_rejected(self):
        def corrupt(files):
            manifest = cjson.loads(files[MANIFEST][1]); manifest['checks'].append(copy.deepcopy(manifest['checks'][0]))
            files[MANIFEST] = ('100644', cjson.dumps(manifest))
        base, target = self.changed_base(corrupt)
        with self.assertRaises(InputError): self.build(base, target)

    def test_wrong_repository_and_unsupported_profile_are_invalid(self):
        for kwargs in [{'repository_id': 'synthetic-other'}, {'profile': 'release'}]:
            args = dict(repo_path=self.git.path, repository_id='synthetic', base=self.base, target=self.target)
            args.update(kwargs)
            with self.assertRaises(InputError): build_plan(**args)

    def test_typed_instance_and_variant_hashes_match_fixed_original_aliases(self):
        aliases = json.loads((FIXTURES / 'planning-cases.json').read_bytes())['fixtureModels'][0]['instanceAliases']
        for value in aliases.values():
            self.assertEqual(variant_id(value['variant']), value['variantId'])
            self.assertEqual(instance_id(value['logicalCheckId'], value['variant']), value['instanceId'])

    def test_variant_set_order_is_canonical(self):
        variant = copy.deepcopy(self.plan['checks'][0]['variant'])
        variant['features'] = ['synthetic-z', 'synthetic-a']
        reversed_variant = copy.deepcopy(variant); reversed_variant['features'].reverse()
        self.assertEqual(variant_id(variant), variant_id(reversed_variant))
        self.assertEqual(instance_id('synthetic', variant), instance_id('synthetic', reversed_variant))

    def test_r01_missing_base_fixed_observation(self):
        expected = CASES['r01']['expected']
        self.assertEqual((expected['status'], expected['exitCode']), ('blocked', 4))
        with self.assertRaises(BlockedError) as raised:
            self.build('0' * 40, self.target)
        self.assertEqual(raised.exception.reason_code, expected['observations'][0]['reason'])
        self.assertEqual(expected['selectedInstanceIds'], [])
        self.assertEqual(expected['notSelectedInstanceIds'], [])

    def test_r01_negative_implicit_base_is_detected(self):
        # Inject the fault at the implementation's commit-input boundary, then
        # run the same request and assertions as the positive observation.
        from ci_contract import gitsource
        real_sha = gitsource._sha
        real_paths = gitsource.GitSource.paths
        def infer_base(value):
            return self.base if value == '0' * 40 else real_sha(value)
        def inferred_paths(reader, commit, *args, **kwargs):
            return real_paths(reader, infer_base(commit), *args, **kwargs)
        # paths keeps a commit-keyed directory cache, so its input must receive
        # the same erroneous fallback as the object's SHA validation boundary.
        with patch.object(gitsource, '_sha', side_effect=infer_base) as fault, \
             patch.object(gitsource.GitSource, 'paths', inferred_paths):
            with self.assertRaises(AssertionError):
                self.test_r01_missing_base_fixed_observation()
        self.assertTrue(any(call.args == ('0' * 40,) for call in fault.call_args_list))

    def test_r05_unrelated_private_ledger_does_not_change_plan(self):
        # An unrelated synthetic ledger lives outside the synthetic repository.
        # It is intentionally not an argument, registry, or control dependency.
        ledger = self.directory / 'synthetic-unrelated-ledger.json'
        ledger.write_bytes(b'{"synthetic":"L1"}')
        before = self.build()
        ledger.write_bytes(b'{"synthetic":"L2"}')
        after = self.build()
        expected = CASES['r05']['expected']
        self.assertEqual((expected['status'], expected['exitCode']), ('plan-ready', 0))
        self.assertEqual(plan_bytes(before), plan_bytes(after))
        self.assertEqual(plan_digest(before) == plan_digest(after), expected['observations'][0]['plan_digests_equal'])
        # Runtime execution side effects are not instrumented by this stage.
        # The original execution_started expectation is retained, not claimed observed.

    def test_r05_negative_private_ledger_digest_dependency_is_detected(self):
        # The implementation now reads an unrelated ledger as a policy input;
        # the positive observation must detect this actual planner dependency.
        from ci_contract import plan as planner
        real_policy = planner._policy
        ledger = self.directory / 'synthetic-unrelated-ledger.json'
        def contaminate_policy(*args, **kwargs):
            return real_policy(*args, **kwargs) + ledger.read_bytes()
        with patch.object(planner, '_policy', side_effect=contaminate_policy) as fault:
            with self.assertRaises(AssertionError):
                self.test_r05_unrelated_private_ledger_does_not_change_plan()
        self.assertEqual(fault.call_count, 2)

    def test_r23_mode_only_change_has_new_source_identity(self):
        git = GitSource(self.git.path)
        before = git.source(self.target, self.target)
        after = git.source(self.target, self.mode)
        path = CASES['r23']['given']['path']
        a = next(e for e in before['inputs'] if e['path'] == path)
        b = next(e for e in after['inputs'] if e['path'] == path)
        self.assertEqual(a['bytesSha256'], b['bytesSha256'])
        self.assertEqual(a['mode'], CASES['r23']['given']['before']['mode'])
        self.assertEqual(b['mode'], CASES['r23']['given']['after']['mode'])
        self.assertEqual(before['digest'] == after['digest'], CASES['r23']['expected']['observations'][0]['source_digest_equal'])
        self.assertEqual(CASES['r23']['expected']['status'], 'new-source-identity')
        self.assertIsNone(CASES['r23']['expected']['exitCode'])

    def test_r23_negative_path_content_only_identity_is_detected(self):
        # Patch the digest dependency used by GitSource.source itself, rather
        # than computing an alternate digest on the comparison side.
        def path_content_only(inventory):
            return canonical_hash([{k: entry[k] for k in ('path', 'bytesSha256')}
                                   for entry in inventory['entries']])
        with patch('ci_contract.gitsource.source_digest', side_effect=path_content_only) as fault:
            with self.assertRaises(AssertionError):
                self.test_r23_mode_only_change_has_new_source_identity()
        self.assertEqual(fault.call_count, 2)


class PlanProvenanceTests(unittest.TestCase):
    def test_exact_source_pointers_and_digest(self):
        sources = json.loads((ROOT / 'src/ci_contract/data/SOURCES.json').read_bytes())
        entry = sources['planFiles'][0]
        self.assertEqual(len(CASES), 3)
        self.assertEqual(set(CASES), {'r01', 'r05', 'r23'})
        self.assertEqual(entry['bytes'], len(CASE_FILE.read_bytes()))
        self.assertEqual(entry['sha256'], raw_hash(CASE_FILE.read_bytes()))
        self.assertTrue(all(c['execution'] == 'not-run' for c in CASES.values()))

    def test_immutable_original_matches_extracted_values(self):
        sources = json.loads((ROOT / 'src/ci_contract/data/SOURCES.json').read_bytes())
        entry = sources['planFiles'][0]
        original = json.loads(transformed_source(self, 'acceptance-cases.json', entry['sourceSha256']))
        self.assertEqual(list(CASES.values()), [original['cases'][int(p.split('/')[-1])] for p in entry['jsonPointers']])
        self.assertEqual(sources['planInterpretation']['value'], original['interpretation']['selectedInstances'])

    def test_synthetic_placeholders_are_named_and_valid(self):
        for name in ['synthetic-engine-lock.json', 'synthetic-quality-projection.json', 'synthetic-manifest-template.json']:
            with self.subTest(name=name): validate(fixture(name))
        self.assertIn('synthetic', fixture('synthetic-engine-lock.json')['engine']['version'])
        self.assertEqual(fixture('synthetic-policy.json')['kind'], 'synthetic-plan-policy')


class PlanCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-cli-')
        cls.directory = Path(cls.temp.name)
        cls.history = synthetic_history(cls.directory / 'synthetic.git')

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def invoke(self, out, **changes):
        git, _, base, target, *_ = self.history
        values = {'repo': 'synthetic', 'repo-path': str(git.path), 'base': base, 'target': target,
                  'profile': 'change', 'out': str(out)}
        values.update(changes)
        args = ['plan'] + [value for pair in values.items() for value in ('--' + pair[0], pair[1])]
        stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        stderr = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        with patch.object(sys, 'stdout', stdout), patch.object(sys, 'stderr', stderr):
            code = cli.main(args)
            output, error = stdout.buffer.getvalue(), stderr.buffer.getvalue()
        return code, output, error

    def test_success_writes_canonical_plan_and_domain_hash(self):
        out = self.directory / 'success-plan.json'
        code, stdout, stderr = self.invoke(out)
        self.assertEqual((code, stderr), (0, b''))
        data = out.read_bytes(); plan = cjson.loads(data)
        self.assertEqual(data, plan_bytes(plan))
        self.assertEqual(stdout, plan_digest(plan).encode() + b'\n')
        validate(plan)

    def test_existing_output_is_never_overwritten(self):
        out = self.directory / 'existing.json'; out.write_bytes(b'synthetic existing')
        self.assertEqual(self.invoke(out), (3, b'', b'ci-contract: invalid input\n'))
        self.assertEqual(out.read_bytes(), b'synthetic existing')

    def test_invalid_and_blocked_inputs_never_create_output(self):
        cases = [('base', 'HEAD', 3), ('target', 'A' * 40, 3), ('base', '1234567', 3),
                 ('base', '0' * 40, 4), ('target', '0' * 40, 4), ('profile', 'release', 3),
                 ('repo', 'SYNTHETIC_SECRET', 3)]
        for index, (key, value, code) in enumerate(cases):
            with self.subTest(key=key, value=value):
                out = self.directory / ('failure-' + str(index) + '.json')
                result = self.invoke(out, **{key: value})
                expected = b'ci-contract: blocked\n' if code == 4 else b'ci-contract: invalid input\n'
                self.assertEqual(result, (code, b'', expected))
                self.assertFalse(out.exists())

    def test_internal_error_diagnostic_is_fixed_and_no_output(self):
        out = self.directory / 'internal.json'
        with patch('ci_contract.plan.build_plan', side_effect=RuntimeError('SYNTHETIC_SECRET')):
            self.assertEqual(self.invoke(out), (9, b'', b'ci-contract: internal error\n'))
        self.assertFalse(out.exists())

    def test_failed_write_and_close_remove_only_new_output(self):
        real_open = Path.open
        for fault in ['write', 'close', 'short']:
            with self.subTest(fault=fault):
                out = self.directory / ('failed-' + fault + '.json')
                class FailedOutput:
                    def __init__(self, stream): self.stream = stream
                    def __enter__(self): return self
                    def write(self, data):
                        if fault == 'close': return self.stream.write(data)
                        self.stream.write(data[:20])
                        if fault == 'short': return 20
                        raise OSError('synthetic write failure')
                    def __exit__(self, *args):
                        self.stream.close()
                        if fault == 'close': raise OSError('synthetic close failure')
                def faulty_open(path, mode='r', *args, **kwargs):
                    stream = real_open(path, mode, *args, **kwargs)
                    return FailedOutput(stream) if path == out and mode == 'xb' else stream
                with patch.object(Path, 'open', faulty_open):
                    self.assertEqual(self.invoke(out), (3, b'', b'ci-contract: invalid input\n'))
                self.assertFalse(out.exists())

    def test_module_entrypoint_returns_same_binary_hash(self):
        git, _, base, target, *_ = self.history
        out = self.directory / 'module.json'
        result = subprocess.run([sys.executable, '-m', 'ci_contract', 'plan', '--repo', 'synthetic',
                                 '--repo-path', str(git.path), '--base', base, '--target', target,
                                 '--profile', 'change', '--out', str(out)],
                                env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')},
                                capture_output=True, check=False)
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(result.stdout, (plan_digest(cjson.loads(out.read_bytes())) + '\n').encode())


if __name__ == '__main__': unittest.main()
