"""Synthetic regression evidence for M5's retained M4 boundaries."""
import copy
import hashlib
import inspect
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from ci_contract import cjson, selection
from ci_contract.errors import InputError
import test_contract_bytes as contract
import test_publication as publication
import test_selection as selection_tests
import publication_source


def changed(module, before, after):
    source = inspect.getsource(module)
    if source.count(before) != 1:
        raise AssertionError('fault location changed')
    result = types.ModuleType('synthetic_carryover_fault')
    result.__package__ = module.__package__
    result.__file__ = module.__file__
    exec(compile(source.replace(before, after), '<synthetic-carryover-fault>', 'exec'), result.__dict__)
    return result


class SelectionShapeCarryovers(unittest.TestCase):
    def assert_alias_definitions(self, selector):
        for group in ('excluded', 'public'):
            for aliases in ([], {'a': 5}, {'': 'public'}):
                value = selection_tests.simple_input()
                value['scope'] = {'repositoryGroup': group, 'aliases': aliases}
                result = selector(value)
                self.assertEqual((result['status'], result['exitCode']), ('invalid-input', 3))

    def test_l1_alias_definitions_in_both_groups(self):
        self.assert_alias_definitions(selection.select)

    def test_l1_removed_loop_fault_is_detected(self):
        loop = "    for alias, canonical in aliases.items():\n        _name(alias)\n        _name(canonical)\n"
        faulty = changed(selection, loop, '')
        with self.assertRaises(AssertionError):
            self.assert_alias_definitions(faulty.select)

    def test_l1_late_definitions_fault_is_detected(self):
        source = inspect.getsource(selection)
        first = source.index("    aliases = scope.get('aliases', {})")
        end = source.index("    requested = scope.get('requestedAlias')", first)
        block = source[first:end]
        marker = "    if group == 'excluded':\n        return _result('blocked', 4, 'excluded-scope')\n"
        source = source.replace(block, '').replace(marker, marker + block)
        module = types.ModuleType('ci_contract.synthetic_late_alias')
        module.__package__ = 'ci_contract'
        exec(compile(source, '<synthetic-late-alias>', 'exec'), module.__dict__)
        with self.assertRaises(AssertionError):
            self.assert_alias_definitions(module.select)

    def assert_root_shapes(self, selector):
        changes = [
            {'baseAvailable': 5}, {'repoFullProfileApproved': 5},
            {'changedPaths': 5}, {'changedPaths': ['']},
            {'changedPaths': ['src/x', 'src/x']}, {'changedPaths': ['src/x', 'SRC/x']},
            {'changes': 5}, {'changes': [{}]},
            {'changes': [{'status': 'rename', 'old': 'src/x'}]},
            {'changes': [{'status': 'modify', 'path': 'src/x', 'unexpected': True}]},
            {'profile': 5}, {'profile': ''}, {'profile': 'unknown'},
            {'requiredInstanceIds': 5}, {'requiredInstanceIds': ['']},
        ]
        scopes = [{'repositoryGroup': group} for group in ('excluded', 'public', 'private', 'github-only', 'unknown')]
        scopes += [{'repositoryGroup':'public','requestedAlias':'unknown','aliases':{}},
                   {'repositoryGroup':'public','requestedAlias':'alias','aliases':{'alias':'private'}}]
        for scope in scopes:
            for update in changes:
                value = selection_tests.simple_input()
                value.pop('changedPaths')
                value.update(copy.deepcopy(update))
                value['scope'] = copy.deepcopy(scope)
                result = selector(value)
                self.assertEqual((result['status'], result['exitCode']), ('invalid-input', 3))
            value = selection_tests.simple_input()
            value['scope'] = copy.deepcopy(scope)
            value['changes'] = []
            self.assertEqual(selector(value)['exitCode'], 3)

    def test_l2_model_independent_shapes_precede_admission(self):
        self.assert_root_shapes(selection.select)

    def test_l2_early_scope_fault_is_detected(self):
        source = inspect.getsource(selection)
        block = "    if group == 'excluded':\n        return _result('blocked', 4, 'excluded-scope')\n"
        source = source.replace(block, '')
        marker = "    for field in ('baseAvailable', 'repoFullProfileApproved'):"
        source = source.replace(marker, block + marker)
        module = types.ModuleType('ci_contract.synthetic_late_root')
        module.__package__ = 'ci_contract'
        exec(compile(source, '<synthetic-late-root>', 'exec'), module.__dict__)
        with self.assertRaises(AssertionError):
            self.assert_root_shapes(module.select)

    def test_l2_early_alias_group_rejection_fault_is_detected(self):
        source = inspect.getsource(selection)
        start = source.index("    if requested is not None:", source.index("    # Shape validation precedes rejection"))
        end = source.index("    target = _model", start)
        block = source[start:end]
        source = source[:start] + source[end:]
        marker = "    for field in ('baseAvailable', 'repoFullProfileApproved'):"
        source = source.replace(marker, block + marker)
        module = types.ModuleType('ci_contract.synthetic_early_group')
        module.__package__ = 'ci_contract'
        exec(compile(source, '<synthetic-early-group>', 'exec'), module.__dict__)
        with self.assertRaises(AssertionError):
            self.assert_root_shapes(module.select)

    def test_l2_unused_model_keeps_excluded_result(self):
        value = selection_tests.simple_input()
        value['model'] = 5
        value['scope']['repositoryGroup'] = 'excluded'
        self.assertEqual(selection.select(value)['exitCode'], 4)
        value['scope']['repositoryGroup'] = 'public'
        self.assertEqual(selection.select(value)['exitCode'], 3)


class PublicationCarryovers(unittest.TestCase):
    def test_l3_duplicate_artifact_key_is_rejected(self):
        asset = {'path': 'tests/fixtures/plan-cases.json',
                 'jsonPointers': publication.POINTERS['tests/fixtures/plan-cases.json']}
        raw = ('{"sourceFile":"wrong","sourceFile":"acceptance-cases.json",'
               '"sourceSha256":"' + publication.SOURCE_SHA256 + '","cases":[]}').encode()
        with self.assertRaises(InputError):
            publication.assert_extraction_shape(self, asset, raw)
        faulty = changed(publication, 'extracted = cjson.loads(artifact)',
                         'extracted = json.loads(artifact)')
        self.assertEqual(faulty.assert_extraction_shape(self, asset, raw)['cases'], [])

    def test_l3_selection_fixture_duplicate_key_is_rejected(self):
        original = selection_tests.FIXTURE_PATH.read_bytes()
        raw = b'{"sourceFile":"wrong",' + original.lstrip()[1:]
        reader = Path.read_bytes
        def altered(path):
            return raw if path == selection_tests.FIXTURE_PATH else reader(path)
        source = inspect.getsource(selection_tests)
        module = types.ModuleType('synthetic_selection_fixture')
        module.__file__ = selection_tests.__file__
        with patch.object(Path, 'read_bytes', altered), self.assertRaises(InputError):
            exec(compile(source, '<synthetic-duplicate-fixture>', 'exec'), module.__dict__)
        source = source.replace('FIXTURE = cjson.loads(FIXTURE_PATH.read_bytes())',
                                'FIXTURE = json.loads(FIXTURE_PATH.read_bytes())')
        with patch.object(Path, 'read_bytes', altered):
            exec(compile(source, '<synthetic-duplicate-fixture-fault>', 'exec'), module.__dict__)
        self.assertEqual(module.FIXTURE['sourceFile'], 'acceptance-cases.json')

    def public_copy(self, temporary):
        root = Path(temporary)
        sources = cjson.loads((publication.ROOT / 'src/ci_contract/data/SOURCES.json').read_bytes())
        for key in ('files', 'planningFiles', 'planFiles', 'verifyFiles', 'requestFiles', 'claimFiles'):
            for asset in sources.get(key, []):
                dest = root / asset['path']
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((publication.ROOT / asset['path']).read_bytes())
        manifest = root / 'src/ci_contract/data/SOURCES.json'
        manifest.write_bytes(cjson.dumps(sources))
        return root, sources, manifest

    def run_publication(self, module, root):
        result = unittest.TestResult()
        with patch.object(module, 'ROOT', root), patch.object(module, 'INPUT', root / 'missing-input'), \
                patch.object(publication_source, 'INPUT', root / 'missing-input'):
            module.PublicationTests('test_exact_transformed_sources_and_extracted_values').run(result)
        return result

    def test_l3_duplicate_manifest_key_is_rejected_before_map_skip(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-duplicate-manifest-') as tmp:
            root, sources, manifest = self.public_copy(tmp)
            manifest.write_bytes(b'{"files":[],' + cjson.dumps(sources)[1:])
            result = self.run_publication(publication, root)
            self.assertEqual(len(result.errors), 1)
            self.assertIn('InputError', result.errors[0][1])
            faulty = changed(publication,
                             "sources = cjson.loads((ROOT / 'src/ci_contract/data/SOURCES.json').read_bytes())",
                             "sources = json.loads((ROOT / 'src/ci_contract/data/SOURCES.json').read_bytes())")
            result = self.run_publication(faulty, root)
            self.assertEqual(result.errors + result.failures, [])

    def test_l4_public_copy_checks_metadata_before_skipping_originals(self):
        for key, value in [('jsonPointers', ['/unknown']), ('sourceFile', 'wrong.json'),
                           ('sourceSha256', '0' * 64), ('bytes', 0), ('sha256', '0' * 64)]:
            with self.subTest(field=key), tempfile.TemporaryDirectory(prefix='synthetic-public-metadata-') as tmp:
                root, sources, manifest = self.public_copy(tmp)
                sources['planFiles'][0][key] = value
                manifest.write_bytes(cjson.dumps(sources))
                result = self.run_publication(publication, root)
                self.assertTrue(result.failures)
                self.assertFalse(result.errors)

    def test_l4_public_copy_checks_artifact_keys_and_scope(self):
        for key, value in [('scope', 'wrong'), ('sourceFile', 'wrong'),
                           ('sourceSha256', '0' * 64), ('unexpected', True)]:
            with self.subTest(field=key), tempfile.TemporaryDirectory(prefix='synthetic-public-artifact-') as tmp:
                root, sources, manifest = self.public_copy(tmp)
                asset = sources['planningFiles'][0]
                path = root / asset['path']
                document = cjson.loads(path.read_bytes())
                document[key] = value
                raw = cjson.dumps(document)
                path.write_bytes(raw)
                asset.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                manifest.write_bytes(cjson.dumps(sources))
                result = self.run_publication(publication, root)
                self.assertTrue(result.failures)
                self.assertFalse(result.errors)

    def test_l4_removing_public_pass_fault_is_detected(self):
        source = inspect.getsource(publication)
        start = source.index('        # This first pass runs in public copies too:')
        end = source.index('        # Only original-value comparisons can be skipped', start)
        faulty = changed(publication, source[start:end], '')
        with tempfile.TemporaryDirectory(prefix='synthetic-public-pass-') as tmp:
            root, sources, manifest = self.public_copy(tmp)
            sources['planFiles'][0]['jsonPointers'] = ['/unknown']
            manifest.write_bytes(cjson.dumps(sources))
            healthy = self.run_publication(publication, root)
            self.assertTrue(healthy.failures)
            result = self.run_publication(faulty, root)
            self.assertFalse(result.failures or result.errors)
            self.assertTrue(result.skipped)

    def test_l5_non_schema_asset_and_manifest_tampering_fails_without_map(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-asset-pin-') as tmp:
            root, sources, manifest = self.public_copy(tmp)
            asset = next(a for a in sources['files'] if a['path'].endswith('golden-vectors.json'))
            path = root / asset['path']
            value = cjson.loads(path.read_bytes())
            value[0]['name'] = 'synthetic modified name'
            raw = cjson.dumps(value)
            path.write_bytes(raw)
            asset.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            manifest.write_bytes(cjson.dumps(sources))
            (root / 'tests').mkdir(exist_ok=True)
            with patch.object(contract, '__file__', str(root / 'tests/test_contract_bytes.py')):
                with self.assertRaises(AssertionError):
                    contract.SourceIntegrityTests().test_six_pinned_assets_match_sources_manifest()
            faulty = changed(contract,
                             '        self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(), SOURCES_SHA256)',
                             '        pass')
            with patch.object(faulty, '__file__', str(root / 'tests/test_contract_bytes.py')):
                faulty.SourceIntegrityTests().test_six_pinned_assets_match_sources_manifest()


class TargetInventoryInvestigation(unittest.TestCase):
    """L6 retains the redundant defensive check and exercises its two cases."""
    def test_l6_target_only_condition_has_no_sole_effect_in_file_cases(self):
        from ci_contract import plan
        from ci_contract.errors import BlockedError
        from test_plan import canonical, synthetic_history
        before = "any(entry['kind'] == 'file' and entry['path'] not in target_roles for entry in source['inputs'])"
        faulty = changed(plan, before, 'False')
        with tempfile.TemporaryDirectory(prefix='synthetic-inventory-partition-') as tmp:
            git, anchor, _, _, _, manifest, base_files, _ = synthetic_history(Path(tmp) / 'synthetic.git')
            for changed_path in (True, False):
                files = copy.deepcopy(base_files)
                if not changed_path:
                    files['unknown/item.txt'] = ('100644', b'synthetic unchanged input')
                base = git.commit(files, parents=(anchor,), message='synthetic base partition')
                files['unknown/item.txt'] = ('100644', b'synthetic new input' if changed_path else b'synthetic unchanged input')
                files['src/main.txt'] = ('100644', b'synthetic changed declared input')
                target = git.commit(files, parents=(base,), message='synthetic target partition')
                reason = 'unknown-path-no-approved-fallback' if changed_path else 'undeclared-source-input'
                for builder in (plan.build_plan, faulty.build_plan):
                    with self.subTest(changed=changed_path, builder=builder.__module__):
                        with self.assertRaisesRegex(BlockedError, '^' + reason + '$'):
                            builder(git.path, 'synthetic', base, target)
            # Removing a base input rule at target does not remove its role:
            # the broadening pass begins with a deep copy of the base graph.
            target_manifest = copy.deepcopy(manifest)
            target_manifest['selectionModel']['inputRules'] = [
                r for r in target_manifest['selectionModel']['inputRules'] if r['path'] != 'src/main.txt']
            merged, _ = plan._broaden_manifest(manifest, target_manifest)
            _, _, base_roles, _ = plan._compile(manifest, 'change')
            _, _, target_roles, _ = plan._compile(merged, 'change')
            self.assertTrue(base_roles.keys() <= target_roles.keys())
            self.assertIn('src/main.txt', target_roles)


if __name__ == '__main__':
    unittest.main()
