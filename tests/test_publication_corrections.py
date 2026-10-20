"""Synthetic negative controls for provenance strictness; no private terms."""
import copy
import inspect
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from ci_contract import cjson
import test_contract_bytes as contract_tests
import test_publication as publication


def changed_module(module, replacements):
    source = inspect.getsource(module)
    for before, after in replacements:
        if source.count(before) != 1:
            raise AssertionError('fault location changed')
        source = source.replace(before, after)
    result = types.ModuleType('synthetic_provenance_fault')
    result.__file__ = module.__file__
    exec(compile(source, '<synthetic-provenance-fault>', 'exec'), result.__dict__)
    return result


class PublicationCorrectionTests(unittest.TestCase):
    def multi_asset(self):
        asset = {'path': 'tests/fixtures/plan-cases.json',
                 'jsonPointers': ['/cases/29', '/cases/33', '/cases/51']}
        original = {'cases': [{'value': i} for i in range(52)]}
        artifact = {'sourceFile': 'acceptance-cases.json',
                    'sourceSha256': publication.SOURCE_SHA256,
                    'cases': [original['cases'][i] for i in (29, 33, 51)]}
        return asset, artifact, original

    def test_g2_rfc6901_nested_and_escaped_tokens(self):
        source = {'a/b': {'~key': [{'': {'~1': True}}]}}
        self.assertIs(publication.resolve_pointer(source, '/a~1b/~0key/0//~01'), True)
        self.assertIs(publication.resolve_pointer(source, ''), source)
        for pointer in ('missing', '/absent', '/a~2b', '/a~', '/a~1b/~0key/01',
                        '/a~1b/~0key/-', '/a~1b/~0key/1', '/a~1b/~0key/0//~01/x'):
            with self.subTest(pointer=pointer), self.assertRaises(AssertionError):
                publication.resolve_pointer(source, pointer)

    def test_g2_all_top_level_keys_and_metadata_are_checked(self):
        asset, artifact, original = self.multi_asset()
        publication.assert_extraction(self, asset, cjson.dumps(artifact), original)
        bad_values = []
        extra = copy.deepcopy(artifact)
        extra['unexpected'] = True
        bad_values.append(extra)
        for key in artifact:
            missing = copy.deepcopy(artifact)
            del missing[key]
            bad_values.append(missing)
        for key in ('sourceFile', 'sourceSha256'):
            changed = copy.deepcopy(artifact)
            changed[key] = 'synthetic incorrect metadata'
            bad_values.append(changed)
        for changed in bad_values:
            with self.assertRaises(AssertionError):
                publication.assert_extraction(self, asset, cjson.dumps(changed), original)

    def assert_unknown_pointer_rejected(self, checker):
        asset, artifact, original = self.multi_asset()
        asset['jsonPointers'].append('/unexpected')
        original['unexpected'] = 'synthetic value'
        with self.assertRaises(AssertionError):
            checker(self, asset, cjson.dumps(artifact), original)

    def test_g2_unknown_pointer_is_not_silently_ignored(self):
        self.assert_unknown_pointer_rejected(publication.assert_extraction)

    def test_g2_silent_unknown_pointer_mutant_is_detected(self):
        mutant = changed_module(publication, [
            ('    test.assertEqual(asset[field], declared)', '    pass'),
            ('        for pointer in declared:', '        for pointer in asset[field]:'),
            ("                raise AssertionError('unknown extraction pointer')", '                continue')])
        with self.assertRaises(AssertionError):
            self.assert_unknown_pointer_rejected(mutant.assert_extraction)

    def assert_boolean_integer_distinct(self, checker):
        asset, artifact, original = self.multi_asset()
        original['cases'][29] = {'value': True}
        artifact['cases'][0] = {'value': 1}
        with self.assertRaises(AssertionError):
            checker(self, asset, cjson.dumps(artifact), original)

    def test_g3_extraction_distinguishes_boolean_and_integer(self):
        self.assert_boolean_integer_distinct(publication.assert_extraction)

    def test_g3_python_equality_mutant_is_detected(self):
        mutant = changed_module(publication, [
            ('    test.assertEqual(cjson.dumps(extracted), cjson.dumps(expected))',
             '    test.assertEqual(extracted, expected)')])
        with self.assertRaises(AssertionError):
            self.assert_boolean_integer_distinct(mutant.assert_extraction)

    def assert_schema_tamper_rejected(self, module, mutate_pointer=False):
        with tempfile.TemporaryDirectory(prefix='synthetic-schema-pin-') as temporary:
            root = Path(temporary)
            (root / 'tests').mkdir()
            original = Path(contract_tests.__file__).resolve().parents[1]
            sources = json.loads((original / 'src/ci_contract/data/SOURCES.json').read_bytes())
            for asset in sources['files']:
                target = root / asset['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                data = (original / asset['path']).read_bytes()
                if asset['jsonPointer'] == '':
                    value = json.loads(data)
                    value['title'] = 'synthetic altered schema'
                    data = cjson.dumps(value)
                    digest = publication.hashlib.sha256(data).hexdigest()
                    asset.update(bytes=len(data), sha256=digest,
                                 transformedSourceBytes=len(data), transformedSourceSha256=digest)
                if mutate_pointer and asset['path'] == 'src/ci_contract/data/contract-v1.schema.json':
                    asset['jsonPointer'] = '/unused'
                target.write_bytes(data)
            (root / 'src/ci_contract/data/SOURCES.json').write_text(json.dumps(sources))
            with patch.object(module, '__file__', str(root / 'tests/test_contract_bytes.py')):
                with self.assertRaises(AssertionError):
                    module.SourceIntegrityTests().test_six_pinned_assets_match_sources_manifest()

    def test_g4_schema_and_sources_tampering_fails_without_map(self):
        self.assert_schema_tamper_rejected(contract_tests)

    def test_g4_schema_pin_is_independent_of_manifest_pointer(self):
        self.assert_schema_tamper_rejected(contract_tests, mutate_pointer=True)

    def test_g4_removing_independent_digest_mutant_is_detected(self):
        mutant = changed_module(contract_tests, [
            ("        self.assertEqual(hashlib.sha256((root / 'src/ci_contract/data/contract-v1.schema.json').read_bytes()).hexdigest(),\n                         TRANSFORMED_SCHEMA_SHA256)",
             '        pass'),
            # The independent manifest pin also detects this tampering in M5.
            # Disable both pins to preserve this original negative control.
            ('        self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(), SOURCES_SHA256)',
             '        pass')])
        with self.assertRaises(AssertionError):
            self.assert_schema_tamper_rejected(mutant)

    def assert_relative_name_is_scanned(self, counter):
        with tempfile.TemporaryDirectory(prefix='synthetic-name-scan-') as temporary:
            root = Path(temporary)
            (root / 'SYNTHETIC-MARKER.txt').write_bytes(b'ordinary bytes')
            self.assertGreater(counter(root, ['synthetic-marker']), 0)

    def test_g5_relative_names_are_scanned_case_insensitively(self):
        self.assert_relative_name_is_scanned(publication.forbidden_count)

    def test_g5_content_only_scan_mutant_is_detected(self):
        mutant = changed_module(publication, [
            ('        matches += sum(relative.count(term.lower()) for term in terms)',
             '        matches += 0')])
        with self.assertRaises(AssertionError):
            self.assert_relative_name_is_scanned(mutant.forbidden_count)


if __name__ == '__main__':
    unittest.main()
