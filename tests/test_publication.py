"""Transformation provenance and public-copy regression checks."""
import hashlib
import json
import re
import unittest

from ci_contract import cjson
from publication_source import ROOT, INPUT, transformed_source

SOURCE_SHA256 = '98c356bf50e6f872f5d61aa47341fb6009d592bc7650b5b2640c8404bea30f37'
PLANNING_SCOPE = ('Exact fixtureModels and thirteen design-case subtrees. Their '
                  'execution fields are preserved source declarations, not local test outcomes.')
# These independent extraction declarations reject omitted or invented pointers.
POINTERS = {
    'src/ci_contract/data/contract-v1.schema.json': '',
    'src/ci_contract/data/canonical-array-registry.json': '/canonicalArrayRegistry',
    'src/ci_contract/data/domain-hash-projections.json': '/domainHashProjections',
    'tests/fixtures/golden-vectors.json': '/goldenVectors',
    'tests/fixtures/array-registry.json': '/canonicalArrayRegistry',
    'tests/fixtures/domain-projections.json': '/domainHashProjections',
    'tests/fixtures/planning-cases.json': ['/fixtureModels'] + [
        '/cases/' + str(i) for i in (0, 2, 3, 4, 6, 13, 33, 34, 35, 36, 37, 38, 65)],
    'tests/fixtures/plan-cases.json': ['/cases/' + str(i) for i in (29, 33, 51)],
}
TOP_LEVEL_KEYS = {
    'src/ci_contract/data/contract-v1.schema.json': {'$schema', '$id', 'title', 'description', 'oneOf', '$defs'},
    'src/ci_contract/data/canonical-array-registry.json': {'version', 'semantics', 'entries'},
    'src/ci_contract/data/domain-hash-projections.json': {'version', 'formula', 'entries', 'rawCanonicalKinds', 'noGenericHashRemoval'},
    'tests/fixtures/golden-vectors.json': None,
    'tests/fixtures/array-registry.json': {'version', 'semantics', 'entries'},
    'tests/fixtures/domain-projections.json': {'version', 'formula', 'entries', 'rawCanonicalKinds', 'noGenericHashRemoval'},
    'tests/fixtures/planning-cases.json': {'sourceFile', 'sourceSha256', 'scope', 'fixtureModels', 'cases'},
    'tests/fixtures/plan-cases.json': {'sourceFile', 'sourceSha256', 'cases'},
}


def resolve_pointer(document, pointer):
    """Resolve the JSON string form of an RFC 6901 pointer, failing closed."""
    if not isinstance(pointer, str) or (pointer and not pointer.startswith('/')):
        raise AssertionError('invalid JSON pointer')
    value = document
    for encoded in pointer.split('/')[1:] if pointer else ():
        if re.search(r'~(?![01])', encoded):
            raise AssertionError('invalid pointer escape')
        token = encoded.replace('~1', '/').replace('~0', '~')
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and re.fullmatch(r'0|[1-9][0-9]*', token):
            index = int(token)
            if index >= len(value):
                raise AssertionError('pointer index out of range')
            value = value[index]
        else:
            raise AssertionError('unresolved JSON pointer')
    return value


def assert_extraction(test, asset, artifact, original):
    path = asset['path']
    test.assertIn(path, POINTERS)
    declared = POINTERS[path]
    field = 'jsonPointers' if isinstance(declared, list) else 'jsonPointer'
    test.assertEqual(asset[field], declared)
    test.assertNotIn('jsonPointer' if field == 'jsonPointers' else 'jsonPointers', asset)
    extracted = json.loads(artifact)
    keys = TOP_LEVEL_KEYS[path]
    if keys is None:
        test.assertIsInstance(extracted, list)
    else:
        test.assertIsInstance(extracted, dict)
        test.assertEqual(set(extracted), keys)
    if isinstance(declared, list):
        expected = {'sourceFile': 'acceptance-cases.json', 'sourceSha256': SOURCE_SHA256,
                    'cases': []}
        if path == 'tests/fixtures/planning-cases.json':
            expected['scope'] = PLANNING_SCOPE
        for pointer in declared:
            value = resolve_pointer(original, pointer)
            if pointer == '/fixtureModels':
                expected['fixtureModels'] = value
            elif re.fullmatch(r'/cases/(0|[1-9][0-9]*)', pointer):
                expected['cases'].append(value)
            else:
                raise AssertionError('unknown extraction pointer')
    else:
        expected = resolve_pointer(original, declared)
    test.assertEqual(cjson.dumps(extracted), cjson.dumps(expected))


def forbidden_count(root, terms):
    matches = 0
    for path in root.rglob('*'):
        if path == root / 'RESULTS.md':
            continue
        relative = path.relative_to(root).as_posix().lower()
        matches += sum(relative.count(term.lower()) for term in terms)
        if path.is_file():
            data = path.read_bytes().lower()
            matches += sum(data.count(term.encode('utf-8').lower()) for term in terms)
    return matches


class PublicationTests(unittest.TestCase):
    def test_exact_transformed_sources_and_extracted_values(self):
        sources = json.loads((ROOT / 'src/ci_contract/data/SOURCES.json').read_bytes())
        assets = sources['files'] + sources['planningFiles'] + sources['planFiles']
        self.assertEqual(len(assets), len(POINTERS))
        self.assertEqual({asset['path'] for asset in assets}, set(POINTERS))
        for asset in assets:
            with self.subTest(path=asset['path']):
                data = transformed_source(self, asset['sourceFile'], asset['sourceSha256'])
                self.assertEqual(hashlib.sha256((INPUT / 'publication-map.json').read_bytes()).hexdigest(),
                                 asset['publicationMapSha256'])
                self.assertEqual(hashlib.sha256(data).hexdigest(), asset['transformedSourceSha256'])
                self.assertEqual(len(data), asset['transformedSourceBytes'])
                artifact = (ROOT / asset['path']).read_bytes()
                self.assertEqual(len(artifact), asset['bytes'])
                self.assertEqual(hashlib.sha256(artifact).hexdigest(), asset['sha256'])
                if asset.get('jsonPointer') == '':
                    self.assertEqual(artifact, data)
                assert_extraction(self, asset, artifact, json.loads(data))

    def test_public_copy_contains_zero_forbidden_terms(self):
        publication = INPUT / 'publication-map.json'
        if not publication.is_file():
            self.skipTest('read-only publication map is not present')
        terms = json.loads(publication.read_bytes())['forbiddenAfterApplication']
        self.assertEqual(len(terms), 4)
        # Only counts are reported; content and relative names are both scanned.
        self.assertEqual(forbidden_count(ROOT, terms), 0,
                         'public-copy forbidden-term count must be zero')
        self.assertFalse((ROOT / 'publication-map.json').exists())


if __name__ == '__main__':
    unittest.main()
