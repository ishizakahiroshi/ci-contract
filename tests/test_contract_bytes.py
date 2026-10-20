"""Synthetic M1 unit tests. These are not the 74 end-to-end acceptance cases."""
import copy
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

from ci_contract import arrays, cjson, cli, hashing, schema
from ci_contract.errors import InputError, DependencyError

TRANSFORMED_SCHEMA_SHA256 = '20c1cf31a59058e0e25f9f652327ed315990a9d45b0c4fb6036a6767e715c992'

FIXTURES = Path(__file__).with_name('fixtures')

def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))

GOLDENS = fixture('golden-vectors.json')
REGISTRY = fixture('array-registry.json')['entries']
PROJECTIONS = fixture('domain-projections.json')['entries']


def nested(tokens, leaf):
    if not tokens:
        return leaf
    child = nested(tokens[1:], leaf)
    # Populate parent set sort fields independently of the field under test.
    if tokens[0] == '*':
        if isinstance(child, dict):
            child = {'id': 'item', 'path': 'item', 'checkId': 'item',
                     'externalReference': 'item', **child}
        return [child]
    return {tokens[0]: child}


def at(value, tokens):
    for token in tokens:
        value = value[0] if token == '*' else value[token]
    return value


class SourceIntegrityTests(unittest.TestCase):
    def test_six_pinned_assets_match_sources_manifest(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(hashlib.sha256((root / 'src/ci_contract/data/contract-v1.schema.json').read_bytes()).hexdigest(),
                         TRANSFORMED_SCHEMA_SHA256)
        manifest = json.loads((root / 'src/ci_contract/data/SOURCES.json').read_text())
        self.assertEqual(len(manifest['files']), 6)
        expected_sources = {
            'contract-v1.schema.json': 'b50a2d6cee5ccf8e7ea376f65b36618efa064b56fe6439e9759dc83c56673a10',
            'acceptance-cases.json': '98c356bf50e6f872f5d61aa47341fb6009d592bc7650b5b2640c8404bea30f37'}
        for asset in manifest['files']:
            with self.subTest(asset=asset['path']):
                path = Path(asset['path'])
                self.assertFalse(path.is_absolute())
                self.assertNotIn('..', path.parts)
                data = (root / path).read_bytes()
                self.assertEqual(len(data), asset['bytes'])
                self.assertEqual(hashlib.sha256(data).hexdigest(), asset['sha256'])
                self.assertEqual(asset['sourceSha256'], expected_sources[asset['sourceFile']])
                if asset['jsonPointer'] == '':
                    self.assertEqual(asset['sha256'], asset['transformedSourceSha256'])
                    self.assertEqual(asset['bytes'], asset['transformedSourceBytes'])
        self.assertEqual(arrays.load_registry(), fixture('array-registry.json'))

    def test_acceptance_coverage_is_complete_and_conservative(self):
        coverage = json.loads(Path(__file__).with_name('acceptance-coverage.json').read_text())
        self.assertEqual(len(coverage['cases']), 74)
        self.assertEqual(len({case['id'] for case in coverage['cases']}), 74)
        self.assertEqual(coverage['fullAcceptanceCasesPassed'], 0)
        partial = {case['id'] for case in coverage['cases'] if case['status'] == 'partial-unit-coverage'}
        self.assertEqual(partial, {'r21', 'r22', 'r23', 'r32', 'r33', 'r34'})


class CanonicalJsonTests(unittest.TestCase):
    def test_escape_equivalence_r21(self):
        a, b = '{"s":"あ"}', r'{"s":"\u3042"}'
        self.assertNotEqual(hashing.raw_hash(a.encode()), hashing.raw_hash(b.encode()))
        self.assertEqual(cjson.dumps(cjson.loads(a)), cjson.dumps(cjson.loads(b)))
        self.assertEqual(hashing.canonical_hash(cjson.loads(a)),
                         '096882159c40984bbd8bdad20c368d79d032b015acc43c8ea90bac4e3ebed009')

    def test_rejected_lexical_inputs(self):
        bad = [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'1.0', b'1e0',
               b'NaN', b'Infinity', b'-Infinity', b'9007199254740992',
               b'-9007199254740992', b'"\\ud800"', b'"\\udfff"', b'"\xff"',
               b'\xef\xbb\xbf{}', b'{} garbage', b'01', b'+1', b'', b'"\x01"']
        for value in bad:
            with self.subTest(value=repr(value)), self.assertRaises(InputError):
                cjson.loads(value)

    def test_serialization_rejects_invalid_python_values(self):
        for value in [1.0, float('nan'), float('inf'), 9007199254740992,
                      '\ud800', {'\udfff': 1}, {1: 'a'}, object(), {1, 2}]:
            with self.subTest(type=type(value).__name__), self.assertRaises(InputError):
                cjson.dumps(value)

    def test_unicode_and_scalars(self):
        self.assertEqual(cjson.dumps(cjson.loads('-0')), b'0')
        self.assertEqual(cjson.dumps([True, False, None]), b'[true,false,null]')
        self.assertEqual(cjson.dumps(cjson.loads(r'"\ud83d\ude00"')), '"😀"'.encode())
        self.assertNotEqual(cjson.dumps('é'), cjson.dumps('e\u0301'))
        for codepoint in list(range(32)) + list(range(127, 160)):
            self.assertEqual(cjson.dumps(chr(codepoint)), ('"\\u%04x"' % codepoint).encode())
        self.assertEqual(cjson.dumps('/'), b'"/"')
        self.assertEqual(cjson.dumps({'z': 1, 'a': 2}), b'{"a":2,"z":1}')
        self.assertEqual(cjson.dumps({'values': ['z', 'a']}), b'{"values":["z","a"]}')

    def test_all_eight_golden_vectors_five_outputs(self):
        self.assertEqual(len(GOLDENS), 8)
        for vector in GOLDENS:
            with self.subTest(name=vector['name']):
                encoded = cjson.dumps(vector['input'])
                self.assertEqual(encoded.decode(), vector['canonicalText'])
                self.assertEqual(encoded.hex(), vector['utf8Hex'])
                self.assertEqual(len(encoded), vector['bytes'])
                self.assertEqual(hashing.raw_hash(encoded), vector['rawCanonicalSha256'])
                self.assertEqual(hashing.domain_digest(vector['kind'], encoded), vector['domainSha256'])


class ArrayRegistryTests(unittest.TestCase):
    def test_registry_has_123_unique_entries(self):
        self.assertEqual(len(REGISTRY), 123)
        self.assertEqual(len({(r['documentKind'], r['pointer']) for r in REGISTRY}), 123)

    def test_unknown_paths_are_ordered(self):
        value = {'kind': 'plan', 'unknown': {'checkIds': ['z', 'a', 'z']}}
        self.assertEqual(arrays.normalize(value), value)

    def test_wildcard_matches_array_index_only(self):
        value = {'checks': {'not-an-index': {'dependsOn': ['z', 'a']}}}
        self.assertEqual(arrays.normalize(value, 'plan'), value)
        numeric = {'checks': {'0': {'dependsOn': ['z', 'a']}}}
        self.assertEqual(arrays.normalize(numeric, 'plan'), numeric)

    def test_r22_sets_equal_argv_different(self):
        a = {'checks': [{'id': 'one', 'dependsOn': ['z', 'a'], 'argv': ['run', 'first', 'second']}]}
        b = copy.deepcopy(a); b['checks'][0]['dependsOn'].reverse()
        self.assertEqual(hashing.canonical_hash(a, 'plan'), hashing.canonical_hash(b, 'plan'))
        b['checks'][0]['argv'].reverse()
        self.assertNotEqual(hashing.canonical_hash(a, 'plan'), hashing.canonical_hash(b, 'plan'))


def registry_test(entry):
    def test(self):
        tokens = entry['pointer'].split('/')[1:]
        keys = entry.get('sortKey')
        if entry['classification'] == 'ordered' or keys == ['$value']:
            low, high = 'a', 'z'
        elif keys == ['$canonicalBytes']:
            low, high = {'synthetic': 'a'}, {'synthetic': 'z'}
        else:
            low = {}; high = {}
            for key in keys:
                low[key[1:]] = 'a'; high[key[1:]] = 'z'
        values = [high, low]
        document = nested(tokens, values)
        original = copy.deepcopy(document)
        result = arrays.normalize(document, entry['documentKind'])
        expected = values if entry['classification'] == 'ordered' else [low, high]
        self.assertEqual(at(result, tokens), expected)
        self.assertEqual(document, original, 'normalization must not mutate caller data')
        repeated = nested(tokens, [low, copy.deepcopy(low)])
        if entry['classification'] == 'ordered':
            self.assertEqual(at(arrays.normalize(repeated, entry['documentKind']), tokens), [low, low])
        else:
            with self.assertRaises(InputError):
                arrays.normalize(repeated, entry['documentKind'])
            if keys not in (['$value'], ['$canonicalBytes']):
                changed = copy.deepcopy(low); changed['other'] = 'different'
                with self.assertRaises(InputError):
                    arrays.normalize(nested(tokens, [low, changed]), entry['documentKind'])
    return test

for index, entry in enumerate(REGISTRY):
    setattr(ArrayRegistryTests, 'test_registry_%03d_%s' % (index, entry['documentKind'].replace('-', '_')),
            registry_test(entry))


class RegistryRuleValidationTests(unittest.TestCase):
    def load_entry(self, classification, duplicates, sort_key):
        value = {'entries': [{'documentKind': 'plan', 'pointer': '/requirements',
                             'classification': classification, 'duplicates': duplicates,
                             'sortKey': sort_key}]}
        with patch('ci_contract.arrays.files') as resource:
            resource.return_value.joinpath.return_value.read_bytes.return_value = json.dumps(value).encode()
            return arrays.load_registry()

    def test_fixed_registry_loads_all_123_rules(self):
        self.assertEqual(arrays.load_registry(), fixture('array-registry.json'))
        self.assertEqual(len(arrays.load_registry()['entries']), 123)

    def test_supported_rule_combinations(self):
        for classification, duplicates, key in [
                ('ordered', 'allowed', None),
                ('set', 'reject-exact-value', ['$value']),
                ('set', 'reject-equal-sort-key', ['$value']),
                ('set', 'reject-equal-sort-key', ['$canonicalBytes']),
                ('set', 'reject-equal-sort-key', ['/id', '/nested/a~1b/~0'])]:
            with self.subTest(rule=(classification, duplicates, key)):
                self.assertEqual(len(self.load_entry(classification, duplicates, key)['entries']), 1)

    def test_unsupported_rule_combinations_are_internal_errors(self):
        for classification, duplicates, key in [
                ('ordered', 'allowed', ['$value']),
                ('ordered', 'reject-exact-value', None),
                ('set', 'allowed', ['$value']),
                ('set', 'reject-exact-value', ['/id']),
                ('set', 'reject-exact-value', ['$canonicalBytes']),
                ('set', 'reject-exact-value', ['$value', '/id']),
                ('set', 'reject-equal-sort-key', None),
                ('set', 'reject-equal-sort-key', []),
                ('set', 'reject-equal-sort-key', '$value'),
                ('set', 'reject-equal-sort-key', [1]),
                ('set', 'reject-equal-sort-key', ['$unknown']),
                ('set', 'reject-equal-sort-key', ['/bad~2']),
                ('set', 'reject-equal-sort-key', ['/bad~']),
                ('unknown', 'allowed', None),
                ('set', 'unknown', ['$value'])]:
            with self.subTest(rule=(classification, duplicates, key)), self.assertRaises(RuntimeError):
                self.load_entry(classification, duplicates, key)

    def test_invalid_registry_shape_is_internal_error(self):
        for value in [[], {}, {'entries': {}}, {'entries': [None]}, {'entries': [{}]}]:
            with self.subTest(value=value), patch('ci_contract.arrays.files') as resource:
                resource.return_value.joinpath.return_value.read_bytes.return_value = json.dumps(value).encode()
                with self.assertRaises(RuntimeError):
                    arrays.load_registry()

    def test_subprocess_bad_bundle_load_returns_9_without_import_traceback(self):
        # Intercept the resource before importing the CLI or arrays module.
        # Other bundled resources remain real; no installed files are modified.
        script = r"""
import importlib.resources as resources
import runpy
import sys
from types import SimpleNamespace
from unittest.mock import patch
original = resources.files
class Bundle:
    def __init__(self, package):
        self.root = original(package)
    def joinpath(self, path):
        if path == 'data/canonical-array-registry.json':
            return SimpleNamespace(read_bytes=lambda: b'{"entries":[{"classification":"set","duplicates":"allowed","sortKey":["$value"]}]}')
        return self.root.joinpath(path)
sys.argv = ['ci-contract', 'canon']
with patch.object(resources, 'files', Bundle):
    runpy.run_module('ci_contract', run_name='__main__')
"""
        result = subprocess.run([sys.executable, '-c', script], input=b'{}', capture_output=True, check=False)
        self.assertEqual(result.returncode, 9)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'ci-contract: internal error\n')


class DomainHashTests(unittest.TestCase):
    def test_nine_domain_prefixes_once(self):
        digests = set()
        for entry in PROJECTIONS:
            kind = entry['kind']; data = b'{}'
            digest = hashing.domain_digest(kind, data)
            self.assertEqual(digest, hashlib.sha256(('ci-contract/v1:' + kind + '\n').encode() + data).hexdigest())
            digests.add(digest)
        self.assertEqual(len(digests), 9)
        with self.assertRaises(InputError):
            hashing.domain_digest('unknown', b'{}')

    def test_every_projection_key_and_unknown_rejection(self):
        for entry in PROJECTIONS:
            kind = entry['kind']
            value = {key: 'synthetic' for key in entry['keys']}
            value.update(entry.get('constants', {}))
            if kind == 'inventory': value['entries'] = []
            if kind == 'journal-record':
                value.update(payloadKind='claim', payloadProjection={'claimId': 'synthetic'})
            expected = copy.deepcopy(value)
            for excluded in entry['exclude']: value[excluded] = 'a' * 64
            with self.subTest(kind=kind):
                self.assertEqual(hashing.project(kind, value), expected)
                self.assertEqual(hashing.domain_hash(kind, value), hashing.domain_digest(kind, cjson.dumps(expected)))
                value['unrecognized'] = True
                with self.assertRaises(InputError): hashing.project(kind, value)

    def test_all_journal_payload_keys_and_exact_backlink_exclusion(self):
        journal = next(p for p in PROJECTIONS if p['kind'] == 'journal-record')
        for name, projection in journal['payloads'].items():
            payload = {key: 'synthetic' for key in projection['keys']}
            expected = copy.deepcopy(payload)
            for key in projection['exclude']: payload[key] = 'a' * 64
            value = {'sequence': 1, 'fence': 1, 'previousRecordSha256': 'b' * 64,
                     'recordType': 'synthetic', 'payloadKind': name,
                     'payloadProjection': payload, 'recordSha256': 'c' * 64}
            with self.subTest(payload=name):
                projected = hashing.project('journal-record', value)
                self.assertEqual(projected['payloadProjection'], expected)
                self.assertNotIn('recordSha256', projected)
                payload['unrecognized'] = 1
                with self.assertRaises(InputError): hashing.project('journal-record', value)
        with self.assertRaises(InputError):
            hashing.project('journal-record', {'payloadKind': 'unknown', 'payloadProjection': {}})

    def test_hash_fields_are_not_removed_recursively(self):
        a = {'source': {'digest': 'a' * 64}}
        b = {'source': {'digest': 'b' * 64}}
        self.assertNotEqual(hashing.domain_hash('plan', a), hashing.domain_hash('plan', b))
        a = {'claimId': 'one', 'ledgerRecordSha256': 'a' * 64}
        b = dict(a, ledgerRecordSha256='b' * 64)
        self.assertEqual(hashing.domain_hash('claim', a), hashing.domain_hash('claim', b))

    def test_inventory_source_mapping_and_r23_mode(self):
        inventory = copy.deepcopy(GOLDENS[5]['input'])
        mapped = hashing.inventory_from_source({'inputs': inventory['entries'], 'digest': 'a' * 64})
        self.assertEqual(mapped, inventory)
        first = hashing.domain_hash('inventory', inventory)
        inventory['entries'][0]['mode'] = '100755'
        self.assertNotEqual(first, hashing.domain_hash('inventory', inventory))
        self.assertNotEqual(hashing.raw_hash(b'x\n'), hashing.raw_hash(b'x\r\n'))
        for key, bad in [('kind', 'plan'), ('version', 2), ('canonicalizationVersion', 'other')]:
            wrong = copy.deepcopy(inventory); wrong[key] = bad
            with self.assertRaises(InputError): hashing.project('inventory', wrong)

    def test_wrappers_are_not_accepted_as_bindings(self):
        with self.assertRaises(InputError): hashing.domain_hash('request-binding', {'binding': {}})
        with self.assertRaises(InputError): hashing.domain_hash('inventory', {'inputs': []})


    def test_noncanonical_domain_bytes_rejected(self):
        for data in [b'{ "x":1}', b'{}\n', b'{"x":1,"x":2}', b'1e0']:
            with self.subTest(data=data), self.assertRaises(InputError):
                hashing.domain_digest('plan', data)

    def test_nested_result_registry_in_journal_payload(self):
        value = {'payloadKind': 'result', 'payloadProjection': {
            'checks': [{'id': 'z'}, {'id': 'a'}]}}
        projected = hashing.project('journal-record', value)
        self.assertEqual([v['id'] for v in projected['payloadProjection']['checks']], ['a', 'z'])


class SchemaTests(unittest.TestCase):
    def test_valid_inventory_and_invalid_shapes(self):
        value = copy.deepcopy(GOLDENS[5]['input'])
        self.assertIsNone(schema.validate(value))
        for bad in [{}, dict(value, unknown=True), dict(value, version=2), dict(value, entries=[])]:
            with self.subTest(keys=list(bad)), self.assertRaises(InputError): schema.validate(bad)
        value['entries'][0]['bytesSha256'] += '\n'
        with self.assertRaises(InputError): schema.validate(value)

    def test_r32_r33_r34_lexical_definitions(self):
        source = schema.load_schema()
        for name, good in [('id', 'guard'), ('hash', 'a' * 64), ('git', 'b' * 40),
                           ('utc', '2026-01-01T00:00:00Z'), ('semver', '1.2.3-alpha.1+build')]:
            validator = schema.make_validator({'$schema': source['$schema'], '$defs': source['$defs'], '$ref': '#/$defs/' + name})
            self.assertTrue(validator.is_valid(good), name)
            for suffix in ['\n', '\r', ' ']:
                self.assertFalse(validator.is_valid(good + suffix), name)

    def test_format_checker_enabled(self):
        validator = schema.make_validator({'type': 'string', 'format': 'date-time'})
        self.assertTrue(validator.is_valid('2026-01-01T00:00:00Z'))
        self.assertFalse(validator.is_valid('2026-02-30T00:00:00Z'))
        self.assertFalse(validator.is_valid('2026-01-01T00:00:00+01:99'))

    def test_offline_schema_reference_rejected(self):
        # No remote schema retrieval, even when a caller supplies a schema.
        with patch('socket.socket', side_effect=AssertionError('network forbidden')) as network:
            try:
                validator = schema.make_validator({'$ref': 'https://example.invalid/schema'})
                validator.validate({})
            except Exception:
                pass
            else:
                self.fail('external reference unexpectedly accepted')
            network.assert_not_called()


class CliTests(unittest.TestCase):
    def run_cli(self, args, data):
        stdin = io.TextIOWrapper(io.BytesIO(data), encoding='utf-8')
        stdout_bytes = io.BytesIO(); stdout = io.TextIOWrapper(stdout_bytes, encoding='utf-8')
        stderr_bytes = io.BytesIO()
        # Force Windows-style text translation even on non-Windows hosts.
        stderr = io.TextIOWrapper(stderr_bytes, encoding='utf-8', newline='\r\n')
        with patch('sys.stdin', stdin), patch('sys.stdout', stdout), patch('sys.stderr', stderr):
            code = cli.main(args)
            stdout.flush()
            output = stdout_bytes.getvalue()
            stderr.flush()
            error = stderr_bytes.getvalue()
        return code, output, error

    def test_canon_stdout_is_exact_bytes(self):
        code, output, error = self.run_cli(['canon', '-'], b'{ "z": 1, "a": 2 }\n')
        self.assertEqual((code, output, error), (0, b'{"a":2,"z":1}', b''))

    def test_raw_and_canonical_hashes(self):
        for flag, expected in [('--raw', hashing.raw_hash(b'{ "x": 1 }\n')),
                               ('--canonical', hashing.canonical_hash({'x': 1}))]:
            code, output, error = self.run_cli(['hash', '-', flag], b'{ "x": 1 }\n')
            self.assertEqual(code, 0); self.assertEqual(output.strip().decode(), expected)
            self.assertEqual(error, b'')

    def test_domain_hash_cli(self):
        code, output, _ = self.run_cli(['hash', '-', '--domain', 'scope'], b'{"repositoryId":"synthetic"}')
        self.assertEqual(code, 0)
        self.assertEqual(output.strip().decode(), hashing.domain_hash('scope', {'repositoryId': 'synthetic'}))

    def test_validation(self):
        code, _, error = self.run_cli(['validate', '-'], json.dumps(GOLDENS[5]['input']).encode())
        self.assertEqual(code, 0); self.assertEqual(error, b'')

    def test_input_errors_do_not_echo_content_or_traceback(self):
        sentinel = b'SYNTHETIC_SECRET_SENTINEL'
        for args, data in [(['canon', '-'], b'{"' + sentinel + b'":NaN}'),
                           (['validate', '-'], b'{"' + sentinel + b'":1}'),
                           (['hash', '-', '--domain', 'scope'], b'{"' + sentinel + b'":1}')]:
            with self.subTest(args=args):
                code, output, error = self.run_cli(args, data)
                self.assertEqual(code, 3); self.assertEqual(output, b'')
                self.assertNotIn(sentinel, error)
                self.assertNotIn(b'Traceback', error)
                self.assertTrue(error)


    def test_invalid_arguments_and_missing_file_are_safe(self):
        for args in [[], ['execute'], ['hash'], ['hash', '--raw', '--canonical'],
                     ['hash', '--raw', '--kind', 'plan'], ['canon', 'missing-synthetic-file.json']]:
            with self.subTest(args=args):
                code, output, error = self.run_cli(args, b'{}')
                self.assertEqual(code, 3); self.assertEqual(output, b'')
                self.assertNotIn(b'Traceback', error)
                self.assertNotIn(b'missing-synthetic-file.json', error)

    def test_internal_error_is_fixed_diagnostic(self):
        with patch('ci_contract.cli.cjson.loads', side_effect=RuntimeError('SYNTHETIC_SECRET_SENTINEL')):
            code, output, error = self.run_cli(['canon'], b'{}')
        self.assertEqual(code, 9); self.assertEqual(output, b'')
        self.assertNotIn(b'SYNTHETIC_SECRET_SENTINEL', error)
        self.assertNotIn(b'Traceback', error)

    def test_raw_hash_accepts_non_json_bytes(self):
        data = b'\xff\x00\r\n'
        code, output, error = self.run_cli(['hash', '--raw'], data)
        self.assertEqual(code, 0); self.assertEqual(error, b'')
        self.assertEqual(output.strip().decode(), hashlib.sha256(data).hexdigest())


    def test_all_lexical_input_errors_exit_three(self):
        bad = [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'1.0', b'1e0',
               b'NaN', b'Infinity', b'-Infinity', b'9007199254740992',
               b'-9007199254740992', b'"\\ud800"', b'"\\udfff"', b'"\xff"',
               b'\xef\xbb\xbf{}', b'{} garbage', b'01', b'+1', b'', b'"\x01"']
        for data in bad:
            with self.subTest(data=repr(data)):
                code, output, error = self.run_cli(['canon', '-'], data)
                self.assertEqual(code, 3); self.assertEqual(output, b'')
                self.assertEqual(error, b'ci-contract: invalid input\n')

    def test_missing_schema_dependency_exit_nine(self):
        with patch('ci_contract.schema.make_validator', side_effect=DependencyError('synthetic missing dependency')):
            code, output, error = self.run_cli(['validate'], b'{}')
        self.assertEqual(code, 9); self.assertEqual(output, b'')
        self.assertEqual(error, b'ci-contract: internal error\n')


if __name__ == '__main__':
    unittest.main()
