"""Independent conjuncts of request identity guards, with repaired fixed hashes."""
import copy
import inspect
import types
import unittest
from ci_contract import cjson, request
from ci_contract.arrays import normalize
from ci_contract.errors import InputError, BlockedError
from ci_contract.hashing import raw_hash
from synthetic_request import fixed_model


def mutant(old, new='False'):
    source = inspect.getsource(request)
    if source.count(old) != 1:
        raise AssertionError('one request term must be removed')
    module = types.ModuleType('ci_contract.synthetic_request_term_mutant')
    module.__package__ = 'ci_contract'
    exec(compile(source.replace(old, new, 1), '<synthetic-request-term-mutant>', 'exec'), module.__dict__)
    module.StaleError = request.StaleError
    return module


def code(call):
    try:
        call()
        return 0
    except request.StaleError:
        return 5
    except InputError:
        return 3
    except BlockedError:
        return 4


BUILD_TERMS = {
    'source_base': ("source['baseCommit'] != selection['baseCommit']", 4),
    'source_comparison': ("source['comparison'] != selection['comparison']", 4),
    'request_repository': ("repository['id'] != selection['repositoryId']", 4),
    'target_repository': ("target_manifest['repository']['id'] != repository['id']", 4),
    'policy_repository': ("docs['policy']['repositoryId'] != repository['id']", 4),
    'engine_identity': ("lock['engine'] != manifest['engine']", 5),
    'engine_schema': ("lock['engine']['schemaSha256'] != raw_hash(files('ci_contract').joinpath('data/contract-v1.schema.json').read_bytes())", 5),
    'policy_pin': ("manifest['policySha256'] != selection['expectedPins']['policy']['sha256']", 5),
    'quality_ref': ("manifest['qualityProjectionRef'] != selection['expectedPins']['qualityProjection']", 5),
    'quality_bytes': ("cjson.dumps(normalize(projection)) != trusted_inputs['qualityProjection']['bytes']", 5),
    'source_inventory': ("source_digest(normalize_inventory(source['inputs'])) != source['digest']", 5),
    'base_inventory': ("source_digest(normalize_inventory(base_source['inputs'])) != base_source['digest']", 5),
}


class RequestFieldPredicateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selection, cls.inputs = fixed_model()

    def scenario(self, name):
        selection, inputs = copy.deepcopy((self.selection, self.inputs))
        controls = inputs['trusted_inputs']
        def load(key):
            return cjson.loads(controls[key]['bytes'])
        def save(key, value, suffix=b''):
            item = controls[key]
            item['bytes'] = cjson.dumps(normalize(value)) + suffix
            item['ref']['sha256'] = raw_hash(item['bytes'])
            selection['expectedPins'][key] = copy.deepcopy(item['ref'])
        manifest = load('manifest')
        if name == 'source_base': inputs['source']['baseCommit'] = 'c' * 40
        elif name == 'source_comparison': inputs['source']['comparison'] = 'merge'
        elif name == 'request_repository': selection['repositoryId'] = 'synthetic-other'
        elif name == 'target_repository': inputs['target_manifest']['repository']['id'] = 'synthetic-other'
        elif name == 'policy_repository':
            policy = load('policy'); policy['repositoryId'] = 'synthetic-other'; save('policy', policy)
            manifest['policySha256'] = controls['policy']['ref']['sha256']; save('manifest', manifest)
        elif name == 'engine_identity':
            lock = load('engineLock'); lock['engine']['bundleSha256'] = '0' * 64; save('engineLock', lock)
        elif name == 'engine_schema':
            lock = load('engineLock'); lock['engine']['schemaSha256'] = '0' * 64; save('engineLock', lock)
            manifest['engine'] = copy.deepcopy(lock['engine']); save('manifest', manifest)
        elif name == 'policy_pin':
            manifest['policySha256'] = '0' * 64; save('manifest', manifest)
        elif name == 'quality_ref':
            manifest['qualityProjectionRef']['commit'] = 'c' * 40; save('manifest', manifest)
        elif name == 'quality_bytes':
            save('qualityProjection', load('qualityProjection'), b'\n')
            manifest['qualityProjectionRef'] = copy.deepcopy(controls['qualityProjection']['ref']); save('manifest', manifest)
        elif name == 'source_inventory': inputs['source']['digest'] = '0' * 64
        elif name == 'base_inventory': inputs['base_source']['digest'] = '0' * 64
        return selection, inputs

    def assert_term(self, name, module):
        selection, inputs = self.scenario(name)
        self.assertEqual(code(lambda: module.build_selection_plan(selection, 'change', **inputs)), BUILD_TERMS[name][1])

    def test_pin_reference_fields_individually(self):
        for pin in request.PIN_PATHS:
            for field, value in [('repositoryId', 'synthetic-other'), ('commit', 'c' * 40), ('path', '.ci/synthetic-other.json')]:
                with self.subTest(pin=pin, field=field):
                    selection, inputs = copy.deepcopy((self.selection, self.inputs))
                    selection['expectedPins'][pin][field] = value
                    self.assertEqual(code(lambda: request.match_pins(selection, inputs['trusted_inputs'])), 4)
                    broken = mutant("actual['ref'][key] != expected[key] for key in ('repositoryId','commit','path')",
                                    "actual['ref'][key] != expected[key] for key in ('repositoryId','commit','path') if key != '" + field + "'")
                    self.assertEqual(code(lambda: broken.match_pins(selection, inputs['trusted_inputs'])), 0)
                    with self.assertRaises(AssertionError):
                        self.assertEqual(code(lambda: broken.match_pins(selection, inputs['trusted_inputs'])), 4)

    def test_pin_byte_hash_and_ref_hash_individually(self):
        for pin in request.PIN_PATHS:
            for field in ('bytes', 'ref'):
                with self.subTest(pin=pin, field=field):
                    selection, inputs = copy.deepcopy((self.selection, self.inputs))
                    actual = inputs['trusted_inputs'][pin]
                    if field == 'bytes':
                        actual['bytes'] += b'\n'
                        term = "raw_hash(actual['bytes']) != expected['sha256']"
                    else:
                        actual['ref']['sha256'] = '0' * 64
                        term = "actual['ref']['sha256'] != expected['sha256']"
                    self.assertEqual(code(lambda: request.match_pins(selection, inputs['trusted_inputs'])), 5)
                    broken = mutant(term)
                    self.assertIs(broken.StaleError, request.StaleError)
                    self.assertEqual(code(lambda: broken.match_pins(selection, inputs['trusted_inputs'])), 0)
                    with self.assertRaises(AssertionError):
                        self.assertEqual(code(lambda: broken.match_pins(selection, inputs['trusted_inputs'])), 5)


def field_test(name):
    def test(self):
        self.assert_term(name, request)
        broken = mutant(BUILD_TERMS[name][0])
        selection, inputs = self.scenario(name)
        self.assertEqual(code(lambda: broken.build_selection_plan(selection, 'change', **inputs)), 0)
        with self.assertRaises(AssertionError):
            self.assert_term(name, broken)
    return test


for name in BUILD_TERMS:
    setattr(RequestFieldPredicateTests, 'test_' + name, field_test(name))
