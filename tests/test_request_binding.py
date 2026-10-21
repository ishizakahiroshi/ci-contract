"""Request-bound verification and single-predicate negative controls."""
import copy
import inspect
from pathlib import Path
import unittest
from unittest.mock import patch
from ci_contract import cjson
from ci_contract.errors import InputError
from ci_contract.hashing import canonical_hash, domain_hash, domain_digest, PROJECTIONS
import ci_contract.request_binding as binding_module
import ci_contract.verify as verifier
from ci_contract.request_binding import make_request_binding, request_digest, scope_key
from synthetic_verify import digest, START, END, DEADLINE, MODEL, record_observation
from synthetic_request_binding import bound_documents, bind_hashes, refresh, verify_bound

FIXTURE = cjson.loads((Path(__file__).parent / 'fixtures/request-cases.json').read_bytes())
CASES = {case['id']: case for case in FIXTURE['cases']}


def binding_mutant(old, new):
    source = inspect.getsource(binding_module)
    if source.count(old) != 1:
        raise AssertionError('exactly one binding predicate must be mutated')
    namespace = {'__name__': 'ci_contract.synthetic_binding_mutant', '__package__': 'ci_contract'}
    exec(compile(source.replace(old, new, 1), '<synthetic-binding-mutant>', 'exec'), namespace)
    return namespace


def verifier_mutant(old, new):
    source = inspect.getsource(verifier)
    if source.count(old) != 1:
        raise AssertionError('exactly one verifier predicate must be mutated')
    namespace = {'__name__': 'ci_contract.synthetic_request_mutant', '__package__': 'ci_contract'}
    exec(compile(source.replace(old, new, 1), '<synthetic-request-mutant>', 'exec'), namespace)
    return namespace['verify']


def field_mismatch(key, value):
    docs = bound_documents()
    docs[4][key] = value
    if key == 'workflowCommit':
        docs[3]['githubObservation']['workflowCommit'] = value
    return bind_hashes(docs)


def envelope_mismatch(key, value):
    docs = bound_documents()
    docs[1]['requestBinding'][key] = value
    if key in ('requestId', 'requestDigest'):
        docs[1]['requestBinding']['attemptAuthority'][key] = value
    return refresh(docs)


def authority_kind_mismatch():
    docs = bound_documents()
    docs[4]['authorityKind'] = 'github-run-v1'
    return bind_hashes(docs)


def before_creation():
    docs = bound_documents()
    docs[4]['createdAt'] = '2026-01-01T00:00:01Z'
    return bind_hashes(docs)


def expired_request():
    docs = bound_documents()
    docs[4]['expiresAt'] = '2026-01-01T00:00:59Z'
    return bind_hashes(docs)


def observation_mismatch(key):
    docs = bound_documents()
    docs[3]['githubObservation'][key] = 'a' * 40
    return docs


def missing_observation():
    docs = bound_documents()
    del docs[3]['githubObservation']
    return docs


# Each identity field has its own single-fault input with all digest fields repaired.
EXPECTED_FIELDS = {
    'repositoryId': 'synthetic-other', 'sourceDigest': digest('other-source'),
    'planSha256': digest('other-plan'), 'selectionRequestSha256': digest('other-selection'),
    'engineLockSha256': digest('other-lock'), 'profile': 'case', 'target': 'local',
    'workflowCommit': 'a' * 40, 'authorityId': 'synthetic-other-authority', 'trust': 'untrusted'}

PREDICATES = [
    ('binding_' + key, lambda key=key, value=value: field_mismatch(key, value), 4,
     'binding[key] != value for key, value in expected.items()',
     "binding[key] != value for key, value in expected.items() if key != '" + key + "'", 0)
    for key, value in EXPECTED_FIELDS.items()]
PREDICATES += [
    ('envelope_' + key, lambda key=key, value=value: envelope_mismatch(key, value), 4,
     'for document in (execution, result) for key, value in digests.items()',
     "for document in (execution, result) for key, value in digests.items() if key != '" + key + "'", 0)
    for key, value in {'requestId': 'synthetic-other-request', 'requestDigest': digest('other-request'),
                       'scopeKey': digest('other-scope')}.items()]
PREDICATES += [
    ('envelope_authority_kind', authority_kind_mismatch, 4,
     'for document in (execution, result) for key, value in digests.items()',
     "for document in (execution, result) for key, value in digests.items() if key != 'authorityKind'", 0),
    ('creation_boundary', before_creation, 4,
     "_utc(execution['startedAt']) < _utc(binding['createdAt'])", 'False', 0),
    ('expiry_boundary', expired_request, 4,
     "_utc(result['completedAt']) > _utc(binding['expiresAt'])", 'False', 0),
    ('workflow_observation', lambda: observation_mismatch('workflowCommit'), 5,
     "observation['workflowCommit'] != binding['workflowCommit']", 'False', 0),
    ('target_observation', lambda: observation_mismatch('targetCommit'), 5,
     "observation['targetCommit'] != plan['source']['targetCommit']", 'False', 0),
]


class BindingPredicateTests(unittest.TestCase):
    pass


def predicate_test(case):
    name, builder, expected, old, new, mutated = case
    def test(self):
        docs = builder()
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], expected)
        with patch.object(binding_module, 'binding_status', binding_mutant(old, new)['binding_status']):
            mutant_code = verify_bound(verifier.verify, docs)['exitCode']
            self.assertEqual(mutant_code, mutated)
            with self.assertRaises(AssertionError):
                self.assertEqual(mutant_code, expected)
        self.assertNotEqual(mutated, expected)
    return test


for case in PREDICATES:
    setattr(BindingPredicateTests, 'test_' + case[0], predicate_test(case))


class BindingShapeTests(unittest.TestCase):
    def test_binding_schema_guard_negative_control(self):
        binding = bound_documents()[4]
        binding['syntheticExtra'] = 'synthetic'
        with self.assertRaises(InputError):
            binding_module.validate_request_binding(binding)
        mutant = binding_mutant('if next(make_validator(schema).iter_errors(binding), None) is not None:',
                                'if False:')
        self.assertEqual(mutant['validate_request_binding'](binding), binding)

    def test_timestamp_lexical_guard_negative_control(self):
        value = START + '\n'
        with self.assertRaises(InputError):
            binding_module._utc(value)
        old = "if type(value) is not str or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value) is None:"
        mutant = binding_mutant(old, 'if False:')
        self.assertEqual(mutant['_utc'](value), binding_module._utc(START))

    def test_builder_kind_guard_negative_control(self):
        execution = bound_documents()[1]
        kwargs = dict(request_id='synthetic-request', authority_id='synthetic-authority', target='local',
                      trust='trusted', workflow_commit=None, created_at=START, expires_at=DEADLINE,
                      authority_kind='local-single-supervisor-v1')
        with self.assertRaises(InputError):
            make_request_binding(execution, **kwargs)
        mutant = binding_mutant("if plan['kind'] != 'plan':", 'if False:')
        with self.assertRaises(KeyError):
            mutant['make_request_binding'](execution, **kwargs)

    def test_closed_binding_and_calendar_errors_precede_stale(self):
        faults = [('unknown', 'synthetic'), ('requestId', 'bad\n'), ('planSha256', 'a' * 63),
                  ('createdAt', '2026-02-30T00:00:00Z'), ('expiresAt', '2026-01-01T24:00:00Z'),
                  ('expiresAt', '2026-01-01T00:00:60Z'), ('expiresAt', START)]
        for key, value in faults:
            with self.subTest(key=key, value=value):
                docs = observation_mismatch('workflowCommit')
                docs[4][key] = value
                self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 3)

    def test_calendar_and_interval_guards_have_negative_controls(self):
        docs = bound_documents()
        docs[4]['expiresAt'] = START
        mutant = binding_mutant('if expires <= created:', 'if False:')
        with self.assertRaises(InputError):
            binding_module.validate_request_binding(docs[4])
        mutant['validate_request_binding'](docs[4])
        with self.assertRaises(InputError):
            binding_module._utc('2026-01-01T24:00:00Z')
        mutant = binding_mutant('int(value[11:13]), int(value[14:16]), int(value[17:19]), tzinfo=timezone.utc)',
                                '0, int(value[14:16]), int(value[17:19]), tzinfo=timezone.utc)')
        self.assertEqual(mutant['_utc']('2026-01-01T24:00:00Z').hour, 0)

    def test_observation_shape_precedes_other_mismatch(self):
        for observation in ({'workflowCommit': 'a'*40},
                            {'workflowCommit': 'a'*40, 'targetCommit': 'd'*40, 'extra': True},
                            {'workflowCommit': 'a'*40+'\n', 'targetCommit': 'd'*40}):
            docs = bound_documents()
            docs[3]['githubObservation'] = observation
            self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 3)

    def test_observation_closed_shape_negative_control(self):
        docs = bound_documents()
        docs[3]['githubObservation']['extra'] = 'synthetic'
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 3)
        mutant = verifier_mutant("'required': ['workflowCommit', 'targetCommit'], 'additionalProperties': False",
                                 "'required': ['workflowCommit', 'targetCommit'], 'additionalProperties': True")
        self.assertEqual(verify_bound(mutant, docs)['exitCode'], 0)

    def test_optional_binding_hook_negative_control(self):
        docs = expired_request()
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 4)
        mutant = verifier_mutant('if rejection is not None:', 'if False:')
        self.assertEqual(verify_bound(mutant, docs)['exitCode'], 0)

    def test_missing_independent_observation_blocks(self):
        docs = missing_observation()
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 4)
        mutant = binding_mutant("if observation is None:\n            return 'blocked'",
                                "if observation is None:\n            return None")
        with patch.object(binding_module, 'binding_status', mutant['binding_status']):
            self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 0)

    def test_exact_expiry_is_allowed(self):
        docs = bound_documents()
        docs[4]['expiresAt'] = END
        bind_hashes(docs)
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 0)
        mutant = binding_mutant("_utc(result['completedAt']) > _utc(binding['expiresAt'])",
                                "_utc(result['completedAt']) >= _utc(binding['expiresAt'])")
        with patch.object(binding_module, 'binding_status', mutant['binding_status']):
            self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 4)

    def test_result_and_execution_are_each_compared_to_the_request(self):
        for index in (1, 2):
            for key, value in {'requestId': 'synthetic-other', 'requestDigest': digest('different'),
                               'scopeKey': digest('different')}.items():
                with self.subTest(document=index, field=key):
                    docs = bound_documents()
                    docs[index]['requestBinding'][key] = value
                    self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 4)

    def test_plan_and_selection_are_not_mutated_by_binding_construction(self):
        docs = bound_documents()
        before = cjson.dumps(docs[0])
        make_request_binding(docs[0], request_id='synthetic-new', authority_id='synthetic-authority',
                             target='local', trust='trusted', workflow_commit=None, created_at=START,
                             expires_at=DEADLINE, authority_kind='local-single-supervisor-v1')
        self.assertEqual(cjson.dumps(docs[0]), before)

    def test_each_domain_projection_key_is_committed_once(self):
        binding = bound_documents()[4]
        for kind, actual in (('request-binding', request_digest(binding)), ('scope', scope_key(binding))):
            keys = next(entry['keys'] for entry in PROJECTIONS['entries'] if entry['kind'] == kind)
            projected = {key: binding[key] for key in keys}
            self.assertEqual(actual, domain_digest(kind, cjson.dumps(projected)))
            for key in keys:
                changed = dict(projected)
                del changed[key]
                self.assertNotEqual(actual, domain_digest(kind, cjson.dumps(changed)))
            changed = dict(projected, syntheticExtra='synthetic')
            self.assertNotEqual(actual, domain_digest(kind, cjson.dumps(changed)))
            with self.assertRaises(InputError):
                domain_hash(kind, changed)

    def test_request_and_scope_projection_negative_controls(self):
        binding = bound_documents()[4]
        mutant = binding_mutant("return domain_hash('request-binding', binding)",
                                "return domain_hash('request-binding', {key: value for key, value in binding.items() if key != 'requestId'})")
        self.assertNotEqual(request_digest(binding), mutant['request_digest'](binding))
        mutant = binding_mutant("return domain_hash('scope', {key: binding[key] for key in _SCOPE_KEYS})",
                                "return domain_hash('scope', {key: binding[key] for key in _SCOPE_KEYS if key != 'trust'})")
        self.assertNotEqual(scope_key(binding), mutant['scope_key'](binding))


def workflow_documents(case):
    """Map model aliases only; expected status and selected IDs are not inputs."""
    docs = bound_documents(full=True)
    plan, execution, result, ledger, binding = docs
    given = case['given']
    aliases = FIXTURE['fixtureModels'][0]['identities']
    names = {'W1': 'workflow1', 'W2': 'workflow2', 'T1': 'target'}
    def commit(value):
        return aliases[names.get(value, value)]
    workflow = commit(given.get('workflowRequested', given.get('requested_workflow_commit')))
    target = commit(given.get('targetRequested', given.get('requested_target_commit')))
    plan['source']['targetCommit'] = execution['github']['targetCommit'] = target
    execution['github']['expectedWorkflowCommit'] = workflow
    execution['github']['event'] = given.get('event', 'workflow_dispatch')
    binding['workflowCommit'] = workflow
    binding['planSha256'] = domain_hash('plan', plan)
    ledger['githubObservation'] = {
        'workflowCommit': commit(given.get('workflowObserved', given.get('actual_workflow_commit'))),
        'targetCommit': commit(given.get('targetObserved', given.get('actual_target_commit')))}
    return bind_hashes(docs)


class RequestAcceptanceTests(unittest.TestCase):
    def assert_case(self, key):
        case = CASES[key]
        docs = workflow_documents(case)
        verdict = verify_bound(verifier.verify, docs)
        self.assertEqual(verdict, {name: case['expected'][name] for name in ('status', 'exitCode')})
        self.assertEqual(set(docs[0]['selectionEvidence']['selectedInstanceIds']),
                         set(case['expected']['selectedInstanceIds']))
        self.assertFalse(set(docs[0]['selectionEvidence']['selectedInstanceIds']) &
                         set(case['expected']['notSelectedInstanceIds']))
        return docs

    def test_c15(self):
        docs = self.assert_case('c15')
        docs[3]['githubObservation']['targetCommit'] = 'a' * 40
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 5)
        mutant = binding_mutant("observation['targetCommit'] != plan['source']['targetCommit']", 'False')
        with patch.object(binding_module, 'binding_status', mutant['binding_status']):
            mutant_code = verify_bound(verifier.verify, docs)['exitCode']
            self.assertEqual(mutant_code, 0)
            with self.assertRaises(AssertionError):
                self.assertEqual(mutant_code, 5)

    def test_c15b(self):
        docs = self.assert_case('c15b')
        mutant = binding_mutant("observation['workflowCommit'] != binding['workflowCommit']", 'False')
        with patch.object(binding_module, 'binding_status', mutant['binding_status']):
            mutant_code = verify_bound(verifier.verify, docs)['exitCode']
            self.assertEqual(mutant_code, 0)
            with self.assertRaises(AssertionError):
                self.assertEqual(mutant_code, CASES['c15b']['expected']['exitCode'])

    def test_r26(self):
        docs = self.assert_case('r26')
        self.assertNotEqual(docs[4]['workflowCommit'], docs[0]['source']['targetCommit'])
        mutant = binding_mutant("observation['workflowCommit'] != binding['workflowCommit']",
                                "observation['workflowCommit'] != plan['source']['targetCommit']")
        with patch.object(binding_module, 'binding_status', mutant['binding_status']):
            mutant_code = verify_bound(verifier.verify, docs)['exitCode']
            self.assertEqual(mutant_code, 5)
            with self.assertRaises(AssertionError):
                self.assertEqual(mutant_code, CASES['r26']['expected']['exitCode'])

    def test_r27(self):
        docs = self.assert_case('r27')
        mutant = binding_mutant("observation['workflowCommit'] != binding['workflowCommit']", 'False')
        with patch.object(binding_module, 'binding_status', mutant['binding_status']):
            mutant_code = verify_bound(verifier.verify, docs)['exitCode']
            self.assertEqual(mutant_code, 0)
            with self.assertRaises(AssertionError):
                self.assertEqual(mutant_code, CASES['r27']['expected']['exitCode'])

    def compare_targets(self, key):
        case = CASES[key]
        from synthetic_request import rebuilt_model
        plan = rebuilt_model()
        local, remote = (bound_documents(target, full=True, supplied_plan=plan)
                         for target in case['given']['targets'])
        for docs in (local, remote):
            self.assertEqual(verify_bound(verifier.verify, docs),
                             {name: case['expected'][name] for name in ('status', 'exitCode')})
            self.assertEqual(set(check['id'] for check in docs[0]['checks']),
                             set(case['expected']['selectedInstanceIds']))
        self.assertEqual(cjson.dumps(local[0]), cjson.dumps(remote[0]))
        self.assertEqual(domain_hash('plan', local[0]), domain_hash('plan', remote[0]))
        self.assertNotEqual(local[1]['executionId'], remote[1]['executionId'])
        self.assertNotEqual(local[4]['requestId'], remote[4]['requestId'])
        # A transport must not silently make a smaller target-specific plan.
        mutant = copy.deepcopy(remote)
        secret = MODEL['instanceAliases']['guard.secrets.linux']['instanceId']
        mutant[1]['plan']['checks'] = [check for check in mutant[1]['plan']['checks'] if check['id'] != secret]
        mutant[1]['plan']['selectionEvidence']['selectedInstanceIds'].remove(secret)
        mutant[1]['planSha256'] = domain_hash('plan', mutant[1]['plan'])
        mutant[2]['executionSha256'] = mutant[3]['executionSha256'] = domain_hash('execution', mutant[1])
        self.assertEqual(verify_bound(verifier.verify, mutant)['exitCode'], 4)
        # Rebuild a fully self-consistent smaller remote envelope, but retain the
        # binding made from the independently trusted complete rebuilt plan.
        smaller_plan = copy.deepcopy(plan)
        smaller_plan['checks'] = [check for check in smaller_plan['checks'] if check['id'] != secret]
        smaller_plan['selectionEvidence']['selectedInstanceIds'].remove(secret)
        smaller = bound_documents('github', full=True, supplied_plan=smaller_plan)
        self.assertEqual(verify_bound(verifier.verify, smaller)['exitCode'], 0)
        smaller = (*smaller[:4], copy.deepcopy(remote[4]))
        bind_hashes(smaller)
        self.assertEqual(verify_bound(verifier.verify, smaller)['exitCode'], 4)
        removed = binding_mutant(
            "expected = {\n        **plan_binding_fields(plan),\n        'planSha256': domain_hash('plan', plan),",
            "expected = {\n        **plan_binding_fields(plan),")
        with patch.object(binding_module, 'binding_status', removed['binding_status']):
            self.assertEqual(verify_bound(verifier.verify, smaller)['exitCode'], 0)

    def test_c02(self):
        self.compare_targets('c02')

    def test_r03(self):
        self.compare_targets('r03')
