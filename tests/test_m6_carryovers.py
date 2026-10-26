"""Synthetic P1-P7 regressions and one-predicate negative controls."""
import copy
import argparse
import hashlib
import inspect
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from ci_contract import cjson, cli
import ci_contract.verify as verifier
from ci_contract.hashing import domain_hash, canonical_hash
from synthetic_verify import digest, START, END, DEADLINE, LATE
from test_verify_predicates import baseline, rebind, observe, proof_field, mutate_source, verdict


def failed():
    d = baseline()
    d[2].update(status='failed', exitCode=2)
    d[2]['checks'][0].update(status='failed', exitCode=1)
    d[2]['checks'][0]['proof']['invocation']['exitCode'] = 1
    return observe(d)


def failed_result_field(field, value):
    d = failed(); d[2][field] = value
    return d


def extra_ledger_proof():
    d = baseline()
    proof = copy.deepcopy(d[3]['proofs'][0])
    proof['identity']['instanceId'] = 'synthetic-extra'
    d[3]['proofs'].append(proof)
    return d


def missing_failed_proof():
    d = failed(); d[3]['proofs'] = []
    return d


def overlapping_test(field):
    d = baseline('test')
    collection = d[2]['checks'][0]['proof']['collection']
    identifier = collection['passedCaseIds'][0]
    collection[field] = ([{'id': identifier, 'reasonCode': 'synthetic-skip'}]
                         if field == 'skippedCases' else [identifier])
    return observe(d)


def unknown_result(field, value):
    d = baseline(); d[2].update(status='unknown', exitCode=8)
    d[2][field] = value
    return d


def late_failed_proof():
    d = failed(); d[2]['checks'][0]['proof']['invocation']['completedAt'] = LATE
    return observe(d)


def payload_input():
    d = baseline('artifact')
    d[2]['checks'][0]['proof']['payloads'][0]['inputDigests'] = [digest('other-input')]
    return observe(d)


def receipt_logical():
    d = baseline(); d[2]['checks'][0]['logicalCheckId'] = 'synthetic-other-logical'
    return d


def early_cancel():
    d = baseline()
    d[3].update(terminalObservation='cancelled', observedAt='2025-12-31T23:59:59Z')
    return d


def late_result():
    d = baseline()
    d[2]['completedAt'] = d[3]['observedAt'] = '2026-01-01T00:02:01Z'
    return d


def proof_after_result():
    return proof_field('invocation', 'completedAt', '2026-01-01T00:01:01Z')


def swapped_documents():
    p, e, r, l = baseline()
    return e, p, r, l


def plan_field(field, value):
    d = baseline(); d[0][field] = value
    return rebind(d)


def stale_inventory():
    d = baseline(); p, e, r, l = d
    p['source']['digest'] = digest('other-inventory')
    r['sourceDigestBefore'] = r['sourceDigestAfter'] = p['source']['digest']
    r['checks'][0]['proof']['identity']['sourceDigest'] = p['source']['digest']
    return rebind(d)


def blocked_passed_result():
    d = baseline(); d[2].update(status='blocked', exitCode=4)
    return d


def blocked_failed_result():
    d = failed(); d[2].update(status='blocked', exitCode=4)
    return d


def selection_field(field, value):
    d = baseline(); d[0]['selectionRequest'][field] = value
    d[0]['selectionRequestSha256'] = canonical_hash(d[0]['selectionRequest'])
    return rebind(d)


def projection_pin_mismatch():
    d = baseline()
    d[0]['selectionRequest']['expectedPins']['qualityProjection']['sha256'] = digest('other-projection')
    d[0]['selectionRequestSha256'] = canonical_hash(d[0]['selectionRequest'])
    return rebind(d)


def failed_zero_receipt():
    d = failed()
    d[2]['checks'][0]['exitCode'] = d[2]['checks'][0]['proof']['invocation']['exitCode'] = 0
    return observe(d)


def artifact_field(field, value):
    d = baseline('artifact'); d[2]['artifacts'][0][field] = value
    return d


def artifact_producer_check_mismatch():
    d = baseline('artifact')
    d[2]['checks'][0]['proof']['payloads'][0]['producerInstanceId'] = 'synthetic-other-instance'
    d[2]['artifacts'][0]['producerCheckId'] = 'synthetic-other-instance'
    return observe(d)


def invocation_reverse_interval():
    d = baseline()
    d[2]['checks'][0]['proof']['invocation'].update(
        startedAt='2026-01-01T00:00:30Z', completedAt=START)
    return observe(d)


# Each tuple preserves all derived hashes except the single named defect.
# A KeyError mutant is a detected failure, never an accepted verdict.
PREDICATES = [
    ('collector_run', lambda: proof_field('collector', 'runId', '124'), 4,
     "collector['runId'] != github['runId']", 'False', 0),
    ('collector_attempt', lambda: proof_field('collector', 'attempt', 2), 4,
     "collector['attempt'] != github['attempt']", 'False', 0),
    ('extra_proof', extra_ledger_proof, 4, 'set(proofs) != set(ids)', 'False', 0),
    ('missing_failed_proof', missing_failed_proof, 4, 'set(proofs) != set(ids)', 'False', KeyError),
    ('failed_missing_checks', lambda: failed_result_field('missingCheckIds', ['synthetic-missing']), 4,
     "result['missingCheckIds']", 'False', 2),
    ('failed_unresolved_requirement', lambda: failed_result_field('unresolvedRequirementIds', ['synthetic-missing']), 4,
     "result['unresolvedRequirementIds']", 'False', 2),
    ('passed_and_failed_case', lambda: overlapping_test('failedCaseIds'), 4,
     "collection['failedCaseIds']", 'False', 0),
    ('passed_and_skipped_case', lambda: overlapping_test('skippedCases'), 4,
     "collection['skippedCases']", 'False', 0),
    ('unknown_cleanup', lambda: unknown_result('cleanupConfirmed', False), 8,
     "not result['cleanupConfirmed']", 'False', 4),
    ('unknown_pending', lambda: unknown_result('pendingChildren', 1), 8,
     "result['pendingChildren']", 'False', 4),
    ('late_failed_invocation', late_failed_proof, 4,
     "_time(invocation['completedAt']) > _time(execution['deadlineAt'])", 'False', 2),
    ('analysis_incomplete', lambda: proof_field('collection', 'analysisCompleted', False), 4,
     "not collection['analysisCompleted']", 'False', 0),
    ('payload_input_digests', payload_input, 4,
     "set(payload['inputDigests']) != {identity['sourceDigest'], *identity['generatedInputDigests']}", 'False', 0),
    ('invocation_before_start', lambda: proof_field('invocation', 'startedAt', '2025-12-31T23:59:59Z'), 4,
     "_time(invocation['startedAt']) < _time(execution['startedAt'])", 'False', 0),
    ('invocation_directory', lambda: proof_field('invocation', 'cwd', 'synthetic-other'), 4,
     "invocation['cwd'] != check['cwd']", 'False', 0),
    ('receipt_logical_id', receipt_logical, 4,
     "receipt['logicalCheckId'] != check['logicalCheckId']", 'False', 0),
    ('cancel_before_start', early_cancel, 4,
     "_time(ledger['observedAt']) < _time(execution['startedAt'])", 'False', 6),
    ('completion_after_deadline', late_result, 4,
     "_time(result['completedAt']) > _time(execution['deadlineAt'])", 'False', 0),
    ('proof_after_completion', proof_after_result, 4,
     "any(_time(proof['invocation']['completedAt']) > _time(result['completedAt']) for proof in proofs.values())", 'False', 0),
    ('document_kind', swapped_documents, 3,
     "document['kind'] != kind", 'False', KeyError),
    ('selection_hash', lambda: plan_field('selectionRequestSha256', digest('other-selection')), 4,
     "plan['selectionRequestSha256'] != canonical_hash(plan['selectionRequest'])", 'False', 0),
    ('manifest_pin', lambda: plan_field('manifestSha256', digest('other-manifest')), 4,
     "pins['manifest']['sha256'] != plan['manifestSha256']", 'False', 0),
    ('inventory_digest', stale_inventory, 5,
     "source_digest(inventory) != plan['source']['digest']", 'False', 0),
    ('blocked_with_passed_checks', blocked_passed_result, 4,
     "result['status'] != 'accepted'", 'False', 0),
    # R4: individual terms, not removal of their enclosing compound condition.
    ('invocation_argv', lambda: proof_field('invocation', 'argv', ['synthetic-other']), 4,
     "invocation['argv'] != check['argv']", 'False', 0),
    ('policy_pin', lambda: plan_field('policySha256', digest('other-policy')), 4,
     "pins['policy']['sha256'] != plan['policySha256']", 'False', 0),
    ('selection_repository', lambda: selection_field('repositoryId', 'synthetic-other'), 4,
     "request['repositoryId'] != plan['repository']['id']", 'False', 0),
    ('selection_base', lambda: selection_field('baseCommit', 'a' * 40), 4,
     "request['baseCommit'] != plan['source']['baseCommit']", 'False', 0),
    ('projection_pin', projection_pin_mismatch, 4,
     "not _same(pins['qualityProjection'], projection)", 'False', 0),
    ('runtime_dataset', lambda: proof_field('runtime', 'datasetSha256', digest('other-dataset')), 4,
     "runtime['datasetSha256'] != variant['dataset']['sha256']", 'False', 0),
    ('invocation_exit_code', lambda: proof_field('invocation', 'exitCode', 1), 4,
     "invocation['exitCode'] != receipt['exitCode']", 'False', 0),
    ('invocation_signal', lambda: proof_field('invocation', 'signal', 'SIGTERM'), 4,
     "invocation['signal'] is not None", 'False', 0),
    ('invocation_reverse_interval', invocation_reverse_interval, 4,
     "_time(invocation['completedAt']) < _time(invocation['startedAt'])", 'False', 0),
    ('collector_target', lambda: proof_field('collector', 'target', 'local'), 4,
     "collector['target'] != execution['target']", 'False', 0),
    ('failed_zero_receipt', failed_zero_receipt, 4,
     "receipt['exitCode'] != 0", 'True', 2),
    ('executed_case_ids', lambda: proof_field('collection', 'executedCaseIds', [], 'test'), 4,
     "set(collection['executedCaseIds']) != required", 'False', 0),
    ('artifact_size', lambda: artifact_field('sizeBytes', 987), 4,
     "artifact['sizeBytes'] != payload['sizeBytes']", 'False', 0),
    ('artifact_producer', lambda: artifact_field('producerCheckId', 'synthetic-other'), 4,
     "artifact['producerCheckId'] != payload['producerInstanceId']", 'False', 0),
    ('artifact_source', lambda: artifact_field('sourceDigest', digest('other-source')), 4,
     "artifact['sourceDigest'] != identity['sourceDigest']", 'False', 0),
    ('artifact_plan', lambda: artifact_field('planSha256', digest('other-plan')), 4,
     "artifact['planSha256'] != identity['planSha256']", 'False', 0),
    ('blocked_with_failed_checks', blocked_failed_result, 4,
     "result['status'] == 'failed' and all(", 'all(', 2),
    # S2/T3: remove only the previously uncovered term of each condition.
    ('projection_sha', lambda: plan_field('qualityProjectionSha256', digest('other-projection-digest')), 4,
     "projection['sha256'] != plan['qualityProjectionSha256']", 'False', 0),
    ('runtime_arch', lambda: proof_field('runtime', 'arch', 'aarch64'), 4,
     "runtime['arch'] != variant['arch']", 'False', 0),
    ('selection_comparison', lambda: selection_field('comparison', 'merge'), 4,
     "request['comparison'] != plan['source']['comparison']", 'False', 0),
    ('payload_producer_check', artifact_producer_check_mismatch, 4,
     "payload['producerInstanceId'] != check['id']", 'False', 0),
]


class CarryoverPredicateTests(unittest.TestCase):
    def test_failed_control_is_valid(self):
        self.assertEqual(verdict(verifier.verify, failed()), 2)


def predicate_test(case):
    name, builder, expected, old, new, removed = case
    def test(self):
        docs = builder(); original = copy.deepcopy(docs)
        self.assertEqual(verdict(verifier.verify, docs), expected)
        self.assertEqual(docs, original)
        mutant = mutate_source(old, new)
        if isinstance(removed, type) and issubclass(removed, Exception):
            with self.assertRaises(removed): verdict(mutant, docs)
        else:
            self.assertEqual(verdict(mutant, docs), removed)
            self.assertNotEqual(expected, removed)
    return test


for case in PREDICATES:
    setattr(CarryoverPredicateTests, 'test_' + case[0], predicate_test(case))


def assert_coverage_counts(test, value):
    cases = value['cases']
    test.assertEqual(value['caseCount'], len(cases))
    test.assertEqual(value['notImplementedCount'], sum(c['status'] == 'not-implemented' for c in cases))
    test.assertEqual(value['partialUnitCoverageCount'], sum(c['status'] == 'partial-unit-coverage' for c in cases))
    test.assertEqual(value['fullAcceptanceCasesPassed'], 0)
    counts = {'selectionCore': {'selectionProjectionPassedCount': 'selection-projection-passed',
                               'unexecutedCount': 'UNEXECUTED', 'delegatedToPlanCount': 'delegated-to-plan-tests'},
              'planCore': {'stageObservationPassedCount': 'stage-observation-passed'}}
    for key, section in value.items():
        if not isinstance(section, dict) or 'cases' not in section: continue
        test.assertEqual(section['caseCount'], len(section['cases']))
        if 'fullAcceptanceCasesPassed' in section:
            test.assertEqual(section['fullAcceptanceCasesPassed'], 0)
        for count, status in counts.get(key, {}).items():
            test.assertEqual(section[count], sum(c['status'] == status for c in section['cases']))
        count = key + 'ImplementedCount'
        if count in value:
            test.assertEqual(value[count], sum(c['status'] == 'implemented' for c in section['cases']))
    implemented = {c['id'] for key in ('verifyCore', 'requestCore', 'claimCore', 'executeCore') if key in value
                   for c in value[key]['cases'] if c['status'] == 'implemented'}
    test.assertEqual({c['id'] for c in cases if c['status'] == 'implemented'}, implemented)


class CoverageCountTests(unittest.TestCase):
    def test_all_stage_counts_match_case_statuses(self):
        value = cjson.loads(Path(__file__).with_name('acceptance-coverage.json').read_bytes())
        assert_coverage_counts(self, value)

    def test_each_count_shift_is_detected(self):
        value = cjson.loads(Path(__file__).with_name('acceptance-coverage.json').read_bytes())
        paths = [(key,) for key, val in value.items() if type(val) is int]
        paths += [(key, field) for key, val in value.items() if isinstance(val, dict)
                  for field, number in val.items() if type(number) is int]
        for path in paths:
            with self.subTest(path=path):
                changed = copy.deepcopy(value); node = changed
                for key in path[:-1]: node = node[key]
                node[path[-1]] += 1
                with self.assertRaises(AssertionError): assert_coverage_counts(self, changed)


class EnvironmentIsolationTests(unittest.TestCase):
    def test_checkout_controls_ignore_injected_git_configuration(self):
        from test_verify_corrections import FixedByteAttributesTests, CorrectiveMutationTests
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / 'synthetic-config'
            config.write_text('[core]\n autocrlf = false\n', encoding='utf-8')
            poison = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.autocrlf',
                      'GIT_CONFIG_VALUE_0': 'false', 'GIT_CONFIG_PARAMETERS': "'core.autocrlf=false'",
                      'GIT_CONFIG_GLOBAL': str(config), 'GIT_CONFIG_SYSTEM': str(config)}
            with patch.dict(os.environ, poison):
                FixedByteAttributesTests().test_autocrlf_checkout_preserves_synthetic_asset_bytes()
                CorrectiveMutationTests().test_missing_byte_attributes_control_changes_checkout_bytes()

    def test_environment_isolation_removal_is_detected(self):
        import test_verify_corrections as controls
        method = controls.CorrectiveMutationTests.test_missing_byte_attributes_control_changes_checkout_bytes
        source = textwrap.dedent(inspect.getsource(method))
        self.assertEqual(source.count(',env=env'), 1)
        namespace = dict(controls.__dict__)
        exec(compile(source.replace(',env=env', ''), '<synthetic-git-env-fault>', 'exec'), namespace)
        poison = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.autocrlf', 'GIT_CONFIG_VALUE_0': 'false'}
        with patch.dict(os.environ, poison), self.assertRaises(AssertionError):
            namespace[method.__name__](self)

    def test_fixed_asset_hashes_survive_autocrlf_checkout(self):
        root = Path(__file__).resolve().parents[1]
        manifest = cjson.loads((root / 'src/ci_contract/data/SOURCES.json').read_bytes())
        assets = [item for section in manifest.values() if isinstance(section, list)
                  for item in section if isinstance(item, dict) and {'path', 'bytes', 'sha256'} <= set(item)]
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            env = {key: val for key, val in os.environ.items() if not key.upper().startswith('GIT_CONFIG_')}
            def git(*args):
                return subprocess.run(['git', '-C', str(repo), *args], env=env, check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
            git('init'); git('config', 'core.autocrlf', 'true')
            (repo / '.gitattributes').write_bytes((root / '.gitattributes').read_bytes())
            for item in assets:
                path = repo / item['path']; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((root / item['path']).read_bytes())
            git('add', '.')
            for item in assets: (repo / item['path']).unlink()
            git('checkout-index', '-a')
            for item in assets:
                data = (repo / item['path']).read_bytes()
                self.assertEqual(len(data), item['bytes'])
                self.assertEqual(hashlib.sha256(data).hexdigest(), item['sha256'])

    def test_lf_attributes_normalize_crlf_on_add_and_checkout(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            env = {key: val for key, val in os.environ.items() if not key.upper().startswith('GIT_CONFIG_')}
            def git(*args):
                return subprocess.run(['git', '-C', str(repo), *args], env=env, check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
            git('init'); git('config', 'core.autocrlf', 'true')
            (repo / '.gitattributes').write_bytes((root / '.gitattributes').read_bytes())
            path = repo / 'synthetic.json'; path.write_bytes(b'{"synthetic":true}\r\n')
            git('add', '.')
            self.assertEqual(git('show', ':synthetic.json'), b'{"synthetic":true}\n')
            path.unlink(); git('checkout-index', '-a')
            self.assertEqual(path.read_bytes(), b'{"synthetic":true}\n')

    def test_old_no_conversion_attributes_fail_crlf_normalization(self):
        original = Path.read_bytes
        def old_attributes(path):
            if path.name == '.gitattributes': return b'* -text\n'
            return original(path)
        with patch.object(Path, 'read_bytes', old_attributes), self.assertRaises(AssertionError):
            self.test_lf_attributes_normalize_crlf_on_add_and_checkout()


class SetShapeTests(unittest.TestCase):
    def test_duplicate_plan_and_execution_sets_precede_other_mismatches(self):
        for where in ('plan', 'execution', 'embedded-plan'):
            for mismatch in ('binding', 'source', 'pin'):
                with self.subTest(where=where, mismatch=mismatch):
                    p, e, r, l = baseline()
                    if where == 'plan': p['checks'][0]['inputPaths'] *= 2
                    elif where == 'execution': e['capabilities'] *= 2
                    else: e['plan']['checks'][0]['inputPaths'] *= 2
                    if mismatch == 'binding': e['planSha256'] = digest('foreign')
                    elif mismatch == 'source': p['source']['digest'] = digest('foreign')
                    else: p['manifestSha256'] = digest('foreign')
                    self.assertEqual(verdict(verifier.verify, (p, e, r, l)), 3)

    def test_set_shape_guard_removal_is_detected(self):
        mutant = mutate_source('normalize(document, kind)', 'None')
        for index in (1, 2):
            d = baseline()
            if index == 1: d[1]['capabilities'] *= 2
            else: d[1]['plan']['checks'][0]['inputPaths'] *= 2
            d[1]['planSha256'] = digest('foreign')
            self.assertEqual(verdict(verifier.verify, d), 3)
            self.assertEqual(verdict(mutant, d), 4)


class SelectionStrictJsonTests(unittest.TestCase):
    def test_manifest_and_original_loaders_reject_duplicate_keys(self):
        import test_selection as selection_tests
        from ci_contract.errors import InputError
        for method_name in ('test_planning_fixture_is_pinned_and_m1_source_list_is_untouched',
                            'test_fixed_case_extractions_match_original_when_local_input_is_available'):
            method = getattr(selection_tests.SelectionProvenanceTests, method_name)
            source = textwrap.dedent(inspect.getsource(method))
            self.assertEqual(source.count('cjson.loads'), 1)
            namespace = dict(selection_tests.__dict__)
            exec(compile(source.replace('cjson.loads', 'json.loads'), '<synthetic-json-loader-fault>', 'exec'), namespace)
            instance = selection_tests.SelectionProvenanceTests()
            if method_name.startswith('test_planning'):
                path = selection_tests.ROOT / 'src/ci_contract/data/SOURCES.json'
                original = Path.read_text
                body = path.read_bytes()
                duplicate = b'{"files":[],' + body.lstrip()[1:]
                def read(file, *args, **kwargs):
                    return duplicate.decode('utf-8') if file == path else original(file, *args, **kwargs)
                context = patch.object(Path, 'read_text', read)
            else:
                body = cjson.dumps({'fixtureModels': selection_tests.FIXTURE['fixtureModels'],
                                    'cases': selection_tests.FIXTURE['cases']})
                duplicate = b'{"fixtureModels":[],' + body[1:]
                context = patch.object(selection_tests, 'transformed_source', return_value=duplicate)
            with context:
                with self.assertRaises(InputError): method(instance)
                namespace[method_name](instance)


class HelpStatusTests(unittest.TestCase):
    def test_help_guard_removal_is_detected(self):
        # Each parser's independent help guard restores a zero exit when removed.
        import types
        for command in (None, 'canon', 'hash', 'validate', 'explain', 'plan', 'verify'):
            source = inspect.getsource(cli)
            before = ("description='Byte operations and M2 selection explanation', add_help=False)" if command is None
                      else "commands.add_parser('" + command + "', add_help=False)")
            self.assertEqual(source.count(before), 1)
            faulty = types.ModuleType('ci_contract.synthetic_help_route'); faulty.__package__ = 'ci_contract'
            exec(compile(source.replace(before, before.replace(', add_help=False', '')), '<synthetic-help-route>', 'exec'), faulty.__dict__)
            for flag in ('-h', '--help'):
                with self.subTest(command=command, flag=flag), patch.object(sys, 'stdout', io.StringIO()), self.assertRaises(SystemExit) as failure:
                    faulty.main([flag] if command is None else [command, flag])
                self.assertEqual(failure.exception.code, 0)

    def test_help_never_reports_ready_or_accepted(self):
        class Stream(io.StringIO):
            def __init__(self):
                super().__init__(); self.buffer = io.BytesIO()
        for command in (None, 'canon', 'hash', 'validate', 'explain', 'plan', 'verify'):
            for flag in ('-h', '--help'):
                args = [flag] if command is None else [command, flag]
                with self.subTest(args=args):
                    out, err = Stream(), Stream()
                    with patch.object(sys, 'stdout', out), patch.object(sys, 'stderr', err):
                        code = cli.main(args)
                    self.assertEqual(code, 3)
                    self.assertEqual(err.buffer.getvalue(), b'ci-contract: invalid input\n')
                    self.assertEqual(out.buffer.getvalue(), b'invalid-input\n' if command == 'verify' else b'')
                    self.assertEqual(out.getvalue(), '')
                    self.assertEqual(err.getvalue(), '')
        with patch.object(sys, 'stdout', Stream()), patch.object(sys, 'stderr', Stream()):
            self.assertEqual(cli.main(['--help', 'verify', '--plan', 'synthetic']), 3)
