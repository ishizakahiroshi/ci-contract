"""M8 C3-C5: execute --target local on synthetic repositories with a synthetic adapter.

Every check process is the synthetic adapter (tests/synthetic_execute.py) in a
private copy of a synthetic repository. Journals and anchors are in per-test
temporary folders; the clock is replaced. No real repository, network or secret.
"""
import copy
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from ci_contract import cjson
from ci_contract.execute import execute, host_platform
from ci_contract.plan import build_plan
from ci_contract.verify import verify
from synthetic_claim import Clock, Workspace
from synthetic_execute import (ADAPTER_PATH, execute_history, execute_manifest, host, quality_projection, sha256,
                               target_files, write_tree)

IDENTITY = host_platform()
FOREIGN = 'linux' if IDENTITY[0] != 'linux' else 'windows'


def blocked(reason):
    return {'status': 'blocked', 'exitCode': 4, 'reasonCode': reason}


def read(out, name):
    return cjson.loads((Path(out) / name).read_bytes())


class Repository:
    """One synthetic repository and helpers to plan and execute against it."""

    def __init__(self, root, name, manifest, projection=None):
        self.root, self.name = root, name
        self.git, self.base, self.files = execute_history(root / (name + '.git'), manifest, projection=projection)
        self.count = 0

    def commit(self, text):
        return self.git.commit(target_files(self.files, text), parents=(self.base,), message='synthetic target')

    def plan(self, text=b'synthetic pass\n'):
        return build_plan(self.git.path, 'synthetic', self.base, self.commit(text))

    def snapshot(self, text=b'synthetic pass\n'):
        self.count += 1
        directory = self.root / ('%s-snapshot-%d' % (self.name, self.count))
        write_tree(directory, target_files(self.files, text))
        return directory

    def out(self):
        self.count += 1
        return str(self.root / ('%s-out-%d' % (self.name, self.count)))


class ExecuteCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-execute-test-')
        cls.root = Path(cls.temp.name)
        cls.repo = Repository(cls.root, 'host', execute_manifest(*IDENTITY))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def space(self):
        """A workspace with a new anchored journal (``space.anchored``)."""
        space = Workspace()
        self.addCleanup(space.__exit__)
        (space.root / 'anchor').mkdir()
        space.anchored = space.journal(anchor_path=str(space.root / 'anchor' / 'journal.anchor'))
        return space

    def execute(self, plan, space=None, repo=None, **options):
        repo = self.repo if repo is None else repo
        space = self.space() if space is None else space
        options.setdefault('host', host())
        options.setdefault('clock', Clock())
        options.setdefault('target', 'local')
        out = options.pop('out', None) or repo.out()
        journal = options.pop('journal', None) or space.anchored
        verdict = execute(plan, out=out, repo_path=str(repo.git.path), journal=journal, **options)
        return verdict, out, space


class PrecheckTests(ExecuteCase):
    """C3: refusals before any Git read or process; no journal record, no receipt folder."""

    def refused(self, plan, reason, **options):
        space = self.space()
        before = space.bytes()
        with patch('subprocess.Popen') as popen, patch('subprocess.run') as run:
            verdict, out, _ = self.execute(plan, space=space, **options)
        popen.assert_not_called()
        run.assert_not_called()
        self.assertEqual(verdict, blocked(reason))
        self.assertFalse(os.path.exists(out))
        self.assertEqual(space.bytes(), before)

    def test_r42_operations_is_blocked_contract_and_reads_nothing(self):
        plan = self.repo.plan()
        plan['profile'] = 'operations'
        self.refused(plan, 'blocked-contract')

    def test_c09_a_check_this_host_cannot_run_blocks_the_whole_plan(self):
        repo = Repository(self.root, 'foreign', execute_manifest(*IDENTITY, foreign=FOREIGN))
        plan = repo.plan()
        tests = [check for check in plan['checks'] if check['logicalCheckId'] == 'app.test']
        self.assertEqual({check['variant']['os'] for check in tests}, {IDENTITY[0], FOREIGN})
        # The foreign variant is neither dropped nor replaced: nothing runs.
        self.assertEqual(len(plan['selectionEvidence']['selectedInstanceIds']), len(plan['checks']))
        self.refused(plan, 'capability-unavailable', repo=repo)

    def test_a_missing_capability_blocks_until_the_host_declares_it(self):
        needed = [{'id': 'synthetic-sdk', 'value': '1'}]
        repo = Repository(self.root, 'capability', execute_manifest(*IDENTITY, capabilities={'guard.type': needed}))
        plan = repo.plan()
        self.refused(plan, 'capability-unavailable', repo=repo)
        self.refused(plan, 'capability-unavailable', repo=repo,
                     host=host(capabilities=[{'id': 'synthetic-sdk', 'value': '2'}]))
        verdict, out, _ = self.execute(plan, repo=repo, host=host(capabilities=needed))
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        self.assertIn({'id': 'synthetic-sdk', 'value': '1'}, read(out, 'execution.json')['capabilities'])

    def test_network_github_target_adapter_and_dataset_refusals(self):
        repo = Repository(self.root, 'network', execute_manifest(*IDENTITY, network='synthetic-service'))
        self.refused(repo.plan(), 'network-unavailable', repo=repo)
        plan = self.repo.plan()
        self.refused(plan, 'execute-target-unsupported', target='github')
        self.refused(plan, 'adapter-unregistered', host=host(adapters=[]))
        self.refused(plan, 'dataset-unregistered', host=host(datasets=[]))
        self.refused(plan, 'capability-unavailable', platform_identity=(FOREIGN, IDENTITY[1]))

    def test_invalid_inputs_are_three(self):
        plan = self.repo.plan()
        for options in ({'host': {'kind': 'other'}}, {'target': 'elsewhere'}, {'request_id': 'Not-An-Id'},
                        {'host': host(capabilities=[{'id': 'os', 'value': 'windows'}])}):
            with self.subTest(options=sorted(options)):
                verdict, out, _ = self.execute(plan, **options)
                self.assertEqual(verdict, {'status': 'invalid-input', 'exitCode': 3})
                self.assertFalse(os.path.exists(out))
        with Workspace() as space:
            unanchored = space.journal()
            verdict, _, _ = self.execute(plan, space=self.space(), journal=unanchored)
        self.assertEqual(verdict['exitCode'], 3)


class TrustedTreeTests(ExecuteCase):
    """C3: the plan file and the private copy must match the repository before any check runs."""

    def not_started(self, plan, expected, **options):
        space = self.space()
        before = space.bytes()
        with patch('ci_contract.execute._launch') as launch:
            verdict, out, _ = self.execute(plan, space=space, **options)
        launch.assert_not_called()
        self.assertEqual(verdict, expected)
        self.assertFalse(os.path.exists(out))
        self.assertEqual(space.bytes(), before)

    def test_a_plan_the_planner_did_not_produce_is_blocked(self):
        plan = self.repo.plan()
        changed = copy.deepcopy(plan)
        changed['checks'][0]['argv'] = changed['checks'][0]['argv'] + ['--synthetic-extra']
        self.not_started(changed, blocked('plan-reconstruction-mismatch'))
        fewer = copy.deepcopy(plan)
        removed = fewer['checks'].pop()
        fewer['selectionEvidence']['selectedInstanceIds'].remove(removed['id'])
        self.not_started(fewer, blocked('plan-reconstruction-mismatch'))

    def test_an_adapter_or_dataset_with_other_bytes_is_blocked(self):
        plan = self.repo.plan()
        other = host(adapters=[{'id': 'synthetic-local-adapter', 'runner': 'python', 'entry': 'bin/helper'}])
        self.not_started(plan, blocked('adapter-digest-mismatch'), host=other)
        absent = host(adapters=[{'id': 'synthetic-local-adapter', 'runner': 'python', 'entry': 'tools/absent.py'}])
        self.not_started(plan, blocked('adapter-entry-unavailable'), host=absent)
        dataset = host(datasets=[{'id': 'synthetic-dataset', 'path': 'docs/readme.md'}])
        self.not_started(plan, blocked('dataset-mismatch'), host=dataset)

    def test_an_existing_receipt_folder_is_invalid_input(self):
        out = self.repo.out()
        os.mkdir(out)
        space = self.space()
        before = space.bytes()
        verdict, _, _ = self.execute(self.repo.plan(), space=space, out=out)
        self.assertEqual(verdict['exitCode'], 3)
        self.assertEqual(os.listdir(out), [])
        self.assertEqual(space.bytes(), before)


class RunTests(ExecuteCase):
    """C4/C5: checks run, are observed, verified, recorded and closed."""

    def test_an_accepted_run_is_verified_recorded_and_closed(self):
        plan = self.repo.plan()
        verdict, out, space = self.execute(plan)
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        self.assertEqual(sorted(os.listdir(out)),
                         ['events.json', 'execution.json', 'ledger.json', 'logs', 'plan.json', 'result.json'])
        execution, result, ledger = (read(out, name) for name in ('execution.json', 'result.json', 'ledger.json'))
        self.assertEqual(read(out, 'plan.json'), plan)
        self.assertEqual((result['status'], result['exitCode'], result['evidenceOrigin']),
                         ('accepted', 0, 'local-receipt'))
        self.assertEqual((execution['target'], execution['github']), ('local', None))
        authority = execution['requestBinding']['attemptAuthority']
        self.assertEqual((authority['adoptedRunId'], authority['adoptedProviderAttempt']), (None, None))
        self.assertEqual(verify(plan, execution, result, synthetic_collector_ledger=ledger),
                         {'status': 'accepted', 'exitCode': 0})
        for receipt in result['checks']:
            proof = receipt['proof']
            self.assertEqual(proof['invocation']['adapterEntry'], ADAPTER_PATH)
            self.assertEqual((proof['runtime']['os'], proof['runtime']['arch']), IDENTITY)
            self.assertEqual((proof['collector']['runId'], proof['collector']['jobId']), (None, None))
        types = [r['recordType'] for r in space.records()]
        self.assertEqual([t for t in types if t != 'claim-heartbeat'],
                         ['request', 'claim-acquired', 'submit-unknown', 'adoption', 'receipt', 'claim-closed'])
        # The lease is renewed before each check and once more before the receipt.
        self.assertEqual(types.count('claim-heartbeat'), len(plan['checks']) + 1)
        self.assertEqual(types[types.index('adoption') + 1:types.index('receipt')],
                         ['claim-heartbeat'] * (len(plan['checks']) + 1))
        # Without the local ledger the documents alone are not accepted.
        self.assertEqual(verify(plan, execution, result)['exitCode'], 4)

    def test_the_same_request_stops_at_the_claim_and_a_new_request_runs(self):
        plan = self.repo.plan()
        space = self.space()
        journal = space.anchored
        first, _, _ = self.execute(plan, space=space, journal=journal)
        self.assertEqual(first['exitCode'], 0)
        before = space.bytes()
        with patch('ci_contract.execute._launch') as launch:
            again, out, _ = self.execute(plan, space=space, journal=journal)
        launch.assert_not_called()
        self.assertEqual(again, blocked('request-id-exists'))
        self.assertFalse(os.path.exists(out))
        self.assertEqual(space.bytes(), before)
        fresh, _, _ = self.execute(plan, space=space, journal=journal, request_id='synthetic-request-second')
        self.assertEqual(fresh, {'status': 'accepted', 'exitCode': 0})

    def run_text(self, text, repo=None, **options):
        repo = self.repo if repo is None else repo
        return self.execute(repo.plan(text), repo=repo, **options)

    def test_a_failing_check_is_failed_and_every_check_ran(self):
        verdict, out, space = self.run_text(b'fail app.test\n')
        self.assertEqual(verdict, {'status': 'failed', 'exitCode': 2})
        result = read(out, 'result.json')
        self.assertEqual(result['missingCheckIds'], [])
        self.assertEqual(sorted(c['status'] for c in result['checks']), ['failed', 'passed', 'passed', 'passed'])
        self.assertEqual(space.records()[-1]['recordType'], 'claim-closed')

    def test_a_check_over_its_time_limit_is_stopped_and_timeout(self):
        repo = Repository(self.root, 'slow', execute_manifest(*IDENTITY, timeout=1))
        began = time.monotonic()
        verdict, out, space = self.run_text(b'sleep app.test\n', repo=repo)
        self.assertLess(time.monotonic() - began, 30)
        self.assertEqual(verdict, {'status': 'timeout', 'exitCode': 7})
        result, ledger = read(out, 'result.json'), read(out, 'ledger.json')
        self.assertEqual(ledger['terminalObservation'], 'check-timeout')
        self.assertTrue(result['cleanupConfirmed'])
        app = next(c['id'] for c in read(out, 'plan.json')['checks'] if c['logicalCheckId'] == 'app.test')
        self.assertIn(app, result['missingCheckIds'])
        self.assertEqual(space.records()[-1]['recordType'], 'claim-closed')

    def test_an_unusable_report_is_unknown(self):
        for action in ('noreport', 'malformed', 'shape'):
            with self.subTest(action=action):
                verdict, out, space = self.run_text((action + ' app.test\n').encode())
                self.assertEqual(verdict, {'status': 'unknown', 'exitCode': 8})
                ledger = read(out, 'ledger.json')
                self.assertIsNone(ledger['terminalObservation'])
                self.assertEqual(read(out, 'result.json')['status'], 'unknown')
                self.assertEqual(space.records()[-1]['recordType'], 'claim-closed')

    def test_a_check_cannot_answer_for_a_later_check(self):
        order = [c['logicalCheckId'] for c in self.repo.plan()['checks']]
        first, last = order[0], order[-1]
        self.assertNotEqual(first, last)
        verdict, out, _ = self.run_text(('forge %s\nnoreport %s\n' % (first, last)).encode())
        self.assertEqual(verdict, {'status': 'unknown', 'exitCode': 8})
        missing = read(out, 'result.json')['missingCheckIds']
        self.assertEqual(len(missing), 1)

    def test_a_test_that_executes_nothing_is_not_accepted(self):
        verdict, out, _ = self.run_text(b'skip app.test\n')
        self.assertEqual(verdict, {'status': 'blocked', 'exitCode': 4})
        statuses = {c['proof']['identity']['logicalCheckId']: c['status'] for c in read(out, 'result.json')['checks']}
        self.assertEqual(statuses['app.test'], 'skipped')

    def test_the_result_states_the_verifiers_decision_not_the_adapters_claim(self):
        # Every check exits 0, but one collection is incomplete: the verifier refuses it.
        verdict, out, space = self.run_text(b'incomplete guard.type\n')
        self.assertEqual(verdict, {'status': 'blocked', 'exitCode': 4})
        result = read(out, 'result.json')
        self.assertEqual({c['status'] for c in result['checks']}, {'passed'})
        self.assertEqual((result['status'], result['exitCode']), ('blocked', 4))
        receipt = next(r for r in space.records() if r['recordType'] == 'receipt')
        self.assertEqual(receipt['payloadProjection']['status'], 'blocked')

    def test_the_child_sees_only_the_minimal_environment_and_the_private_tree(self):
        canary = {'GIT_DIR': str(self.repo.git.path), 'GIT_WORK_TREE': str(self.root),
                  'CI_CONTRACT_SYNTHETIC_CANARY': 'synthetic'}
        with patch.dict(os.environ, canary):
            verdict, out, _ = self.run_text(b'envcheck *\n')
        # The adapter prints the names it did not expect (console logs are kept in the receipt folder).
        seen = [line for path in sorted((Path(out) / 'logs').glob('*.log'))
                for line in path.read_text(encoding='utf-8').splitlines() if line.startswith('unexpected-environment')]
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0}, seen)

    def test_a_descendant_left_running_is_stopped(self):
        marker = self.root / 'descendant-survived'
        verdict, out, _ = self.run_text(('linger app.test ' + str(marker) + '\n').encode())
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        self.assertTrue(all(c['cleanupConfirmed'] for c in read(out, 'result.json')['checks']))
        time.sleep(4)
        self.assertFalse(marker.exists())

    def test_a_check_that_rewrites_a_declared_input_is_stale(self):
        verdict, out, _ = self.run_text(b'mutate guard.static\n')
        self.assertEqual(verdict, {'status': 'stale', 'exitCode': 5})
        result = read(out, 'result.json')
        self.assertNotEqual(result['sourceDigestAfter'], result['sourceDigestBefore'])

    def test_a_lease_lost_after_the_last_check_is_unknown(self):
        import ci_contract.execute as module
        plan = self.repo.plan()
        clock = Clock()
        original = module._Supervisor.run

        def run(supervisor, index, check):
            outcome = original(supervisor, index, check)
            if index == len(plan['checks']) - 1:
                clock.advance(61)  # the lease ends after the last check, before the receipt
            return outcome
        with patch.object(module._Supervisor, 'run', run):
            verdict, out, space = self.execute(plan, clock=clock)
        self.assertEqual(verdict, {'status': 'unknown', 'exitCode': 8})
        self.assertIsNone(read(out, 'ledger.json')['terminalObservation'])
        self.assertIn('claim-orphaned', [r['recordType'] for r in space.records()])

    def test_the_order_does_not_depend_on_the_order_in_the_plan_file(self):
        plan = self.repo.plan()
        _, out, _ = self.execute(plan)
        reversed_plan = copy.deepcopy(plan)
        reversed_plan['checks'].reverse()
        verdict, again, _ = self.execute(reversed_plan)
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        self.assertEqual(sorted(os.listdir(Path(out) / 'logs')), sorted(os.listdir(Path(again) / 'logs')))

    def test_the_lease_is_renewed_while_a_check_runs(self):
        verdict, _, space = self.run_text(b'pause app.test 1.5\n', heartbeat_seconds=0.3)
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        self.assertIn('claim-heartbeat', [r['recordType'] for r in space.records()])


class GenerationAndCoalescingTests(ExecuteCase):
    """A generation check's payload, and a request of a scope whose claim is already active."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.generating = Repository(cls.root, 'generate', execute_manifest(*IDENTITY, generation=True),
                                    projection=quality_projection(generation=True))

    def test_a_generated_payload_is_measured_kept_and_bound_to_its_dependent(self):
        plan = self.generating.plan()
        ids = {check['logicalCheckId']: check['id'] for check in plan['checks']}
        self.assertEqual(plan['checks'][[c['id'] for c in plan['checks']].index(ids['app.test'])]['dependsOn'],
                         [ids['app.generate']])
        verdict, out, _ = self.execute(plan, repo=self.generating)
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        result = read(out, 'result.json')
        payload = b'synthetic payload\n'
        self.assertEqual([(a['id'], a['sha256'], a['sizeBytes'], a['producerCheckId'], a['privacy'])
                          for a in result['artifacts']],
                         [('synthetic-payload', sha256(payload), len(payload), ids['app.generate'], 'private')])
        self.assertEqual((Path(out) / 'artifacts' / 'synthetic-payload').read_bytes(), payload)
        proofs = {receipt['id']: receipt['proof'] for receipt in result['checks']}
        self.assertEqual(proofs[ids['app.test']]['identity']['generatedInputDigests'], [sha256(payload)])
        self.assertEqual(proofs[ids['app.generate']]['payloads'][0]['inputDigests'], [plan['source']['digest']])

    def test_a_payload_the_check_did_not_write_is_unknown(self):
        verdict, out, _ = self.execute(self.generating.plan(b'nopayload app.generate\n'), repo=self.generating)
        self.assertEqual(verdict, {'status': 'unknown', 'exitCode': 8})
        self.assertFalse((Path(out) / 'artifacts').exists())

    def test_a_payload_over_the_size_limit_is_unknown(self):
        import ci_contract.execute as module
        with patch.object(module, 'MAX_PAYLOAD_BYTES', len(b'synthetic payload\n') - 1):
            verdict, out, _ = self.execute(self.generating.plan(), repo=self.generating)
        self.assertEqual(verdict, {'status': 'unknown', 'exitCode': 8})
        self.assertFalse((Path(out) / 'artifacts').exists())

    def test_a_request_of_a_scope_already_running_is_coalesced_and_not_started(self):
        from ci_contract import claim
        from ci_contract.request_binding import make_request_binding
        plan = self.repo.plan()
        space, clock = self.space(), Clock()
        running = make_request_binding(plan, request_id='synthetic-request-running',
                                       authority_id=space.anchored.authority_id, target='local', trust='trusted',
                                       workflow_commit=None, created_at='2026-01-01T00:00:00Z',
                                       expires_at='2026-01-02T00:00:00Z', authority_kind='local-single-supervisor-v1')
        self.assertEqual(claim.acquire(space.anchored, running, owner_id='synthetic-other', clock=clock)['status'],
                         'acquired')
        with patch('ci_contract.execute._launch') as launch:
            verdict, out, _ = self.execute(plan, space=space, clock=clock)
        launch.assert_not_called()
        self.assertEqual(verdict, blocked('request-coalesced'))
        self.assertFalse(os.path.exists(out))
        types = [record['recordType'] for record in space.records()]
        self.assertEqual(types[-2:], ['request', 'claim-coalesced'])
        self.assertNotIn('submit-unknown', types)


class SnapshotTests(ExecuteCase):
    """c10 and c12 through execute."""

    def test_c10_a_snapshot_is_accepted_with_the_same_digest_and_no_commit(self):
        text = b'synthetic pass\n'
        directory = self.repo.snapshot(text)
        plan = build_plan(self.repo.git.path, 'synthetic', self.repo.base, None, snapshot_dir=str(directory))
        verdict, out, _ = self.execute(plan, snapshot_dir=str(directory))
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        source = read(out, 'execution.json')['plan']['source']
        self.assertEqual((source['mode'], source['targetCommit'], source['tree']), ('snapshot', None, None))
        self.assertEqual(source['digest'], self.repo.plan(text)['source']['digest'])
        self.assertEqual(read(out, 'result.json')['sourceDigestAfter'], source['digest'])

    def test_c12_a_changed_input_is_stale_and_an_undeclared_input_is_not_visible(self):
        directory = self.repo.snapshot(b'undeclared *\n')
        plan = build_plan(self.repo.git.path, 'synthetic', self.repo.base, None, snapshot_dir=str(directory))
        # An undeclared file beside the declared inputs is never copied into the check's tree.
        (directory / 'private-user-config').write_bytes(b'synthetic private\n')
        verdict, _, _ = self.execute(plan, snapshot_dir=str(directory))
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        # A declared input changed after planning is stale before any check starts.
        (directory / 'src' / 'main.txt').write_bytes(b'synthetic changed after planning\n')
        space = self.space()
        before = space.bytes()
        with patch('ci_contract.execute._launch') as launch:
            verdict, out, _ = self.execute(plan, space=space, snapshot_dir=str(directory))
        launch.assert_not_called()
        self.assertEqual(verdict, {'status': 'stale', 'exitCode': 5, 'reasonCode': 'source-changed'})
        self.assertFalse(os.path.exists(out))
        self.assertEqual(space.bytes(), before)

    def test_c12_an_included_input_removed_after_planning_is_stale(self):
        directory = self.repo.snapshot()
        (directory / 'src' / 'extra.txt').write_bytes(b'synthetic included\n')
        plan = build_plan(self.repo.git.path, 'synthetic', self.repo.base, None, snapshot_dir=str(directory),
                          include=['src/extra.txt'])
        self.assertIn('src/extra.txt', {entry['path'] for entry in plan['source']['inputs']})
        (directory / 'src' / 'extra.txt').unlink()
        with patch('ci_contract.execute._launch') as launch:
            verdict, out, _ = self.execute(plan, snapshot_dir=str(directory))
        launch.assert_not_called()
        self.assertEqual(verdict, {'status': 'stale', 'exitCode': 5, 'reasonCode': 'source-changed'})
        self.assertFalse(os.path.exists(out))

    def test_a_snapshot_plan_needs_its_directory_and_a_commit_plan_refuses_one(self):
        directory = self.repo.snapshot()
        plan = build_plan(self.repo.git.path, 'synthetic', self.repo.base, None, snapshot_dir=str(directory))
        self.assertEqual(self.execute(plan)[0]['exitCode'], 3)
        self.assertEqual(self.execute(self.repo.plan(), snapshot_dir=str(directory))[0]['exitCode'], 3)


class LocalLedgerTests(ExecuteCase):
    """C5: verify accepts the local supervisor ledger only for the local execution it observed."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        out = cls.repo.out()
        with Workspace() as space:
            (space.root / 'anchor').mkdir()
            journal = space.journal(anchor_path=str(space.root / 'anchor' / 'journal.anchor'))
            verdict = execute(cls.repo.plan(), target='local', out=out, repo_path=str(cls.repo.git.path),
                              host=host(), journal=journal, clock=Clock())
        assert verdict['exitCode'] == 0
        cls.documents = tuple(read(out, name) for name in ('plan.json', 'execution.json', 'result.json',
                                                           'ledger.json'))

    def verdict(self, change=None):
        plan, execution, result, ledger = copy.deepcopy(self.documents)
        if change is not None:
            change(plan, execution, result, ledger)
        return verify(plan, execution, result, synthetic_collector_ledger=ledger)

    def test_a_local_ledger_never_accepts_a_github_execution(self):
        self.assertEqual(self.verdict(), {'status': 'accepted', 'exitCode': 0})
        from synthetic_verify import documents
        plan, execution, result, ledger = documents()
        local = dict(copy.deepcopy(ledger), kind='local-supervisor-ledger-v1', collectorId='local-supervisor')
        local.pop('githubObservation', None)
        for proof in local['proofs'] + [receipt['proof'] for receipt in result['checks']]:
            proof['collector']['collectorId'] = 'local-supervisor'
        from synthetic_verify import record_observation
        record_observation(result, local)
        self.assertEqual(verify(plan, execution, result, synthetic_collector_ledger=local)['exitCode'], 4)
        # The same documents with the synthetic collector are still accepted (unchanged M5 behaviour).
        plan, execution, result, ledger = documents()
        self.assertEqual(verify(plan, execution, result, synthetic_collector_ledger=ledger)['exitCode'], 0)

    def test_local_ledger_shapes(self):
        def kind(prefix):
            def change(plan, execution, result, ledger):
                ledger['collectorId'] = prefix + 'supervisor'
            return change

        def github(plan, execution, result, ledger):
            ledger['githubObservation'] = {'workflowCommit': 'f' * 40, 'targetCommit': 'd' * 40}
        self.assertEqual(self.verdict(kind('synthetic-'))['exitCode'], 3)
        self.assertEqual(self.verdict(github)['exitCode'], 3)
        from synthetic_verify import documents
        plan, execution, result, ledger = documents()
        ledger['terminalObservation'] = 'check-timeout'
        self.assertEqual(verify(plan, execution, result, synthetic_collector_ledger=ledger)['exitCode'], 3)

    def test_a_check_timeout_is_seven_only_with_confirmed_cleanup(self):
        def timeout(plan, execution, result, ledger):
            ledger['terminalObservation'] = 'check-timeout'

        def unconfirmed(plan, execution, result, ledger):
            ledger.update(terminalObservation='check-timeout', cleanupConfirmed=False, pendingChildren=1)
        self.assertEqual(self.verdict(timeout), {'status': 'timeout', 'exitCode': 7})
        self.assertEqual(self.verdict(unconfirmed), {'status': 'unknown', 'exitCode': 8})


class ExecuteCoverageTests(unittest.TestCase):
    """The executeCore rows name existing tests and the original cases' expected status and code."""
    SOURCE_SHA256 = '98c356bf50e6f872f5d61aa47341fb6009d592bc7650b5b2640c8404bea30f37'

    def rows(self):
        coverage = cjson.loads(Path(__file__).with_name('acceptance-coverage.json').read_bytes())
        return coverage['executeCore']['cases']

    def test_each_row_names_a_test_of_this_module(self):
        for row in self.rows():
            module, cls, method = row['test'].split('.')
            self.assertEqual(module, __name__.split('.')[-1] if __name__ != '__main__' else 'test_m8_execute')
            self.assertTrue(callable(getattr(globals()[cls], method)))

    def test_expected_values_are_the_original_cases(self):
        from publication_source import transformed_source
        original = cjson.loads(transformed_source(self, 'acceptance-cases.json', self.SOURCE_SHA256))
        cases = {case['id']: case for case in original['cases']}
        for row in self.rows():
            with self.subTest(case=row['id']):
                expected = cases[row['id']]['expected']
                self.assertEqual((row['expectedStatus'], row['expectedExitCode']),
                                 (expected['status'], expected['exitCode']))
        self.assertEqual(cases['r42']['expected']['observations'][0]['reason'], 'blocked-contract')


class CommandLineTests(ExecuteCase):
    def test_the_cli_runs_once_and_refuses_the_same_request_again(self):
        plan = self.repo.plan()
        folder = self.root / 'cli'
        folder.mkdir()
        (folder / 'anchor').mkdir()
        (folder / 'authority').mkdir()
        plan_path, host_path = folder / 'plan.json', folder / 'host.json'
        plan_path.write_bytes(cjson.dumps(plan))
        host_path.write_bytes(cjson.dumps(host()))
        import ci_contract
        # The child imports the same engine as this test (a mutated copy too).
        env = {**os.environ, 'PYTHONPATH': str(Path(ci_contract.__file__).resolve().parents[1])}
        common = [sys.executable, '-m', 'ci_contract', 'execute', '--plan', str(plan_path), '--target', 'local',
                  '--repo-path', str(self.repo.git.path), '--host', str(host_path),
                  '--journal', str(folder / 'authority' / 'journal.jsonl'),
                  '--anchor', str(folder / 'anchor' / 'journal.anchor'), '--authority-id', 'synthetic-authority']

        def run(*extra):
            return subprocess.run(common + list(extra), env=env, capture_output=True, check=False, timeout=300)
        first = run('--out', str(folder / 'out-1'), '--new-journal')
        self.assertEqual((first.returncode, first.stdout, first.stderr), (0, b'accepted\n', b''))
        again = run('--out', str(folder / 'out-2'))
        self.assertEqual((again.returncode, again.stdout, again.stderr),
                         (4, b'blocked\n', b'ci-contract: blocked: request-id-exists\n'))
        self.assertFalse((folder / 'out-2').exists())
        github = run('--out', str(folder / 'out-3'), '--target', 'github')
        self.assertEqual(github.returncode, 4)
        recreated = run('--out', str(folder / 'out-4'), '--new-journal')
        self.assertEqual(recreated.returncode, 4)  # the journal exists; it is never recreated


if __name__ == '__main__':
    unittest.main()
