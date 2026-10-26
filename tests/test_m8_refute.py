"""M8 refutation: execute --target local against README's table (synthetic data only).

Each test states the behaviour README (section "M8: execute on this computer") or
the supervisor's own comments promise, and fails on 5206f30 for the reason in its
assertion message. Synthetic repositories (test_m8_refute_support), a synthetic
adapter, temporary folders and a replaced clock only.
"""
import glob
import os
import shutil
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from ci_contract import cjson, claim as claim_module, execute as execute_module
from ci_contract.request_binding import make_request_binding
from synthetic_claim import Clock
from test_m8_refute_support import Base


def read(out, name):
    return cjson.loads((Path(out) / name).read_bytes())


def utc(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


class SharedTreeTests(Base, unittest.TestCase):
    """R1, R2: the checks of one execution share one private tree that they can write."""

    def test_r1_a_check_cannot_make_a_later_check_run_other_adapter_bytes(self):
        order = [c['logicalCheckId'] for c in execute_module._order(self.repo.plan(b'synthetic probe\n')['checks'])]
        first, second = order[0], order[1]
        baseline, _, _ = self.run_plan(self.repo.plan(('fail %s\n' % second).encode()))
        self.assertEqual(baseline, {'status': 'failed', 'exitCode': 2})
        # The first check rewrites tools/adapter.py; the second check runs those bytes, which
        # report a pass without doing the work and then put the pinned bytes back.
        verdict, out, _ = self.run_plan(self.repo.plan(('swap %s\nfail %s\n' % (first, second)).encode()))
        result = read(out, 'result.json')
        pinned = {receipt['proof']['identity']['adapterSha256'] for receipt in result['checks']}
        self.assertNotEqual(verdict['exitCode'], 0,
                            'accepted although %s ran other adapter bytes than its proof names (%d pinned digest)'
                            % (second, len(pinned)))

    def test_r2_a_declared_file_replaced_by_a_directory_or_hardlinked_is_recorded_stale(self):
        for line in (b'dirdecl guard.type docs/readme.md\n', b'hardlink guard.type bin/helper\n'):
            with self.subTest(action=line.split()[0].decode()):
                verdict, out, space = self.run_plan(self.repo.plan(line))
                types = self.types(space)
                observed = (verdict, os.path.exists(os.path.join(out, 'result.json')), 'receipt' in types, types[-1])
                self.assertEqual(observed, ({'status': 'stale', 'exitCode': 5}, True, True, 'claim-closed'),
                                 'README: a declared input changed by a check is stale (5), and every outcome '
                                 'after start_local is written and recorded')

    def test_r2_the_unrecorded_attempt_wedges_its_scope(self):
        plan = self.repo.plan(b'dirdecl guard.type docs/readme.md\n')
        clock = Clock()
        verdict, _, space = self.run_plan(plan, clock=clock)
        # On 5206f30 this was blocked (snapshot-unsupported-entry) with no receipt; now stale and closed.
        self.assertEqual(verdict, {'status': 'stale', 'exitCode': 5})
        self.assertEqual(self.types(space)[-1], 'claim-closed')
        clock.advance(61)
        again, _, _ = self.run_plan(plan, space=space, clock=clock, request_id='synthetic-request-again')
        closing = claim_module.close(space.anchored, 'local-' + execute_module.domain_hash('plan', plan))
        self.assertNotEqual(again.get('reasonCode'), 'scope-claim-orphaned',
                            'the scope can never run again; close() of the first request answers %s'
                            % closing.get('reasonCode'))


class RecordedOutcomeTests(Base, unittest.TestCase):
    """R3: an operating-system error after start_local escapes instead of becoming a recorded outcome."""

    def test_r3_an_os_error_after_the_start_is_a_recorded_unknown(self):
        space = self.space()
        try:
            verdict, _, _ = self.run_plan(self.repo.plan(b'breakhome guard.type\n'), space=space)
        except OSError as error:
            self.fail('execute raised %s after start_local; journal ends with %s'
                      % (type(error).__name__, self.types(space)[-2:]))
        self.assertEqual(verdict['exitCode'], 8)
        self.assertIn('receipt', self.types(space))
        # No process of the failed check was started, so its cleanup is confirmed and the claim closes.
        self.assertEqual(self.types(space)[-1], 'claim-closed')


class LeaseTests(Base, unittest.TestCase):
    """R4: the lease is renewed only while one check runs longer than the heartbeat interval."""

    def run_with_jump(self, other_request):
        plan = self.repo.plan(b'synthetic pass\n')
        space, clock = self.space(), Clock()
        launches, observed = [], []
        original_run, original_launch = execute_module._Supervisor.run, execute_module._launch

        def run(supervisor, index, check):
            outcome = original_run(supervisor, index, check)
            if index == 0:
                clock.advance(61)  # the claim's 60-second lease has ended; no heartbeat happened
                if other_request:
                    binding = make_request_binding(
                        plan, request_id='synthetic-other-request', authority_id=space.anchored.authority_id,
                        target='local', trust='trusted', workflow_commit=None, created_at=utc(clock.now),
                        expires_at=utc(clock.now + timedelta(hours=1)),
                        authority_kind='local-single-supervisor-v1')
                    observed.append(claim_module.acquire(space.anchored, binding, owner_id='synthetic-other',
                                                         clock=clock))
            return outcome

        def launch(*args, **kwargs):
            launches.append(clock.now)
            return original_launch(*args, **kwargs)
        with patch.object(execute_module._Supervisor, 'run', run), patch.object(execute_module, '_launch', launch):
            verdict, _, _ = self.run_plan(plan, space=space, clock=clock)
        return verdict, len(launches), observed, self.types(space)

    def test_r4_no_check_starts_after_the_lease_expired(self):
        verdict, launches, _, types = self.run_with_jump(False)
        self.assertEqual((verdict['exitCode'], launches), (8, 1),
                         'README: a lost claim is unknown (8); got %s after %d launches, records %s'
                         % (verdict['status'], launches, types))

    def test_r4_no_check_starts_after_the_journal_recorded_the_claim_orphaned(self):
        verdict, launches, observed, types = self.run_with_jump(True)
        self.assertEqual(observed[0].get('reasonCode'), 'scope-claim-orphaned')
        self.assertIn('claim-orphaned', types)
        self.assertEqual((verdict['exitCode'], launches), (8, 1),
                         'checks kept starting after claim-orphaned was journaled; got %s after %d launches'
                         % (verdict['status'], launches))


class ReceiptFolderTests(Base, unittest.TestCase):
    """R5, R6: the receipt folder and the private tree."""

    def test_r5_every_listed_artifact_is_a_file_of_artifacts(self):
        verdict, out, _ = self.run_plan(self.repo.plan(b'payload guard.type nul,a,a.\n'))
        ids = sorted(item['id'] for item in read(out, 'result.json')['artifacts'])
        folder = os.path.join(out, 'artifacts')
        files = sorted(os.listdir(folder)) if os.path.isdir(folder) else []
        self.assertEqual(files, ids, 'verdict %s: result lists %s, artifacts/ holds %s'
                         % (verdict['status'], ids, files))

    def test_a_duplicate_artifact_id_is_unknown(self):
        # Added by the integrating session: one artifacts/ file per listed ID, so an ID is unique
        # in the execution. Two checks naming the same ID: the second report is unusable.
        order = [c['logicalCheckId'] for c in execute_module._order(self.repo.plan(b'synthetic probe\n')['checks'])]
        verdict, out, _ = self.run_plan(self.repo.plan(('payload %s a\npayload %s a\n' % (order[0], order[1])).encode()))
        self.assertEqual(verdict, {'status': 'unknown', 'exitCode': 8})
        result = read(out, 'result.json')
        self.assertEqual([item['id'] for item in result['artifacts']], ['a'])
        self.assertEqual(os.listdir(os.path.join(out, 'artifacts')), ['a'])

    def leftovers(self, line):
        pattern = os.path.join(tempfile.gettempdir(), 'ci-contract-execute-*')
        before = set(glob.glob(pattern))
        verdict, _, _ = self.run_plan(self.repo.plan(line))
        left = sorted(set(glob.glob(pattern)) - before)
        for path in left:
            self.addCleanup(shutil.rmtree, '\\\\?\\' + path, onexc=lambda f, p, e: (os.chmod(p, 0o666), f(p)))
        return verdict, left

    @unittest.skipUnless(os.name == 'nt', 'Windows file names')
    def test_r6_the_private_tree_is_removed_at_the_end(self):
        for line in (b'readonly guard.type\n', b'oddname guard.type\n'):
            with self.subTest(action=line.split()[0].decode()):
                verdict, left = self.leftovers(line)
                self.assertEqual(left, [], 'verdict %s; private folder left in the temporary directory'
                                 % verdict['status'])


class CommandLineTests(Base, unittest.TestCase):
    """R7: README says execute prints the final status on stdout and status and reason on stderr."""

    def cli(self, plan_bytes):
        import subprocess
        import sys
        from test_m8_refute_support import host
        with tempfile.TemporaryDirectory(prefix='ci-contract-refute-cli-') as folder:
            plan, host_path = os.path.join(folder, 'plan.json'), os.path.join(folder, 'host.json')
            with open(plan, 'wb') as handle:
                handle.write(plan_bytes)
            with open(host_path, 'wb') as handle:
                handle.write(cjson.dumps(host()))
            os.mkdir(os.path.join(folder, 'j'))
            os.mkdir(os.path.join(folder, 'a'))
            # The child imports the same engine as this test (a mutated copy too).
            env = {**os.environ, 'PYTHONPATH': str(Path(execute_module.__file__).resolve().parents[1])}
            command = [sys.executable, '-m', 'ci_contract', 'execute', '--plan', plan, '--target', 'github',
                       '--out', os.path.join(folder, 'out'), '--repo-path', str(self.repo.git.path),
                       '--host', host_path, '--journal', os.path.join(folder, 'j', 'journal.jsonl'),
                       '--anchor', os.path.join(folder, 'a', 'journal.anchor'), '--authority-id',
                       'synthetic-authority', '--new-journal']
            done = subprocess.run(command, env=env, capture_output=True, check=False, timeout=60)
        return done.returncode, done.stdout, done.stderr

    def test_r7_target_github_prints_its_status_and_reason(self):
        self.assertEqual(self.cli(cjson.dumps(self.repo.plan(b'synthetic pass\n'))),
                         (4, b'blocked\n', b'ci-contract: blocked: execute-target-unsupported\n'))

    def test_r7_shapes_precede_target_github(self):
        # README step 1: shapes (3) first, then --target github (4).
        self.assertEqual(self.cli(b'{"kind":')[0], 3)
        # JSON that is not a valid plan (added by the integrating session).
        self.assertEqual(self.cli(b'{"kind":"plan"}'), (3, b'invalid-input\n', b'ci-contract: invalid-input\n'))


if __name__ == '__main__':
    unittest.main()
