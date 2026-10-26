"""M8 refutation, controls that held on 5206f30 (synthetic data only).

These are the double-start and report cases the refutation tried and did not
break: they pass on 5206f30 and are kept as differential controls.
"""
import threading
import unittest
from unittest.mock import patch
from ci_contract import execute as execute_module
from synthetic_claim import Clock
from test_m8_refute_support import Base


class DoubleStartControls(Base, unittest.TestCase):

    def concurrent(self, request_ids):
        plan = self.repo.plan(b'pause * 1\n')
        space = self.space()
        outs = [self.repo.out() for _ in request_ids]
        launches, verdicts, lock = [], [None] * len(request_ids), threading.Lock()
        original = execute_module._launch

        def launch(*args, **kwargs):
            with lock:
                launches.append(1)
            return original(*args, **kwargs)

        # One journal object per caller, as two processes would open the same files.
        journals = [space.journal(create=False, anchor_path=space.anchored.anchor_path) for _ in request_ids]

        def worker(index):
            verdicts[index] = self.run_plan(plan, space=space, out=outs[index], journal=journals[index],
                                            request_id=request_ids[index])[0]
        with patch.object(execute_module, '_launch', launch):
            threads = [threading.Thread(target=worker, args=(index,)) for index in range(len(request_ids))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(170)
            self.assertFalse(any(thread.is_alive() for thread in threads), 'hang')
        return plan, verdicts, len(launches), self.types(space)

    def test_two_executes_of_one_scope_at_once_start_one_attempt(self):
        plan, verdicts, launches, types = self.concurrent(['synthetic-request-a', 'synthetic-request-b'])
        self.assertEqual(sorted((v['status'], v.get('reasonCode')) for v in verdicts),
                         [('accepted', None), ('blocked', 'request-coalesced')])
        self.assertEqual(launches, len(plan['checks']))
        self.assertEqual(types.count('adoption'), 1)

    def test_two_executes_of_one_request_at_once_start_one_attempt(self):
        plan, verdicts, launches, types = self.concurrent(['synthetic-request-same', 'synthetic-request-same'])
        self.assertEqual(sorted((v['status'], v.get('reasonCode')) for v in verdicts),
                         [('accepted', None), ('blocked', 'request-id-exists')])
        self.assertEqual(launches, len(plan['checks']))

    def test_a_crash_between_start_and_receipt_is_never_started_again(self):
        plan = self.repo.plan(b'synthetic pass\n')
        space, clock = self.space(), Clock()

        def crash(*_):
            raise KeyboardInterrupt  # the supervisor stops between start_local and any receipt
        with patch.object(execute_module._Supervisor, 'run', crash):
            with self.assertRaises(KeyboardInterrupt):
                self.run_plan(plan, space=space, clock=clock)
        self.assertEqual(self.types(space)[-1], 'adoption')
        with patch('ci_contract.execute._launch') as launch:
            same, _, _ = self.run_plan(plan, space=space, clock=clock)
            other, _, _ = self.run_plan(plan, space=space, clock=clock, request_id='synthetic-request-new')
            clock.advance(61)
            later, _, _ = self.run_plan(plan, space=space, clock=clock, request_id='synthetic-request-later')
        launch.assert_not_called()
        self.assertEqual([v.get('reasonCode') for v in (same, other, later)],
                         ['request-id-exists', 'request-coalesced', 'scope-claim-orphaned'])


class ReportControls(Base, unittest.TestCase):

    def test_a_hardlinked_report_is_unknown(self):
        verdict, _, _ = self.run_plan(self.repo.plan(b'linkreport guard.type\n'))
        self.assertEqual(verdict, {'status': 'unknown', 'exitCode': 8})

    def test_the_baseline_adapter_is_accepted(self):
        verdict, _, space = self.run_plan(self.repo.plan(b'synthetic pass\n'))
        self.assertEqual(verdict, {'status': 'accepted', 'exitCode': 0})
        self.assertEqual(self.types(space)[-1], 'claim-closed')


if __name__ == '__main__':
    unittest.main()
