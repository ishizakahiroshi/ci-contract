"""r17 with real concurrency: separate processes, one OS-locked journal, one send.

Children are spawned Python processes inside the test's temporary folder. Their
number (2-4) and wall time (60 seconds each) are bounded; a late child fails.
No sleep is used to wait: barriers and process joins with time limits do.
"""
from pathlib import Path
import unittest
from ci_contract import cjson
from ci_contract.request_binding import scope_key
from synthetic_claim import run_clients

FIXTURE = cjson.loads((Path(__file__).parent / 'fixtures/claim-cases.json').read_bytes())
CASE = next(case for case in FIXTURE['cases'] if case['id'] == 'r17')
WORDS = {0: 'zero', 1: 'one', 2: 'two', 3: 'three', 4: 'four'}


def observed(run):
    """Compose the observation from the clients' actual outcomes; nothing is assumed."""
    outcomes = run['outcomes']
    sent = [item for item in outcomes if item.get('dispatch', {}).get('status') == 'submitted']
    attached = [item for item in outcomes if item.get('acquire', {}).get('status') == 'coalesced']
    codes = [item[stage]['exitCode'] for item in outcomes for stage in ('acquire', 'dispatch')
             if stage in item and item[stage]['exitCode'] is not None]
    return {'status': '%s-request-observed-%s-attached' % (WORDS[len(sent)], WORDS[len(attached)]),
            'exit_code': codes[0] if codes else None,
            'new_dispatch_count': run['sends'],
            'accepted': any(item.get(stage, {}).get('status') == 'accepted'
                            for item in outcomes for stage in ('acquire', 'dispatch'))}


class ConcurrencyTests(unittest.TestCase):
    def assert_r17(self, run):
        expected = CASE['expected']
        self.assertTrue(all('error' not in item for item in run['outcomes']), run['outcomes'])
        observation = observed(run)
        self.assertEqual({'status': observation['status'], 'exitCode': observation['exit_code']},
                         {'status': expected['status'], 'exitCode': expected['exitCode']}, run['outcomes'])
        self.assertEqual(observation, expected['observations'][0])

    def test_r17(self):
        given = CASE['given']
        run = run_clients(len(given['clients']))
        self.assertEqual(given['claim_digest'], 'same')
        self.assertEqual(len({scope_key(binding) for binding in run['bindings']}), 1)
        self.assertEqual(len({binding['requestId'] for binding in run['bindings']}), len(given['clients']))
        self.assert_r17(run)
        self.assertEqual(CASE['expected']['executionDocument'], 'not-produced-before-start')
        self.assertFalse(any('execution' in stage for item in run['outcomes'] for stage in item.values()))

    def test_four_clients_send_once(self):
        run = run_clients(4)
        self.assertEqual(run['sends'], 1, run['outcomes'])
        self.assertEqual(observed(run)['status'], 'one-request-observed-three-attached', run['outcomes'])

    def test_r17_negative_control_digest_as_acquisition(self):
        run = run_clients(2, 'digest-as-acquisition')
        self.assertEqual(run['sends'], 2)
        with self.assertRaises(AssertionError):
            self.assert_r17(run)

    def test_unlocked_append_is_detected(self):
        run = run_clients(2, 'unlocked-append')
        with self.assertRaises(AssertionError):
            self.assert_r17(run)

    def test_lock_file_existence_as_acquisition_is_detected(self):
        run = run_clients(2, 'lock-file-existence')
        with self.assertRaises(AssertionError):
            self.assert_r17(run)

    def test_client_count_is_bounded(self):
        for count in (1, 5):
            with self.subTest(count=count), self.assertRaises(ValueError):
                run_clients(count)

    def test_late_client_fails_the_run(self):
        with self.assertRaisesRegex(AssertionError, 'time limit'):
            run_clients(2, limit_seconds=0.05)


if __name__ == '__main__':
    unittest.main()
