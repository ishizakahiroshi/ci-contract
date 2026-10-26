"""M7 fixed examples c19, c19b, r18 and r20 against the local authority journal.

Only fixtureModels and given build inputs; expected values are used in
assertions only. Missing schema fields are synthetic and listed in RESULTS.md.
r17 needs real concurrency and lives in test_claim_concurrency.
"""
import copy
from pathlib import Path
import unittest
from ci_contract import cjson, claim
from ci_contract.hashing import domain_hash
from ci_contract.request_binding import request_digest
from synthetic_claim import (Clock, Query, Sender, Workspace, adopted_documents, adopted_flow, binding_for,
                             candidate, force_append, inputs_for, module_fault, record_types, shared_plan)
from synthetic_verify import digest

FIXTURE = cjson.loads((Path(__file__).parent / 'fixtures/claim-cases.json').read_bytes())
CASES = {case['id']: case for case in FIXTURE['cases']}
MODEL = FIXTURE['fixtureModels'][0]


def outcome(observation):
    return {'status': observation['status'], 'exitCode': observation['exitCode']}


class ClaimAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def assert_selected(self, case):
        """The M3 reading: exact selected set; forbidden examples declared and absent."""
        expected = case['expected']
        selected = self.plan['selectionEvidence']['selectedInstanceIds']
        self.assertEqual(len(selected), len(set(selected)))
        self.assertEqual(set(selected), set(expected['selectedInstanceIds']))
        universe = {iid for ids in MODEL['componentInstances'].values() for iid in ids} | set(MODEL['guardInstanceIds'])
        self.assertEqual(len(expected['notSelectedInstanceIds']), len(set(expected['notSelectedInstanceIds'])))
        for identifier in expected['notSelectedInstanceIds']:
            self.assertIn(identifier, universe)
            self.assertNotIn(identifier, selected)

    # c19 -----------------------------------------------------------------
    def c19_flow(self, module=claim, dispatch_second=True):
        given = CASES['c19']['given']
        with Workspace() as space:
            journal = space.journal(authority_id=given['authority'])
            clock, sender = Clock(), Sender()
            one, two = (binding_for(self.plan, 'request-' + client, authority_id=given['authority'])
                        for client in given['clients'])
            first = module.acquire(journal, one, owner_id=given['clients'][0], clock=clock)
            sent = module.dispatch(journal, inputs_for(self.plan, one), one, sender, clock=clock.advance(1), **self.fixed)
            second = module.acquire(journal, two, owner_id=given['clients'][1], clock=clock.advance(1))
            again = None
            if dispatch_second:
                again = module.dispatch(journal, inputs_for(self.plan, two), two, sender,
                                        clock=clock.advance(1), **self.fixed)
            return {'first': first, 'sent': sent, 'second': second, 'again': again,
                    'sends': len(sender.calls), 'types': record_types(space), 'two': two}

    def assert_c19(self, flow, dispatch_second=True):
        expected = CASES['c19']['expected']
        self.assertEqual(flow['first']['status'], 'acquired')
        self.assertEqual(flow['sent']['status'], 'submitted')
        self.assertEqual(outcome(flow['second']), {'status': expected['status'], 'exitCode': expected['exitCode']})
        self.assertIsNone(flow['second']['exitCode'])
        self.assertNotIn('execution', flow['second'])
        self.assertEqual(flow['second']['attachedRequestId'], flow['first']['requestId'])
        self.assertNotIn('adoption', flow['types'])
        if dispatch_second:
            self.assertEqual(outcome(flow['again']), {'status': 'blocked', 'exitCode': 4})
        self.assertEqual(flow['sends'], expected['newDispatchCount'])
        self.assertFalse(expected['accepted'])

    def test_c19(self):
        flow = self.c19_flow()
        self.assert_c19(flow)
        self.assertEqual(flow['again']['reasonCode'], 'dispatch-claim-coalesced')
        self.assertEqual(CASES['c19']['expected']['executionDocument'], 'not-produced-for-coalesced-client')
        self.assert_selected(CASES['c19'])

    def test_c19_negative_control_ignoring_the_active_claim_boundary(self):
        fault = module_fault(claim, "            if other['state'] == 'leased':\n                active = other",
                             "            if False:\n                active = other")
        flow = self.c19_flow(fault)
        self.assertEqual(flow['second']['status'], 'acquired')
        self.assertEqual(flow['sends'], 2)
        with self.assertRaises(AssertionError):
            self.assert_c19(flow)

    def test_c19_negative_control_terminal_code_at_a_non_terminal_point(self):
        fault = module_fault(claim, "return _observation('coalesced', requestId=binding['requestId'],",
                             "return _observation('coalesced', exitCode=0, requestId=binding['requestId'],")
        flow = self.c19_flow(fault, dispatch_second=False)
        self.assertEqual(flow['second']['exitCode'], 0)
        with self.assertRaises(AssertionError):
            self.assert_c19(flow, dispatch_second=False)

    # c19b ----------------------------------------------------------------
    def c19b_state(self, space):
        given = CASES['c19b']['given']
        clock = Clock()
        binding = binding_for(self.plan, 'synthetic-request-selected')
        attached = binding_for(self.plan, 'synthetic-request-attached')
        journal, sender, acquired, submitted, adopted = adopted_flow(space, self.plan, self.fixed, binding, clock)
        coalesced = claim.acquire(journal, attached, owner_id='synthetic-client', clock=clock.advance(1))
        self.assertEqual(adopted['attemptAuthority']['attemptNumber'], given['selectedAttempt'])
        self.assertTrue(given['terminalProofsAvailable'])
        docs = adopted_documents(self.plan, binding, adopted['attemptAuthority'], acquired['claim'])
        return journal, sender, docs, [acquired, submitted, adopted, coalesced]

    def test_c19b(self):
        case = CASES['c19b']
        with Workspace() as space:
            journal, sender, docs, observations = self.c19b_state(space)
            self.assertEqual([item['status'] for item in observations], ['acquired', 'submitted', 'adopted', 'coalesced'])
            self.assertTrue(all(item['exitCode'] is None for item in observations))
            sends = len(sender.calls)
            early = claim.observe_completion(journal, *docs[:3], synthetic_collector_ledger=docs[3])
            self.assertEqual(early, {'status': 'blocked', 'exitCode': 4, 'reasonCode': 'observation-receipt-unrecorded'})
            recorded = claim.ingest_receipt(journal, docs[2])
            self.assertEqual(outcome(recorded), {'status': 'recorded', 'exitCode': None})
            verdict = claim.observe_completion(journal, *docs[:3], synthetic_collector_ledger=docs[3])
            self.assertEqual(verdict, {'status': case['expected']['status'], 'exitCode': case['expected']['exitCode']})
            self.assertEqual(len(sender.calls) - sends, case['expected']['newDispatchCount'])
            self.assertTrue(case['expected']['accepted'])
            self.assertEqual(case['expected']['executionDocument'], 'produced')
            self.assertNotIn('execution', observations[3])
        self.assert_selected(case)

    def test_c19b_negative_control_missing_one_proof(self):
        with Workspace() as space:
            journal, _, docs, _ = self.c19b_state(space)
            claim.ingest_receipt(journal, docs[2])
            ledger = copy.deepcopy(docs[3])
            ledger['proofs'] = ledger['proofs'][1:]
            self.assertEqual(claim.observe_completion(journal, *docs[:3], synthetic_collector_ledger=ledger)['exitCode'], 4)

    def test_c19b_negative_control_ignoring_the_adopted_attempt_boundary(self):
        fault = module_fault(claim, '            if any(authority[name] != value for name, value in adoption.items()):',
                             '            if False:')
        with Workspace() as space:
            journal, _, docs, observations = self.c19b_state(space)
            adoption = dict(observations[2]['attemptAuthority'], adoptedRunId='124')
            binding = docs[4]
            foreign = adopted_documents(self.plan, binding, adoption, observations[0]['claim'])
            force_append(space, 'receipt', foreign[2])
            self.assertEqual(claim.observe_completion(journal, *foreign[:3], synthetic_collector_ledger=foreign[3]),
                             {'status': 'blocked', 'exitCode': 4, 'reasonCode': 'observation-attempt-mismatch'})
            self.assertEqual(fault.observe_completion(journal, *foreign[:3], synthetic_collector_ledger=foreign[3]),
                             {'status': 'accepted', 'exitCode': 0})

    # r18 -----------------------------------------------------------------
    def r18_flow(self, module=claim):
        case = CASES['r18']
        given = case['given']
        with Workspace() as space:
            journal = space.journal()
            clock = Clock()
            sender = Sender(lose=given['dispatch_response'] == 'lost')
            binding = binding_for(self.plan, 'synthetic-request-lost')
            module.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
            lost = module.dispatch(journal, inputs_for(self.plan, binding), binding, sender,
                                   clock=clock.advance(1), **self.fixed)
            before = len(sender.calls)
            # The listing may lag and no definitive non-acceptance evidence exists.
            query = Query([candidate(binding)] * given['query_matches'])
            observed = module.reconcile(journal, binding['requestId'], query, clock=clock.advance(1))
            if observed['status'] == 'unknown':
                # A faulty caller would treat zero matches as "never sent" and dispatch again.
                sender.lose = False
                module.dispatch(journal, inputs_for(self.plan, binding), binding, sender,
                                clock=clock.advance(1), **self.fixed)
            return {'lost': lost, 'observed': observed, 'new': len(sender.calls) - before,
                    'types': record_types(space), 'query': query}

    def assert_r18(self, flow):
        expected = CASES['r18']['expected']
        self.assertEqual(outcome(flow['lost']), {'status': 'unknown', 'exitCode': 8})
        self.assertEqual(flow['lost']['sendCount'], 1)
        self.assertEqual(outcome(flow['observed']), {'status': expected['status'], 'exitCode': expected['exitCode']})
        observation = expected['observations'][0]
        self.assertEqual(flow['new'], observation['new_dispatch_count'])
        self.assertEqual(observation['execution_document'], 'not-invented')
        self.assertNotIn('attemptAuthority', flow['observed'])
        self.assertNotIn('adoption', flow['types'])
        self.assertEqual(flow['types'].count('submit-unknown'), 1)
        self.assertEqual(len(flow['query'].calls), 1)

    def test_r18(self):
        self.assert_r18(self.r18_flow())

    def test_r18_negative_control_zero_matches_as_proof_of_non_submission(self):
        # The dispatch check only: start_local (M8) has the same two lines before other ones.
        fault = module_fault(claim, "        if claim['claimId'] in state.submitted:\n            raise AuthorityUnknown('submission-already-recorded')\n"
                                    "        transaction.append('submit-unknown', claim)\n    try:\n",
                             "        transaction.append('submit-unknown', claim)\n    try:\n")
        flow = self.r18_flow(fault)
        self.assertEqual(flow['new'], 1)
        with self.assertRaises(AssertionError):
            self.assert_r18(flow)

    # r20 -----------------------------------------------------------------
    def r20_flow(self, module=claim):
        case = CASES['r20']
        with Workspace() as space:
            clock = Clock()
            binding = binding_for(self.plan, 'synthetic-request-receipt')
            journal, _, acquired, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, clock)
            docs = adopted_documents(self.plan, binding, adopted['attemptAuthority'], acquired['claim'])
            first = docs[2]
            second = copy.deepcopy(first)
            second['completedAt'] = '2026-01-01T00:01:30Z'
            receipts = {'D1': first, 'D2': second}
            keys = {event['receipt_key'] for event in case['given']['timeline']}
            self.assertEqual(keys, {'R1'})
            observations, sizes = [], []
            for event in case['given']['timeline']:
                observations.append(module.ingest_receipt(journal, receipts[event['digest']]))
                sizes.append(len(space.bytes()))
            recorded = [record['payloadProjection'] for record in space.records() if record['recordType'] == 'receipt']
            return {'observations': observations, 'sizes': sizes, 'recorded': recorded, 'first': first,
                    'types': record_types(space)}

    def assert_r20(self, flow):
        expected = CASES['r20']['expected']
        observation = expected['observations'][0]
        first, second, third = flow['observations']
        self.assertEqual(outcome(first), {'status': 'recorded', 'exitCode': None})
        self.assertEqual(second['status'], observation['second_event'])
        self.assertIsNone(second['exitCode'])
        self.assertEqual(flow['sizes'][0], flow['sizes'][1])
        self.assertEqual(outcome(third), {'status': expected['status'], 'exitCode': expected['exitCode']})
        self.assertEqual(third['reasonCode'], observation['third_event'])
        self.assertEqual([domain_hash('result', item) for item in flow['recorded']],
                         [domain_hash('result', flow['first'])])
        self.assertEqual(observation['new_execution_count'],
                         sum('execution' in item for item in flow['observations']))
        self.assertEqual(expected['executionDocument'], 'not-produced-before-start')

    def test_r20(self):
        self.assert_r20(self.r20_flow())
        self.assert_selected(CASES['r20'])

    def test_r20_negative_control_last_digest_overwrites(self):
        fault = module_fault(
            claim,
            "            transaction.append('receipt-conflict', result)\n            raise BlockedError('content-conflict')\n",
            "            transaction.append('receipt', result)\n            return _observation('recorded', receiptKey=list(key), digest=digest)\n")
        flow = self.r20_flow(fault)
        self.assertEqual(flow['observations'][2]['status'], 'recorded')
        with self.assertRaises(AssertionError):
            self.assert_r20(flow)


class CoalescedRequestIsNeverAccepted(unittest.TestCase):
    """c19's accepted=false at a completion observation for the attached request."""

    def test_attached_request_has_no_acceptable_execution(self):
        plan, fixed = shared_plan()
        with Workspace() as space:
            clock = Clock()
            binding = binding_for(plan, 'synthetic-request-selected')
            attached = binding_for(plan, 'synthetic-request-attached')
            journal, _, acquired, _, adopted = adopted_flow(space, plan, fixed, binding, clock, stub=True)
            coalesced = claim.acquire(journal, attached, owner_id='synthetic-client', clock=clock)
            fake = {'authorityId': 'synthetic-authority', 'requestId': attached['requestId'],
                    'requestDigest': request_digest(attached), 'attemptNumber': 1, 'adopted': True,
                    'adoptedRunId': '123', 'adoptedProviderAttempt': 1, 'fence': coalesced['claim']['fence'],
                    'claimId': coalesced['claim']['claimId'], 'adoptionRecordSha256': digest('synthetic-adoption'),
                    'previousTerminalReceiptSha256': None}
            docs = adopted_documents(plan, attached, fake, coalesced['claim'])
            verdict = claim.observe_completion(journal, *docs[:3], synthetic_collector_ledger=docs[3])
            self.assertEqual(verdict, {'status': 'blocked', 'exitCode': 4, 'reasonCode': 'observation-request-not-acquired'})


if __name__ == '__main__':
    unittest.main()
