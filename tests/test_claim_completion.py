"""The completion observation point: journal evidence before the M5/M6 verifier.

Single-field faults rebuild the synthetic documents consistently (so the M5
and M6 checks pass) and, where the changed evidence could never be ingested,
record its receipt with force_append so that exactly one journal comparison
rejects it.
"""
import copy
import unittest
from ci_contract import claim
from ci_contract.request_binding import request_digest
from synthetic_claim import (Clock, Query, Workspace, adopted_documents, adopted_flow, binding_for, candidate,
                             force_append, record_types, shared_plan, stub_reconstruction, inputs_for, Sender)
from synthetic_verify import LATE, digest


def blocked(reason):
    return {'status': 'blocked', 'exitCode': 4, 'reasonCode': reason}


ACCEPTED = {'status': 'accepted', 'exitCode': 0}


class CompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def adopted(self, space, request_id='synthetic-request-complete'):
        binding = binding_for(self.plan, request_id)
        clock = Clock()
        journal, _, acquired, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, clock, stub=True)
        docs = adopted_documents(self.plan, binding, adopted['attemptAuthority'], acquired['claim'])
        return journal, binding, acquired, adopted, docs, clock

    def observe(self, journal, docs):
        return claim.observe_completion(journal, *docs[:3], synthetic_collector_ledger=docs[3])

    def test_recorded_adopted_attempt_is_accepted(self):
        with Workspace() as space:
            journal, binding, acquired, adopted, docs, _ = self.adopted(space)
            self.assertEqual(self.observe(journal, docs), blocked('observation-receipt-unrecorded'))
            claim.ingest_receipt(journal, docs[2])
            self.assertEqual(self.observe(journal, docs), ACCEPTED)

    def test_each_adopted_tuple_field_alone_is_rejected(self):
        changes = {'attemptNumber': 2, 'adoptedRunId': '124', 'adoptedProviderAttempt': 2, 'fence': 2,
                   'claimId': 'synthetic-other-claim', 'adoptionRecordSha256': digest('synthetic-other-adoption'),
                   'previousTerminalReceiptSha256': digest('synthetic-other-terminal')}
        for field, value in changes.items():
            with self.subTest(field=field), Workspace() as space:
                journal, binding, acquired, adopted, _, _ = self.adopted(space)
                authority = dict(adopted['attemptAuthority'], **{field: value})
                docs = adopted_documents(self.plan, binding, authority, acquired['claim'])
                force_append(space, 'receipt', docs[2])
                self.assertEqual(self.observe(journal, docs), blocked('observation-attempt-mismatch'))

    def test_claim_hash_must_be_the_acquired_claim(self):
        with Workspace() as space:
            journal, binding, acquired, adopted, _, _ = self.adopted(space)
            other = dict(acquired['claim'], ownerId='synthetic-other-owner')
            docs = adopted_documents(self.plan, binding, adopted['attemptAuthority'], other)
            force_append(space, 'receipt', docs[2])
            self.assertEqual(self.observe(journal, docs), blocked('observation-claim-mismatch'))

    def test_unknown_request_and_missing_adoption(self):
        with Workspace() as space:
            journal, binding, acquired, adopted, docs, _ = self.adopted(space)
            other = Workspace()
            with other:
                empty = other.journal()
                self.assertEqual(self.observe(empty, docs), blocked('observation-request-unknown'))
        with Workspace() as space:
            journal = space.journal()
            binding = binding_for(self.plan, 'synthetic-request-unadopted')
            acquired = claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=Clock())
            with stub_reconstruction():
                claim.dispatch(journal, inputs_for(self.plan, binding), binding, Sender(), clock=Clock(), **self.fixed)
            authority = {'authorityId': 'synthetic-authority', 'requestId': binding['requestId'],
                         'requestDigest': request_digest(binding), 'attemptNumber': 1, 'adopted': True,
                         'adoptedRunId': '123', 'adoptedProviderAttempt': 1, 'fence': 1,
                         'claimId': acquired['claim']['claimId'], 'adoptionRecordSha256': digest('synthetic-adoption'),
                         'previousTerminalReceiptSha256': None}
            docs = adopted_documents(self.plan, binding, authority, acquired['claim'])
            force_append(space, 'receipt', docs[2])
            self.assertEqual(self.observe(journal, docs), blocked('observation-not-adopted'))

    def test_coalesced_request_with_a_forged_adoption_is_rejected(self):
        with Workspace() as space:
            journal, binding, acquired, adopted, _, clock = self.adopted(space)
            attached = binding_for(self.plan, 'synthetic-request-attached')
            coalesced = claim.acquire(journal, attached, owner_id='synthetic-client', clock=clock)['claim']
            forged = dict(adopted['attemptAuthority'], requestId=attached['requestId'],
                          requestDigest=request_digest(attached), claimId=coalesced['claimId'])
            record = force_append(space, 'adoption', forged)
            forged['adoptionRecordSha256'] = space.records()[-1]['recordSha256']
            docs = adopted_documents(self.plan, attached, forged, coalesced)
            force_append(space, 'receipt', docs[2])
            self.assertEqual(self.observe(journal, docs), blocked('observation-request-not-acquired'))
            self.assertTrue(record)

    def test_conflicted_receipt_key_is_held(self):
        with Workspace() as space:
            journal, binding, acquired, adopted, docs, _ = self.adopted(space)
            claim.ingest_receipt(journal, docs[2])
            claim.ingest_receipt(journal, dict(copy.deepcopy(docs[2]), completedAt='2026-01-01T00:01:30Z'))
            self.assertEqual(self.observe(journal, docs), blocked('receipt-conflict-unresolved'))

    def test_missing_proof_and_shape_errors(self):
        with Workspace() as space:
            journal, binding, acquired, adopted, docs, _ = self.adopted(space)
            # Before the receipt is recorded the journal would block (4); shape wins with 3.
            plan = dict(copy.deepcopy(docs[0]), unexpected=True)
            self.assertEqual(claim.observe_completion(journal, plan, *docs[1:3], synthetic_collector_ledger=docs[3]),
                             {'status': 'invalid-input', 'exitCode': 3})
            claim.ingest_receipt(journal, docs[2])
            ledger = copy.deepcopy(docs[3])
            ledger['proofs'].pop()
            self.assertEqual(claim.observe_completion(journal, *docs[:3], synthetic_collector_ledger=ledger)['exitCode'], 4)

    def test_recorded_binding_is_compared_by_the_verifier(self):
        from synthetic_request_binding import bind_hashes
        with Workspace() as space:
            journal, binding, acquired, adopted, docs, _ = self.adopted(space)
            docs[1]['github']['trust'] = 'untrusted'
            bind_hashes(docs)
            force_append(space, 'receipt', docs[2])
            self.assertEqual(self.observe(journal, docs), {'status': 'blocked', 'exitCode': 4})

    def test_invalid_journal_configuration_is_invalid_input(self):
        from ci_contract.journal import LocalJournal
        with Workspace() as space:
            journal, binding, acquired, adopted, docs, _ = self.adopted(space)
            claim.ingest_receipt(journal, docs[2])
            misconfigured = LocalJournal(space.path, authority_id='synthetic-authority',
                                         repository_roots=(str(space.repository),))
            self.assertEqual(self.observe(misconfigured, docs), {'status': 'invalid-input', 'exitCode': 3})

    def test_unverifiable_journal_is_unknown(self):
        with Workspace() as space:
            journal, binding, acquired, adopted, docs, _ = self.adopted(space)
            claim.ingest_receipt(journal, docs[2])
            space.write(space.bytes()[:-1])
            self.assertEqual(self.observe(journal, docs)['exitCode'], 8)

    def test_late_older_success_does_not_replace_the_newer_terminal(self):
        def timeout(docs):
            docs[2].update(status='timeout', exitCode=7)
            docs[3].update(terminalObservation='deadline-exceeded', observedAt=LATE)
        def cancelled(docs):
            docs[2].update(status='cancelled', exitCode=6)
            docs[3]['terminalObservation'] = 'cancelled'
        def failed(docs):
            docs[2].update(status='failed', exitCode=2)
            receipt = docs[2]['checks'][0]
            receipt.update(status='failed', exitCode=1)
            receipt['proof']['invocation']['exitCode'] = 1
        for name, change, verdict in (('timeout', timeout, 7), ('cancelled', cancelled, 6), ('failed', failed, 2)):
            with self.subTest(newer=name), Workspace() as space:
                self.assert_newer_terminal_is_kept(space, change, {'status': name, 'exitCode': verdict})

    def assert_newer_terminal_is_kept(self, space, change, verdict):
        from synthetic_request_binding import bind_hashes
        journal, binding, acquired, adopted, docs, _ = self.adopted(space)
        later = Clock().advance(61)
        claim.heartbeat(journal, binding['requestId'], clock=later)
        # The first attempt ends truly terminal (timeout, exit 7); an unknown receipt would block the retry (M7 fix 3).
        first = dict(copy.deepcopy(docs[2]), status='timeout', exitCode=7)
        claim.ingest_receipt(journal, first)
        claim.approve_retry(journal, binding['requestId'], clock=later)
        retried = claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=later)
        with stub_reconstruction():
            claim.dispatch(journal, inputs_for(self.plan, binding), binding, Sender(), clock=later, **self.fixed)
        second = claim.reconcile(journal, binding['requestId'], Query([candidate(binding, run_id='124')]), clock=later)
        newer = list(adopted_documents(self.plan, binding, second['attemptAuthority'], retried['claim']))
        change(newer)
        bind_hashes(newer)
        self.assertEqual(claim.ingest_receipt(journal, newer[2])['status'], 'recorded')
        # The late success of attempt 1 meets attempt 1's own recorded key: a conflict there only.
        self.assertEqual(claim.ingest_receipt(journal, docs[2]), blocked('content-conflict'))
        self.assertEqual(self.observe(journal, newer), verdict)
        self.assertEqual(self.observe(journal, docs), blocked('observation-attempt-mismatch'))
        self.assertEqual(record_types(space).count('receipt'), 2)


if __name__ == '__main__':
    unittest.main()
