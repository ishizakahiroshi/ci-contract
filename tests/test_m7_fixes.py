"""M7 fixes: one journal per authority, reconcile observation failure, unknown is not terminal.

Synthetic data only. Tests named ``test_fails_on_1b92698_*`` state a required
behavior that the reviewed commit 1b92698 does not meet; they fail there and pass
after the fixes. The other tests are positive or unchanged-behavior controls.
"""
import copy
import unittest
from ci_contract import claim
from ci_contract.journal import AuthorityUnknown
from synthetic_claim import (AUTHORITY, Clock, Query, Sender, Workspace, adopted_documents, adopted_flow,
                             binding_for, candidate, encode, force_append, inputs_for, record_types, seal,
                             shared_plan, stub_reconstruction)

OTHER = 'synthetic-other-authority'
JOURNAL_MISMATCH = {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'journal-authority-mismatch'}


def claim_payload(binding, *, fence=1, authority_id=AUTHORITY):
    """A journaled acquired claim of the given authority, shaped as the M7 claim record."""
    from ci_contract.request_binding import request_digest, scope_key
    return {'kind': 'claim', 'authority': 'local-single-supervisor-v1', 'authorityId': authority_id,
            'claimId': 'synthetic-claim-%d' % fence, 'ownerId': 'synthetic-supervisor',
            'scopeKey': scope_key(binding), 'requestId': binding['requestId'],
            'requestDigest': request_digest(binding), 'fence': fence, 'acquisition': 'acquired',
            'state': 'leased', 'leaseUntil': '2026-01-01T00:01:00Z', 'ledgerSequence': 1,
            'ledgerRecordSha256': '0' * 64}


class JournalAuthorityFix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def dispatch(self, journal, binding, sender, clock):
        with stub_reconstruction():
            return claim.dispatch(journal, inputs_for(self.plan, binding), binding, sender, clock=clock, **self.fixed)

    def test_one_authority_journal_still_coalesces_its_own_requests(self):
        # Positive control: a journal of one authority behaves as before.
        with Workspace() as space:
            journal, clock = space.journal(), Clock()
            claim.acquire(journal, binding_for(self.plan, 'synthetic-request-a'), owner_id='synthetic-supervisor', clock=clock)
            outcome = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-b'),
                                    owner_id='synthetic-client', clock=clock)
            self.assertEqual(outcome['status'], 'coalesced')

    def test_fails_on_1b92698_same_file_under_another_authority_is_refused(self):
        with Workspace() as space:
            clock = Clock()
            claim.acquire(space.journal(), binding_for(self.plan, 'synthetic-request-a'),
                          owner_id='synthetic-supervisor', clock=clock)
            before = space.bytes()
            other = space.journal(create=False, authority_id=OTHER)
            foreign = binding_for(self.plan, 'synthetic-request-b', authority_id=OTHER)
            outcome = claim.acquire(other, foreign, owner_id='synthetic-other-supervisor', clock=clock)
            self.assertEqual(outcome, JOURNAL_MISMATCH)
            self.assertEqual(space.bytes(), before, 'a refused operation must not write')

    def test_fails_on_1b92698_foreign_request_record_stops_a_new_acquisition(self):
        with Workspace() as space:
            journal = space.journal()
            force_append(space, 'request', binding_for(self.plan, 'synthetic-request-foreign', authority_id=OTHER),
                         fence=0)
            outcome = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-new'),
                                    owner_id='synthetic-supervisor', clock=Clock())
            self.assertEqual(outcome, JOURNAL_MISMATCH)
            self.assertNotIn('claim-acquired', record_types(space))

    def test_fails_on_1b92698_foreign_claim_record_stops_dispatch(self):
        with Workspace() as space:
            space.journal()
            binding = binding_for(self.plan, 'synthetic-request-foreign-claim')
            force_append(space, 'request', binding, fence=0)
            force_append(space, 'claim-acquired', claim_payload(binding, authority_id=OTHER), fence=1)
            sender = Sender()
            outcome = self.dispatch(space.journal(create=False), binding, sender, Clock())
            self.assertEqual(outcome, JOURNAL_MISMATCH)
            self.assertEqual(sender.calls, [])

    def test_fails_on_1b92698_each_authority_carrying_record_type_is_checked(self):
        # Each record that names an authority (request, claim, submit-unknown, adoption) must
        # name the journal's authority; one foreign record of any of these types stops the journal.
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-every-record')
            adopted_flow(space, self.plan, self.fixed, binding, Clock(), stub=True)
            template = space.records()
            kinds = []
            for item in template:
                if item['recordType'] not in kinds:
                    kinds.append(item['recordType'])
            self.assertIn('adoption', kinds)
            for kind in kinds:
                with self.subTest(recordType=kind):
                    items = copy.deepcopy(template)
                    next(item for item in items if item['recordType'] == kind)['payloadProjection']['authorityId'] = OTHER
                    space.write(encode(seal(items)))
                    with self.assertRaises(AuthorityUnknown) as raised:
                        space.journal(create=False).records()
                    self.assertEqual(raised.exception.reason_code, 'journal-authority-mismatch')


class ReconcileObservationFix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def submitted(self, space, request_id):
        """Acquired and sent once, not yet observed or adopted."""
        journal, clock = space.journal(), Clock()
        binding = binding_for(self.plan, request_id)
        claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
        sender = Sender()
        with stub_reconstruction():
            claim.dispatch(journal, inputs_for(self.plan, binding), binding, sender, clock=clock, **self.fixed)
        return journal, sender, binding

    def test_fails_on_1b92698_failing_query_is_unknown_for_each_exception_type(self):
        for failure in (ConnectionError, TimeoutError, OSError, RuntimeError, ValueError, KeyError):
            with self.subTest(failure=failure.__name__), Workspace() as space:
                journal, sender, binding = self.submitted(space, 'synthetic-request-observe-' + failure.__name__.lower())

                def unavailable(identity, failure=failure):
                    raise failure('synthetic observation failure')
                outcome = claim.reconcile(journal, binding['requestId'], unavailable, clock=Clock())
                self.assertEqual(outcome, {'status': 'unknown', 'exitCode': 8,
                                           'reasonCode': 'reconcile-observation-failed'})
                self.assertEqual(len(sender.calls), 1)
                self.assertNotIn('adoption', record_types(space))

    def test_fails_on_1b92698_a_later_good_observation_adopts_after_a_failure(self):
        with Workspace() as space:
            journal, sender, binding = self.submitted(space, 'synthetic-request-observed-later')

            def unavailable(identity):
                raise ConnectionError('synthetic observation failure')
            failed = claim.reconcile(journal, binding['requestId'], unavailable, clock=Clock())
            self.assertEqual(failed['reasonCode'], 'reconcile-observation-failed')
            adopted = claim.reconcile(journal, binding['requestId'], Query([candidate(binding)]), clock=Clock())
            self.assertEqual(adopted['status'], 'adopted')
            self.assertEqual(len(sender.calls), 1)

    def test_malformed_candidates_stay_invalid_input(self):
        # Unchanged handling: a malformed observation is exit 3, not unknown.
        with Workspace() as space:
            journal, sender, binding = self.submitted(space, 'synthetic-request-malformed')
            for candidates in ('not-a-list', [{'runId': '123'}]):
                with self.subTest(candidates=candidates):
                    observed = claim.reconcile(journal, binding['requestId'], Query(candidates), clock=Clock())
                    self.assertEqual(observed, {'status': 'invalid-input', 'exitCode': 3})
            self.assertEqual(len(sender.calls), 1)


class UnknownReceiptFix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def dispatch(self, journal, binding, sender, clock):
        with stub_reconstruction():
            return claim.dispatch(journal, inputs_for(self.plan, binding), binding, sender, clock=clock, **self.fixed)

    def orphaned_attempt(self, space, request_id, status, exit_code):
        """Adopted attempt 1 whose receipt has the given status, confirmed cleanup, then a retry approval."""
        binding = binding_for(self.plan, request_id)
        journal, sender, acquired, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, Clock(), stub=True)
        self.assertEqual(len(sender.calls), 1)
        later = Clock().advance(61)
        self.assertEqual(claim.heartbeat(journal, request_id, clock=later)['reasonCode'], 'heartbeat-lease-expired')
        result = adopted_documents(self.plan, binding, adopted['attemptAuthority'], acquired['claim'])[2]
        result.update(status=status, exitCode=exit_code, cleanupConfirmed=True, pendingChildren=0)
        self.assertEqual(claim.ingest_receipt(journal, result)['status'], 'recorded')
        self.assertEqual(claim.approve_retry(journal, request_id, clock=later)['status'], 'retry-approved')
        return journal, sender, binding, later

    def test_fails_on_1b92698_unknown_receipt_blocks_retry_and_a_second_send(self):
        with Workspace() as space:
            journal, sender, binding, later = self.orphaned_attempt(space, 'synthetic-request-unknown-receipt', 'unknown', 8)
            outcome = claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=later)
            self.assertEqual(outcome, {'status': 'blocked', 'exitCode': 4, 'reasonCode': 'attempt-terminal-unknown'})
            self.assertEqual(self.dispatch(journal, binding, sender, later)['status'], 'blocked')
            self.assertEqual(len(sender.calls), 1, 'the same request was sent again after an unknown receipt')
            self.assertEqual(record_types(space).count('claim-acquired'), 1)

    def test_fails_on_1b92698_unknown_receipt_block_survives_a_restart(self):
        with Workspace() as space:
            journal, sender, binding, later = self.orphaned_attempt(space, 'synthetic-request-restart', 'unknown', 8)
            restarted = space.journal(create=False)
            outcome = claim.retry(restarted, binding['requestId'], owner_id='synthetic-supervisor', clock=later)
            self.assertEqual(outcome, {'status': 'blocked', 'exitCode': 4, 'reasonCode': 'attempt-terminal-unknown'})

    def test_positive_control_timeout_receipt_allows_one_retry_send(self):
        with Workspace() as space:
            journal, sender, binding, later = self.orphaned_attempt(space, 'synthetic-request-timeout', 'timeout', 7)
            outcome = claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=later)
            self.assertEqual((outcome['status'], outcome['attemptNumber']), ('acquired', 2))
            self.assertEqual(self.dispatch(journal, binding, Sender(), later)['status'], 'submitted')

    def test_closing_an_unknown_attempt_lets_the_owner_issue_a_new_request(self):
        # The owner's path: close the orphaned claim (no send); a new request ID may then acquire the scope.
        with Workspace() as space:
            journal, sender, binding, later = self.orphaned_attempt(space, 'synthetic-request-replaced', 'unknown', 8)
            self.assertEqual(claim.close(journal, binding['requestId'])['status'], 'closed')
            self.assertEqual(claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor',
                                         clock=later)['reasonCode'], 'retry-claim-not-orphaned')
            new = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-new-after-unknown'),
                                owner_id='synthetic-supervisor', clock=later)
            self.assertEqual((new['status'], new['claim']['fence']), ('acquired', 2))
            self.assertEqual(len(sender.calls), 1)


if __name__ == '__main__':
    unittest.main()