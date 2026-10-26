"""M8 C1: the local attempt of an acquired claim (start_local). Synthetic data only."""
import unittest
from ci_contract import claim
from ci_contract.request_binding import make_request_binding
from synthetic_claim import (AUTHORITY, CREATED, EXPIRES, Clock, Workspace, adopted_documents, binding_for,
                             record_types, shared_plan)


def blocked(reason):
    return {'status': 'blocked', 'exitCode': 4, 'reasonCode': reason}


def unknown(reason):
    return {'status': 'unknown', 'exitCode': 8, 'reasonCode': reason}


class LocalStartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def local_binding(self, request_id):
        return make_request_binding(self.plan, request_id=request_id, authority_id=AUTHORITY, target='local',
                                    trust='trusted', workflow_commit=None, created_at=CREATED,
                                    expires_at=EXPIRES, authority_kind='local-single-supervisor-v1')

    def started(self, space, request_id):
        journal, clock, binding = space.journal(), Clock(), self.local_binding(request_id)
        self.assertEqual(claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)['status'],
                         'acquired')
        return journal, clock, binding, claim.start_local(journal, binding, clock=clock)

    def test_start_records_the_submission_and_a_run_free_adoption_once(self):
        with Workspace() as space:
            journal, clock, binding, started = self.started(space, 'synthetic-request-local-start')
            self.assertEqual(started['status'], 'started')
            self.assertIsNone(started['exitCode'])
            authority = started['attemptAuthority']
            self.assertEqual((authority['attemptNumber'], authority['adoptedRunId'], authority['adoptedProviderAttempt']),
                             (1, None, None))
            self.assertEqual(started['claim']['acquisition'], 'acquired')
            self.assertEqual(record_types(space), ['request', 'claim-acquired', 'submit-unknown', 'adoption'])
            before = space.bytes()
            self.assertEqual(claim.start_local(journal, binding, clock=clock), unknown('submission-already-recorded'))
            self.assertEqual(space.bytes(), before)

    def test_a_github_binding_or_an_unjournaled_request_is_not_started(self):
        with Workspace() as space:
            journal, clock = space.journal(), Clock()
            github = binding_for(self.plan, 'synthetic-request-github-start')
            claim.acquire(journal, github, owner_id='synthetic-supervisor', clock=clock)
            self.assertEqual(claim.start_local(journal, github, clock=clock), blocked('local-start-target-not-local'))
            absent = self.local_binding('synthetic-request-not-journaled')
            self.assertEqual(claim.start_local(journal, absent, clock=clock), blocked('dispatch-request-not-journaled'))
            self.assertNotIn('submit-unknown', record_types(space))

    def test_an_expired_lease_is_not_started(self):
        with Workspace() as space:
            journal, clock, binding = space.journal(), Clock(), self.local_binding('synthetic-request-late-start')
            claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
            self.assertEqual(claim.start_local(journal, binding, clock=clock.advance(60)),
                             blocked('dispatch-lease-expired'))
            self.assertNotIn('submit-unknown', record_types(space))

    def test_the_started_attempt_takes_its_receipt_and_closes(self):
        with Workspace() as space:
            journal, _, binding, started = self.started(space, 'synthetic-request-local-close')
            # The synthetic documents model a GitHub run; the receipt key (fence, adoption hash) is the local one.
            modeled = dict(started['attemptAuthority'], adoptedRunId='123', adoptedProviderAttempt=1)
            result = adopted_documents(self.plan, binding, modeled, started['claim'])[2]
            result.update(status='timeout', exitCode=7, cleanupConfirmed=True, pendingChildren=0)
            self.assertEqual(claim.ingest_receipt(journal, result)['status'], 'recorded')
            self.assertEqual(claim.close(journal, binding['requestId'])['status'], 'closed')


if __name__ == '__main__':
    unittest.main()
