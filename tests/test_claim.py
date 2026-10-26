"""Claim lifecycle: acquisition, coalescing, lease, reconciliation, adoption, receipts, close, retry.

Journal setup uses the public operations; dispatch uses stub_reconstruction to
isolate the journal decision (the real reconstruction is covered by
test_claim_dispatch and the acceptance tests). Times come from a replaced clock.
"""
import copy
from datetime import datetime, timedelta, timezone
import unittest
from ci_contract import claim
from ci_contract.hashing import domain_hash
from synthetic_claim import (AUTHORITY, Clock, Query, Sender, T0, Workspace, adopted_documents, adopted_flow,
                             binding_for, candidate, force_append, inputs_for, record_types, shared_plan,
                             stub_reconstruction)


def blocked(reason):
    return {'status': 'blocked', 'exitCode': 4, 'reasonCode': reason}


INVALID = {'status': 'invalid-input', 'exitCode': 3}


class ClaimCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def binding(self, request_id='synthetic-request-unit', **options):
        return binding_for(self.plan, request_id, **options)

    def acquire(self, journal, binding, clock, owner='synthetic-supervisor', **options):
        return claim.acquire(journal, binding, owner_id=owner, clock=clock, **options)

    def dispatch(self, journal, binding, clock, sender=None):
        with stub_reconstruction():
            return claim.dispatch(journal, inputs_for(self.plan, binding), binding,
                                  Sender() if sender is None else sender, clock=clock, **self.fixed)

    def adopted(self, space, binding=None, clock=None, run_id='123'):
        binding = self.binding() if binding is None else binding
        clock = Clock() if clock is None else clock
        journal, sender, acquired, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, clock,
                                                             run_id=run_id, stub=True)
        self.assertEqual(adopted['status'], 'adopted')
        return journal, clock, binding, acquired, adopted

    def documents(self, binding, adopted, acquired):
        return adopted_documents(self.plan, binding, adopted['attemptAuthority'], acquired['claim'])

    def submitted(self, space, binding=None):
        binding = self.binding() if binding is None else binding
        journal = space.journal()
        clock = Clock()
        self.acquire(journal, binding, clock)
        sender = Sender()
        self.assertEqual(self.dispatch(journal, binding, clock, sender)['status'], 'submitted')
        return journal, clock, binding, sender

    def terminal(self, result, cleanup=True, pending=0):
        """A schema-valid truly terminal receipt (timeout, exit 7 as the schema pairs it) with the chosen cleanup.

        An unknown receipt is not terminal for retry (M7 fix 3, attempt-terminal-unknown), so the
        retry fixtures must not use it.
        """
        result = copy.deepcopy(result)
        result.update(status='timeout', exitCode=7, cleanupConfirmed=cleanup, pendingChildren=pending)
        return result


class AcquisitionTests(ClaimCase):
    def test_acquired_claim_fields_and_lease(self):
        with Workspace() as space:
            observation = self.acquire(space.journal(), self.binding(), Clock(), heartbeat_seconds=20)
            self.assertEqual((observation['status'], observation['exitCode']), ('acquired', None))
            held = observation['claim']
            self.assertEqual((held['acquisition'], held['state'], held['fence'], held['authorityId']),
                             ('acquired', 'leased', 1, AUTHORITY))
            self.assertEqual(held['leaseUntil'], '2026-01-01T00:01:00Z')
            self.assertEqual(observation['heartbeatDueAt'], '2026-01-01T00:00:20Z')
            self.assertEqual(record_types(space), ['request', 'claim-acquired'])

    def test_input_shapes_precede_the_journal(self):
        with Workspace() as space:
            journal = space.journal(create=False)
            binding = self.binding()
            for changed, options in ((dict(binding, extra=True), {}), (binding, {'owner': 'Synthetic'}),
                                     (binding, {'heartbeat_seconds': True}), (binding, {'heartbeat_seconds': 0}),
                                     (binding, {'heartbeat_seconds': 21})):
                with self.subTest(options=options):
                    self.assertEqual(self.acquire(journal, changed, Clock(), **options), INVALID)

    def test_clock_must_return_aware_utc(self):
        with Workspace() as space:
            journal = space.journal()
            for value in ('2026-01-01T00:00:00Z', datetime(2026, 1, 1),
                          datetime(2026, 1, 1, 9, tzinfo=timezone(timedelta(hours=9)))):
                with self.subTest(value=repr(value)):
                    self.assertEqual(self.acquire(journal, self.binding(), lambda: value), INVALID)
            self.assertEqual(space.bytes(), b'')

    def test_registration_rejects_other_authorities_and_reused_ids(self):
        with Workspace() as space:
            journal = space.journal()
            self.assertEqual(self.acquire(journal, self.binding(kind='github-run-v1'), Clock()),
                             blocked('authority-kind-unsupported'))
            self.assertEqual(self.acquire(journal, self.binding(authority_id='synthetic-other'), Clock()),
                             blocked('authority-mismatch'))
            self.assertEqual(space.bytes(), b'')
            self.acquire(journal, self.binding(), Clock())
            self.assertEqual(self.acquire(journal, self.binding(), Clock().advance(1)), blocked('request-id-exists'))

    def test_request_window_at_acquisition(self):
        with Workspace() as space:
            journal = space.journal()
            binding = self.binding(created='2026-01-01T00:00:10Z', expires='2026-01-01T00:00:20Z')
            self.assertEqual(self.acquire(journal, binding, Clock().advance(9)), blocked('request-not-yet-valid'))
            self.assertEqual(self.acquire(journal, binding, Clock().advance(20)), blocked('request-expired'))
            self.assertEqual(self.acquire(journal, binding, Clock().advance(19))['status'], 'acquired')

    def test_same_scope_coalesces_and_other_scope_acquires(self):
        with Workspace() as space:
            journal = space.journal()
            first = self.acquire(journal, self.binding('synthetic-request-a'), Clock())
            second = self.acquire(journal, self.binding('synthetic-request-b'), Clock().advance(30), 'synthetic-client')
            self.assertEqual((second['status'], second['exitCode']), ('coalesced', None))
            self.assertEqual((second['attachedRequestId'], second['attachedClaimId']),
                             ('synthetic-request-a', first['claim']['claimId']))
            self.assertEqual((second['claim']['fence'], second['claim']['leaseUntil']),
                             (1, first['claim']['leaseUntil']))
            other = self.acquire(journal, self.binding('synthetic-request-c', trust='untrusted'), Clock())
            self.assertEqual((other['status'], other['claim']['fence']), ('acquired', 2))
            self.assertEqual([r['fence'] for r in space.records()], [0, 1, 1, 1, 1, 2])
            # A later request attaches to the acquired claim, never to an attachment.
            third = self.acquire(journal, self.binding('synthetic-request-d'), Clock().advance(31), 'synthetic-other')
            self.assertEqual((third['status'], third['attachedRequestId']), ('coalesced', 'synthetic-request-a'))

    def test_request_left_without_a_claim_does_not_hold_its_scope(self):
        import os
        from unittest.mock import patch
        from ci_contract import journal as journal_module
        original, calls = os.write, []
        def second_write_fails(descriptor, data):
            calls.append(len(data))
            if len(calls) == 2:
                raise OSError('synthetic write failure')
            return original(descriptor, data)
        with Workspace() as space:
            journal = space.journal()
            with patch.object(journal_module.os, 'write', second_write_fails):
                failed = self.acquire(journal, self.binding('synthetic-request-a'), Clock())
            self.assertEqual(failed, {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'journal-write-failed'})
            self.assertEqual(record_types(space), ['request'])
            other = self.acquire(journal, self.binding('synthetic-request-b'), Clock().advance(1))
            self.assertEqual((other['status'], other['claim']['fence']), ('acquired', 1))

    def test_expired_active_claim_freezes_its_scope(self):
        with Workspace() as space:
            journal = space.journal()
            self.acquire(journal, self.binding('synthetic-request-a'), Clock())
            self.assertEqual(self.acquire(journal, self.binding('synthetic-request-b'), Clock().advance(60)),
                             blocked('scope-claim-orphaned'))
            self.assertEqual(record_types(space)[-1], 'claim-orphaned')
            # A clock moved back cannot revive the frozen claim.
            self.assertEqual(self.acquire(journal, self.binding('synthetic-request-c'), Clock().advance(1)),
                             blocked('scope-claim-orphaned'))
            self.assertEqual(record_types(space).count('request'), 1)

    def test_closed_claim_releases_its_scope(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            docs = self.documents(binding, adopted, acquired)
            claim.ingest_receipt(journal, docs[2])
            self.assertEqual(claim.close(journal, binding['requestId'])['status'], 'closed')
            # Past the closed claim's lease end: closed is not orphaned and does not freeze the scope.
            following = self.acquire(journal, self.binding('synthetic-request-next'), clock.advance(61))
            self.assertEqual((following['status'], following['claim']['fence']), ('acquired', 2))
            self.assertNotIn('claim-orphaned', record_types(space))


class HeartbeatTests(ClaimCase):
    def test_renewal_extends_by_sixty_seconds(self):
        with Workspace() as space:
            journal = space.journal()
            self.acquire(journal, self.binding(), Clock())
            renewed = claim.heartbeat(journal, 'synthetic-request-unit', clock=Clock().advance(59))
            self.assertEqual((renewed['status'], renewed['claim']['leaseUntil']), ('leased', '2026-01-01T00:01:59Z'))
            self.assertEqual(renewed['heartbeatDueAt'], '2026-01-01T00:01:19Z')
            later = claim.heartbeat(journal, 'synthetic-request-unit', clock=Clock().advance(118), heartbeat_seconds=5)
            self.assertEqual(later['claim']['leaseUntil'], '2026-01-01T00:02:58Z')

    def test_expired_lease_is_frozen_not_renewed(self):
        with Workspace() as space:
            journal = space.journal()
            self.acquire(journal, self.binding(), Clock())
            self.assertEqual(claim.heartbeat(journal, 'synthetic-request-unit', clock=Clock().advance(60)),
                             blocked('heartbeat-lease-expired'))
            self.assertEqual(record_types(space)[-1], 'claim-orphaned')
            self.assertEqual(claim.heartbeat(journal, 'synthetic-request-unit', clock=Clock().advance(1)),
                             blocked('heartbeat-claim-not-leased'))

    def test_heartbeat_interval_over_twenty_seconds_is_invalid(self):
        with Workspace() as space:
            journal = space.journal()
            self.acquire(journal, self.binding(), Clock())
            for value in (21, 0, True, 20.0):
                with self.subTest(value=value):
                    self.assertEqual(claim.heartbeat(journal, 'synthetic-request-unit', clock=Clock(),
                                                     heartbeat_seconds=value), INVALID)
            self.assertEqual(claim.heartbeat(journal, 'Synthetic', clock=Clock()), INVALID)

    def test_only_an_acquired_leased_claim_is_renewed(self):
        with Workspace() as space:
            journal = space.journal()
            self.acquire(journal, self.binding('synthetic-request-a'), Clock())
            self.acquire(journal, self.binding('synthetic-request-b'), Clock(), 'synthetic-client')
            for request_id in ('synthetic-request-absent', 'synthetic-request-b'):
                with self.subTest(request_id=request_id):
                    self.assertEqual(claim.heartbeat(journal, request_id, clock=Clock()),
                                     blocked('heartbeat-claim-not-acquired'))

    def test_closed_claim_is_not_renewed(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            claim.ingest_receipt(journal, self.documents(binding, adopted, acquired)[2])
            claim.close(journal, binding['requestId'])
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock),
                             blocked('heartbeat-claim-not-leased'))

    def test_request_window_bounds_renewal(self):
        with Workspace() as space:
            journal = space.journal()
            self.acquire(journal, self.binding(expires='2026-01-01T00:00:30Z'), Clock())
            self.assertEqual(claim.heartbeat(journal, 'synthetic-request-unit', clock=Clock().advance(30)),
                             blocked('request-expired'))


class ReconciliationTests(ClaimCase):
    def test_zero_matches_is_unknown_and_nothing_is_resent(self):
        with Workspace() as space:
            journal, clock, binding, sender = self.submitted(space)
            query = Query([])
            observation = claim.reconcile(journal, binding['requestId'], query, clock=clock)
            self.assertEqual(observation, {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'reconcile-no-observed-run'})
            self.assertEqual(query.calls, [{'requestId': binding['requestId'], 'planSha256': binding['planSha256'],
                                            'workflowSha': binding['workflowCommit']}])
            self.assertEqual(len(sender.calls), 1)
            self.assertNotIn('adoption', record_types(space))

    def test_expired_lease_and_restart_do_not_resend(self):
        with Workspace() as space:
            journal, clock, binding, sender = self.submitted(space)
            later = Clock().advance(61)
            self.assertEqual(claim.reconcile(journal, binding['requestId'], Query([]), clock=later)['exitCode'], 8)
            restarted = space.journal(create=False)
            self.assertEqual(claim.reconcile(restarted, binding['requestId'], Query([]), clock=later)['exitCode'], 8)
            self.assertEqual(self.dispatch(restarted, binding, later, sender), blocked('dispatch-lease-expired'))
            self.assertEqual(claim.reconcile(restarted, binding['requestId'], Query([candidate(binding)]), clock=later),
                             blocked('adoption-claim-not-leased'))
            self.assertEqual(len(sender.calls), 1)
            self.assertTrue(all(r['payloadProjection'].get('target', 'github') == 'github' for r in space.records()))

    def test_multiple_candidates_are_a_conflict(self):
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            query = Query([candidate(binding), candidate(binding, run_id='124')])
            self.assertEqual(claim.reconcile(journal, binding['requestId'], query, clock=clock),
                             blocked('reconcile-multiple-runs'))
            query = Query([candidate(binding), candidate(binding, attempt=2)])
            self.assertEqual(claim.reconcile(journal, binding['requestId'], query, clock=clock),
                             blocked('reconcile-multiple-runs'))

    def test_foreign_runs_are_not_candidates(self):
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            for field, value in (('requestId', 'synthetic-other'), ('planSha256', 'a' * 64), ('workflowSha', 'a' * 40)):
                with self.subTest(field=field):
                    observation = claim.reconcile(journal, binding['requestId'],
                                                  Query([candidate(binding, **{field: value})]), clock=clock)
                    self.assertEqual(observation['exitCode'], 8)

    def test_malformed_query_results_are_invalid(self):
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            good = candidate(binding)
            for value in ({'runs': []}, [dict(good, extra=True)], [{k: v for k, v in good.items() if k != 'runId'}],
                          [dict(good, providerAttempt=True)], [dict(good, runId='0123')], [good] * 1001):
                with self.subTest(value=str(value)[:40]):
                    self.assertEqual(claim.reconcile(journal, binding['requestId'], Query(value), clock=clock), INVALID)

    def test_one_match_is_adopted_once(self):
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            adopted = claim.reconcile(journal, binding['requestId'], Query([candidate(binding)]), clock=clock)
            authority = adopted['attemptAuthority']
            record = space.records()[-1]
            self.assertEqual(record['recordType'], 'adoption')
            self.assertEqual((authority['attemptNumber'], authority['adoptedRunId'], authority['adoptedProviderAttempt'],
                              authority['fence'], authority['previousTerminalReceiptSha256']), (1, '123', 1, 1, None))
            self.assertEqual(authority['adoptionRecordSha256'], record['recordSha256'])
            query = Query([candidate(binding, run_id='999')])
            again = claim.reconcile(journal, binding['requestId'], query, clock=clock)
            self.assertEqual(again['attemptAuthority'], authority)
            self.assertEqual(query.calls, [])

    def test_request_state_preconditions(self):
        with Workspace() as space:
            journal = space.journal()
            clock = Clock()
            self.assertEqual(claim.reconcile(journal, 'synthetic-request-absent', Query([]), clock=clock),
                             blocked('reconcile-request-not-journaled'))
            self.acquire(journal, self.binding('synthetic-request-a'), clock)
            self.assertEqual(claim.reconcile(journal, 'synthetic-request-a', Query([]), clock=clock),
                             blocked('reconcile-not-submitted'))
            self.acquire(journal, self.binding('synthetic-request-b'), clock, 'synthetic-client')
            self.assertEqual(claim.reconcile(journal, 'synthetic-request-b', Query([]), clock=clock),
                             blocked('reconcile-claim-not-acquired'))
            self.assertEqual(claim.reconcile(journal, 'Synthetic', Query([]), clock=clock), INVALID)
            self.assertEqual(claim.reconcile(journal, 'synthetic-request-a', None, clock=clock), INVALID)


class AdoptionTests(ClaimCase):
    def adopt(self, journal, request_id, clock, run_id='123', attempt=1):
        return claim.adopt(journal, request_id, run_id=run_id, provider_attempt=attempt, clock=clock)

    def test_compare_and_set_of_run_and_provider_attempt(self):
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            first = self.adopt(journal, binding['requestId'], clock)
            size = len(space.bytes())
            self.assertEqual(self.adopt(journal, binding['requestId'], clock)['attemptAuthority'], first['attemptAuthority'])
            self.assertEqual(len(space.bytes()), size)
            self.assertEqual(self.adopt(journal, binding['requestId'], clock, run_id='124'), blocked('adoption-conflict'))
            self.assertEqual(self.adopt(journal, binding['requestId'], clock, attempt=2), blocked('adoption-conflict'))

    def test_adoption_requires_a_live_submitted_acquired_claim(self):
        with Workspace() as space:
            journal = space.journal()
            clock = Clock()
            self.assertEqual(self.adopt(journal, 'synthetic-request-absent', clock), blocked('adoption-claim-not-acquired'))
            self.acquire(journal, self.binding('synthetic-request-a'), clock)
            self.assertEqual(self.adopt(journal, 'synthetic-request-a', clock), blocked('adoption-before-submit'))
            self.acquire(journal, self.binding('synthetic-request-b'), clock, 'synthetic-client')
            self.assertEqual(self.adopt(journal, 'synthetic-request-b', clock), blocked('adoption-claim-not-acquired'))
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            self.assertEqual(self.adopt(journal, binding['requestId'], Clock().advance(60)), blocked('adoption-lease-expired'))
            self.assertEqual(record_types(space)[-1], 'claim-orphaned')
            self.assertEqual(self.adopt(journal, binding['requestId'], Clock()), blocked('adoption-claim-not-leased'))

    def test_closed_claim_is_not_adopted(self):
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            current = space.records()[-1]['payloadProjection']
            force_append(space, 'claim-closed', dict(current, state='closed'))
            self.assertEqual(self.adopt(journal, binding['requestId'], clock), blocked('adoption-claim-not-leased'))

    def test_adoption_input_shapes(self):
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            for run_id, attempt in (('0', 1), ('abc', 1), (123, 1), ('123', 0), ('123', True), ('123', 2 ** 53)):
                with self.subTest(run_id=run_id, attempt=attempt):
                    self.assertEqual(self.adopt(journal, binding['requestId'], clock, run_id, attempt), INVALID)

    def test_non_json_provider_attempt_is_invalid_even_when_equal(self):
        # The schema integer type admits 1.0; canonical JSON does not. Without that
        # check the equal-valued float would pass the compare-and-set as idempotent.
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            self.assertEqual(self.adopt(journal, binding['requestId'], clock)['status'], 'adopted')
            self.assertEqual(self.adopt(journal, binding['requestId'], clock, attempt=1.0), INVALID)


class ShapePrecedenceTests(unittest.TestCase):
    """Invalid arguments are invalid input (3) before any journal decision.

    The journal file does not exist, so every operation that reached the journal
    would be blocked (4) with journal-missing instead.
    """

    def test_each_operation_checks_its_arguments_first(self):
        bad, good = 'Synthetic Bad Id', 'synthetic-request'
        calls = {
            'heartbeat-request': lambda j: claim.heartbeat(j, bad, clock=Clock()),
            'heartbeat-policy': lambda j: claim.heartbeat(j, good, clock=Clock(), heartbeat_seconds=21),
            'reconcile-request': lambda j: claim.reconcile(j, bad, Query([]), clock=Clock()),
            'adopt-request': lambda j: claim.adopt(j, bad, run_id='123', provider_attempt=1, clock=Clock()),
            'adopt-run': lambda j: claim.adopt(j, good, run_id='0', provider_attempt=1, clock=Clock()),
            'adopt-attempt': lambda j: claim.adopt(j, good, run_id='123', provider_attempt=0, clock=Clock()),
            'close-request': lambda j: claim.close(j, bad),
            'approve-request': lambda j: claim.approve_retry(j, bad, clock=Clock()),
            'retry-request': lambda j: claim.retry(j, bad, owner_id='synthetic-owner', clock=Clock()),
            'retry-owner': lambda j: claim.retry(j, good, owner_id=bad, clock=Clock()),
        }
        with Workspace() as space:
            journal = space.journal(create=False)
            self.assertEqual(claim.close(journal, good), blocked('journal-missing'))
            for name, call in calls.items():
                with self.subTest(call=name):
                    self.assertEqual(call(journal), INVALID)


class ReceiptTests(ClaimCase):
    def test_receipt_preconditions(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            docs = self.documents(binding, adopted, acquired)
            result = docs[2]
            other = copy.deepcopy(result)
            other['requestBinding']['requestId'] = 'synthetic-request-absent'
            self.assertEqual(claim.ingest_receipt(journal, other), blocked('receipt-request-unknown'))
            other = copy.deepcopy(result)
            other['requestBinding']['attemptNumber'] = 2
            self.assertEqual(claim.ingest_receipt(journal, other), blocked('receipt-attempt-not-adopted'))
            for field, value in (('requestDigest', 'a' * 64), ('scopeKey', 'b' * 64), ('authorityKind', 'github-run-v1'),
                                 ('fence', 2), ('adoptionRecordSha256', 'c' * 64)):
                with self.subTest(field=field):
                    other = copy.deepcopy(result)
                    other['requestBinding'][field] = value
                    self.assertEqual(claim.ingest_receipt(journal, other), blocked('receipt-binding-mismatch'))
            self.assertNotIn('receipt', record_types(space))

    def test_receipt_shapes_are_invalid_first(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            plan, execution, result, _, _ = self.documents(binding, adopted, acquired)
            # An unknown request would be blocked (4); each shape error must win with 3.
            result = copy.deepcopy(result)
            result['requestBinding']['requestId'] = 'synthetic-request-absent'
            missing = copy.deepcopy(result)
            del missing['artifacts']
            calendar = dict(copy.deepcopy(result), completedAt='2026-02-30T00:00:00Z')
            duplicate = copy.deepcopy(result)
            duplicate['checks'].append(copy.deepcopy(duplicate['checks'][0]))
            other_kind = copy.deepcopy(execution)
            other_kind['requestBinding']['requestId'] = 'synthetic-request-absent'
            for name, value in (('missing', missing), ('kind', other_kind), ('calendar', calendar),
                                ('duplicate', duplicate)):
                with self.subTest(name):
                    self.assertEqual(claim.ingest_receipt(journal, value), INVALID)
            self.assertEqual(claim.ingest_receipt(journal, result), blocked('receipt-request-unknown'))

    def test_conflict_is_held_for_its_key(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            result = self.documents(binding, adopted, acquired)[2]
            claim.ingest_receipt(journal, result)
            changed = dict(copy.deepcopy(result), completedAt='2026-01-01T00:01:30Z')
            self.assertEqual(claim.ingest_receipt(journal, changed), blocked('content-conflict'))
            self.assertEqual(claim.ingest_receipt(journal, result), blocked('receipt-conflict-unresolved'))
            self.assertEqual(record_types(space)[-2:], ['receipt', 'receipt-conflict'])


class CloseAndRetryTests(ClaimCase):
    def orphaned(self, space, receipt=True, cleanup=True, pending=0, approve=True):
        journal, clock, binding, acquired, adopted = self.adopted(space)
        docs = self.documents(binding, adopted, acquired)
        later = Clock().advance(61)
        self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=later), blocked('heartbeat-lease-expired'))
        first = self.terminal(docs[2], cleanup, pending)
        if receipt:
            self.assertEqual(claim.ingest_receipt(journal, first)['status'], 'recorded')
        if approve:
            self.assertEqual(claim.approve_retry(journal, binding['requestId'], clock=later)['status'], 'retry-approved')
        return journal, later, binding, first

    def test_close_requires_terminal_receipt_cleanup_and_no_conflict(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            result = self.documents(binding, adopted, acquired)[2]
            self.assertEqual(claim.close(journal, binding['requestId']), blocked('attempt-terminal-missing'))
            self.assertEqual(claim.close(journal, 'synthetic-request-absent'), blocked('close-claim-not-acquired'))
            self.assertEqual(claim.close(journal, 'Synthetic'), INVALID)
            claim.ingest_receipt(journal, result)
            self.assertEqual(claim.close(journal, binding['requestId'])['status'], 'closed')
            self.assertEqual(claim.close(journal, binding['requestId']), blocked('close-claim-already-closed'))
        for cleanup, pending in ((False, 0), (True, 1)):
            with self.subTest(cleanup=cleanup, pending=pending), Workspace() as space:
                journal, clock, binding, acquired, adopted = self.adopted(space)
                result = self.terminal(self.documents(binding, adopted, acquired)[2], cleanup, pending)
                claim.ingest_receipt(journal, result)
                self.assertEqual(claim.close(journal, binding['requestId']), blocked('attempt-cleanup-unconfirmed'))
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            result = self.documents(binding, adopted, acquired)[2]
            claim.ingest_receipt(journal, result)
            claim.ingest_receipt(journal, dict(copy.deepcopy(result), completedAt='2026-01-01T00:01:30Z'))
            self.assertEqual(claim.close(journal, binding['requestId']), blocked('receipt-conflict-unresolved'))

    def test_close_of_an_unadopted_claim_is_rejected(self):
        with Workspace() as space:
            journal, clock, binding, _ = self.submitted(space)
            self.assertEqual(claim.close(journal, binding['requestId']), blocked('attempt-terminal-missing'))

    def test_close_of_a_coalesced_request_is_rejected(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            self.acquire(journal, self.binding('synthetic-request-attached'), clock, 'synthetic-client')
            self.assertEqual(claim.close(journal, 'synthetic-request-attached'), blocked('close-claim-not-acquired'))

    def test_approval_requires_an_orphaned_claim(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            self.assertEqual(claim.approve_retry(journal, binding['requestId'], clock=clock), blocked('retry-claim-not-orphaned'))
            self.assertEqual(claim.approve_retry(journal, 'synthetic-request-absent', clock=clock),
                             blocked('retry-claim-not-acquired'))
            self.assertEqual(claim.approve_retry(journal, binding['requestId'], clock=Clock().advance(60))['status'],
                             'retry-approved')
            self.assertEqual(record_types(space)[-2:], ['claim-orphaned', 'retry-approval'])

    def test_orphaned_attempt_is_not_readopted(self):
        with Workspace() as space:
            journal, later, binding, _ = self.orphaned(space, approve=False)
            self.assertEqual(claim.adopt(journal, binding['requestId'], run_id='124', provider_attempt=1, clock=later),
                             blocked('adoption-claim-not-leased'))
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=later), blocked('heartbeat-claim-not-leased'))

    def test_retry_requires_terminal_cleanup_and_later_approval(self):
        cases = (({'receipt': False}, 'attempt-terminal-missing'),
                 ({'cleanup': False}, 'attempt-cleanup-unconfirmed'),
                 ({'pending': 2}, 'attempt-cleanup-unconfirmed'),
                 ({'approve': False}, 'retry-not-approved'))
        for options, reason in cases:
            with self.subTest(options=options), Workspace() as space:
                journal, later, binding, _ = self.orphaned(space, **options)
                self.assertEqual(claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=later),
                                 blocked(reason))
                self.assertEqual(record_types(space).count('claim-acquired'), 1)

    def test_retry_preconditions_on_claim_window_and_conflict(self):
        with Workspace() as space:
            journal, clock, binding, acquired, adopted = self.adopted(space)
            self.assertEqual(claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=clock),
                             blocked('retry-claim-not-orphaned'))
            self.assertEqual(claim.retry(journal, 'synthetic-request-absent', owner_id='synthetic-supervisor', clock=clock),
                             blocked('retry-claim-not-acquired'))
            self.assertEqual(claim.retry(journal, binding['requestId'], owner_id='Synthetic', clock=clock), INVALID)
        with Workspace() as space:
            journal, later, binding, first = self.orphaned(space)
            claim.ingest_receipt(journal, dict(copy.deepcopy(first), completedAt='2026-01-01T00:01:30Z'))
            self.assertEqual(claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=later),
                             blocked('receipt-conflict-unresolved'))
        with Workspace() as space:
            journal, later, binding, _ = self.orphaned(space)
            self.assertEqual(claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor',
                                         clock=Clock().advance(3600)), blocked('request-expired'))

    def test_retry_adopts_a_new_attempt_bound_to_the_previous_terminal(self):
        with Workspace() as space:
            journal, later, binding, first = self.orphaned(space)
            again = claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=later)
            self.assertEqual((again['status'], again['attemptNumber'], again['claim']['fence']), ('acquired', 2, 2))
            self.assertEqual(self.dispatch(journal, binding, later)['status'], 'submitted')
            adopted = claim.reconcile(journal, binding['requestId'], Query([candidate(binding, run_id='124')]), clock=later)
            authority = adopted['attemptAuthority']
            self.assertEqual((authority['attemptNumber'], authority['fence'], authority['adoptedRunId']), (2, 2, '124'))
            self.assertEqual(authority['previousTerminalReceiptSha256'], domain_hash('result', first))

    def test_retry_after_an_unknown_attempt_is_blocked_and_sends_nothing(self):
        # An unknown receipt is not terminal: the owner's retry is refused and no second send is made.
        with Workspace() as space:
            binding = self.binding()
            journal, sender, acquired, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, Clock(),
                                                                 stub=True)
            self.assertEqual((adopted['status'], len(sender.calls)), ('adopted', 1))
            later = Clock().advance(61)
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=later), blocked('heartbeat-lease-expired'))
            result = self.documents(binding, adopted, acquired)[2]
            result.update(status='unknown', exitCode=8, cleanupConfirmed=True, pendingChildren=0)
            self.assertEqual(claim.ingest_receipt(journal, result)['status'], 'recorded')
            self.assertEqual(claim.approve_retry(journal, binding['requestId'], clock=later)['status'], 'retry-approved')
            before = record_types(space)
            self.assertEqual(claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=later),
                             blocked('attempt-terminal-unknown'))
            self.assertEqual(record_types(space), before)
            self.assertEqual(self.dispatch(journal, binding, later, sender)['status'], 'blocked')
            self.assertEqual(len(sender.calls), 1)

    def test_an_earlier_approval_does_not_cover_a_later_orphaning(self):
        with Workspace() as space:
            journal, later, binding, first = self.orphaned(space)
            claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=later)
            self.dispatch(journal, binding, later)
            adopted = claim.reconcile(journal, binding['requestId'], Query([candidate(binding, run_id='124')]), clock=later)
            latest = Clock().advance(61 + 61)
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=latest), blocked('heartbeat-lease-expired'))
            acquired = next(r['payloadProjection'] for r in reversed(space.records()) if r['recordType'] == 'claim-acquired')
            second = self.terminal(adopted_documents(self.plan, binding, adopted['attemptAuthority'], acquired)[2])
            self.assertEqual(claim.ingest_receipt(journal, second)['status'], 'recorded')
            self.assertEqual(claim.retry(journal, binding['requestId'], owner_id='synthetic-supervisor', clock=latest),
                             blocked('retry-not-approved'))


if __name__ == '__main__':
    unittest.main()
