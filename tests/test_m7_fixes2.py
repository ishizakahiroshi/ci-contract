"""M7 fixes 4 (third refutation, F1-F6): receipt binding and duplicate keys, clock and
location-probe and journal-read failures, and the two internal dispatch authority checks.

Synthetic data only. Tests named ``test_fails_on_f390cb4_*`` state a required behavior that
the reviewed commit f390cb4 does not meet; they fail there and pass after the fixes. The
white-box tests in DispatchAuthorityChecks pass on f390cb4 as well, because those two
branches already exist there; their proof is a mutant that removes each branch (RESULTS.md).
"""
import copy
import os
import unittest
from datetime import datetime, tzinfo
from unittest.mock import patch
from ci_contract import claim
from ci_contract import journal as journal_module
from ci_contract.errors import BlockedError
from ci_contract.journal import LocalJournal, SystemProbe
from ci_contract.request_binding import request_digest
from synthetic_claim import (AUTHORITY, T0, Clock, Sender, Workspace, adopted_documents, adopted_flow, binding_for,
                             force_append, inputs_for, record_types, shared_plan, stub_reconstruction)

OTHER = 'synthetic-other-authority'
INVALID = {'status': 'invalid-input', 'exitCode': 3}


def blocked(reason):
    return {'status': 'blocked', 'exitCode': 4, 'reasonCode': reason}


def unknown(reason):
    return {'status': 'unknown', 'exitCode': 8, 'reasonCode': reason}


def _raising_clock():
    raise RuntimeError('synthetic clock failure')


class BrokenZone(tzinfo):
    def utcoffset(self, value):
        raise RuntimeError('synthetic tzinfo failure')

    def dst(self, value):
        return None

    def tzname(self, value):
        return 'synthetic'


class RaisingProbe(SystemProbe):
    """Every OS query of the Windows and POSIX placement branches raises."""

    def drive_type(self, root):
        raise RuntimeError('synthetic probe failure')

    def owner_mode(self, value):
        raise RuntimeError('synthetic probe failure')

    def effective_uid(self):
        raise RuntimeError('synthetic probe failure')


class RaisingRealpath(SystemProbe):
    """A probe query that is common to both branches and is not an OSError."""

    def realpath(self, value):
        raise RuntimeError('synthetic probe failure')


class NoAppend:
    """Stands in for a transaction where a refusal must happen before any append."""

    def append(self, *args, **kwargs):
        raise AssertionError('no journal write is expected before the refusal')


def claim_payload(binding, *, fence=1, authority_id=AUTHORITY):
    """A journaled acquired claim of the given authority, shaped as the M7 claim record."""
    from ci_contract.request_binding import scope_key
    return {'kind': 'claim', 'authority': 'local-single-supervisor-v1', 'authorityId': authority_id,
            'claimId': 'synthetic-claim-%d' % fence, 'ownerId': 'synthetic-supervisor',
            'scopeKey': scope_key(binding), 'requestId': binding['requestId'],
            'requestDigest': request_digest(binding), 'fence': fence, 'acquisition': 'acquired',
            'state': 'leased', 'leaseUntil': '2026-01-01T00:01:00Z', 'ledgerSequence': 1,
            'ledgerRecordSha256': '0' * 64}


class CaseBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def adopted_result(self, space, request_id):
        """An adopted attempt 1 of a fresh request, with its synthetic result document."""
        binding = binding_for(self.plan, request_id)
        journal, _, acquired, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, Clock(), stub=True)
        self.assertEqual(adopted['status'], 'adopted')
        result = adopted_documents(self.plan, binding, adopted['attemptAuthority'], acquired['claim'])[2]
        return journal, binding, result


class ReceiptBindingFix(CaseBase):
    """F1: a journaled receipt must name the digest of the journaled request with its requestId."""

    def test_fails_on_f390cb4_receipt_naming_another_request_is_journal_corruption(self):
        rid = 'synthetic-request-foreign-digest'
        with Workspace() as space:
            journal, binding, result = self.adopted_result(space, rid)
            result.update(status='timeout', exitCode=7, cleanupConfirmed=True, pendingChildren=0)
            result['requestBinding']['requestDigest'] = request_digest(binding_for(self.plan, rid, authority_id=OTHER))
            force_append(space, 'receipt', result)
            before = space.bytes()
            self.assertEqual(claim.close(journal, rid), unknown('journal-receipt-binding-mismatch'))
            self.assertNotIn('claim-closed', record_types(space))
            # The corruption stops every decision on this journal, not only the close.
            other = binding_for(self.plan, 'synthetic-request-after-corruption')
            self.assertEqual(claim.acquire(journal, other, owner_id='synthetic-supervisor', clock=Clock()),
                             unknown('journal-receipt-binding-mismatch'))
            self.assertEqual(space.bytes(), before)

    def test_fails_on_f390cb4_receipt_without_a_journaled_request_is_journal_corruption(self):
        rid = 'synthetic-request-not-journaled'
        with Workspace() as other_space:
            _, _, result = self.adopted_result(other_space, rid)
        with Workspace() as space:
            journal = space.journal()
            force_append(space, 'receipt', result)
            self.assertEqual(claim.close(journal, rid), unknown('journal-receipt-binding-mismatch'))
            self.assertNotIn('claim-closed', record_types(space))

    def test_own_digest_receipt_is_still_recorded_and_closes(self):
        # Positive control: the API path with the journaled request's own digest is unchanged.
        with Workspace() as space:
            journal, binding, result = self.adopted_result(space, 'synthetic-request-own-digest')
            result.update(status='timeout', exitCode=7, cleanupConfirmed=True, pendingChildren=0)
            self.assertEqual(claim.ingest_receipt(journal, result)['status'], 'recorded')
            self.assertEqual(claim.close(journal, binding['requestId'])['status'], 'closed')


class DuplicateReceiptFix(CaseBase):
    """F2: a second receipt record with the same (requestId, attemptNumber, fence) is journal corruption."""

    def test_fails_on_f390cb4_second_receipt_for_the_same_key_is_journal_corruption(self):
        for second in ('same-digest', 'other-digest'):
            with self.subTest(second=second), Workspace() as space:
                journal, binding, result = self.adopted_result(space, 'synthetic-request-duplicate-' + second)
                rid = binding['requestId']
                first = dict(copy.deepcopy(result), status='unknown', exitCode=8, cleanupConfirmed=True, pendingChildren=0)
                self.assertEqual(claim.ingest_receipt(journal, first)['status'], 'recorded')
                later = Clock().advance(61)
                self.assertEqual(claim.heartbeat(journal, rid, clock=later)['reasonCode'], 'heartbeat-lease-expired')
                self.assertEqual(claim.approve_retry(journal, rid, clock=later)['status'], 'retry-approved')
                if second == 'same-digest':
                    duplicate = copy.deepcopy(first)
                else:
                    duplicate = dict(copy.deepcopy(first), status='timeout', exitCode=7)
                force_append(space, 'receipt', duplicate)
                before = space.bytes()
                self.assertEqual(claim.retry(journal, rid, owner_id='synthetic-supervisor', clock=later),
                                 unknown('journal-duplicate-receipt'))
                self.assertEqual(space.bytes(), before)
                self.assertEqual(record_types(space).count('claim-acquired'), 1)

    def test_api_same_digest_is_a_no_op_and_a_different_digest_is_a_conflict(self):
        # Positive control: the API path is unchanged by the fold check.
        with Workspace() as space:
            journal, binding, result = self.adopted_result(space, 'synthetic-request-api-receipts')
            self.assertEqual(claim.ingest_receipt(journal, result)['status'], 'recorded')
            self.assertEqual(claim.ingest_receipt(journal, result)['status'], 'idempotent-no-op')
            changed = dict(copy.deepcopy(result), completedAt='2026-01-01T00:01:30Z')
            self.assertEqual(claim.ingest_receipt(journal, changed), blocked('content-conflict'))
            self.assertEqual(record_types(space).count('receipt'), 1)
            self.assertEqual(record_types(space).count('receipt-conflict'), 1)


class ClockFailureFix(CaseBase):
    """F3: a clock that raises, or whose tzinfo raises, is invalid input (3), and nothing is appended."""

    def test_fails_on_f390cb4_a_raising_clock_or_tzinfo_is_invalid_input(self):
        clocks = (('clock', _raising_clock), ('tzinfo', lambda: datetime(2026, 1, 1, tzinfo=BrokenZone())))
        for name, clock in clocks:
            with self.subTest(clock=name), Workspace() as space:
                journal = space.journal()
                before = space.bytes()
                binding = binding_for(self.plan, 'synthetic-request-broken-' + name)
                self.assertEqual(claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock), INVALID)
                self.assertEqual(space.bytes(), before)

    def test_fails_on_f390cb4_a_raising_clock_in_each_clock_using_operation_is_invalid_input(self):
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-clock-operations')
            journal, _, _, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, Clock(), stub=True)
            self.assertEqual(adopted['status'], 'adopted')
            rid = binding['requestId']

            def dispatch():
                with stub_reconstruction():
                    return claim.dispatch(journal, inputs_for(self.plan, binding), binding, Sender(),
                                          clock=_raising_clock, **self.fixed)
            calls = {
                'acquire': lambda: claim.acquire(journal, binding_for(self.plan, 'synthetic-request-clock-new'),
                                                 owner_id='synthetic-supervisor', clock=_raising_clock),
                'heartbeat': lambda: claim.heartbeat(journal, rid, clock=_raising_clock),
                'adopt': lambda: claim.adopt(journal, rid, run_id='124', provider_attempt=1, clock=_raising_clock),
                'approve-retry': lambda: claim.approve_retry(journal, rid, clock=_raising_clock),
                'retry': lambda: claim.retry(journal, rid, owner_id='synthetic-supervisor', clock=_raising_clock),
                'dispatch': dispatch,
            }
            before = space.bytes()
            for name, call in calls.items():
                with self.subTest(operation=name):
                    self.assertEqual(call(), INVALID)
                    self.assertEqual(space.bytes(), before)


class ProbeFailureFix(CaseBase):
    """F4: an exception from the location probe is blocked (4) with journal-location-unverified."""

    def test_fails_on_f390cb4_a_raising_location_probe_is_blocked_and_appends_nothing(self):
        for probe in (RaisingProbe(), RaisingRealpath()):
            with self.subTest(probe=type(probe).__name__), Workspace() as space:
                space.journal()
                before = space.bytes()
                journal = space.journal(create=False, probe=probe)
                request_id = 'synthetic-request-probe-' + type(probe).__name__.lower()
                outcome = claim.acquire(journal, binding_for(self.plan, request_id),
                                        owner_id='synthetic-supervisor', clock=Clock())
                self.assertEqual(outcome, blocked('journal-location-unverified'))
                self.assertEqual(space.bytes(), before)

    def test_fails_on_f390cb4_a_raising_probe_creates_no_journal(self):
        with Workspace() as space:
            with self.assertRaises(BlockedError) as raised:
                LocalJournal.create(space.path, authority_id=AUTHORITY, repository_roots=[str(space.repository)],
                                    probe=RaisingRealpath())
            self.assertEqual(raised.exception.reason_code, 'journal-location-unverified')
            self.assertFalse(os.path.exists(space.path))


class UnreadableJournalFix(CaseBase):
    """F5: an OSError while reading the journal after the existence check is blocked (4)."""

    def test_fails_on_f390cb4_journal_removed_after_the_check_is_unreadable(self):
        with Workspace() as space:
            space.journal()
            os.remove(space.path)
            journal = space.journal(create=False)
            with patch.object(journal_module.os.path, 'isfile', return_value=True):
                outcome = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-removed'),
                                        owner_id='synthetic-supervisor', clock=Clock())
            self.assertEqual(outcome, blocked('journal-unreadable'))
            self.assertFalse(os.path.exists(space.path))

    def test_fails_on_f390cb4_a_read_error_after_the_check_is_unreadable(self):
        for failure in (PermissionError, OSError):
            with self.subTest(failure=failure.__name__), Workspace() as space:
                journal = space.journal()
                before = space.bytes()
                request_id = 'synthetic-request-read-' + failure.__name__.lower()
                with patch.object(journal_module, 'read_records', side_effect=failure('synthetic read failure')):
                    outcome = claim.acquire(journal, binding_for(self.plan, request_id),
                                            owner_id='synthetic-supervisor', clock=Clock())
                self.assertEqual(outcome, blocked('journal-unreadable'))
                self.assertEqual(space.bytes(), before)


class DispatchAuthorityChecks(CaseBase):
    """F6: the two internal dispatch authority checks, executed by calling _authorized_claim directly.

    Through dispatch both branches are unreachable (check_authority and the binding comparison
    refuse first), so these tests are the only executions of the two branches.
    """

    def test_dispatch_authority_mismatch_branch_is_refused_and_its_control_passes(self):
        with Workspace() as space:
            journal = space.journal()
            binding = binding_for(self.plan, 'synthetic-request-branch-authority')
            acquired = claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=Clock())
            self.assertEqual(acquired['status'], 'acquired')
            before = space.bytes()
            with journal.transaction() as transaction:
                state = claim._State(transaction.records)
                with self.assertRaises(BlockedError) as raised:
                    claim._authorized_claim(transaction, state, binding, T0, OTHER)
                self.assertEqual(raised.exception.reason_code, 'dispatch-authority-mismatch')
                control = claim._authorized_claim(transaction, state, binding, T0, AUTHORITY)
                self.assertEqual(control['claimId'], acquired['claim']['claimId'])
            self.assertEqual(space.bytes(), before)

    def test_dispatch_claim_authority_mismatch_branch_is_refused_and_its_control_passes(self):
        binding = binding_for(self.plan, 'synthetic-request-branch-claim')

        def records(claim_authority):
            # Not reachable through a journal (check_authority refuses a foreign claim), so the fold is fed directly.
            return [{'sequence': 1, 'recordType': 'request', 'payloadProjection': binding},
                    {'sequence': 2, 'recordType': 'claim-acquired',
                     'payloadProjection': claim_payload(binding, authority_id=claim_authority)}]
        with self.assertRaises(BlockedError) as raised:
            claim._authorized_claim(NoAppend(), claim._State(records(OTHER)), binding, T0, AUTHORITY)
        self.assertEqual(raised.exception.reason_code, 'dispatch-claim-authority-mismatch')
        control = claim._authorized_claim(NoAppend(), claim._State(records(AUTHORITY)), binding, T0, AUTHORITY)
        self.assertEqual(control['authorityId'], AUTHORITY)


if __name__ == '__main__':
    unittest.main()