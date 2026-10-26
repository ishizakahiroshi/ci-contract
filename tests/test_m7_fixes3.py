"""M7 fixes 5 (fourth refutation, A and B): a clock so late that the lease cannot be
represented, a clock zone consulted again after the single read, and impossible calendar
times in a resealed journal.

Synthetic data only. Tests named ``test_fails_on_399b449_*`` state a required behavior that
the reviewed commit 399b449 does not meet; they fail there and pass after the fixes. The
other tests are positive controls and pass on 399b449 as well.
"""
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
from ci_contract import claim
from synthetic_claim import (Clock, Workspace, adopted_documents, adopted_flow, binding_for, encode, record_types,
                             seal, shared_plan)

INVALID = {'status': 'invalid-input', 'exitCode': 3}
END_CREATED = '9999-12-31T23:00:00Z'
END_EXPIRES = '9999-12-31T23:59:59Z'


def unknown(reason):
    return {'status': 'unknown', 'exitCode': 8, 'reasonCode': reason}


def at_the_end(hour, minute, second):
    return datetime(9999, 12, 31, hour, minute, second, tzinfo=timezone.utc)


class OnceZone(tzinfo):
    """Answers UTC to the first offset query and raises on every later one."""

    def __init__(self):
        self.queries = 0

    def utcoffset(self, value):
        self.queries += 1
        if self.queries > 1:
            raise RuntimeError('synthetic tzinfo failure')
        return timedelta(0)

    def dst(self, value):
        return None

    def tzname(self, value):
        return 'synthetic'


class CaseBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def submitted(self, space, request_id):
        """Acquired and sent once; the journal holds request, claim-acquired and submit-unknown."""
        binding = binding_for(self.plan, request_id)
        journal, sender, _, _, _ = adopted_flow(space, self.plan, self.fixed, binding, Clock(), stub=True)
        self.assertEqual(len(sender.calls), 1)
        return journal, binding

    def resealed(self, space, change):
        """Apply one payload change to the journal and reseal it (chain and hashes consistent)."""
        records = space.records()
        change(records)
        space.write(encode(seal(records)))
        return space.journal(create=False), space.bytes()


class ClockRangeFix(CaseBase):
    """A: every lease and heartbeat time is the clock plus at most 60 seconds; a clock where that
    cannot be represented is invalid input (3), refused before any record is appended."""

    def test_fails_on_399b449_acquire_near_the_end_of_year_9999_is_invalid_input_and_writes_nothing(self):
        with Workspace() as space:
            journal = space.journal()
            before = space.bytes()
            binding = binding_for(self.plan, 'synthetic-request-clock-end', created=END_CREATED,
                                  expires=END_EXPIRES)
            outcome = claim.acquire(journal, binding, owner_id='synthetic-supervisor',
                                    clock=lambda: at_the_end(23, 59, 58))
            self.assertEqual(outcome, INVALID)
            self.assertEqual(space.bytes(), before)
            # The request was not registered, so the same request ID is not refused later.
            acquired = claim.acquire(journal, binding, owner_id='synthetic-supervisor',
                                     clock=lambda: at_the_end(23, 30, 0))
            self.assertEqual(acquired['status'], 'acquired')

    def test_fails_on_399b449_heartbeat_near_the_end_of_year_9999_is_invalid_input_and_writes_nothing(self):
        with Workspace() as space:
            journal = space.journal()
            binding = binding_for(self.plan, 'synthetic-request-heartbeat-end', created=END_CREATED,
                                  expires=END_EXPIRES)
            clock = Clock(at_the_end(23, 58, 0))
            self.assertEqual(claim.acquire(journal, binding, owner_id='synthetic-supervisor',
                                           clock=clock)['status'], 'acquired')
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock.advance(58))['status'],
                             'leased')
            before = space.bytes()
            # 23:59:30 is inside the request window and the live lease, but now + 60 s is past year 9999.
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock.advance(32)), INVALID)
            self.assertEqual(space.bytes(), before)

    def test_the_last_representable_lease_is_still_acquired(self):
        # Positive control: now + 60 s exactly at the last second of year 9999 is representable.
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-last-lease', created=END_CREATED,
                                  expires=END_EXPIRES)
            outcome = claim.acquire(space.journal(), binding, owner_id='synthetic-supervisor',
                                    clock=lambda: at_the_end(23, 58, 59))
            self.assertEqual(outcome['status'], 'acquired')
            self.assertEqual(outcome['claim']['leaseUntil'], END_EXPIRES)


class ClockReadOnceFix(CaseBase):
    """A, same class: the clock value is read once; its zone is not consulted again afterwards."""

    def test_fails_on_399b449_a_zone_consulted_again_does_not_escape(self):
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-once-zone')
            zone = OnceZone()
            outcome = claim.acquire(space.journal(), binding, owner_id='synthetic-supervisor',
                                    clock=lambda: datetime(2026, 1, 1, 0, 0, 1, tzinfo=zone))
            self.assertEqual(outcome['status'], 'acquired')
            self.assertEqual(zone.queries, 1)
            self.assertEqual(outcome['claim']['leaseUntil'], '2026-01-01T00:01:01Z')


class ImpossibleCalendarFix(CaseBase):
    """B: a resealed journal whose payload holds an impossible UTC time, or a request binding
    the write path would refuse, is an invalid record (unknown 8), never invalid input (3)."""

    def test_fails_on_399b449_impossible_lease_time_is_an_invalid_record(self):
        with Workspace() as space:
            _, binding = self.submitted(space, 'synthetic-request-calendar-claim')

            def change(records):
                [item for item in records if item['payloadKind'] == 'claim'][-1]['payloadProjection'][
                    'leaseUntil'] = '2026-02-30T00:00:00Z'
            journal, before = self.resealed(space, change)
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=Clock().advance(1)),
                             unknown('journal-record-invalid'))
            self.assertEqual(space.bytes(), before)

    def test_fails_on_399b449_impossible_request_time_is_an_invalid_record(self):
        with Workspace() as space:
            self.submitted(space, 'synthetic-request-calendar-binding')

            def change(records):
                next(item for item in records if item['recordType'] == 'request')['payloadProjection'][
                    'expiresAt'] = '2026-02-31T00:00:00Z'
            journal, before = self.resealed(space, change)
            outcome = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-second'),
                                    owner_id='synthetic-supervisor', clock=Clock())
            self.assertEqual(outcome, unknown('journal-record-invalid'))
            self.assertEqual(space.bytes(), before)

    def test_fails_on_399b449_request_the_write_path_refuses_is_an_invalid_record(self):
        # A real calendar time, but an empty interval: validate_request_binding refuses it on write.
        with Workspace() as space:
            self.submitted(space, 'synthetic-request-empty-interval')

            def change(records):
                request = next(item for item in records if item['recordType'] == 'request')['payloadProjection']
                request['expiresAt'] = request['createdAt']
            journal, before = self.resealed(space, change)
            outcome = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-third'),
                                    owner_id='synthetic-supervisor', clock=Clock())
            self.assertEqual(outcome, unknown('journal-record-invalid'))
            self.assertEqual(space.bytes(), before)

    def test_fails_on_399b449_impossible_receipt_time_is_an_invalid_record(self):
        rid = 'synthetic-request-calendar-receipt'
        with Workspace() as space:
            binding = binding_for(self.plan, rid)
            journal, _, acquired, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, Clock(), stub=True)
            result = adopted_documents(self.plan, binding, adopted['attemptAuthority'], acquired['claim'])[2]
            result.update(status='timeout', exitCode=7, cleanupConfirmed=True, pendingChildren=0)
            self.assertEqual(claim.ingest_receipt(journal, result)['status'], 'recorded')

            def change(records):
                next(item for item in records if item['recordType'] == 'receipt')['payloadProjection'][
                    'completedAt'] = '2026-02-30T00:00:00Z'
            journal, before = self.resealed(space, change)
            self.assertEqual(claim.close(journal, rid), unknown('journal-record-invalid'))
            self.assertNotIn('claim-closed', record_types(space))
            self.assertEqual(space.bytes(), before)

    def test_a_consistent_resealed_journal_is_still_read(self):
        # Positive control: resealing without a change keeps the journal readable.
        with Workspace() as space:
            _, binding = self.submitted(space, 'synthetic-request-calendar-control')
            journal, _ = self.resealed(space, lambda records: None)
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=Clock().advance(1))['status'],
                             'leased')


if __name__ == '__main__':
    unittest.main()
