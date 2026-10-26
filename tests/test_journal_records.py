"""Journal record verification, append/sync ordering and transaction boundaries.

Each crafted journal changes one property and reseals everything else with the
pinned journal-record domain hash, so exactly one verification rule rejects it.
A rejected journal is reported unknown; it is never repaired, truncated or
renumbered, and no further record is appended to it.
"""
import copy
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from ci_contract import cjson, claim
from ci_contract import journal as journal_module
from ci_contract.errors import BlockedError, InputError
from ci_contract.hashing import domain_hash
from ci_contract.journal import AuthorityUnknown, LocalJournal, parse_records
from synthetic_claim import (AUTHORITY, Clock, Workspace, adopted_documents, adopted_flow, binding_for, encode,
                             seal, shared_plan)
from synthetic_verify import digest


class Template:
    data = None

    @classmethod
    def build(cls):
        if cls.data is None:
            plan, fixed = shared_plan()
            with Workspace() as space:
                clock = Clock()
                binding = binding_for(plan, 'synthetic-request-template')
                journal, _, acquired, _, adopted = adopted_flow(space, plan, fixed, binding, clock, stub=True)
                claim.acquire(journal, binding_for(plan, 'synthetic-request-attached'),
                              owner_id='synthetic-client', clock=clock)
                docs = adopted_documents(plan, binding, adopted['attemptAuthority'], acquired['claim'])
                claim.ingest_receipt(journal, docs[2])
                cls.data = space.bytes()
                cls.plan = plan
        return cls.data


def records():
    return [cjson.loads(line) for line in Template.build().split(b'\n') if line]


def index_of(items, record_type):
    return next(i for i, record in enumerate(items) if record['recordType'] == record_type)


class RecordVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Template.build()

    def unknown(self, data, reason):
        with self.assertRaises(AuthorityUnknown) as raised:
            parse_records(data)
        self.assertEqual(raised.exception.reason_code, reason)

    def test_template_covers_every_payload_kind(self):
        items = parse_records(Template.data)
        self.assertEqual([r['recordType'] for r in items],
                         ['request', 'claim-acquired', 'submit-unknown', 'adoption', 'request', 'claim-coalesced', 'receipt'])
        self.assertEqual([r['sequence'] for r in items], list(range(1, len(items) + 1)))
        self.assertIsNone(items[0]['previousRecordSha256'])
        for previous, current in zip(items, items[1:]):
            self.assertEqual(current['previousRecordSha256'], previous['recordSha256'])
        self.assertEqual([r['fence'] for r in items], [0, 1, 1, 1, 1, 1, 1])
        self.assertEqual(parse_records(b''), [])

    def test_review_tampering_forms_all_stop(self):
        data = Template.data
        lines = data.split(b'\n')[:-1]
        position = data.index(b'synthetic-request-template') + 12
        self.assertEqual(data[position:position + 1], b'q')
        one_byte = data[:position] + b'z' + data[position + 1:]
        removed = b'\n'.join(lines[:2] + lines[3:]) + b'\n'
        swapped = b'\n'.join(lines[:1] + [lines[2], lines[1]] + lines[3:]) + b'\n'
        for name, changed, reason in (('one byte', one_byte, 'journal-record-hash-mismatch'),
                                      ('one removed', removed, 'journal-sequence-gap'),
                                      ('two swapped', swapped, 'journal-sequence-gap'),
                                      ('cut last line', data[:-40], 'journal-unterminated-record'),
                                      ('final LF missing', data[:-1], 'journal-unterminated-record')):
            with self.subTest(name):
                self.unknown(changed, reason)

    def test_stopped_journal_is_never_repaired_or_extended(self):
        plan = Template.plan
        with Workspace() as space:
            space.write(Template.data[:-1])
            journal = space.journal(create=False)
            before = space.bytes()
            for observation in (claim.acquire(journal, binding_for(plan, 'synthetic-request-new'),
                                              owner_id='synthetic-client', clock=Clock()),
                                claim.heartbeat(journal, 'synthetic-request-template', clock=Clock())):
                self.assertEqual((observation['status'], observation['exitCode']), ('unknown', 8))
            self.assertEqual(space.bytes(), before)

    def test_invalid_json_and_empty_line(self):
        lines = Template.data.split(b'\n')[:-1]
        self.unknown(b'\n'.join(lines[:1] + [b'{not json'] + lines[1:]) + b'\n', 'journal-record-invalid')
        self.unknown(b'\n'.join(lines[:1] + [b''] + lines[1:]) + b'\n', 'journal-record-invalid')

    def test_noncanonical_bytes(self):
        lines = Template.data.split(b'\n')[:-1]
        lines[1] = lines[1].replace(b'":', b'": ', 1)
        self.unknown(b'\n'.join(lines) + b'\n', 'journal-record-noncanonical')
        crlf = Template.data.replace(b'\n', b'\r\n')
        self.unknown(crlf, 'journal-record-noncanonical')

    def test_non_object_record_and_text_input(self):
        self.unknown(b'7\n', 'journal-record-invalid')
        with self.assertRaises(InputError):
            parse_records(Template.data.decode('utf-8'))

    def test_payload_whose_projection_cannot_be_hashed(self):
        items = records()
        # Schema-valid, but the registered result check set rejects a duplicate ID.
        checks = items[index_of(items, 'receipt')]['payloadProjection']['checks']
        checks.append(copy.deepcopy(checks[0]))
        self.unknown(encode(items), 'journal-record-invalid')

    def test_closed_record_keys(self):
        items = records()
        del items[1]['fence']
        with self.assertRaises(AuthorityUnknown) as raised:
            parse_records(encode(items))
        self.assertEqual(raised.exception.reason_code, 'journal-record-invalid')
        items = records()
        items[1]['extra'] = True
        self.unknown(encode(items), 'journal-record-invalid')

    def test_record_type_and_payload_kind(self):
        items = records()
        items[0]['recordType'] = ['request']
        self.unknown(encode(seal(items)), 'journal-record-invalid')
        items = records()
        items[0]['recordType'] = 'synthetic-other'
        items[0]['payloadKind'] = None
        self.unknown(encode(items), 'journal-record-invalid')
        items = records()
        claim_record = items[1]
        claim_record['recordType'], claim_record['payloadKind'] = 'claim-acquired', 'requestBinding'
        claim_record['payloadProjection'] = copy.deepcopy(items[0]['payloadProjection'])
        self.unknown(encode(seal(items)), 'journal-record-invalid')

    def test_boolean_sequence_and_fence_are_not_integers(self):
        items = records()[:1]
        items[0]['sequence'] = True
        self.unknown(encode(seal(items)), 'journal-record-invalid')
        items = records()[:1]
        items[0]['fence'] = False
        self.unknown(encode(seal(items)), 'journal-record-invalid')

    def test_payload_must_match_its_pinned_definition(self):
        items = records()
        del items[0]['payloadProjection']['trust']
        self.unknown(encode(seal(items)), 'journal-record-invalid')

    def test_sequence_gap_with_a_resealed_chain(self):
        items = records()
        del items[2]
        self.unknown(encode(seal(items)), 'journal-sequence-gap')

    def test_chain_mismatch_with_resealed_hashes(self):
        items = records()
        items[3]['previousRecordSha256'] = digest('synthetic-other-record')
        self.unknown(encode(seal(items, chain=False)), 'journal-chain-mismatch')

    def test_record_hash_mismatch(self):
        items = records()
        items[4]['payloadProjection']['trust'] = 'untrusted'
        self.unknown(encode(items), 'journal-record-hash-mismatch')

    def test_current_record_backlinks(self):
        items = records()
        items[1]['payloadProjection']['ledgerSequence'] = 9
        self.unknown(encode(seal(items)), 'journal-backlink-mismatch')
        items = seal(records())
        items[1]['payloadProjection']['ledgerRecordSha256'] = digest('synthetic-other-record')
        self.unknown(encode(items), 'journal-backlink-mismatch')
        items = seal(records())
        items[index_of(items, 'adoption')]['payloadProjection']['adoptionRecordSha256'] = digest('synthetic-other')
        self.unknown(encode(items), 'journal-backlink-mismatch')

    def test_fence_progression(self):
        items = records()
        items[1]['payloadProjection']['fence'] = 2
        for item in items[1:]:
            item['fence'] = 2
        self.unknown(encode(seal(items)), 'journal-fence-invalid')
        items = records()
        items[1]['payloadProjection']['fence'] = 2
        self.unknown(encode(seal(items)), 'journal-fence-invalid')
        items = records()
        items[4]['fence'] = 2
        self.unknown(encode(seal(items)), 'journal-fence-invalid')

    def test_resigned_reordering_is_not_claimed_detectable(self):
        # The chain is unkeyed: a writer able to reseal every record forges a new
        # journal. Placement, not the hash, is the defense; this is documented.
        items = records()
        items[4], items[5] = items[5], items[4]
        for number, item in enumerate(items, 1):
            item['sequence'] = number
            if item['payloadKind'] == 'claim':
                item['payloadProjection']['ledgerSequence'] = number
        self.assertEqual(len(parse_records(encode(seal(items)))), 7)


class StateConsistencyTests(unittest.TestCase):
    def test_duplicate_request_record_is_unknown(self):
        items = records()
        items.append(copy.deepcopy(items[0]))
        items[-1]['sequence'], items[-1]['fence'] = len(items), items[-2]['fence']
        with Workspace() as space:
            space.write(encode(seal(items)))
            journal = space.journal(create=False)
            observation = claim.acquire(journal, binding_for(Template.plan, 'synthetic-request-new'),
                                        owner_id='synthetic-client', clock=Clock())
            self.assertEqual(observation, {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'journal-duplicate-request'})


class AppendAndSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, _ = shared_plan()

    def test_each_record_is_synced_before_acquisition_returns(self):
        events = []
        with Workspace() as space:
            def sync(descriptor):
                os.fsync(descriptor)
                events.append(('sync', len(space.bytes())))
            journal = space.journal(sync=sync)
            events.clear()
            observation = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-sync'),
                                        owner_id='synthetic-client', clock=Clock())
            events.append(('returned', observation['status']))
            data = space.bytes()
            lines = data.split(b'\n')[:-1]
            self.assertEqual(events, [('sync', len(lines[0]) + 1), ('sync', len(data)), ('returned', 'acquired')])

    def test_sync_failure_is_never_a_success(self):
        def failing(descriptor):
            raise OSError('synthetic sync failure')
        with Workspace() as space:
            space.journal()
            journal = space.journal(create=False, sync=failing)
            observation = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-sync'),
                                        owner_id='synthetic-client', clock=Clock())
            self.assertEqual(observation, {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'journal-sync-failed'})
        with Workspace() as space, self.assertRaises(AuthorityUnknown):
            space.journal(sync=failing)

    def test_write_failure_is_unknown(self):
        with Workspace() as space:
            journal = space.journal()
            with patch.object(journal_module.os, 'write', side_effect=OSError('synthetic write failure')):
                observation = claim.acquire(journal, binding_for(self.plan, 'synthetic-request-write'),
                                            owner_id='synthetic-client', clock=Clock())
            self.assertEqual(observation['reasonCode'], 'journal-write-failed')
            self.assertEqual(observation['exitCode'], 8)

    def test_partial_writes_are_completed(self):
        original = os.write
        with Workspace() as space:
            journal = space.journal()
            with patch.object(journal_module.os, 'write', lambda fd, data: original(fd, bytes(data[:7]))):
                claim.acquire(journal, binding_for(self.plan, 'synthetic-request-partial'),
                              owner_id='synthetic-client', clock=Clock())
            self.assertEqual(len(journal.records()), 2)

    def test_append_validates_before_writing(self):
        with Workspace() as space:
            journal = space.journal()
            with journal.transaction() as transaction, self.assertRaises(InputError):
                transaction.append('request', {'requestId': 'synthetic-only'})
            self.assertEqual(space.bytes(), b'')


class TransactionBoundaryTests(unittest.TestCase):
    def test_lock_failure_is_blocked_and_nothing_is_unlocked(self):
        with Workspace() as space:
            journal = space.journal()
            with patch.object(journal_module, '_lock', side_effect=OSError('synthetic lock failure')), \
                    patch.object(journal_module, '_unlock') as unlock:
                with self.assertRaises(BlockedError) as raised, journal.transaction():
                    pass
            self.assertEqual(raised.exception.reason_code, 'journal-lock-unavailable')
            unlock.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'msvcrt byte-range locks are a Windows mechanism')
    def test_windows_lock_waits_a_bounded_number_of_attempts(self):
        # Each real LK_LOCK call already retries for about ten seconds; six calls
        # bound the wait at about a minute. The fake answers at once, so no time
        # passes. A held region is refused at once.
        import msvcrt
        real, limit = msvcrt.locking, 6
        for failures in (0, limit - 1, limit):
            calls, held = [], []
            def locking(descriptor, mode, size):
                if mode == msvcrt.LK_LOCK:
                    calls.append(mode)
                    if held or len(calls) <= failures:
                        raise PermissionError('synthetic lock contention')
                    real(descriptor, mode, size)
                    held.append(True)
                    return
                real(descriptor, mode, size)
                held.clear()
            with self.subTest(failures=failures), Workspace() as space:
                journal = space.journal()
                with patch.object(msvcrt, 'locking', locking):
                    if failures < limit:
                        with journal.transaction() as transaction:
                            self.assertEqual(transaction.records, [])
                    else:
                        with self.assertRaises(BlockedError) as raised, journal.transaction():
                            pass
                        self.assertEqual(raised.exception.reason_code, 'journal-lock-unavailable')
                self.assertEqual(len(calls), min(failures + 1, limit))
                self.assertEqual(held, [])

    def test_lock_file_open_failure_is_blocked(self):
        original = os.open
        def refuse(path, *args, **kwargs):
            if str(path).endswith('.lock'):
                raise PermissionError('synthetic open failure')
            return original(path, *args, **kwargs)
        with Workspace() as space:
            journal = space.journal()
            with patch.object(journal_module.os, 'open', refuse), self.assertRaises(BlockedError) as raised, \
                    journal.transaction():
                pass
            self.assertEqual(raised.exception.reason_code, 'journal-lock-unavailable')

    def test_missing_journal_creates_nothing(self):
        with Workspace() as space:
            journal = space.journal(create=False)
            with self.assertRaises(BlockedError) as raised, journal.transaction():
                pass
            self.assertEqual(raised.exception.reason_code, 'journal-missing')
            self.assertEqual(list(space.authority.iterdir()), [])

    def test_create_requires_an_existing_directory_and_a_new_file(self):
        with Workspace() as space:
            missing = space.root / 'missing' / 'journal.jsonl'
            with self.assertRaises(BlockedError) as raised:
                LocalJournal.create(str(missing), authority_id=AUTHORITY, repository_roots=[str(space.repository)])
            self.assertEqual(raised.exception.reason_code, 'journal-location-missing-directory')
            self.assertFalse(missing.parent.exists())
            space.journal()
            with self.assertRaises(BlockedError) as raised:
                space.journal()
            self.assertEqual(raised.exception.reason_code, 'journal-exists')
            if os.name != 'nt':
                self.assertEqual(os.stat(space.path).st_mode & 0o777, 0o600)

    def test_unwritable_new_journal_is_blocked(self):
        original = os.open
        def refuse(path, flags, *args, **kwargs):
            if flags & os.O_EXCL:
                raise PermissionError('synthetic create failure')
            return original(path, flags, *args, **kwargs)
        with Workspace() as space, patch.object(journal_module.os, 'open', refuse):
            with self.assertRaises(BlockedError) as raised:
                space.journal()
            self.assertEqual(raised.exception.reason_code, 'journal-location-unwritable')

    def test_no_default_location_and_valid_authority(self):
        import inspect
        parameters = inspect.signature(LocalJournal).parameters
        self.assertIs(parameters['path'].default, inspect.Parameter.empty)
        with Workspace() as space:
            for value in ('', 'Synthetic', 7):
                with self.subTest(value=value), self.assertRaises(InputError):
                    LocalJournal(space.path, authority_id=value, repository_roots=[str(space.repository)])

    def test_authority_id_must_be_a_plain_json_string(self):
        # The schema type check accepts a str subclass; the canonical JSON check does not.
        class Text(str):
            pass
        with Workspace() as space, self.assertRaises(InputError):
            LocalJournal(space.path, authority_id=Text('synthetic-authority'),
                         repository_roots=[str(space.repository)])

    def test_records_are_copies(self):
        with Workspace() as space:
            journal = space.journal()
            plan, _ = shared_plan()
            claim.acquire(journal, binding_for(plan, 'synthetic-request-copy'), owner_id='synthetic-client', clock=Clock())
            first = journal.records()
            first[0]['sequence'] = 99
            self.assertEqual(journal.records()[0]['sequence'], 1)


if __name__ == '__main__':
    unittest.main()
