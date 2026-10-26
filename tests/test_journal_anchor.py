"""Journal anchor (M8 C2, owner decision A): holes 4 and 5 of the M7 journal.

Synthetic data only. The anchor sits in its own folder of the synthetic workspace,
outside the repository root and the journal's folder. Tests named
``test_fails_without_anchor_*`` show the hole on a journal opened without an anchor
(a positive control of the hole) and its refusal with one.
"""
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch
from ci_contract import cjson, claim
from ci_contract import journal as journal_module
from ci_contract.errors import BlockedError
from ci_contract.journal import AuthorityUnknown, LocalJournal, read_anchor
from synthetic_claim import (AUTHORITY, Clock, Sender, Workspace, adopted_flow, binding_for, inputs_for,
                             record_types, shared_plan, stub_reconstruction)

OTHER = 'synthetic-other-authority'


def unknown(reason):
    return {'status': 'unknown', 'exitCode': 8, 'reasonCode': reason}


def anchor_file(space):
    folder = space.root / 'anchor'
    folder.mkdir(exist_ok=True)
    return str(folder / 'journal.anchor')


def anchored(space, create=True, **options):
    options.setdefault('anchor_path', anchor_file(space))
    return space.journal(create=create, **options)


class AnchorCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def dispatch(self, journal, binding, sender, clock):
        with stub_reconstruction():
            return claim.dispatch(journal, inputs_for(self.plan, binding), binding, sender, clock=clock, **self.fixed)

    def assert_anchor_on_last_record(self, space):
        records = space.records()
        anchor = read_anchor(anchor_file(space))
        self.assertEqual(anchor['sequence'], len(records))
        self.assertEqual(anchor['recordSha256'], records[-1]['recordSha256'] if records else None)

    def lost_send(self, journal, request_id):
        """acquire, then a dispatch whose response is lost: request, claim-acquired, submit-unknown."""
        clock, binding = Clock(), binding_for(self.plan, request_id)
        self.assertEqual(claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)['status'],
                         'acquired')
        sender = Sender(lose=True)
        self.assertEqual(self.dispatch(journal, binding, sender, clock)['exitCode'], 8)
        self.assertEqual(len(sender.calls), 1)
        return binding, sender, clock


class TrailingRecordHole(AnchorCase):
    """Hole 4: a whole trailing record removed at its LF boundary."""

    def drop_last_record(self, space):
        lines = space.bytes().split(b'\n')[:-1]
        space.write(b'\n'.join(lines[:-1]) + b'\n')

    def test_fails_without_anchor_dropping_the_submit_record_sends_twice(self):
        # Positive control of the hole: no anchor, the shortened journal verifies and the request goes out again.
        with Workspace() as space:
            journal = space.journal()
            binding, sender, clock = self.lost_send(journal, 'synthetic-request-tail-plain')
            self.drop_last_record(space)
            sender.lose = False
            self.dispatch(journal, binding, sender, clock)
            self.assertEqual(len(sender.calls), 2)

    def test_dropping_the_submit_record_is_unknown_and_sends_nothing_with_an_anchor(self):
        with Workspace() as space:
            journal = anchored(space)
            binding, sender, clock = self.lost_send(journal, 'synthetic-request-tail-anchored')
            self.drop_last_record(space)
            before = space.bytes()
            sender.lose = False
            self.assertEqual(self.dispatch(journal, binding, sender, clock), unknown('journal-truncated'))
            self.assertEqual(len(sender.calls), 1)
            self.assertEqual(space.bytes(), before)

    def test_a_journal_restored_to_an_older_copy_is_unknown(self):
        with Workspace() as space:
            journal = anchored(space)
            clock, binding = Clock(), binding_for(self.plan, 'synthetic-request-restored')
            claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
            older = space.bytes()
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock.advance(1))['status'], 'leased')
            space.write(older)
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock.advance(1)),
                             unknown('journal-truncated'))
            self.assertEqual(space.bytes(), older)

    def test_another_record_at_the_anchored_sequence_is_unknown(self):
        # A journal of the same length with another last record (an older copy plus a different append).
        with Workspace() as space:
            journal = anchored(space)
            clock, binding = Clock(), binding_for(self.plan, 'synthetic-request-replaced')
            claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
            older, anchor = space.bytes(), Path(anchor_file(space)).read_bytes()
            claim.heartbeat(journal, binding['requestId'], clock=clock.advance(1))
            newer_anchor = Path(anchor_file(space)).read_bytes()
            space.write(older)
            Path(anchor_file(space)).write_bytes(anchor)
            claim.heartbeat(journal, binding['requestId'], clock=clock.advance(5))
            Path(anchor_file(space)).write_bytes(newer_anchor)
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock.advance(1)),
                             unknown('journal-anchor-mismatch'))


class RecreatedJournalHole(AnchorCase):
    """Hole 5: a removed journal and a new one at the same place."""

    def test_a_removed_journal_is_unknown_and_cannot_be_created_again(self):
        with Workspace() as space:
            journal = anchored(space)
            claim.acquire(journal, binding_for(self.plan, 'synthetic-request-removed'),
                          owner_id='synthetic-supervisor', clock=Clock())
            Path(space.path).unlink()
            self.assertEqual(claim.acquire(journal, binding_for(self.plan, 'synthetic-request-after'),
                                           owner_id='synthetic-supervisor', clock=Clock()),
                             unknown('journal-missing-anchored'))
            with self.assertRaises(BlockedError) as refused:
                anchored(space)
            self.assertEqual(refused.exception.reason_code, 'journal-anchor-exists')
            self.assertFalse(Path(space.path).exists())

    def test_fails_without_anchor_a_recreated_journal_accepts_the_same_request_id(self):
        # Positive control of the hole: without an anchor the same request ID is acquired again.
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-reused')
            claim.acquire(space.journal(), binding, owner_id='synthetic-supervisor', clock=Clock())
            Path(space.path).unlink()
            again = claim.acquire(space.journal(), binding, owner_id='synthetic-supervisor', clock=Clock())
            self.assertEqual(again['status'], 'acquired')


class CrashBetweenWrites(AnchorCase):
    def test_a_failed_anchor_write_is_unknown_and_the_next_transaction_catches_up(self):
        with Workspace() as space:
            journal = anchored(space)
            clock, binding = Clock(), binding_for(self.plan, 'synthetic-request-crash')
            claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
            original = journal_module.write_anchor
            with patch.object(journal_module, 'write_anchor',
                              side_effect=AuthorityUnknown('journal-anchor-write-failed')):
                self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock.advance(1)),
                                 unknown('journal-anchor-write-failed'))
            self.assertIs(journal_module.write_anchor, original)
            self.assertEqual(read_anchor(anchor_file(space))['sequence'], len(space.records()) - 1)
            # A read-only transaction catches the anchor up, so a second crash cannot widen the gap.
            journal.records()
            self.assert_anchor_on_last_record(space)
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock.advance(1))['status'], 'leased')
            self.assert_anchor_on_last_record(space)

    def test_an_anchor_rolled_back_by_more_than_one_record_is_unknown(self):
        with Workspace() as space:
            journal = anchored(space)
            clock, binding = Clock(), binding_for(self.plan, 'synthetic-request-anchor-back')
            claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
            older_anchor = Path(anchor_file(space)).read_bytes()
            for _ in range(2):
                claim.heartbeat(journal, binding['requestId'], clock=clock.advance(1))
            Path(anchor_file(space)).write_bytes(older_anchor)
            before = space.bytes()
            self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=clock.advance(1)),
                             unknown('journal-anchor-stale'))
            self.assertEqual(space.bytes(), before)


class AnchorFile(AnchorCase):
    def rewrite(self, space, **fields):
        value = read_anchor(anchor_file(space))
        value.update(fields)
        Path(anchor_file(space)).write_bytes(cjson.dumps(value))

    def test_a_damaged_missing_or_foreign_anchor_is_unknown(self):
        cases = {
            'journal-anchor-invalid': lambda space: Path(anchor_file(space)).write_bytes(b'{}'),
            'journal-anchor-missing': lambda space: Path(anchor_file(space)).unlink(),
            'journal-anchor-foreign': lambda space: self.rewrite(space, journal=str(space.root / 'elsewhere.jsonl')),
        }
        for reason, damage in cases.items():
            with self.subTest(reason=reason), Workspace() as space:
                journal = anchored(space)
                binding = binding_for(self.plan, 'synthetic-request-' + reason)
                claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=Clock())
                damage(space)
                before = space.bytes()
                self.assertEqual(claim.heartbeat(journal, binding['requestId'], clock=Clock().advance(1)),
                                 unknown(reason))
                self.assertEqual(space.bytes(), before)

    def test_an_anchor_of_another_authority_is_unknown(self):
        with Workspace() as space:
            anchored(space)
            other = anchored(space, create=False, authority_id=OTHER)
            self.assertEqual(claim.acquire(other, binding_for(self.plan, 'synthetic-request-foreign',
                                                              authority_id=OTHER),
                                           owner_id='synthetic-supervisor', clock=Clock()),
                             unknown('journal-anchor-foreign'))

    def test_anchor_placement_follows_the_journal_rules_in_another_folder(self):
        cases = {
            'journal-anchor-same-directory': lambda space: str(space.authority / 'journal.anchor'),
            'journal-anchor-location-inside-repository': lambda space: str(space.repository / 'journal.anchor'),
            'journal-anchor-location-relative': lambda space: 'journal.anchor',
            'journal-anchor-location-missing-directory': lambda space: str(space.root / 'absent' / 'journal.anchor'),
        }
        for reason, path in cases.items():
            with self.subTest(reason=reason), Workspace() as space:
                with self.assertRaises(BlockedError) as refused:
                    space.journal(anchor_path=path(space))
                self.assertEqual(refused.exception.reason_code, reason)
                self.assertFalse(Path(space.path).exists())


class AnchoredFlow(AnchorCase):
    def test_the_full_api_flow_keeps_the_anchor_on_the_last_record(self):
        # Positive control: acquire, dispatch, reconcile with an anchor; every append moves the anchor.
        with Workspace() as space:
            journal = anchored(space)
            self.assert_anchor_on_last_record(space)
            binding = binding_for(self.plan, 'synthetic-request-anchored-flow')
            _, sender, _, _, adopted = adopted_flow(space, self.plan, self.fixed, binding, Clock(),
                                                    journal=journal, stub=True)
            self.assertEqual(adopted['status'], 'adopted')
            self.assertEqual(len(sender.calls), 1)
            self.assertEqual(record_types(space), ['request', 'claim-acquired', 'submit-unknown', 'adoption'])
            self.assert_anchor_on_last_record(space)


if __name__ == '__main__':
    unittest.main()
