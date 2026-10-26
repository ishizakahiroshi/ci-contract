"""Q1: the explicit dispatch boundary checks the journaled binding and claim.

Real reconstruction is used for the positive path, the three single-field
binding changes, the shape precedence and the M6 helper. Journal-state
decisions use stub_reconstruction to isolate them; the stub still restores the
six fields and validates the binding shape.
"""
import copy
import os
from pathlib import Path
import unittest
from ci_contract import claim, cjson
from ci_contract.request_binding import request_digest, scope_key
from synthetic_claim import (AUTHORITY, Clock, Sender, Workspace, binding_for, force_append, inputs_for,
                             record_types, shared_plan, stub_reconstruction)


def claim_payload(binding, *, fence=1, acquisition='acquired', state='leased', authority_id=AUTHORITY,
                  lease_until='2026-01-01T00:01:00Z'):
    return {'kind': 'claim', 'authority': 'local-single-supervisor-v1', 'authorityId': authority_id,
            'claimId': 'synthetic-claim-%d' % fence, 'ownerId': 'synthetic-supervisor',
            'scopeKey': scope_key(binding), 'requestId': binding['requestId'],
            'requestDigest': request_digest(binding), 'fence': fence, 'acquisition': acquisition,
            'state': state, 'leaseUntil': lease_until, 'ledgerSequence': 1, 'ledgerRecordSha256': '0' * 64}


class DispatchBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def prepared(self, space, request_id='synthetic-request-dispatch', **options):
        journal = space.journal()
        clock = Clock()
        binding = binding_for(self.plan, request_id, **options)
        acquired = claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
        self.assertEqual(acquired['status'], 'acquired')
        return journal, clock, binding

    def send(self, journal, binding, sender, clock, stub=True, fixed=None, inputs=None):
        inputs = inputs_for(self.plan, binding) if inputs is None else inputs
        fixed = self.fixed if fixed is None else fixed
        if stub:
            with stub_reconstruction():
                return claim.dispatch(journal, inputs, binding, sender, clock=clock, **fixed)
        return claim.dispatch(journal, inputs, binding, sender, clock=clock, **fixed)

    def blocked(self, observation, reason):
        self.assertEqual(observation, {'status': 'blocked', 'exitCode': 4, 'reasonCode': reason})

    # Real reconstruction --------------------------------------------------
    def test_submit_unknown_is_durable_before_the_single_send(self):
        events = []
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            def sync(descriptor):
                os.fsync(descriptor)
                events.append(('sync', len(space.bytes())))
            def inspect(inputs):
                last = space.records()[-1]
                events.append(('send', len(space.bytes()), last['recordType'], last['payloadProjection']['claimId']))
            synced = space.journal(create=False, sync=sync)
            sender = Sender(inspect=inspect)
            observation = self.send(synced, binding, sender, clock.advance(1), stub=False)
            claim_id = next(r['payloadProjection']['claimId'] for r in space.records() if r['recordType'] == 'claim-acquired')
            size = len(space.bytes())
            self.assertEqual(events, [('sync', size), ('send', size, 'submit-unknown', claim_id)])
            self.assertEqual(observation['status'], 'submitted')
            self.assertIsNone(observation['exitCode'])
            self.assertEqual(sender.calls, [inputs_for(self.plan, binding)])

    def assert_single_field_blocks(self, field, value):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            supplied = dict(binding, **{field: value})
            sender = Sender()
            self.blocked(self.send(journal, supplied, sender, clock.advance(1), stub=False),
                         'dispatch-binding-journal-mismatch')
            self.assertEqual(sender.calls, [])
            self.assertNotIn('submit-unknown', record_types(space))

    def test_trust_alone_blocks(self):
        self.assert_single_field_blocks('trust', 'untrusted')

    def test_authority_id_alone_blocks(self):
        self.assert_single_field_blocks('authorityId', 'synthetic-other-authority')

    def test_authority_kind_alone_blocks(self):
        self.assert_single_field_blocks('authorityKind', 'github-run-v1')

    def test_untrusted_request_is_dispatched_when_journaled_untrusted(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space, trust='untrusted')
            self.assertEqual(self.send(journal, binding, Sender(), clock.advance(1), stub=False)['status'], 'submitted')

    def test_fixed_input_shape_precedes_the_journal_decision(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            fixed = copy.deepcopy(self.fixed)
            fixed['target_projection']['unexpected'] = True
            observation = self.send(journal, dict(binding, trust='untrusted'), Sender(), clock, stub=False, fixed=fixed)
            self.assertEqual(observation, {'status': 'invalid-input', 'exitCode': 3})

    def test_stale_fixed_bytes_are_stale_before_the_journal(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            fixed = copy.deepcopy(self.fixed)
            fixed['trusted_inputs']['policy']['bytes'] = b' ' + fixed['trusted_inputs']['policy']['bytes']
            sender = Sender()
            self.assertEqual(self.send(journal, binding, sender, clock, stub=False, fixed=fixed),
                             {'status': 'stale', 'exitCode': 5, 'reasonCode': 'fixed-reference-stale'})
            self.assertEqual(sender.calls, [])

    def test_m6_helper_still_binds_the_six_fields(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            inputs = dict(inputs_for(self.plan, binding), request_id='synthetic-other-request')
            self.blocked(self.send(journal, binding, Sender(), clock, stub=False, inputs=inputs),
                         'dispatch-request-mismatch')

    # Journal-state decisions (stub reconstruction) -------------------------
    def test_request_must_be_journaled(self):
        with Workspace() as space:
            journal = space.journal()
            self.blocked(self.send(journal, binding_for(self.plan, 'synthetic-request-absent'), Sender(), Clock()),
                         'dispatch-request-not-journaled')

    def crafted(self, space, binding, claim_options=None, with_claim=True):
        space.journal()
        force_append(space, 'request', binding, fence=0)
        if with_claim:
            force_append(space, 'claim-acquired', claim_payload(binding, **(claim_options or {})), fence=1)
        return space.journal(create=False)

    def test_recorded_foreign_authority_is_rejected(self):
        # M7 fix 1: a journal holding a record of another authority stops before any decision (unknown 8).
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-foreign', authority_id='synthetic-other-authority')
            journal = self.crafted(space, binding)
            sender = Sender()
            self.assertEqual(self.send(journal, binding, sender, Clock()),
                             {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'journal-authority-mismatch'})
            self.assertEqual(sender.calls, [])
            self.assertNotIn('submit-unknown', record_types(space))

    def test_recorded_native_authority_kind_is_rejected(self):
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-native', kind='github-run-v1')
            journal = self.crafted(space, binding)
            self.blocked(self.send(journal, binding, Sender(), Clock()), 'dispatch-authority-kind-unsupported')

    def test_binding_without_claim_is_rejected(self):
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-unclaimed')
            journal = self.crafted(space, binding, with_claim=False)
            self.blocked(self.send(journal, binding, Sender(), Clock()), 'dispatch-claim-missing')

    def test_coalesced_request_is_never_sent(self):
        with Workspace() as space:
            journal, clock, _ = self.prepared(space)
            attached = binding_for(self.plan, 'synthetic-request-attached')
            self.assertEqual(claim.acquire(journal, attached, owner_id='synthetic-client', clock=clock)['status'], 'coalesced')
            sender = Sender()
            self.blocked(self.send(journal, attached, sender, clock), 'dispatch-claim-coalesced')
            self.assertEqual(sender.calls, [])

    def test_claim_of_another_authority_is_rejected(self):
        # M7 fix 1: a claim record naming another authority makes the journal unknown (8) before any decision.
        with Workspace() as space:
            binding = binding_for(self.plan, 'synthetic-request-foreign-claim')
            journal = self.crafted(space, binding, {'authority_id': 'synthetic-other-authority'})
            sender = Sender()
            self.assertEqual(self.send(journal, binding, sender, Clock()),
                             {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'journal-authority-mismatch'})
            self.assertEqual(sender.calls, [])
            self.assertNotIn('submit-unknown', record_types(space))

    def test_closed_or_orphaned_claim_is_not_leased(self):
        for state in ('closed', 'orphaned'):
            with self.subTest(state=state), Workspace() as space:
                binding = binding_for(self.plan, 'synthetic-request-' + state)
                journal = self.crafted(space, binding, {'state': state})
                self.blocked(self.send(journal, binding, Sender(), Clock()), 'dispatch-claim-not-leased')

    def test_lease_expiry_on_the_replaced_clock_freezes_the_claim(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            sender = Sender()
            self.blocked(self.send(journal, binding, sender, Clock(clock.now).advance(60)), 'dispatch-lease-expired')
            self.assertEqual(record_types(space)[-1], 'claim-orphaned')
            self.blocked(self.send(journal, binding, sender, Clock(clock.now).advance(1)), 'dispatch-claim-not-leased')
            self.assertEqual(sender.calls, [])

    def test_lease_is_valid_until_its_last_second(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            self.assertEqual(self.send(journal, binding, Sender(), clock.advance(59))['status'], 'submitted')

    def test_request_window_is_checked_at_dispatch(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space, expires='2026-01-01T00:00:30Z')
            self.blocked(self.send(journal, binding, Sender(), Clock(clock.now).advance(30)), 'request-expired')
            self.blocked(self.send(journal, binding, Sender(), Clock(clock.now).advance(-1)), 'request-not-yet-valid')
            self.assertEqual(self.send(journal, binding, Sender(), Clock(clock.now).advance(29))['status'], 'submitted')

    def test_second_dispatch_never_sends_again(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            sender = Sender()
            self.assertEqual(self.send(journal, binding, sender, clock)['status'], 'submitted')
            again = self.send(journal, binding, sender, clock)
            self.assertEqual(again, {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'submission-already-recorded'})
            restarted = space.journal(create=False)
            self.assertEqual(self.send(restarted, binding, sender, clock)['exitCode'], 8)
            self.assertEqual(len(sender.calls), 1)
            self.assertEqual(record_types(space).count('submit-unknown'), 1)

    def test_submit_record_sync_failure_prevents_the_send(self):
        with Workspace() as space:
            _, clock, binding = self.prepared(space)
            def failing(descriptor):
                raise OSError('synthetic sync failure')
            sender = Sender()
            observation = self.send(space.journal(create=False, sync=failing), binding, sender, clock)
            self.assertEqual(observation, {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'journal-sync-failed'})
            self.assertEqual(sender.calls, [])

    def test_lost_response_is_unknown_after_one_send(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            sender = Sender(lose=True)
            observation = self.send(journal, binding, sender, clock)
            self.assertEqual(observation, {'status': 'unknown', 'exitCode': 8, 'reasonCode': 'dispatch-response-lost',
                                           'sendCount': 1})
            self.assertEqual(len(sender.calls), 1)
            self.assertEqual(record_types(space)[-1], 'submit-unknown')

    def test_sender_must_be_callable(self):
        with Workspace() as space:
            journal, clock, binding = self.prepared(space)
            self.assertEqual(self.send(journal, binding, None, clock), {'status': 'invalid-input', 'exitCode': 3})


if __name__ == '__main__':
    unittest.main()
