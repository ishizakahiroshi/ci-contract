"""Q2: a request binding is valid for at most 24 hours; exactly 24 hours is allowed.

The bound is an input-layer semantic validation of the binding interval
(invalid input, 3), checked wherever a binding is accepted: construction,
digests, verification, claim acquisition and the dispatch helper.
"""
import copy
import unittest
from ci_contract import claim, request
from ci_contract.errors import InputError
from ci_contract.request_binding import make_request_binding, request_digest, scope_key, validate_request_binding
import ci_contract.verify as verifier
from synthetic_claim import Clock, Workspace, binding_for, inputs_for, shared_plan
from synthetic_request_binding import bind_hashes, bound_documents, verify_bound

CREATED = '2026-01-01T00:00:00Z'
EXACT = '2026-01-02T00:00:00Z'
OVER = '2026-01-02T00:00:01Z'


class RequestValidityTests(unittest.TestCase):
    def binding(self, expires):
        return dict(bound_documents()[4], createdAt=CREATED, expiresAt=expires)

    def test_exactly_twenty_four_hours_is_valid(self):
        binding = self.binding(EXACT)
        self.assertIs(validate_request_binding(binding), binding)
        request_digest(binding)
        scope_key(binding)

    def test_twenty_four_hours_and_one_second_is_invalid(self):
        binding = self.binding(OVER)
        for function in (validate_request_binding, request_digest, scope_key):
            with self.subTest(function=function.__name__), self.assertRaises(InputError):
                function(binding)

    def test_builder_rejects_the_longer_interval(self):
        plan = bound_documents()[0]
        options = dict(request_id='synthetic-request', authority_id='synthetic-authority', target='local',
                       trust='trusted', workflow_commit=None, created_at=CREATED,
                       authority_kind='local-single-supervisor-v1')
        make_request_binding(plan, expires_at=EXACT, **options)
        with self.assertRaises(InputError):
            make_request_binding(plan, expires_at=OVER, **options)

    def test_verifier_returns_invalid_input_before_semantic_decisions(self):
        docs = bound_documents()
        docs[4]['expiresAt'] = EXACT
        bind_hashes(docs)
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 0)
        # One more second: the envelope digests are now stale too, yet the
        # interval error is reported first, also with a stale workflow observation.
        docs[4]['expiresAt'] = OVER
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 3)
        docs[3]['githubObservation']['workflowCommit'] = 'a' * 40
        self.assertEqual(verify_bound(verifier.verify, docs)['exitCode'], 3)


class RequestValidityAtTheAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.fixed = shared_plan()

    def test_acquisition_rejects_before_opening_the_journal(self):
        with Workspace() as space:
            # No journal file exists: the input error still comes first.
            journal = space.journal(create=False)
            longer = dict(binding_for(self.plan, 'synthetic-request-long'), expiresAt=OVER)
            self.assertEqual(claim.acquire(journal, longer, owner_id='synthetic-client', clock=Clock()),
                             {'status': 'invalid-input', 'exitCode': 3})
            exact = binding_for(self.plan, 'synthetic-request-exact', expires=EXACT)
            space.journal()
            self.assertEqual(claim.acquire(journal, exact, owner_id='synthetic-client', clock=Clock())['status'],
                             'acquired')

    def test_dispatch_helper_rejects_the_longer_interval(self):
        binding = binding_for(self.plan, 'synthetic-request-long', expires=EXACT)
        longer = dict(binding, expiresAt=OVER)
        with self.assertRaises(InputError):
            request.reconstruct_bound_dispatch(inputs_for(self.plan, longer), longer, **copy.deepcopy(self.fixed))


if __name__ == '__main__':
    unittest.main()
