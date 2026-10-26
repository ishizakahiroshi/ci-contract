"""Claims, submission, reconciliation, receipts and adoption on the local journal (F05).

Only local-single-supervisor-v1 is implemented. The caller supplies the clock,
the sender and the read-only query; nothing here dispatches, contacts a
provider, reads a worktree or starts a process. Acquisition, coalescing,
submission and adoption are non-terminal request observations: they return
``exitCode`` None and never create an execution document or an accepted result.
Terminal verdicts come only from ``observe_completion``, which reuses the M5
verifier and the M6 binding comparison after the journal checks.

Every decision is taken inside one journal transaction: lock, re-read and
verify, read the clock once, decide, append and sync. Input shapes are checked
before the journal is opened, so invalid input (3) precedes blocked (4).
"""
import copy
from datetime import datetime, timedelta, timezone
from functools import lru_cache, wraps
from . import cjson
from .errors import InputError, BlockedError
from .hashing import domain_hash, raw_hash
from .journal import AuthorityUnknown, AUTHORITY_KIND, conforms
from .request_binding import validate_request_binding, request_digest, scope_key, _utc
from .schema import load_schema, make_validator

LEASE_SECONDS = 60
MAX_HEARTBEAT_SECONDS = 20
# Every lease and heartbeat time is the clock plus at most LEASE_SECONDS (fix 5, A).
LATEST_CLOCK = datetime.max.replace(tzinfo=timezone.utc) - timedelta(seconds=LEASE_SECONDS)
MAX_INTEGER = 9007199254740991
_CODES = {'invalid-input': 3, 'blocked': 4, 'stale': 5, 'unknown': 8}
# A read-only provider observation of one run started from the six dispatch inputs.
_CANDIDATES = {'type': 'array', 'maxItems': 1000, 'items': {
    'type': 'object', 'additionalProperties': False,
    'required': ['runId', 'providerAttempt', 'requestId', 'planSha256', 'workflowSha'],
    'properties': {'runId': {'$ref': '#/$defs/decimalId'},
                   'providerAttempt': {'type': 'integer', 'minimum': 1, 'maximum': MAX_INTEGER},
                   'requestId': {'$ref': '#/$defs/id'}, 'planSha256': {'$ref': '#/$defs/hash'},
                   'workflowSha': {'$ref': '#/$defs/git'}}}}
_PROVIDER_ATTEMPT = {'type': 'integer', 'minimum': 1, 'maximum': MAX_INTEGER}


def _verdict(status, reason=None):
    verdict = {'status': status, 'exitCode': _CODES[status]}
    if reason is not None:
        verdict['reasonCode'] = reason
    return verdict


def _observation(status, **fields):
    return {'status': status, 'exitCode': None, **fields}


def _guarded(function):
    """Map fixed exceptions to verdicts; diagnostics never echo input values."""
    @wraps(function)
    def wrapper(*args, **kwargs):
        from .request import StaleError
        try:
            return function(*args, **kwargs)
        except InputError:
            return _verdict('invalid-input')
        except StaleError as error:
            return _verdict('stale', error.reason_code)
        except BlockedError as error:
            return _verdict('blocked', error.reason_code)
        except AuthorityUnknown as error:
            return _verdict('unknown', error.reason_code)
    return wrapper


@lru_cache(maxsize=None)
def _fragment_validator(name):
    fragment = {'candidates': _CANDIDATES, 'provider-attempt': _PROVIDER_ATTEMPT}[name]
    schema = load_schema()
    return make_validator(dict(fragment, **{'$schema': schema['$schema'], '$defs': schema['$defs']}))


def _fragment(name, value):
    cjson.dumps(value)
    if next(_fragment_validator(name).iter_errors(value), None) is not None:
        raise InputError('invalid claim input')


def _shape(definition, value):
    if not conforms(definition, value):
        raise InputError('invalid claim input')


def _heartbeat_policy(seconds):
    if type(seconds) is not int:
        raise InputError('invalid heartbeat interval')
    if seconds < 1:
        raise InputError('invalid heartbeat interval')
    if seconds > MAX_HEARTBEAT_SECONDS:
        raise InputError('heartbeat interval exceeds 20 seconds')


def _now(clock):
    try:
        value = clock()
        offset = value.utcoffset() if type(value) is datetime else None
    except Exception:
        # A clock that raises, or whose tzinfo raises, is invalid input (3), never an internal error.
        raise InputError('clock failed') from None
    if type(value) is not datetime:
        raise InputError('clock must return a datetime')
    # A naive datetime has no offset (None) and is rejected by the same test.
    if offset != timedelta(0):
        raise InputError('clock must return aware UTC')
    # Fix 5 (A): the zone answered once; later comparisons must not consult it again.
    value = value.replace(tzinfo=timezone.utc)
    # A clock so late that a lease cannot be represented is refused before any append.
    if value > LATEST_CLOCK:
        raise InputError('clock out of range')
    return value


def _text(value):
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')


def _within_window(binding, now):
    if now < _utc(binding['createdAt']):
        raise BlockedError('request-not-yet-valid')
    if now >= _utc(binding['expiresAt']):
        raise BlockedError('request-expired')


def _claim_id(digest, fence):
    return 'claim-' + raw_hash((digest + ':' + str(fence)).encode('ascii'))


def _names_request(binding, digest):
    """True when a journaled request binding exists and its request digest is the one named.

    A receipt that names no journaled request, or the digest of another request, is
    journal corruption (fix 4, F1): the API never writes such a receipt.
    """
    if binding is None:
        return False
    try:
        return request_digest(binding) == digest
    except InputError:
        return False


class _State:
    """Journal records folded into lookups; the operations take the decisions."""

    def __init__(self, records):
        self.bindings, self.claims, self.request_claims = {}, {}, {}
        self.acquired_versions, self.submitted, self.adoptions = {}, set(), {}
        self.receipts, self.cleanup, self.conflicts = {}, {}, set()
        self.statuses = {}
        self.approvals, self.orphaned_at = {}, {}
        for record in records:
            kind, payload = record['recordType'], record['payloadProjection']
            if kind == 'request':
                if payload['requestId'] in self.bindings:
                    raise AuthorityUnknown('journal-duplicate-request')
                self.bindings[payload['requestId']] = payload
            elif kind in ('claim-acquired', 'claim-coalesced'):
                self.claims[payload['claimId']] = payload
                self.acquired_versions[payload['claimId']] = payload
                self.request_claims.setdefault(payload['requestId'], []).append(payload['claimId'])
            elif kind in ('claim-heartbeat', 'claim-orphaned', 'claim-closed', 'submit-unknown'):
                self.claims[payload['claimId']] = payload
                if kind == 'submit-unknown':
                    self.submitted.add(payload['claimId'])
                if kind == 'claim-orphaned':
                    self.orphaned_at[payload['claimId']] = record['sequence']
            elif kind == 'adoption':
                self.adoptions[payload['claimId']] = payload
            elif kind == 'retry-approval':
                self.approvals[payload['requestId']] = record['sequence']
            elif kind == 'receipt':
                bound = payload['requestBinding']
                # F1: the receipt must name the digest of the journaled request with its requestId.
                if not _names_request(self.bindings.get(bound['requestId']), bound['requestDigest']):
                    raise AuthorityUnknown('journal-receipt-binding-mismatch')
                key = (bound['requestId'], bound['attemptNumber'], bound['fence'])
                # F2: ingest_receipt writes one receipt per key; a second one is corruption, never a replacement.
                if key in self.receipts:
                    raise AuthorityUnknown('journal-duplicate-receipt')
                self.receipts[key] = domain_hash('result', payload)
                self.statuses[key] = payload['status']
                self.cleanup[key] = (payload['cleanupConfirmed'], payload['pendingChildren'])
            elif kind == 'receipt-conflict':
                bound = payload['requestBinding']
                self.conflicts.add((bound['requestId'], bound['attemptNumber'], bound['fence']))

    def current_claim(self, request_id):
        claims = self.request_claims.get(request_id)
        return None if not claims else self.claims[claims[-1]]

    def attempt_number(self, request_id, claim_id):
        # A request holds either one coalesced claim or only acquired claims.
        return self.request_claims[request_id].index(claim_id) + 1

    def adoption_for_attempt(self, request_id, attempt):
        for claim_id in self.request_claims.get(request_id, []):
            adoption = self.adoptions.get(claim_id)
            if adoption is not None and adoption['attemptNumber'] == attempt:
                return adoption
        return None

    def receipt_status(self, request_id, attempt):
        """The status of the attempt's recorded receipt (its adopted fence is the key)."""
        adoption = self.adoption_for_attempt(request_id, attempt)
        return None if adoption is None else self.statuses.get((request_id, attempt, adoption['fence']))

    def scope_claims(self, scope):
        """Current acquired claims of every journaled request in this scope."""
        for request_id in self.bindings:
            claim = self.current_claim(request_id)
            if claim is not None and claim['acquisition'] == 'acquired' and claim['scopeKey'] == scope:
                yield claim


def _orphaned(transaction, state, claim, now):
    """True for an orphaned claim. An expired lease is first persisted as orphaned,
    so a later or reset clock cannot revive it."""
    if claim['state'] == 'leased' and now >= _utc(claim['leaseUntil']):
        record = transaction.append('claim-orphaned', dict(claim, state='orphaned'))
        state.claims[claim['claimId']] = record['payloadProjection']
        state.orphaned_at[claim['claimId']] = record['sequence']
        return True
    return claim['state'] == 'orphaned'


def _new_claim(journal, binding, owner_id, fence, acquisition, lease_until):
    digest = request_digest(binding)
    return {'kind': 'claim', 'authority': AUTHORITY_KIND, 'authorityId': journal.authority_id,
            'claimId': _claim_id(digest, fence), 'ownerId': owner_id, 'scopeKey': scope_key(binding),
            'requestId': binding['requestId'], 'requestDigest': digest, 'fence': fence,
            'acquisition': acquisition, 'state': 'leased', 'leaseUntil': lease_until,
            'ledgerSequence': 1, 'ledgerRecordSha256': '0' * 64}


def _terminal_receipt(state, request_id, attempt):
    """The attempt's recorded terminal receipt digest, with confirmed cleanup and no conflict."""
    adoption = state.adoption_for_attempt(request_id, attempt)
    if adoption is None:
        raise BlockedError('attempt-terminal-missing')
    key = (request_id, attempt, adoption['fence'])
    if key not in state.receipts:
        raise BlockedError('attempt-terminal-missing')
    if key in state.conflicts:
        raise BlockedError('receipt-conflict-unresolved')
    confirmed, pending = state.cleanup[key]
    if not confirmed:
        raise BlockedError('attempt-cleanup-unconfirmed')
    if pending != 0:
        raise BlockedError('attempt-cleanup-unconfirmed')
    return state.receipts[key]


def _acquired_claim(state, request_id, reason):
    claim = state.current_claim(request_id)
    if claim is None:
        raise BlockedError(reason)
    if claim['acquisition'] != 'acquired':
        raise BlockedError(reason)
    return claim


@_guarded
def acquire(journal, binding, *, owner_id, clock, heartbeat_seconds=MAX_HEARTBEAT_SECONDS):
    """Register a request and acquire its scope, or coalesce into the active claim.

    The clock is read once, under the lock, after the journal is re-read.
    """
    validate_request_binding(binding)
    _shape('id', owner_id)
    _heartbeat_policy(heartbeat_seconds)
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        now = _now(clock)
        if binding['authorityKind'] != AUTHORITY_KIND:
            raise BlockedError('authority-kind-unsupported')
        if binding['authorityId'] != journal.authority_id:
            raise BlockedError('authority-mismatch')
        if binding['requestId'] in state.bindings:
            raise BlockedError('request-id-exists')
        _within_window(binding, now)
        scope, active = scope_key(binding), None
        for other in list(state.scope_claims(scope)):
            if _orphaned(transaction, state, other, now):
                raise BlockedError('scope-claim-orphaned')
            if other['state'] == 'leased':
                active = other
        transaction.append('request', binding)
        if active is not None:
            claim = _new_claim(journal, binding, owner_id, active['fence'], 'coalesced', active['leaseUntil'])
            record = transaction.append('claim-coalesced', claim)
            return _observation('coalesced', requestId=binding['requestId'],
                                attachedRequestId=active['requestId'],
                                attachedClaimId=active['claimId'], claim=record['payloadProjection'])
        claim = _new_claim(journal, binding, owner_id, transaction.fence + 1, 'acquired',
                           _text(now + timedelta(seconds=LEASE_SECONDS)))
        record = transaction.append('claim-acquired', claim)
        return _observation('acquired', requestId=binding['requestId'], claim=record['payloadProjection'],
                            heartbeatDueAt=_text(now + timedelta(seconds=heartbeat_seconds)))


@_guarded
def heartbeat(journal, request_id, *, clock, heartbeat_seconds=MAX_HEARTBEAT_SECONDS):
    """Renew a live acquired lease by 60 seconds; an expired lease is frozen instead."""
    _shape('id', request_id)
    _heartbeat_policy(heartbeat_seconds)
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        now = _now(clock)
        claim = _acquired_claim(state, request_id, 'heartbeat-claim-not-acquired')
        if claim['state'] != 'leased':
            raise BlockedError('heartbeat-claim-not-leased')
        if _orphaned(transaction, state, claim, now):
            raise BlockedError('heartbeat-lease-expired')
        _within_window(state.bindings[request_id], now)
        renewed = dict(claim, leaseUntil=_text(now + timedelta(seconds=LEASE_SECONDS)))
        record = transaction.append('claim-heartbeat', renewed)
        return _observation('leased', requestId=request_id, claim=record['payloadProjection'],
                            heartbeatDueAt=_text(now + timedelta(seconds=heartbeat_seconds)))


def _authorized_claim(transaction, state, binding, now, authority_id):
    """Q1: the dispatch binding and claim must be exactly this authority's records."""
    recorded = state.bindings.get(binding['requestId'])
    if recorded is None:
        raise BlockedError('dispatch-request-not-journaled')
    if cjson.dumps(recorded) != cjson.dumps(binding):
        raise BlockedError('dispatch-binding-journal-mismatch')
    if binding['authorityKind'] != AUTHORITY_KIND:
        raise BlockedError('dispatch-authority-kind-unsupported')
    # Defense in depth (F6): unreachable through dispatch while check_authority and the
    # binding comparison above hold. Kept on purpose; tested by calling this function directly.
    if binding['authorityId'] != authority_id:
        raise BlockedError('dispatch-authority-mismatch')
    _within_window(binding, now)
    claim = state.current_claim(binding['requestId'])
    if claim is None:
        raise BlockedError('dispatch-claim-missing')
    if claim['acquisition'] != 'acquired':
        raise BlockedError('dispatch-claim-coalesced')
    # Defense in depth (F6): check_authority refuses a journal with a foreign claim, so this is
    # reached only by a direct call with a state built from such a claim.
    if claim['authorityId'] != authority_id:
        raise BlockedError('dispatch-claim-authority-mismatch')
    if claim['state'] != 'leased':
        raise BlockedError('dispatch-claim-not-leased')
    if _orphaned(transaction, state, claim, now):
        raise BlockedError('dispatch-lease-expired')
    return claim


@_guarded
def dispatch(journal, inputs, binding, sender, *, clock, **fixed_inputs):
    """The execution-side dispatch boundary: the only function here that calls a sender.

    The six dispatch fields are first reconstructed and bound by the M6 helper
    (shape errors return 3 before any journal decision). Then, under the lock,
    the binding must equal the journaled record for its request ID, including
    trust, authorityId and authorityKind; authorityKind must be
    local-single-supervisor-v1; the claim must be acquired (not coalesced),
    leased (not closed or orphaned) and unexpired on the supplied clock. A
    submit-unknown record is synced before the single send. A request already
    submitted is never sent again; its outcome is unknown until reconciled.
    """
    from .request import reconstruct_bound_dispatch
    if not callable(sender):
        raise InputError('sender must be callable')
    reconstruct_bound_dispatch(inputs, binding, **fixed_inputs)
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        now = _now(clock)
        claim = _authorized_claim(transaction, state, binding, now, journal.authority_id)
        if claim['claimId'] in state.submitted:
            raise AuthorityUnknown('submission-already-recorded')
        transaction.append('submit-unknown', claim)
    try:
        sender(copy.deepcopy(inputs))
    except Exception:
        return dict(_verdict('unknown', 'dispatch-response-lost'), sendCount=1)
    return _observation('submitted', requestId=binding['requestId'], claimId=claim['claimId'], sendCount=1)


@_guarded
def reconcile(journal, request_id, query, *, clock):
    """Establish a submitted request's run by read-only query; never send again.

    Zero matching runs is not evidence of non-submission: this version has no
    definitive non-acceptance evidence source, so it is unknown (8). More than
    one matching run is a conflict (4). One is adopted by compare-and-set. The
    execution target is never switched.
    """
    _shape('id', request_id)
    if not callable(query):
        raise InputError('query must be callable')
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        binding = state.bindings.get(request_id)
        if binding is None:
            raise BlockedError('reconcile-request-not-journaled')
        claim = _acquired_claim(state, request_id, 'reconcile-claim-not-acquired')
        if claim['claimId'] not in state.submitted:
            raise BlockedError('reconcile-not-submitted')
        existing = state.adoptions.get(claim['claimId'])
        if existing is not None:
            return _observation('adopted', requestId=request_id, attemptAuthority=existing)
    identity = {'requestId': request_id, 'planSha256': binding['planSha256'],
                'workflowSha': binding['workflowCommit']}
    try:
        candidates = query(copy.deepcopy(identity))
    except Exception:
        # A failing observation is not evidence of anything: unknown (8), nothing recorded.
        raise AuthorityUnknown('reconcile-observation-failed') from None
    _fragment('candidates', candidates)
    matches = [item for item in candidates
               if item['requestId'] == identity['requestId']
               and item['planSha256'] == identity['planSha256']
               and item['workflowSha'] == identity['workflowSha']]
    if not matches:
        raise AuthorityUnknown('reconcile-no-observed-run')
    if len(matches) > 1:
        raise BlockedError('reconcile-multiple-runs')
    return adopt(journal, request_id, run_id=matches[0]['runId'],
                 provider_attempt=matches[0]['providerAttempt'], clock=clock)


@_guarded
def adopt(journal, request_id, *, run_id, provider_attempt, clock):
    """Fix the authority attempt, run ID, provider attempt and fence once (compare-and-set)."""
    _shape('id', request_id)
    _shape('decimalId', run_id)
    _fragment('provider-attempt', provider_attempt)
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        now = _now(clock)
        claim = _acquired_claim(state, request_id, 'adoption-claim-not-acquired')
        if claim['state'] != 'leased':
            raise BlockedError('adoption-claim-not-leased')
        if _orphaned(transaction, state, claim, now):
            raise BlockedError('adoption-lease-expired')
        if claim['claimId'] not in state.submitted:
            raise BlockedError('adoption-before-submit')
        existing = state.adoptions.get(claim['claimId'])
        if existing is not None:
            if existing['adoptedRunId'] != run_id:
                raise BlockedError('adoption-conflict')
            if existing['adoptedProviderAttempt'] != provider_attempt:
                raise BlockedError('adoption-conflict')
            return _observation('adopted', requestId=request_id, attemptAuthority=existing)
        attempt = state.attempt_number(request_id, claim['claimId'])
        previous = None
        if attempt > 1:
            previous = _terminal_receipt(state, request_id, attempt - 1)
        authority = {'authorityId': journal.authority_id, 'requestId': request_id,
                     'requestDigest': claim['requestDigest'], 'attemptNumber': attempt, 'adopted': True,
                     'adoptedRunId': run_id, 'adoptedProviderAttempt': provider_attempt,
                     'fence': claim['fence'], 'claimId': claim['claimId'],
                     'adoptionRecordSha256': '0' * 64, 'previousTerminalReceiptSha256': previous}
        record = transaction.append('adoption', authority)
        return _observation('adopted', requestId=request_id, attemptAuthority=record['payloadProjection'])


@_guarded
def start_local(journal, binding, *, clock):
    """Start the local attempt of an acquired claim (M8): the supervisor itself is the run.

    There is no provider run to reconcile, so the submit-unknown record and the
    adoption (adoptedRunId and adoptedProviderAttempt null) are appended in one
    transaction, before any child process starts. The binding must equal the
    journaled record and target local; the claim must be acquired, leased and
    unexpired. An attempt already started is never started again: its outcome is
    unknown (8) until its receipt is recorded.
    """
    validate_request_binding(binding)
    if binding['target'] != 'local':
        raise BlockedError('local-start-target-not-local')
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        now = _now(clock)
        claim = _authorized_claim(transaction, state, binding, now, journal.authority_id)
        if claim['claimId'] in state.submitted:
            raise AuthorityUnknown('submission-already-recorded')
        request_id = binding['requestId']
        attempt = state.attempt_number(request_id, claim['claimId'])
        previous = _terminal_receipt(state, request_id, attempt - 1) if attempt > 1 else None
        transaction.append('submit-unknown', claim)
        authority = {'authorityId': journal.authority_id, 'requestId': request_id,
                     'requestDigest': claim['requestDigest'], 'attemptNumber': attempt, 'adopted': True,
                     'adoptedRunId': None, 'adoptedProviderAttempt': None,
                     'fence': claim['fence'], 'claimId': claim['claimId'],
                     'adoptionRecordSha256': '0' * 64, 'previousTerminalReceiptSha256': previous}
        record = transaction.append('adoption', authority)
        acquired = state.acquired_versions[claim['claimId']]
        return _observation('started', requestId=request_id, attemptAuthority=record['payloadProjection'],
                            claim=copy.deepcopy(acquired))


@_guarded
def ingest_receipt(journal, result):
    """Record one receipt per adopted attempt; never overwrite it.

    The receipt key is the result's own binding (requestId, attemptNumber,
    fence). Same key and same result domain hash is a no-op. Same key and a
    different hash is recorded as a conflict and blocks (4) until an owner
    resolves it; the first receipt stays the record. A late receipt of an older
    attempt can only meet that attempt's own recorded key.
    """
    from .schema import validate
    from .verify import _utc_shapes
    validate(result)
    if result['kind'] != 'result':
        raise InputError('expected result')
    _utc_shapes(result)
    bound = result['requestBinding']
    key = (bound['requestId'], bound['attemptNumber'], bound['fence'])
    digest = domain_hash('result', result)  # normalizes sets; duplicates are invalid input
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        binding = state.bindings.get(bound['requestId'])
        if binding is None:
            raise BlockedError('receipt-request-unknown')
        if key in state.conflicts:
            raise BlockedError('receipt-conflict-unresolved')
        adoption = state.adoption_for_attempt(bound['requestId'], bound['attemptNumber'])
        if adoption is None:
            raise BlockedError('receipt-attempt-not-adopted')
        # requestId and attemptNumber selected the adoption; the other fields must agree.
        expected = {'requestDigest': request_digest(binding), 'scopeKey': scope_key(binding),
                    'authorityKind': binding['authorityKind'], 'fence': adoption['fence'],
                    'adoptionRecordSha256': adoption['adoptionRecordSha256']}
        if any(bound[name] != value for name, value in expected.items()):
            raise BlockedError('receipt-binding-mismatch')
        recorded = state.receipts.get(key)
        if recorded is not None:
            if recorded == digest:
                return _observation('idempotent-no-op', receiptKey=list(key), digest=digest)
            transaction.append('receipt-conflict', result)
            raise BlockedError('content-conflict')
        transaction.append('receipt', result)
        return _observation('recorded', receiptKey=list(key), digest=digest)


@_guarded
def close(journal, request_id):
    """Close a claim whose adopted attempt has a recorded terminal receipt and cleanup."""
    _shape('id', request_id)
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        claim = _acquired_claim(state, request_id, 'close-claim-not-acquired')
        if claim['state'] == 'closed':
            raise BlockedError('close-claim-already-closed')
        _terminal_receipt(state, request_id, state.attempt_number(request_id, claim['claimId']))
        record = transaction.append('claim-closed', dict(claim, state='closed'))
        return _observation('closed', requestId=request_id, claim=record['payloadProjection'])


@_guarded
def approve_retry(journal, request_id, *, clock):
    """Record the owner's explicit approval to retry an orphaned request."""
    _shape('id', request_id)
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        now = _now(clock)
        claim = _acquired_claim(state, request_id, 'retry-claim-not-acquired')
        if not _orphaned(transaction, state, claim, now):
            raise BlockedError('retry-claim-not-orphaned')
        transaction.append('retry-approval', state.bindings[request_id])
        return _observation('retry-approved', requestId=request_id)


@_guarded
def retry(journal, request_id, *, owner_id, clock):
    """Acquire a new attempt only after terminal, cleanup and a later explicit approval."""
    _shape('id', request_id)
    _shape('id', owner_id)
    with journal.transaction() as transaction:
        state = _State(transaction.records)
        now = _now(clock)
        claim = _acquired_claim(state, request_id, 'retry-claim-not-acquired')
        if not _orphaned(transaction, state, claim, now):
            raise BlockedError('retry-claim-not-orphaned')
        binding = state.bindings[request_id]
        _within_window(binding, now)
        attempt = state.attempt_number(request_id, claim['claimId'])
        _terminal_receipt(state, request_id, attempt)
        approval = state.approvals.get(request_id)
        if approval is None:
            raise BlockedError('retry-not-approved')
        if approval < state.orphaned_at[claim['claimId']]:
            raise BlockedError('retry-not-approved')
        # "Terminal" (spec line 167) is read narrowly here: an unknown result never authorizes
        # a second send of the same request. The owner can issue a new request instead.
        if state.receipt_status(request_id, attempt) == 'unknown':
            raise BlockedError('attempt-terminal-unknown')
        new = _new_claim(journal, binding, owner_id, transaction.fence + 1, 'acquired',
                         _text(now + timedelta(seconds=LEASE_SECONDS)))
        record = transaction.append('claim-acquired', new)
        return _observation('acquired', requestId=request_id, claim=record['payloadProjection'],
                            attemptNumber=attempt + 1)


def observe_completion(journal, plan, execution, result, *, synthetic_collector_ledger):
    """A later terminal observation point: journal evidence first, then M5/M6 verification.

    Shape errors in the documents return 3 first. The request must hold an
    acquired claim (a coalesced request has no execution), an adoption of its
    current claim equal in every field to the execution's attemptAuthority, the
    acquired claim's hash, no unresolved conflict for that attempt's receipt key,
    and the recorded receipt of that attempt. Only then can the verifier return 0.
    """
    from .verify import verify
    first = verify(plan, execution, result, synthetic_collector_ledger=synthetic_collector_ledger)
    if first['exitCode'] == 3:
        return first
    request_id = execution['requestBinding']['requestId']
    try:
        with journal.transaction() as transaction:
            state = _State(transaction.records)
            binding = state.bindings.get(request_id)
            if binding is None:
                raise BlockedError('observation-request-unknown')
            claim = _acquired_claim(state, request_id, 'observation-request-not-acquired')
            adoption = state.adoptions.get(claim['claimId'])
            if adoption is None:
                raise BlockedError('observation-not-adopted')
            authority = execution['requestBinding']['attemptAuthority']
            if any(authority[name] != value for name, value in adoption.items()):
                raise BlockedError('observation-attempt-mismatch')
            if execution['claimSha256'] != domain_hash('claim', state.acquired_versions[claim['claimId']]):
                raise BlockedError('observation-claim-mismatch')
            # Keyed by the execution's own attempt, which the comparison above fixed.
            key = (request_id, authority['attemptNumber'], authority['fence'])
            if key in state.conflicts:
                raise BlockedError('receipt-conflict-unresolved')
            if state.receipts.get(key) != domain_hash('result', result):
                raise BlockedError('observation-receipt-unrecorded')
    except InputError:
        return _verdict('invalid-input')
    except BlockedError as error:
        return _verdict('blocked', error.reason_code)
    except AuthorityUnknown as error:
        return _verdict('unknown', error.reason_code)
    return verify(plan, execution, result, synthetic_collector_ledger=synthetic_collector_ledger,
                  request_binding=binding)
