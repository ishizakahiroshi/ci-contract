"""Pure request-binding construction and verification, without an authority journal.

The caller supplies the trusted request binding independently of execution and
result. Hashes bind its fixed fields; they do not establish who approved them.
"""
from datetime import datetime, timedelta, timezone
import re
from . import cjson
from .arrays import normalize
from .errors import InputError
from .hashing import canonical_hash, domain_hash, PROJECTIONS
from .schema import load_schema, make_validator, validate

_SCOPE_KEYS = next(entry['keys'] for entry in PROJECTIONS['entries'] if entry['kind'] == 'scope')
# F05: a request is valid for at most 24 hours. Exactly 24 hours is allowed.
MAX_REQUEST_VALIDITY = timedelta(hours=24)


def _utc(value):
    if type(value) is not str or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value) is None:
        raise InputError('invalid binding timestamp')
    try:
        return datetime(int(value[:4]), int(value[5:7]), int(value[8:10]),
                        int(value[11:13]), int(value[14:16]), int(value[17:19]), tzinfo=timezone.utc)
    except ValueError:
        raise InputError('invalid binding timestamp') from None


def validate_request_binding(binding):
    """Check the fixed closed schema, real UTC calendar and validity bound before decisions.

    The 24-hour bound is a semantic validation of the binding's own interval, in
    the same input layer as the calendar and positive-interval checks (F09), so
    a longer request is invalid input (3) rather than a policy decision.
    """
    cjson.dumps(binding)
    schema = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
              '$defs': load_schema()['$defs'], '$ref': '#/$defs/requestBinding'}
    if next(make_validator(schema).iter_errors(binding), None) is not None:
        raise InputError('invalid request binding')
    check_binding_times(binding)
    return binding


def check_binding_times(binding):
    """The real UTC calendar and validity bound of a binding whose schema is already checked."""
    created, expires = _utc(binding['createdAt']), _utc(binding['expiresAt'])
    if expires <= created:
        raise InputError('invalid binding interval')
    if expires - created > MAX_REQUEST_VALIDITY:
        raise InputError('binding validity exceeds 24 hours')


def request_digest(binding):
    validate_request_binding(binding)
    return domain_hash('request-binding', binding)


def scope_key(binding):
    validate_request_binding(binding)
    return domain_hash('scope', {key: binding[key] for key in _SCOPE_KEYS})


def make_request_binding(plan, *, request_id, authority_id, target, trust,
                         workflow_commit, created_at, expires_at, authority_kind):
    """Build only the fourteen immutable fields; never mutate a plan or claim."""
    validate(plan)
    if plan['kind'] != 'plan':
        raise InputError('expected plan')
    normalize(plan, 'plan')
    binding = {
        'requestId': request_id, 'authorityId': authority_id,
        'repositoryId': plan['repository']['id'], 'sourceDigest': plan['source']['digest'],
        'planSha256': domain_hash('plan', plan),
        'selectionRequestSha256': canonical_hash(plan['selectionRequest'], 'selection-request'),
        'engineLockSha256': plan['selectionRequest']['expectedPins']['engineLock']['sha256'],
        'profile': plan['profile'], 'target': target, 'trust': trust,
        'workflowCommit': workflow_commit, 'createdAt': created_at, 'expiresAt': expires_at,
        'authorityKind': authority_kind}
    validate_request_binding(binding)
    return binding


def plan_binding_fields(plan):
    """The immutable plan-derived request fields shared by dispatch and verify.

    Plan SHA is compared explicitly at each boundary alongside these fields.
    """
    return {
        'repositoryId': plan['repository']['id'], 'sourceDigest': plan['source']['digest'],
        'selectionRequestSha256': canonical_hash(plan['selectionRequest'], 'selection-request'),
        'engineLockSha256': plan['selectionRequest']['expectedPins']['engineLock']['sha256'],
        'profile': plan['profile']}


def binding_status(binding, plan, execution, result, ledger):
    """Return a rejection status or None. The enclosing verifier checks shapes first.

    Expiry is compared with recorded execution/result time, not a hidden wall
    clock. Historical evidence is therefore deterministic and replayable.
    """
    expected = {
        **plan_binding_fields(plan),
        'planSha256': domain_hash('plan', plan),
        'target': execution['target'],
        'workflowCommit': execution['github']['expectedWorkflowCommit'] if execution['github'] is not None else None,
        'authorityId': execution['requestBinding']['attemptAuthority']['authorityId']}
    if execution['github'] is not None:
        expected['trust'] = execution['github']['trust']
    if any(binding[key] != value for key, value in expected.items()):
        return 'blocked'
    digests = {'requestId': binding['requestId'], 'requestDigest': domain_hash('request-binding', binding),
               'scopeKey': domain_hash('scope', {key: binding[key] for key in _SCOPE_KEYS}),
               'authorityKind': binding['authorityKind']}
    if any(document['requestBinding'][key] != value
           for document in (execution, result) for key, value in digests.items()):
        return 'blocked'
    if (_utc(execution['startedAt']) < _utc(binding['createdAt'])
            or _utc(result['completedAt']) > _utc(binding['expiresAt'])):
        return 'blocked'
    if execution['github'] is not None:
        observation = None if ledger is None else ledger.get('githubObservation')
        if observation is None:
            return 'blocked'
        if observation['workflowCommit'] != binding['workflowCommit']:
            return 'stale'
        if observation['targetCommit'] != plan['source']['targetCommit']:
            return 'stale'
    return None
