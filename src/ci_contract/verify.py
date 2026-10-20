"""Pure M5 result verification; never execute a check or discover external trust.

An optional synthetic collector ledger is an explicitly injected test boundary,
not a production collector, authority implementation, or PR-wide acceptance.
The three-document CLI does not manufacture this independent evidence.
"""
from datetime import datetime, timezone
import re
from . import cjson
from .arrays import normalize
from .errors import InputError
from .hashing import canonical_hash, domain_hash
from .inventory import normalize_inventory, source_digest, validate_paths
from .schema import validate, make_validator, load_schema

_CODES = {'accepted': 0, 'failed': 2, 'invalid-input': 3, 'blocked': 4,
          'stale': 5, 'cancelled': 6, 'timeout': 7, 'unknown': 8, 'error': 9}


def _verdict(status):
    return {'status': status, 'exitCode': _CODES[status]}


def _same(left, right, kind=None):
    return cjson.dumps(normalize(left, kind)) == cjson.dumps(normalize(right, kind))


def _time(value):
    if not isinstance(value, str) or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value) is None:
        raise InputError('invalid UTC value')
    try:
        return datetime(int(value[:4]), int(value[5:7]), int(value[8:10]),
                        int(value[11:13]), int(value[14:16]), int(value[17:19]), tzinfo=timezone.utc)
    except ValueError:
        raise InputError('invalid UTC value') from None


def _utc_shapes(value):
    # Collect every UTC property declared by the fixed schema, including fields
    # in nested documents. The synthetic ledger adds its observation timestamp.
    names = {'observedAt'}
    def collect(node):
        if isinstance(node, dict):
            for name, shape in node.get('properties', {}).items():
                if shape.get('$ref') == '#/$defs/utc':
                    names.add(name)
            for child in node.values():
                collect(child)
        elif isinstance(node, list):
            for child in node:
                collect(child)
    collect(load_schema())
    def visit(node):
        if isinstance(node, dict):
            for name, child in node.items():
                if name in names:
                    _time(child)
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)
    visit(value)


def _result_binding(execution):
    binding = execution['requestBinding']
    authority = binding['attemptAuthority']
    return {**{key: binding[key] for key in ('requestId', 'requestDigest', 'scopeKey', 'authorityKind')},
            **{key: authority[key] for key in ('attemptNumber', 'fence', 'adoptionRecordSha256')}}


def _ledger_shape(ledger):
    if ledger is None:
        return
    fields = {'kind', 'collectorId', 'planSha256', 'executionSha256', 'requestBinding',
              'terminalObservation', 'observedAt', 'cleanupConfirmed', 'pendingChildren', 'proofs'}
    if type(ledger) is not dict or set(ledger) != fields:
        raise InputError('invalid synthetic collector ledger')
    if ledger['kind'] != 'synthetic-collector-ledger-v1' or type(ledger['collectorId']) is not str or not ledger['collectorId'].startswith('synthetic-'):
        raise InputError('invalid synthetic collector ledger')
    defs = load_schema()['$defs']
    shape = {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$defs': defs,
             'type': 'object', 'properties': {
                 'collectorId': {'$ref': '#/$defs/id'},
                 'planSha256': {'$ref': '#/$defs/hash'},
                 'executionSha256': {'$ref': '#/$defs/hash'},
                 'requestBinding': {'$ref': '#/$defs/resultBinding'},
                 'observedAt': {'$ref': '#/$defs/utc'},
                 'terminalObservation': {'enum': [None, 'completed', 'cancelled', 'deadline-exceeded']},
                 'cleanupConfirmed': {'type': 'boolean'},
                 'pendingChildren': {'type': 'integer', 'minimum': 0, 'maximum': 9007199254740991},
                 'proofs': {'type': 'array', 'items': {'$ref': '#/$defs/embeddedProof'}, 'maxItems': 10000}}}
    cjson.dumps(ledger)
    _utc_shapes(ledger)
    if next(make_validator(shape).iter_errors(ledger), None) is not None:
        raise InputError('invalid synthetic collector ledger')
    normalize({'checks': [{'id': proof['identity']['instanceId'], 'proof': proof}
                          for proof in ledger['proofs']]}, 'result')


def _bindings(plan, execution, result):
    digest = domain_hash('plan', plan)
    return (execution['planSha256'] == digest and _same(execution['plan'], plan, 'plan')
            and result['planSha256'] == digest
            and result['executionSha256'] == domain_hash('execution', execution)
            and result['executionId'] == execution['executionId']
            and result['target'] == execution['target']
            and result['engineSha256'] == plan['engine']['bundleSha256'])


def _proof_ok(check, receipt, execution, result, trusted):
    proof, identity = receipt['proof'], receipt['proof']['identity']
    policy, variant = check['proofPolicy'], check['variant']
    authority = execution['requestBinding']['attemptAuthority']
    expected_identity = {
        'requestId': execution['requestBinding']['requestId'],
        'executionId': execution['executionId'], 'planSha256': result['planSha256'],
        'claimSha256': execution['claimSha256'], 'instanceId': check['id'],
        'logicalCheckId': check['logicalCheckId'], 'adapterSha256': check['adapterSha256'],
        'sourceDigest': execution['plan']['source']['digest'], 'attempt': authority['attemptNumber']}
    if any(identity[key] != value for key, value in expected_identity.items()):
        return False
    if (receipt['kind'] != check['kind'] or receipt['logicalCheckId'] != check['logicalCheckId']
            or receipt['adapterSha256'] != check['adapterSha256']
            or not _same(receipt['variant'], variant) or not _same(proof['variant'], variant)
            or proof['kind'] != check['kind'] or canonical_hash(proof) != receipt['proofSha256']
            or trusted is None or not _same(proof, trusted)):
        return False
    runtime, invocation, collection, collector = (proof[key] for key in
                                                  ('runtime', 'invocation', 'collection', 'collector'))
    if (runtime['os'] != variant['os'] or runtime['arch'] != variant['arch']
            or runtime['datasetSha256'] != variant['dataset']['sha256']
            or invocation['argv'] != check['argv'] or invocation['cwd'] != check['cwd']
            or invocation['exitCode'] != receipt['exitCode'] or invocation['signal'] is not None
            or _time(invocation['startedAt']) < _time(execution['startedAt'])
            or _time(invocation['completedAt']) < _time(invocation['startedAt'])
            or _time(invocation['completedAt']) > _time(execution['deadlineAt'])
            or collector['target'] != execution['target']):
        return False
    github = execution['github']
    if github is not None:
        if collector['runId'] != github['runId'] or collector['attempt'] != github['attempt']:
            return False
    elif collector['runId'] is not None or collector['jobId'] is not None:
        return False
    cleanup = proof['cleanup']
    if (not receipt['cleanupConfirmed'] or not cleanup['childrenStopped'] or not cleanup['resourcesReleased']
            or cleanup['unresolvedResourceIds'] or not collection['collectionComplete']
            or collection['enumerationContractSha256'] != policy['enumerationContractSha256']):
        return False
    if check['kind'] not in ('generation', 'artifact') and proof['payloads']:
        return False
    if receipt['status'] == 'failed':
        return receipt['exitCode'] != 0
    if check['kind'] == 'test':
        required = set(policy['expectedCaseIds'])
        if (not required or set(collection['expectedCaseIds']) != required
                or set(collection['executedCaseIds']) != required or set(collection['passedCaseIds']) != required
                or collection['failedCaseIds'] or collection['skippedCases']
                or receipt['executedTests'] != len(required)):
            return False
    elif check['kind'] in ('type', 'static', 'secrets'):
        if (receipt['executedTests'] is not None or not collection['analysisCompleted']
                or not policy['expectedTargetPaths']
                or set(collection['targetPaths']) != set(policy['expectedTargetPaths'])
                or collection['diagnosticCount'] != 0):
            return False
    else:
        if (not policy['expectedPayloadIds'] or set(p['artifactId'] for p in proof['payloads']) != set(policy['expectedPayloadIds'])
                or len(proof['payloads']) != len(policy['expectedPayloadIds'])):
            return False
    artifacts = {item['id']: item for item in result['artifacts']}
    for payload in proof['payloads']:
        artifact = artifacts.get(payload['artifactId'])
        if (artifact is None or artifact['sha256'] != payload['sha256'] or artifact['sizeBytes'] != payload['sizeBytes']
                or artifact['producerCheckId'] != payload['producerInstanceId'] or payload['producerInstanceId'] != check['id']
                or artifact['sourceDigest'] != identity['sourceDigest'] or artifact['planSha256'] != identity['planSha256']
                or payload['os'] != variant['os'] or payload['arch'] != variant['arch']
                or set(payload['inputDigests']) != {identity['sourceDigest'], *identity['generatedInputDigests']}):
            return False
    return True


def verify(plan, execution, result, *, synthetic_collector_ledger=None):
    """Return a fixed status/exitCode verdict for exactly this plan's scope.

    All three schemas and ledger shape are checked before any acceptance decision.
    No input file, process, network, clock, Git or mutable worktree is consulted. The
    explicit ledger models a trusted collector in tests only; do not construct it
    from an untrusted result at a real boundary. Skip approval is not implemented,
    therefore every incomplete required test remains blocked.
    """
    try:
        for document, kind in ((plan, 'plan'), (execution, 'execution'), (result, 'result')):
            validate(document)
            _utc_shapes(document)
            if document['kind'] != kind:
                raise InputError('wrong document kind')
        normalize(result, 'result')  # Validate sets without rewriting raw proof-hash bytes.
        _ledger_shape(synthetic_collector_ledger)
        # Canonical path and inventory shape errors precede semantic rejection.
        inventory = normalize_inventory(plan['source']['inputs'])
        for check in plan['checks']:
            validate_paths(check['inputPaths'])
            validate_paths(check['proofPolicy']['expectedTargetPaths'])
        plan_ids = {check['id'] for check in plan['checks']}
        pending = {check['id']: set(check['dependsOn']) & plan_ids for check in plan['checks']}
        while pending:
            ready = {identifier for identifier, dependencies in pending.items() if not dependencies}
            if not ready:
                return _verdict('invalid-input')
            pending = {identifier: dependencies - ready for identifier, dependencies in pending.items() if identifier not in ready}
        if _time(execution['deadlineAt']) <= _time(execution['startedAt']):
            return _verdict('invalid-input')
        if execution['planSha256'] != domain_hash('plan', plan) or not _same(execution['plan'], plan, 'plan'):
            return _verdict('blocked')
        if plan['selectionRequestSha256'] != canonical_hash(plan['selectionRequest']):
            return _verdict('blocked')
        request, projection = plan['selectionRequest'], plan['qualityProjectionRef']
        pins = request['expectedPins']
        if (request['repositoryId'] != plan['repository']['id'] or request['baseCommit'] != plan['source']['baseCommit']
                or request['comparison'] != plan['source']['comparison']
                or pins['manifest']['sha256'] != plan['manifestSha256'] or pins['policy']['sha256'] != plan['policySha256']
                or not _same(pins['qualityProjection'], projection) or projection['sha256'] != plan['qualityProjectionSha256']):
            return _verdict('blocked')
        if source_digest(inventory) != plan['source']['digest']:
            return _verdict('stale')
        ledger = synthetic_collector_ledger
        binding = _result_binding(execution)
        authority = execution['requestBinding']['attemptAuthority']
        github = execution['github']
        if github is not None and (not authority['adopted'] or authority['adoptedRunId'] != github['runId']
                or authority['adoptedProviderAttempt'] != github['attempt'] or github['targetCommit'] != plan['source']['targetCommit']):
            return _verdict('blocked')
        if (authority['requestId'] != binding['requestId'] or authority['requestDigest'] != binding['requestDigest']):
            return _verdict('blocked')
        if ledger is not None and (ledger['planSha256'] != domain_hash('plan', plan)
                or ledger['executionSha256'] != domain_hash('execution', execution) or not _same(ledger['requestBinding'], binding)):
            return _verdict('blocked')
        # Only the selected execution's independent terminal observation can
        # supersede a late older receipt. Its mere arrival never changes state.
        if ledger is not None:
            if _time(ledger['observedAt']) < _time(execution['startedAt']):
                return _verdict('blocked')
            terminal = ledger['terminalObservation']
            if terminal is None or not ledger['cleanupConfirmed'] or ledger['pendingChildren']:
                return _verdict('unknown')
            if terminal == 'cancelled':
                return _verdict('cancelled')
            if terminal == 'deadline-exceeded':
                if _time(ledger['observedAt']) <= _time(execution['deadlineAt']):
                    return _verdict('blocked')
                return _verdict('timeout')
        if not _bindings(plan, execution, result):
            return _verdict('blocked')
        if result['sourceDigestBefore'] != plan['source']['digest'] or result['sourceDigestAfter'] != plan['source']['digest']:
            return _verdict('stale')
        if not _same(result['requestBinding'], binding):
            return _verdict('blocked')
        if ledger is None:
            return _verdict('blocked')
        if not result['cleanupConfirmed'] or result['pendingChildren']:
            return _verdict('unknown')
        checks, receipts = plan['checks'], result['checks']
        ids, received = [c['id'] for c in checks], [c['id'] for c in receipts]
        selected = plan['selectionEvidence']['selectedInstanceIds']
        if (not ids or len(set(ids)) != len(ids)
                or set(ids) != set(selected) or set(received) != set(ids)
                or result['missingCheckIds'] or result['unresolvedRequirementIds']):
            return _verdict('blocked')
        proofs = {proof['identity']['instanceId']: proof for proof in ledger['proofs']}
        if len(proofs) != len(ledger['proofs']) or set(proofs) != set(ids):
            return _verdict('blocked')
        if any(proof['collector']['collectorId'] != ledger['collectorId'] for proof in proofs.values()):
            return _verdict('blocked')
        by_id = {check['id']: check for check in checks}
        capabilities = {cjson.dumps(item) for item in execution['capabilities']}
        if any(not set(check['dependsOn']) <= set(ids) or check['id'] in check['dependsOn']
               or not set(check['requirementIds']) <= set(plan['requirements'])
               or not {cjson.dumps(item) for item in check['requiredCapabilities']} <= capabilities for check in checks):
            return _verdict('blocked')
        # Failed checks require independently matching evidence, not a claim.
        if any(receipt['status'] == 'failed' for receipt in receipts):
            return _verdict('failed' if result['status'] == 'failed' and all(
                _proof_ok(by_id[receipt['id']], receipt, execution, result, proofs[receipt['id']])
                for receipt in receipts) else 'blocked')
        if any(receipt['status'] != 'passed' for receipt in receipts):
            return _verdict('blocked')
        if len({a['id'] for a in result['artifacts']}) != len(result['artifacts']):
            return _verdict('blocked')
        if not all(_proof_ok(by_id[receipt['id']], receipt, execution, result, proofs.get(receipt['id'])) for receipt in receipts):
            return _verdict('blocked')
        payload_ids = [payload['artifactId'] for proof in proofs.values() for payload in proof['payloads']]
        if set(payload_ids) != {a['id'] for a in result['artifacts']} or len(payload_ids) != len(set(payload_ids)):
            return _verdict('blocked')
        for receipt in receipts:
            dependencies = by_id[receipt['id']]['dependsOn']
            generated = {a['sha256'] for a in result['artifacts'] if a['producerCheckId'] in dependencies
                         and by_id[a['producerCheckId']]['kind'] == 'generation'}
            if set(receipt['proof']['identity']['generatedInputDigests']) != generated:
                return _verdict('blocked')
        if (result['status'] != 'accepted' or _time(result['completedAt']) > _time(execution['deadlineAt'])
                or _time(result['completedAt']) < _time(execution['startedAt'])
                or any(_time(proof['invocation']['completedAt']) > _time(result['completedAt']) for proof in proofs.values())
                or _time(ledger['observedAt']) < _time(result['completedAt'])):
            return _verdict('blocked')
        return _verdict('accepted')
    except InputError:
        return _verdict('invalid-input')
