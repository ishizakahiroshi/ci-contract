"""Synthetic request bindings and collector observations, never a real authority."""
import copy
from ci_contract.hashing import domain_hash
from ci_contract.request_binding import make_request_binding, request_digest, scope_key
from synthetic_verify import documents, MODEL, record_observation, START, DEADLINE


def refresh(docs):
    """Recompute derived hashes after a deliberate synthetic evidence edit."""
    plan, execution, result, ledger, binding = docs
    execution['plan'] = copy.deepcopy(plan)
    execution['planSha256'] = domain_hash('plan', plan)
    result['planSha256'] = ledger['planSha256'] = execution['planSha256']
    result['executionId'] = execution['executionId']
    result['executionSha256'] = ledger['executionSha256'] = domain_hash('execution', execution)
    result['requestBinding'] = {key: execution['requestBinding'][key]
                              for key in ('requestId', 'requestDigest', 'scopeKey', 'authorityKind')}
    result['requestBinding'].update({key: execution['requestBinding']['attemptAuthority'][key]
                                    for key in ('attemptNumber', 'fence', 'adoptionRecordSha256')})
    ledger['requestBinding'] = copy.deepcopy(result['requestBinding'])
    for receipt in result['checks']:
        identity = receipt['proof']['identity']
        identity['requestId'] = execution['requestBinding']['requestId']
        identity['executionId'] = execution['executionId']
        identity['planSha256'] = execution['planSha256']
    for artifact in result['artifacts']:
        artifact['planSha256'] = execution['planSha256']
    record_observation(result, ledger)
    return docs


def bind_hashes(docs):
    """Align envelope hashes, without correcting binding-versus-plan fields."""
    execution, binding = docs[1], docs[4]
    execution['requestBinding']['requestDigest'] = request_digest(binding)
    execution['requestBinding']['scopeKey'] = scope_key(binding)
    execution['requestBinding']['attemptAuthority']['requestDigest'] = request_digest(binding)
    return refresh(docs)


def bound_documents(target='github', full=False, supplied_plan=None):
    ids = None if full else [MODEL['instanceAliases']['guard.type.linux']['instanceId']]
    overrides = None
    if supplied_plan is not None:
        ids = [check['id'] for check in supplied_plan['checks']]
        overrides = {check['id']: copy.deepcopy(check) for check in supplied_plan['checks']}
    plan, execution, result, ledger = documents(ids, overrides)
    if supplied_plan is None:
        plan['profile'] = 'change'
        for check in plan['checks']:
            if check['alwaysScope'] is not None:
                check['alwaysScope']['profiles'] = ['change']
    else:
        plan = copy.deepcopy(supplied_plan)
    execution['target'] = result['target'] = target
    execution['executionId'] = 'synthetic-execution-' + target
    execution['requestBinding']['requestId'] = 'synthetic-request-' + target
    authority = execution['requestBinding']['attemptAuthority']
    authority['requestId'] = execution['requestBinding']['requestId']
    execution['requestBinding']['authorityKind'] = 'local-single-supervisor-v1'
    if target == 'local':
        execution['github'] = None
        result['evidenceOrigin'] = 'local-receipt'
        authority['adoptedRunId'] = authority['adoptedProviderAttempt'] = None
    else:
        execution['github']['event'] = 'workflow_dispatch'
        ledger['githubObservation'] = {'workflowCommit': execution['github']['expectedWorkflowCommit'],
                                       'targetCommit': plan['source']['targetCommit']}
    for receipt in result['checks']:
        collector = receipt['proof']['collector']
        collector['target'] = target
        if target == 'local':
            collector['runId'] = collector['jobId'] = None
    binding = make_request_binding(
        plan, request_id=execution['requestBinding']['requestId'],
        authority_id=authority['authorityId'], target=target, trust='trusted',
        workflow_commit=None if target == 'local' else execution['github']['expectedWorkflowCommit'],
        created_at=START, expires_at=DEADLINE, authority_kind='local-single-supervisor-v1')
    return bind_hashes((plan, execution, result, ledger, binding))


def verify_bound(function, docs):
    plan, execution, result, ledger, binding = copy.deepcopy(docs)
    return function(plan, execution, result, synthetic_collector_ledger=ledger,
                    request_binding=binding)
