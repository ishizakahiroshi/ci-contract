"""V3 single-fault inputs with repaired bindings and one-predicate mutants."""
import copy
import inspect
import unittest
import ci_contract.verify as verifier
from ci_contract.hashing import domain_hash
from synthetic_verify import documents, MODEL, digest, record_observation, START


def baseline(kind='type'):
    alias={'type':'guard.type.linux','test':'auth.unit.linux','artifact':'package.verify.linux'}[kind]
    return documents([MODEL['instanceAliases'][alias]['instanceId']])


def rebind(docs):
    """Repair derived identities, leaving only the selected logical defect."""
    p,e,r,l=docs
    e['plan']=copy.deepcopy(p);e['planSha256']=domain_hash('plan',p)
    r['planSha256']=l['planSha256']=e['planSha256']
    r['executionSha256']=l['executionSha256']=domain_hash('execution',e)
    for receipt in r['checks']:receipt['proof']['identity']['planSha256']=e['planSha256']
    for artifact in r['artifacts']:artifact['planSha256']=e['planSha256']
    return observe(docs)


def observe(docs):
    record_observation(docs[2],docs[3]);return docs


def mutate_source(old,new):
    source=inspect.getsource(verifier)
    if source.count(old)!=1:raise AssertionError('mutant must identify one source occurrence: '+old)
    namespace={'__name__':'ci_contract.synthetic_predicate_mutant','__package__':'ci_contract'}
    exec(compile(source.replace(old,new,1),'<synthetic-predicate-mutant>','exec'),namespace)
    return namespace['verify']


def verdict(function,docs):
    p,e,r,l=copy.deepcopy(docs)
    return function(p,e,r,synthetic_collector_ledger=l)['exitCode']


def result_field(field,value):
    d=baseline();d[2][field]=value
    if field=='planSha256':
        d[2]['checks'][0]['proof']['identity']['planSha256']=value;observe(d)
    elif field=='target':d[2]['evidenceOrigin']='local-receipt'
    return d


def authority_field(field,value):
    d=baseline();d[1]['requestBinding']['attemptAuthority'][field]=value;return rebind(d)


def ledger_field(field,value):
    d=baseline();d[3][field]=value;return d


def proof_field(section,field,value,kind='type'):
    d=baseline(kind);d[2]['checks'][0]['proof'][section][field]=value;return observe(d)


def selected_mismatch():
    d=baseline();d[0]['selectionEvidence']['selectedInstanceIds']=['synthetic-other'];return rebind(d)


def payload_policy_mismatch():
    d=baseline('artifact');d[0]['checks'][0]['proofPolicy']['expectedPayloadIds']=['synthetic-other-payload'];return rebind(d)


def unclean_cancel():
    d=ledger_field('terminalObservation','cancelled');d[3]['cleanupConfirmed']=False;return d


def invalid_deadline():
    d=baseline();d[1]['deadlineAt']=START;d[3]['terminalObservation']='cancelled';return rebind(d)


def result_binding_mismatch():
    d=baseline();d[2]['requestBinding']['scopeKey']=digest('other-scope');return d


def ledger_binding_mismatch():
    d=baseline();d[3]['requestBinding']['scopeKey']=digest('other-scope');return d


def receipt_count_mismatch():
    d=baseline('test');d[2]['checks'][0]['executedTests']=1;return d


def bad_proof_hash():
    d=baseline();d[2]['checks'][0]['proofSha256']=digest('other-proof');return d


def ledger_collector_name():
    d=proof_field('collector','collectorId','other-collector')
    d[3]['collectorId']='other-collector'
    return d


def extra_ledger_field():
    d=baseline();d[3]['extra']='synthetic';return d


def failed_receipt_cleanup():
    d=baseline();r=d[2];r.update(status='failed',exitCode=2)
    receipt=r['checks'][0];receipt.update(status='failed',exitCode=1,cleanupConfirmed=False)
    receipt['proof']['invocation']['exitCode']=1
    return observe(d)


def duplicate_receipt():
    d=baseline();d[2]['checks'].append(copy.deepcopy(d[2]['checks'][0]));return d


# Name, builder, exact real exit, removed predicate, replacement, mutant exit.
CASES=[
 ('receipt_cleanup',failed_receipt_cleanup,4,"not receipt['cleanupConfirmed']",'False',2),
 ('collection_complete',lambda:proof_field('collection','collectionComplete',False),4,"not collection['collectionComplete']",'False',0),
 ('enumeration_contract',lambda:proof_field('collection','enumerationContractSha256',digest('other-enumeration')),4,"collection['enumerationContractSha256'] != policy['enumerationContractSha256']",'False',0),
 ('ledger_pending_children',lambda:ledger_field('pendingChildren',1),8,"ledger['pendingChildren']",'0',0),
 ('duplicate_receipt',duplicate_receipt,3,"normalize(result, 'result')","None",0),
 ('result_plan',lambda:result_field('planSha256',digest('other-plan')),4,"result['planSha256'] == digest",'True',0),
 ('result_execution_hash',lambda:result_field('executionSha256',digest('other-execution')),4,"result['executionSha256'] == domain_hash('execution', execution)",'True',0),
 ('result_execution_id',lambda:result_field('executionId','synthetic-other-execution'),4,"result['executionId'] == execution['executionId']",'True',0),
 ('result_target',lambda:result_field('target','local'),4,"result['target'] == execution['target']",'True',0),
 ('result_engine',lambda:result_field('engineSha256',digest('other-engine')),4,"result['engineSha256'] == plan['engine']['bundleSha256']",'True',0),
 ('result_request_binding',result_binding_mismatch,4,"not _same(result['requestBinding'], binding)",'False',0),
 ('source_before',lambda:result_field('sourceDigestBefore',digest('other-source')),5,"result['sourceDigestBefore'] != plan['source']['digest']",'False',0),
 ('source_after',lambda:result_field('sourceDigestAfter',digest('other-source')),5,"result['sourceDigestAfter'] != plan['source']['digest']",'False',0),
 ('authority_request_id',lambda:authority_field('requestId','synthetic-other-request'),4,"authority['requestId'] != binding['requestId']",'False',0),
 ('authority_request_digest',lambda:authority_field('requestDigest',digest('other-request')),4,"authority['requestDigest'] != binding['requestDigest']",'False',0),
 ('ledger_plan',lambda:ledger_field('planSha256',digest('other-plan')),4,"ledger['planSha256'] != domain_hash('plan', plan)",'False',0),
 ('ledger_execution',lambda:ledger_field('executionSha256',digest('other-execution')),4,"ledger['executionSha256'] != domain_hash('execution', execution)",'False',0),
 ('ledger_request_binding',ledger_binding_mismatch,4,"not _same(ledger['requestBinding'], binding)",'False',0),
 ('selected_instances',selected_mismatch,4,"set(ids) != set(selected)",'False',0),
 ('proof_collector_id',lambda:proof_field('collector','collectorId','synthetic-other-collector'),4,"proof['collector']['collectorId'] != ledger['collectorId']",'False',0),
 ('analysis_target_set',lambda:proof_field('collection','targetPaths',['src/other.ts']),4,"set(collection['targetPaths']) != set(policy['expectedTargetPaths'])",'False',0),
 ('analysis_diagnostics',lambda:proof_field('collection','diagnosticCount',1),4,"collection['diagnosticCount'] != 0",'False',0),
 ('executed_test_count',receipt_count_mismatch,4,"receipt['executedTests'] != len(required)",'False',0),
 ('expected_payload_set',payload_policy_mismatch,4,"set(p['artifactId'] for p in proof['payloads']) != set(policy['expectedPayloadIds'])",'False',0),
 ('proof_hash',bad_proof_hash,4,"canonical_hash(proof) != receipt['proofSha256']",'False',0),
 ('cleanup_children',lambda:proof_field('cleanup','childrenStopped',False),4,"not cleanup['childrenStopped']",'False',0),
 ('cleanup_resources',lambda:proof_field('cleanup','resourcesReleased',False),4,"not cleanup['resourcesReleased']",'False',0),
 ('cleanup_unresolved',lambda:proof_field('cleanup','unresolvedResourceIds',['synthetic-resource']),4,"cleanup['unresolvedResourceIds']",'False',0),
 ('terminal_unobserved',lambda:ledger_field('terminalObservation',None),8,"terminal is None",'False',0),
 ('cancel_cleanup_unconfirmed',unclean_cancel,8,"not ledger['cleanupConfirmed']",'False',6),
 ('deadline_observation_early',lambda:ledger_field('terminalObservation','deadline-exceeded'),4,"_time(ledger['observedAt']) <= _time(execution['deadlineAt'])",'False',7),
 ('observation_after_completion',lambda:ledger_field('observedAt','2026-01-01T00:00:30Z'),4,"_time(ledger['observedAt']) < _time(result['completedAt'])",'False',0),
 ('deadline_after_start',invalid_deadline,3,"_time(execution['deadlineAt']) <= _time(execution['startedAt'])",'False',6),
 ('ledger_shape_fields',extra_ledger_field,3,"set(ledger) != fields",'False',0),
 ('ledger_shape_kind',lambda:ledger_field('kind','synthetic-other-ledger'),3,"ledger['kind'] != 'synthetic-collector-ledger-v1'",'False',0),
 ('ledger_shape_collector',ledger_collector_name,3,"not ledger['collectorId'].startswith('synthetic-')",'False',0),
 ('ledger_shape_schema',lambda:ledger_field('pendingChildren',-1),3,"next(make_validator(shape).iter_errors(ledger), None) is not None",'False',8),
]


class PredicateControls(unittest.TestCase):
    def test_failed_receipt_fixture_positive(self):
        docs=failed_receipt_cleanup();docs[2]['checks'][0]['cleanupConfirmed']=True
        self.assertEqual(verdict(verifier.verify,docs),2)


def predicate_test(case):
    name,builder,expected,old,new,mutant_expected=case
    def test(self):
        docs=builder();original=copy.deepcopy(docs)
        self.assertEqual(verdict(verifier.verify,docs),expected)
        self.assertEqual(docs,original,'verification must not mutate input')
        self.assertEqual(verdict(mutate_source(old,new),docs),mutant_expected)
        self.assertNotEqual(mutant_expected,expected)
    test.__doc__='Single-fault boundary and one-predicate mutant: '+name
    return test


for case in CASES:setattr(PredicateControls,'test_'+case[0],predicate_test(case))
