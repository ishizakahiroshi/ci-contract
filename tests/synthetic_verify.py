"""Synthetic complete M5 documents. No service, authority, or real collector."""
import copy
import hashlib
from pathlib import Path
from ci_contract import cjson
from ci_contract.hashing import canonical_hash, domain_hash
from ci_contract.inventory import normalize_inventory, source_digest

ROOT = Path(__file__).resolve().parent
MODELS = cjson.loads((ROOT / 'fixtures/verify-cases.json').read_bytes())
MODEL = MODELS['fixtureModels'][0]
ALIASES = {entry['instanceId']: (name, entry) for name, entry in MODEL['instanceAliases'].items()}
START = '2026-01-01T00:00:00Z'
END = '2026-01-01T00:01:00Z'
DEADLINE = '2026-01-01T00:02:00Z'
LATE = '2026-01-01T00:03:00Z'


def digest(label):
    return hashlib.sha256(('synthetic-only:' + label).encode()).hexdigest()


def make_plan(ids=None, overrides=None):
    manifest = cjson.loads((ROOT / 'fixtures/synthetic-manifest-template.json').read_bytes())
    checks = []
    ids = MODEL['requiredGate']['requiredInstanceIds'] if ids is None else ids
    overrides = {} if overrides is None else overrides
    for identifier in ids:
        name, alias = ALIASES[identifier]
        kind = ('type' if name.startswith('guard.type') else 'secrets' if name.startswith('guard.secrets')
                else 'static' if name.startswith(('guard.static', 'docs.lint')) else 'generation' if name.startswith('assets.generate')
                else 'artifact' if name.startswith('package.verify') else 'test')
        check = copy.deepcopy(manifest['checks'][0])
        check.pop('variants', None)
        check.update(id=identifier, logicalCheckId=alias['logicalCheckId'], variant=copy.deepcopy(alias['variant']), kind=kind,
                     requirementIds=['synthetic.requirement'], adapter='synthetic-adapter', adapterSha256=digest('adapter'),
                     dependsOn=[], requiredCapabilities=[], inputPaths=[entry['path'] for entry in MODEL['sourceInventory']], inputRuleIds=['synthetic-input'], always=kind in ('type','static','secrets','generation'),
                     alwaysScope={'scope':'repo','componentIds':[],'profiles':['integration']} if kind in ('type','static','secrets','generation') else None)
        check['proofPolicy'] = {'enumerationContractSha256':digest('enumeration-'+identifier),
                               'expectedCaseIds':copy.deepcopy(MODEL['defaultTestCases']) if kind == 'test' else [],
                               'expectedTargetPaths':['src/auth.ts'] if kind in ('type','static','secrets') else [],
                               'expectedPayloadIds':['synthetic-payload'] if kind in ('generation','artifact') else [],
                               'assertionReviewSha256':digest('assertion'), 'negativeControlEvidenceSha256':digest('negative')}
        for key,value in overrides.get(identifier, {}).items():
            check[key] = copy.deepcopy(value)
        checks.append(check)
    inv = normalize_inventory(copy.deepcopy(MODEL['sourceInventory']))
    pins = copy.deepcopy(manifest['qualityProjectionRef'])
    expected_pins = {key:copy.deepcopy(pins) for key in ('manifest','policy','engineLock','qualityProjection')}
    for key in ('manifest','policy','engineLock'):
        expected_pins[key]['path'] = '.ci/' + key + '.json'
        expected_pins[key]['sha256'] = digest(key)
    request = {'version':'1','repositoryId':'synthetic','baseCommit':'b'*40,'comparison':'head','mode':'changed',
               'requestedCheckIds':[], 'cases':[], 'expectedPins': expected_pins}
    return {'kind':'plan','contractVersion':'1.0','repository':copy.deepcopy(manifest['repository']),
            'engine':copy.deepcopy(manifest['engine']),'manifestSha256':digest('manifest'),'policySha256':digest('policy'),
            'source':{'mode':'commit','baseCommit':'b'*40,'targetCommit':'d'*40,'tree':'e'*40,'digest':source_digest(inv),
                      'inputs':inv['entries'],'immutable':True,'comparison':'head'},
            'profile':'integration','requirements':['synthetic.requirement'],'checks':checks,'removedObligations':[],
            'exceptions':[],'selectionReasons':['synthetic selection'],'omissionReasons':[],
            'selectionRequest':request,'selectionRequestSha256':canonical_hash(request),
            'qualityProjectionRef':pins,'qualityProjectionSha256':pins['sha256'],
            'selectionEvidence':{'graphVersion':'literal-impact-v1','baseModelSha256':digest('base-model'),
                                 'targetModelSha256':digest('target-model'),'baseInventorySha256':source_digest(inv),
                                 'targetInventorySha256':source_digest(inv),'changes':[],'impactedComponentIds':[],
                                 'selectedInstanceIds':list(ids),'fallback':{'scope':'none','reasons':[],'componentIds':[]},
                                 'completenessVerified':False}}


def documents(ids=None, overrides=None, attempt=1):
    plan = make_plan(ids, overrides)
    pd = domain_hash('plan', plan)
    authority = {'authorityId':'synthetic-authority','requestId':'synthetic-request','requestDigest':digest('request'),
                 'attemptNumber':attempt,'adopted':True,'adoptedRunId':'123','adoptedProviderAttempt':attempt,
                 'fence':attempt,'claimId':'synthetic-claim','adoptionRecordSha256':digest('adoption-'+str(attempt)),
                 'previousTerminalReceiptSha256':None}
    binding = {'requestId':'synthetic-request','requestDigest':digest('request'),'scopeKey':digest('scope'),
               'attemptAuthority':authority,'authorityKind':'github-run-v1'}
    execution = {'kind':'execution','contractVersion':'1.0','executionId':'synthetic-execution-'+str(attempt),
                 'planSha256':pd,'plan':copy.deepcopy(plan),'target':'github','capabilities':[{'id':'synthetic','value':'yes'}],
                 'github':{'callerRepository':'synthetic/repository','workflowPath':'.github/workflows/synthetic.yml',
                           'workflowRef':'synthetic-ref','expectedWorkflowCommit':'f'*40,'targetCommit':'d'*40,
                           'runId':'123','attempt':attempt,'event':'pull_request','trust':'trusted','runnerClass':'standard-hosted'},
                 'startedAt':START,'deadlineAt':DEADLINE,'claimSha256':digest('claim-'+str(attempt)),'requestBinding':binding}
    result_binding = {key:binding[key] for key in ('requestId','requestDigest','scopeKey','authorityKind')}
    result_binding.update({key:authority[key] for key in ('attemptNumber','fence','adoptionRecordSha256')})
    result = {'kind':'result','contractVersion':'1.0','executionId':execution['executionId'],'executionSha256':domain_hash('execution',execution),
              'planSha256':pd,'engineSha256':plan['engine']['bundleSha256'],'sourceDigestBefore':plan['source']['digest'],
              'sourceDigestAfter':plan['source']['digest'],'target':'github','status':'accepted','exitCode':0,'checks':[],
              'missingCheckIds':[],'unresolvedRequirementIds':[],'pendingChildren':0,'cleanupConfirmed':True,
              'evidenceOrigin':'github-artifact','artifacts':[],'completedAt':END,'requestBinding':result_binding}
    for check in plan['checks']:
        policy, variant = check['proofPolicy'], check['variant']
        payloads=[]
        for payload_id in policy['expectedPayloadIds']:
            payloads.append({'artifactId':payload_id,'sha256':digest('payload-a'),'sizeBytes':10,'os':variant['os'],
                             'arch':variant['arch'],'producerInstanceId':check['id'],'inputDigests':[plan['source']['digest']]})
            result['artifacts'].append({'id':payload_id,'sha256':digest('payload-a'),'sizeBytes':10,'sourceDigest':plan['source']['digest'],
                                        'planSha256':pd,'producerCheckId':check['id'],'mediaType':'application/octet-stream','retentionDays':7,'privacy':'public'})
        proof={'proofVersion':'embedded-proof-v1','identity':{'requestId':binding['requestId'],'executionId':execution['executionId'],
               'planSha256':pd,'claimSha256':execution['claimSha256'],'instanceId':check['id'],'logicalCheckId':check['logicalCheckId'],
               'adapterSha256':check['adapterSha256'],'sourceDigest':plan['source']['digest'],'generatedInputDigests':[],'attempt':attempt},
               'kind':check['kind'],'variant':copy.deepcopy(variant),
               'runtime':{'os':variant['os'],'arch':variant['arch'],'toolchains':[{'id':'synthetic-tool','version':'1.0','binarySha256':digest('tool')}],
                          'datasetSha256':variant['dataset']['sha256'],'serviceFixtureDigests':[],'imageIdentity':{'kind':'provider-image-release','name':'synthetic-image','version':'1','fingerprintSha256':digest('image')}},
               'invocation':{'adapterEntry':'tools/synthetic.py','argv':check['argv'],'cwd':check['cwd'],'startedAt':START,'completedAt':END,'exitCode':0,'signal':None},
               'collection':{'enumerationContractSha256':policy['enumerationContractSha256'],
                             'expectedCaseIds':copy.deepcopy(policy['expectedCaseIds']),'executedCaseIds':copy.deepcopy(policy['expectedCaseIds']),
                             'passedCaseIds':copy.deepcopy(policy['expectedCaseIds']),'failedCaseIds':[],'skippedCases':[],
                             'collectionComplete':True,'targetPaths':copy.deepcopy(policy['expectedTargetPaths']),
                             'analysisCompleted':True,'diagnosticCount':0 if check['kind'] in ('type','static','secrets') else None},
               'payloads':payloads,'collector':{'collectorId':'synthetic-collector','collectorBinarySha256':digest('collector'),
                'collectorPolicySha256':digest('collector-policy'),'eventLogSha256':digest('events-'+check['id']),
                'target':'github','runId':'123','jobId':'456','attempt':attempt,'workerNonce':'synthetic-worker',
                'observationBoundary':'supervised-process-and-adapter-protocol','retentionDays':7},
               'cleanup':{'childrenStopped':True,'resourcesReleased':True,'unresolvedResourceIds':[]}}
        result['checks'].append({'id':check['id'],'kind':check['kind'],'status':'passed','exitCode':0,
                                 'executedTests':len(policy['expectedCaseIds']) if check['kind']=='test' else None,
                                 'proofSha256':canonical_hash(proof),'adapterSha256':check['adapterSha256'],'cleanupConfirmed':True,
                                 'logicalCheckId':check['logicalCheckId'],'variant':copy.deepcopy(variant),'proof':proof})
    ledger={'kind':'synthetic-collector-ledger-v1','collectorId':'synthetic-collector','planSha256':pd,
            'executionSha256':result['executionSha256'],'requestBinding':copy.deepcopy(result_binding),'terminalObservation':'completed',
            'observedAt':END,'cleanupConfirmed':True,'pendingChildren':0,'proofs':[copy.deepcopy(r['proof']) for r in result['checks']]}
    return plan, execution, result, ledger


def record_observation(result, ledger):
    """Test-only: capture deliberately built synthetic observation, never trust input."""
    for receipt in result['checks']:
        receipt['proofSha256']=canonical_hash(receipt['proof'])
    ledger['proofs']=[copy.deepcopy(receipt['proof']) for receipt in result['checks']]


def acceptance_documents(case):
    """Translate only given/model data; expected values are never inputs."""
    key, given = case['id'], case['given']
    ids = None
    overrides = {}
    if key in ('r12','r13'):
        ids = given['required_instances']
    elif key == 'r14':
        ids = [c['id'] for c in given['checks']]
        for c in given['checks']:
            policy = make_plan([c['id']])['checks'][0]['proofPolicy']
            policy['expectedTargetPaths'] = c.get('analyzed_files', c.get('scanned_files'))
            overrides[c['id']] = {'proofPolicy':policy}
    elif key == 'c16':
        ids = given['requiredInstances']
    elif key == 'c23':
        ids = given['selectedInstances']
    elif key == 'r16':
        ids = MODEL['requiredGate']['requiredInstanceIds'] + [MODEL['instanceAliases']['package.verify.linux']['instanceId']]
    elif key == 'r40':
        ids = [MODEL['instanceAliases']['auth.unit.linux']['instanceId']]
    p,e,r,l = documents(ids, overrides, attempt=given.get('selected_attempt',given.get('selectedAttempt',1)))
    byid = {c['id']:c for c in r['checks']}
    if key in ('c08','r31'):
        receipt = byid.get(given.get('instanceId')) or next(c for c in r['checks'] if c['kind']=='test')
        receipt.update(given.get('receiptPatch',given.get('check_result')))
    elif key == 'r11':
        receipt = byid[given['check_id']]
        receipt.update(given['summary'])
        collection = receipt['proof']['collection']
        collection['expectedCaseIds'] = given['required_cases']
        collection['executedCaseIds'] = given['proof']['passed']
        collection['passedCaseIds'] = given['proof']['passed']
        collection['skippedCases'] = [{'id':x['case'],'reasonCode':x['reason']} for x in given['proof']['skipped']]
        record_observation(r,l)
    elif key in ('r12','r13'):
        r['checks'] = [byid[x['id']] for x in given['receipts']]
        for c, source in zip(r['checks'],given['receipts']):
            c['status']=source['status']; c['proof']['runtime']['os']=source['actual_os']
        record_observation(r,l)
    elif key == 'r14':
        for item in given['checks']:
            receipt = byid[item['id']]
            for field in ('kind','executedTests','status','exitCode'): receipt[field]=item[field]
            collection=receipt['proof']['collection']
            collection['analysisCompleted']=item['completed']
            collection['diagnosticCount']=item.get('diagnostic_count',item.get('finding_count'))
        record_observation(r,l)
    elif key == 'r15':
        for c in r['checks']: c['proof']['collector']['collectorId']=given['proof_issuer']
        record_observation(r,l)
        l=None
    elif key == 'r16':
        r['checks'][-1]['proof']['payloads'][0]['sha256']=digest(given['tested_payload_digest'])
        record_observation(r,l)
        r['artifacts'][0]['sha256']=digest(given['candidate_payload_digest'])
    elif key in ('c16','c23'):
        r['checks']=[byid[x] for x in given['receivedInstances']]
        if key == 'c16':
            r['planSha256']=digest(given['receiptPlan'])
            r['requestBinding']['attemptNumber']=given['receiptAttempt']
    elif key == 'r19':
        r=documents(attempt=given['timeline'][1]['attempt'])[2]
        l.update(terminalObservation='deadline-exceeded',observedAt=LATE)
    elif key in ('r28','r29','r30','c18','c18a','c18b'):
        terminal=given.get('terminal_observation',given.get('terminalObservation'))
        cleanup=given.get('cleanup_confirmed',given.get('cleanupConfirmed'))
        l.update(terminalObservation=terminal,cleanupConfirmed=cleanup,
                 pendingChildren=given.get('pending_children',given.get('pendingChildren',0)),
                 observedAt=LATE if terminal=='deadline-exceeded' else END)
        # Result is an untrusted last received success; only independent selected
        # terminal observations determine cancellation/deadline/disconnection.
    elif key in ('r32','r33','r34'):
        if key=='r32': r['checks'][0]['id']=given['value']
        elif key=='r33':r['planSha256']=given['value']
        else:p['source']['targetCommit']=given['value']
    elif key=='r40':
        r['checks'][0].update(given['check_result'])
        c=r['checks'][0]['proof']['collection']
        c.update(executedCaseIds=[],passedCaseIds=[],skippedCases=[{'id':x,'reasonCode':given['missing_capability']} for x in c['expectedCaseIds']])
        r.update(status='blocked',exitCode=4)
        record_observation(r,l)
    return p,e,r,l
