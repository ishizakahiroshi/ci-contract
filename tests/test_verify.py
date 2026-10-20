"""Fixed acceptance inputs and independent synthetic collector boundary tests."""
import copy
import unittest
from unittest.mock import patch
from synthetic_verify import MODELS, documents, acceptance_documents, digest, record_observation, START, LATE
from ci_contract.hashing import domain_hash
from ci_contract.verify import verify


def run(docs):
    p,e,r,l=docs
    return verify(p,e,r,synthetic_collector_ledger=l)


class Acceptance(unittest.TestCase):
    pass


def acceptance(case):
    def test(self):
        docs=acceptance_documents(case)
        self.assertEqual(run(docs), {k:case['expected'][k] for k in ('status','exitCode')})
    return test


for case in MODELS['cases']:
    setattr(Acceptance,'test_'+case['id'],acceptance(case))


class Boundary(unittest.TestCase):
    def test_baseline(self):
        self.assertEqual(run(documents())['exitCode'],0)

    def test_self_proof_never_sufficient(self):
        p,e,r,_=documents()
        self.assertEqual(verify(p,e,r)['exitCode'],4)

    def test_every_schema_precedes_terminal(self):
        for index in range(3):
            with self.subTest(index=index):
                docs=list(documents());docs[index]['extra']=True
                docs[3]['terminalObservation']='cancelled'
                self.assertEqual(run(docs)['exitCode'],3)

    def test_receipt_before_start(self):
        p,e,r,l=documents();r['completedAt']='2025-01-01T00:00:00Z'
        self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_observation_before_start(self):
        p,e,r,l=documents();l['observedAt']='2025-01-01T00:00:00Z'
        self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_authority_run_mismatch(self):
        p,e,r,l=documents();e['requestBinding']['attemptAuthority']['adoptedRunId']='999'
        r['executionSha256']=l['executionSha256']=domain_hash('execution',e)
        self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_unproduced_generated_digest(self):
        p,e,r,l=documents();r['checks'][0]['proof']['identity']['generatedInputDigests']=[digest('unproduced')]
        record_observation(r,l)
        self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_extra_artifact(self):
        p,e,r,l=documents()
        r['artifacts'].append({'id':'extra','sha256':digest('extra'),'sizeBytes':1,'sourceDigest':p['source']['digest'],
          'planSha256':r['planSha256'],'producerCheckId':'nonexistent','mediaType':'application/octet-stream','retentionDays':7,'privacy':'public'})
        self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_receipt_tamper_without_observation(self):
        p,e,r,l=documents();r['checks'][0]['proof']['collector']['eventLogSha256']=digest('other')
        record_observation(r,copy.deepcopy(l))
        self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_invalid_schema_mutant_detected(self):
        for key in ('c08','r31','r32','r33','r34'):
            case=next(c for c in MODELS['cases'] if c['id']==key)
            with self.subTest(key=key),patch('ci_contract.verify.validate',lambda value:None):
                self.assertNotEqual(run(acceptance_documents(case))['exitCode'],3)

    def test_incomplete_test_policy_mutant_detected(self):
        case=next(c for c in MODELS['cases'] if c['id']=='r11')
        with patch('ci_contract.verify._proof_ok',return_value=True):
            self.assertEqual(run(acceptance_documents(case))['exitCode'],0)

    def test_wrong_os_and_empty_analysis_rejected(self):
        for key in ('r13','r14'):
            with self.subTest(key=key):
                docs=acceptance_documents(next(c for c in MODELS['cases'] if c['id']==key))
                if key=='r13': docs[2]['checks'][1]['proof']['runtime']['os']='linux'
                else: docs[2]['checks'][0]['proof']['collection']['targetPaths']=[]
                record_observation(docs[2],docs[3])
                self.assertNotEqual(run(docs)['exitCode'],0)

    def test_plan_relations(self):
        for field,value in [('dependsOn',['missing']),('requirementIds',['missing']),('requiredCapabilities',[{'id':'missing','value':'yes'}])]:
            with self.subTest(field=field):
                p,e,r,l=documents();p['checks'][0][field]=value
                e['plan']=copy.deepcopy(p);e['planSha256']=domain_hash('plan',p)
                r['planSha256']=l['planSha256']=e['planSha256']
                r['executionSha256']=l['executionSha256']=domain_hash('execution',e)
                for c in r['checks']:c['proof']['identity']['planSha256']=e['planSha256']
                record_observation(r,l)
                self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_terminal_controls(self):
        import inspect
        import ci_contract.verify as module
        source=inspect.getsource(module.verify)
        start=source.index('        # Only the selected execution')
        end=source.index('        if not _bindings',start)
        # Fault: discard independent terminal and cleanup observations, and
        # proceed directly to the last receipt. Expected cases stay unchanged.
        source=source[:start]+source[end:]
        namespace=dict(module.__dict__)
        exec(compile(source,'<synthetic-terminal-mutant>','exec'),namespace)
        for key in ('c18','c18a','c18b','r19','r28','r29','r30'):
            case=next(c for c in MODELS['cases'] if c['id']==key)
            p,e,r,l=acceptance_documents(case)
            with self.subTest(key=key):
                self.assertNotEqual(namespace['verify'](p,e,r,synthetic_collector_ledger=l)['exitCode'],case['expected']['exitCode'])

    def test_payload_source_only_mutant(self):
        case=next(c for c in MODELS['cases'] if c['id']=='r16')
        with patch('ci_contract.verify._proof_ok',return_value=True):
            self.assertEqual(run(acceptance_documents(case))['exitCode'],0)

    def test_missing_instance_mutant(self):
        import inspect
        import ci_contract.verify as module
        source=inspect.getsource(module.verify)
        source=source.replace("or set(received) != set(ids)", "or False")
        source=source.replace("or set(proofs) != set(ids)", "or False")
        namespace=dict(module.__dict__)
        exec(compile(source, '<synthetic-mutant>', 'exec'), namespace)
        for key in ('r12','c23'):
            case=next(c for c in MODELS['cases'] if c['id']==key)
            p,e,r,l=acceptance_documents(case)
            with self.subTest(key=key):
                self.assertEqual(namespace['verify'](p,e,r,synthetic_collector_ledger=l)['exitCode'],0)

    def test_foreign_binding_mutant(self):
        p,e,r,l=documents();r['planSha256']=digest('foreign')
        with patch('ci_contract.verify._bindings',return_value=True), patch('ci_contract.verify._proof_ok',return_value=True):
            self.assertEqual(run((p,e,r,l))['exitCode'],0)

    def test_no_backing_even_terminal_claims(self):
        for status,code in [('cancelled',6),('timeout',7),('unknown',8)]:
            with self.subTest(status=status):
                p,e,r,l=documents();r.update(status=status,exitCode=code,cleanupConfirmed=False)
                self.assertEqual(verify(p,e,r)['exitCode'],4)

    def test_self_report_trust_mutant(self):
        case=next(c for c in MODELS['cases'] if c['id']=='r15')
        p,e,r,_=acceptance_documents(case)
        # Fault: promote the worker's own artifact to an independent ledger.
        ledger=documents()[3]
        ledger['collectorId']='synthetic-untrusted-worker'
        for receipt in r['checks']:receipt['proof']['collector']['collectorId']=ledger['collectorId']
        record_observation(r,ledger)
        self.assertEqual(run((p,e,r,ledger))['exitCode'],0)
        self.assertEqual(verify(p,e,r)['exitCode'],4)

    def test_skipped_exit_zero_mutant(self):
        import inspect
        import ci_contract.verify as module
        source=inspect.getsource(module.verify)
        source=source.replace("if any(receipt['status'] != 'passed' for receipt in receipts):", "if any(receipt['exitCode'] != 0 for receipt in receipts):")
        source=source.replace("result['status'] != 'accepted'", "result['status'] not in ('accepted','blocked')")
        namespace=dict(module.__dict__)
        namespace['_proof_ok']=lambda check,receipt,*args:receipt['exitCode']==0
        exec(compile(source,'<synthetic-skip-mutant>','exec'),namespace)
        p,e,r,l=acceptance_documents(next(c for c in MODELS['cases'] if c['id']=='r40'))
        self.assertEqual(namespace['verify'](p,e,r,synthetic_collector_ledger=l)['exitCode'],0)

    def test_cycle_is_invalid_before_terminal(self):
        p,e,r,l=documents()
        p['checks'][0]['dependsOn']=[p['checks'][1]['id']]
        p['checks'][1]['dependsOn']=[p['checks'][0]['id']]
        l['terminalObservation']='cancelled'
        self.assertEqual(run((p,e,r,l))['exitCode'],3)

    def test_github_source_mismatch(self):
        p,e,r,l=documents();e['github']['targetCommit']='a'*40
        r['executionSha256']=l['executionSha256']=domain_hash('execution',e)
        self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_failed_needs_bound_proof(self):
        p,e,r,l=documents();r.update(status='failed',exitCode=2)
        receipt=r['checks'][0];receipt.update(status='failed',exitCode=1)
        receipt['proof']['invocation']['exitCode']=1
        record_observation(r,l)
        self.assertEqual(run((p,e,r,l))['exitCode'],2)
        receipt['proof']['identity']['claimSha256']=digest('foreign-claim')
        record_observation(r,l)
        self.assertEqual(run((p,e,r,l))['exitCode'],4)

    def test_targeted_proof_controls(self):
        import inspect
        import ci_contract.verify as module
        source=inspect.getsource(module._proof_ok)
        for key,old,new in (
            ('r11',"if (not required or set(collection['expectedCaseIds']) != required", "if (False and set(collection['expectedCaseIds']) != required"),
            ('r13',"runtime['os'] != variant['os']",'False'),
            ('r14',"receipt['executedTests'] is not None", "receipt['executedTests'] is None"),
            ('r16',"artifact['sha256'] != payload['sha256']", 'False')):
            docs=acceptance_documents(next(c for c in MODELS['cases'] if c['id']==key))
            if key=='r11':
                start=source.index("        required = set(policy['expectedCaseIds'])")
                end=source.index("    elif check['kind']",start)
                mutated=source[:start]+"        return receipt['executedTests'] >= 1\n"+source[end:]
            else:
                mutated=source.replace(old,new)
            if key=='r13':
                docs[2]['checks'][1]['proof']['runtime']['os']='linux'
                record_observation(docs[2],docs[3])
                self.assertEqual(run(docs)['exitCode'],4)
            namespace=dict(module.__dict__)
            exec(compile(mutated,'<synthetic-proof-mutant>','exec'),namespace)
            with self.subTest(key=key),patch.object(module,'_proof_ok',namespace['_proof_ok']):
                self.assertEqual(run(docs)['exitCode'],4 if key=='r14' else 0)
