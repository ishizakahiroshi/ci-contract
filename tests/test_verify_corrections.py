"""Synthetic calendar, shape, deadline, and byte-preservation regressions."""
import copy
from ci_contract import cjson
from datetime import datetime
import inspect
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from ci_contract.hashing import domain_hash
from synthetic_verify import documents,digest,record_observation,START,END,DEADLINE
from test_verify import run


def reseal(p,e,r,l):
    e['plan']=copy.deepcopy(p);e['planSha256']=domain_hash('plan',p)
    r['planSha256']=l['planSha256']=e['planSha256']
    r['executionSha256']=l['executionSha256']=domain_hash('execution',e)
    for receipt in r['checks']:receipt['proof']['identity']['planSha256']=e['planSha256']
    record_observation(r,l)


def with_exception():
    p,e,r,l=documents()
    p['exceptions']=[{'id':'synthetic-exception','requirementId':'synthetic.requirement','reason':'synthetic',
      'owner':'synthetic','expiresAt':DEADLINE,'replacementCheckIds':[],'scopeSha256':digest('scope')}]
    reseal(p,e,r,l)
    return p,e,r,l

UTC_PATHS=[(0,('exceptions',0,'expiresAt')),(1,('plan','exceptions',0,'expiresAt')),
 (1,('startedAt',)),(1,('deadlineAt',)),(2,('completedAt',)),
 (2,('checks',0,'proof','invocation','startedAt')),(2,('checks',0,'proof','invocation','completedAt')),
 (3,('observedAt',)),(3,('proofs',0,'invocation','startedAt')),(3,('proofs',0,'invocation','completedAt'))]

class CalendarTests(unittest.TestCase):
    def test_every_utc_field_rejects_calendar_and_range_errors_before_semantics(self):
        for index,path in UTC_PATHS:
            for bad in ('2026-02-30T00:00:00Z','2026-01-01T00:00:60Z','2026-01-01T24:00:00Z','0000-01-01T00:00:00Z'):
                with self.subTest(document=index,path=path,value=bad):
                    docs=with_exception();node=docs[index]
                    for token in path[:-1]:node=node[token]
                    node[path[-1]]=bad
                    docs[3]['terminalObservation']='cancelled'
                    self.assertEqual(run(docs)['exitCode'],3)

    def test_real_leap_day_is_accepted(self):
        docs=documents()
        for index,path in UTC_PATHS[2:]:
            node=docs[index]
            for token in path[:-1]:node=node[token]
            node[path[-1]]='2024-02-29T00:02:00Z' if path[-1]=='deadlineAt' else '2024-02-29T00:00:00Z' if path[-1]=='startedAt' else '2024-02-29T00:01:00Z'
        for receipt in docs[2]['checks']:
            receipt['proof']['invocation'].update(startedAt='2024-02-29T00:00:00Z',completedAt='2024-02-29T00:01:00Z')
        reseal(*docs)
        self.assertEqual(run(docs)['exitCode'],0)

    def test_legacy_calendar_checker_fault_is_detected(self):
        docs=documents();docs[2]['completedAt']='2026-02-30T00:00:00Z'
        with patch('ci_contract.verify._utc_shapes',lambda value:None),patch('ci_contract.verify._time',lambda value:datetime.fromisoformat(value.replace('Z','+00:00'))):
            with self.assertRaises(ValueError):run(docs)

class ShapeDeadlineTests(unittest.TestCase):
    def test_bad_deadline_precedes_binding_pin_and_source_mismatches(self):
        for fault in ('binding','pin','source'):
            for deadline in (START,'2025-01-01T00:00:00Z'):
                with self.subTest(fault=fault,deadline=deadline):
                    docs=documents();p,e,r,l=docs;e['deadlineAt']=deadline
                    if fault=='binding':e['planSha256']=digest('foreign')
                    elif fault=='pin':p['manifestSha256']=digest('foreign')
                    else:p['source']['digest']=digest('foreign')
                    self.assertEqual(run(docs)['exitCode'],3)

    def test_result_and_ledger_duplicate_paths_are_structural_errors(self):
        for where in ('result','ledger'):
            docs=documents();p,e,r,l=docs
            proof=r['checks'][0]['proof'] if where=='result' else l['proofs'][0]
            proof['collection']['targetPaths']*=2
            if where=='result':record_observation(r,l)
            self.assertEqual(run(docs)['exitCode'],3)

    def test_valid_set_permutation_preserves_raw_proof_hash_semantics(self):
        docs=documents()
        for receipt in docs[2]['checks']:
            collection=receipt['proof']['collection']
            for field in ('expectedCaseIds','executedCaseIds','passedCaseIds'):
                collection[field].reverse()
        record_observation(docs[2],docs[3])
        self.assertEqual(run(docs)['exitCode'],0)

    def test_completion_at_deadline_is_accepted_but_timeout_at_deadline_is_blocked(self):
        docs=documents();p,e,r,l=docs
        r['completedAt']=l['observedAt']=DEADLINE
        for receipt in r['checks']:receipt['proof']['invocation']['completedAt']=DEADLINE
        record_observation(r,l)
        self.assertEqual(run(docs)['exitCode'],0)
        l['terminalObservation']='deadline-exceeded'
        self.assertEqual(run(docs)['exitCode'],4)
        l['observedAt']='2026-01-01T00:02:01Z'
        self.assertEqual(run(docs)['exitCode'],7)

    def test_nonartifact_kind_cannot_smuggle_payload(self):
        for kind in ('test','type','static','secrets'):
            docs=documents();p,e,r,l=docs
            receipt=next(c for c in r['checks'] if c['kind']==kind)
            receipt['proof']['payloads']=[{'artifactId':'synthetic-extra','sha256':digest('payload'),'sizeBytes':1,
              'os':receipt['variant']['os'],'arch':receipt['variant']['arch'],
              'producerInstanceId':receipt['id'],'inputDigests':[p['source']['digest']]}]
            r['artifacts']=[{'id':'synthetic-extra','sha256':digest('payload'),'sizeBytes':1,
              'sourceDigest':p['source']['digest'],'planSha256':r['planSha256'],'producerCheckId':receipt['id'],
              'mediaType':'application/octet-stream','retentionDays':7,'privacy':'public'}]
            record_observation(r,l)
            with self.subTest(kind=kind):
                self.assertEqual(run(docs)['exitCode'],4)
                import ci_contract.verify as module
                source=inspect.getsource(module._proof_ok).replace("if check['kind'] not in ('generation', 'artifact') and proof['payloads']:","if False:")
                namespace=dict(module.__dict__);exec(compile(source,'<synthetic-payload-fault>','exec'),namespace)
                with patch.object(module,'_proof_ok',namespace['_proof_ok']):self.assertEqual(run(docs)['exitCode'],0)

class FixedByteAttributesTests(unittest.TestCase):
    def test_autocrlf_checkout_preserves_synthetic_asset_bytes(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            repo=Path(folder)
            def git(*args):
                env = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith('GIT_CONFIG_')}
                return subprocess.run(['git','-C',str(repo),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env).stdout
            git('init');git('config','core.autocrlf','true')
            (repo/'.gitattributes').write_bytes((root/'.gitattributes').read_bytes())
            paths=['src/ci_contract/data/SOURCES.json','tests/fixtures/synthetic.json','tests/acceptance-coverage.json']
            data=b'{"synthetic":true}\n'
            for path in paths:
                file=repo/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(data)
            git('add','.')
            for path in paths:(repo/path).unlink()
            git('checkout-index','-f','-a')
            for path in paths:self.assertEqual((repo/path).read_bytes(),data)

class CorrectiveMutationTests(unittest.TestCase):
    def test_deadline_priority_regression_is_detected(self):
        import ci_contract.verify as module
        source=inspect.getsource(module.verify)
        block="        if _time(execution['deadlineAt']) <= _time(execution['startedAt']):\n            return _verdict('invalid-input')\n"
        self.assertEqual(source.count(block),1)
        source=source.replace(block,'').replace('        ledger = synthetic_collector_ledger',block+'        ledger = synthetic_collector_ledger')
        namespace=dict(module.__dict__);exec(compile(source,'<synthetic-late-deadline>','exec'),namespace)
        p,e,r,l=documents();e['deadlineAt']=START;e['planSha256']=digest('foreign')
        self.assertEqual(run((p,e,r,l))['exitCode'],3)
        self.assertEqual(namespace['verify'](p,e,r,synthetic_collector_ledger=l)['exitCode'],4)

    def test_deadline_equality_fault_is_detected(self):
        import ci_contract.verify as module
        source=inspect.getsource(module.verify)
        before="if _time(ledger['observedAt']) <= _time(execution['deadlineAt']):"
        self.assertEqual(source.count(before),1)
        source=source.replace(before,before.replace(' <= ',' < '))
        namespace=dict(module.__dict__);exec(compile(source,'<synthetic-deadline-equality>','exec'),namespace)
        p,e,r,l=documents();l.update(terminalObservation='deadline-exceeded',observedAt=DEADLINE)
        self.assertEqual(run((p,e,r,l))['exitCode'],4)
        self.assertEqual(namespace['verify'](p,e,r,synthetic_collector_ledger=l)['exitCode'],7)

    def test_missing_byte_attributes_control_changes_checkout_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=Path(folder)
            def git(*args):
                env = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith('GIT_CONFIG_')}
                return subprocess.run(['git','-C',str(repo),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env).stdout
            git('init');git('config','core.autocrlf','true')
            file=repo/'synthetic.json';data=b'{"synthetic":true}\n';file.write_bytes(data)
            git('add','.');file.unlink();git('checkout-index','-f','-a')
            self.assertEqual(file.read_bytes(),b'{"synthetic":true}\r\n')
            self.assertNotEqual(file.read_bytes(),data)

class CalendarAndLedgerBoundaryTests(unittest.TestCase):
    def test_cli_calendar_error_is_invalid_not_internal_error(self):
        import io,sys
        from ci_contract import cli,cjson
        from test_verify_cli import BinaryStream
        p,e,r,l=documents();r['completedAt']='2026-02-30T00:00:00Z'
        out,err=BinaryStream(),BinaryStream()
        with tempfile.TemporaryDirectory() as folder:
            paths=[Path(folder)/name for name in ('p','e','r')]
            for path,value in zip(paths,(p,e,r)):path.write_bytes(cjson.dumps(value))
            with patch.object(sys,'stdout',out),patch.object(sys,'stderr',err):
                code=cli.main(['verify','--plan',str(paths[0]),'--execution',str(paths[1]),'--result',str(paths[2])])
        self.assertEqual((code,out.buffer.getvalue(),err.buffer.getvalue()),(3,b'invalid-input\n',b'ci-contract: invalid input\n'))

    def test_ledger_duplicate_normalization_removal_is_detected(self):
        import ci_contract.verify as module
        source=inspect.getsource(module._ledger_shape)
        start=source.index("    normalize({'checks':")
        source=source[:start]
        namespace=dict(module.__dict__);exec(compile(source,'<synthetic-ledger-set-fault>','exec'),namespace)
        docs=documents();docs[3]['proofs'][0]['collection']['targetPaths']*=2
        self.assertEqual(run(docs)['exitCode'],3)
        with patch.object(module,'_ledger_shape',namespace['_ledger_shape']):
            self.assertEqual(run(docs)['exitCode'],4)

class CoverageStatusTests(unittest.TestCase):
    def test_stale_top_level_status_matrix_is_detected(self):
        import json
        import test_contract_bytes as contract
        path=Path(__file__).with_name('acceptance-coverage.json')
        value=cjson.loads(path.read_text())
        ids={case['id'] for case in value['verifyCore']['cases']}
        for case in value['cases']:
            if case['id'] in ids:case['status']='not-implemented'
        original=Path.read_text
        def read(file,*args,**kwargs):
            return json.dumps(value) if file==path else original(file,*args,**kwargs)
        with patch.object(Path,'read_text',read),self.assertRaises(AssertionError):
            contract.SourceIntegrityTests().test_acceptance_coverage_is_complete_and_conservative()
