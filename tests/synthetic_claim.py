"""Synthetic local-authority fixtures. No real provider, dispatch, network or authority.

Journals live only in per-test temporary folders. The clock is replaced, the
sender and the read-only query are counting fakes, and crafted journals are
resealed here with the same pinned domain hash so a single fault is isolated.
"""
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import os
from pathlib import Path
import shutil
import tempfile
from ci_contract import cjson, request
from ci_contract.hashing import domain_hash
from ci_contract.journal import LocalJournal
from ci_contract.request_binding import make_request_binding

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
AUTHORITY = 'synthetic-authority'
CREATED = '2026-01-01T00:00:00Z'
EXPIRES = '2026-01-01T01:00:00Z'
WORKFLOW = 'f' * 40


class Clock:
    """A replaceable UTC clock; tests advance it instead of sleeping."""

    def __init__(self, start=T0):
        self.now, self.reads = start, 0

    def __call__(self):
        self.reads += 1
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        return self


class Sender:
    """Counts send calls. ``lose`` simulates a lost response after the call."""

    def __init__(self, lose=False, inspect=None):
        self.calls, self.lose, self.inspect = [], lose, inspect

    def __call__(self, inputs):
        self.calls.append(copy.deepcopy(inputs))
        if self.inspect is not None:
            self.inspect(inputs)
        if self.lose:
            raise ConnectionError('synthetic lost response')


class Query:
    """A read-only provider listing fake that records its calls."""

    def __init__(self, candidates):
        self.candidates, self.calls = candidates, []

    def __call__(self, identity):
        self.calls.append(copy.deepcopy(identity))
        return copy.deepcopy(self.candidates)


@lru_cache(maxsize=None)
def _shared():
    from synthetic_request import fixed_model
    selection, fixed = fixed_model()
    return request.build_selection_plan(selection, 'change', **fixed), fixed


def shared_plan():
    """The real synthetic planner output and its fixed inputs (copied per caller)."""
    plan, fixed = _shared()
    return copy.deepcopy(plan), copy.deepcopy(fixed)


def binding_for(plan, request_id, *, authority_id=AUTHORITY, trust='trusted', created=CREATED,
                expires=EXPIRES, kind='local-single-supervisor-v1', workflow=WORKFLOW):
    return make_request_binding(plan, request_id=request_id, authority_id=authority_id, target='github',
                                trust=trust, workflow_commit=workflow, created_at=created,
                                expires_at=expires, authority_kind=kind)


def inputs_for(plan, binding):
    return request.dispatch_inputs(plan, binding['requestId'], binding['workflowCommit'])


def candidate(binding, run_id='123', attempt=1, **changes):
    return dict({'runId': run_id, 'providerAttempt': attempt, 'requestId': binding['requestId'],
                 'planSha256': binding['planSha256'], 'workflowSha': binding['workflowCommit']}, **changes)


class Workspace:
    """A temporary folder with a synthetic repository root and a separate authority folder."""

    def __init__(self):
        self._folder = tempfile.TemporaryDirectory(prefix='synthetic-journal-')
        self.root = Path(self._folder.name)
        self.repository = self.root / 'repository'
        self.authority = self.root / 'authority'
        self.repository.mkdir()
        self.authority.mkdir()
        self.path = str(self.authority / 'journal.jsonl')

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._folder.cleanup()

    def journal(self, create=True, **options):
        options.setdefault('authority_id', AUTHORITY)
        options.setdefault('repository_roots', [str(self.repository)])
        factory = LocalJournal.create if create else LocalJournal
        return factory(self.path, **options)

    def bytes(self):
        return Path(self.path).read_bytes()

    def write(self, data):
        Path(self.path).write_bytes(data)

    def records(self):
        data = self.bytes()
        return [cjson.loads(line) for line in data.split(b'\n') if line]


def seal(records, chain=True):
    """Recompute chain, backlinks and record hashes, keeping every other field as given."""
    previous = None
    for record in records:
        if chain:
            record['previousRecordSha256'] = previous
        digest = domain_hash('journal-record', record)
        record['recordSha256'] = digest
        payload = record['payloadProjection']
        if record['payloadKind'] == 'claim':
            payload['ledgerRecordSha256'] = digest
        if record['payloadKind'] == 'attemptAuthority':
            payload['adoptionRecordSha256'] = digest
        previous = digest
    return records


def encode(records):
    return b''.join(cjson.dumps(record) + b'\n' for record in records)


def force_append(workspace, record_type, payload, fence=None):
    """Append one correctly chained record without any semantic admission check."""
    records = workspace.records()
    kind = {'request': 'requestBinding', 'retry-approval': 'requestBinding', 'adoption': 'attemptAuthority',
            'receipt': 'result', 'receipt-conflict': 'result'}.get(record_type, 'claim')
    payload = copy.deepcopy(payload)
    record = {'sequence': len(records) + 1, 'recordType': record_type, 'payloadKind': kind,
              'fence': records[-1]['fence'] if fence is None and records else (fence or 0),
              'previousRecordSha256': None, 'payloadProjection': payload, 'recordSha256': '0' * 64}
    if kind == 'claim':
        payload['ledgerSequence'] = record['sequence']
    records.append(record)
    workspace.write(encode(seal(records)))
    return record


def copy_journal(source, workspace):
    shutil.copyfile(source.path, workspace.path)


def adopted_documents(plan, binding, adoption, acquired_claim):
    """Complete synthetic plan/execution/result/ledger for one adopted attempt.

    The execution's attemptAuthority is the journal's adoption, the claim hash is
    the acquired claim's, and the synthetic collector observes the adopted run.
    """
    from synthetic_request_binding import bound_documents, bind_hashes
    docs = list(bound_documents('github', full=True, supplied_plan=plan))
    plan_document, execution, result, ledger, _ = docs
    docs[4] = copy.deepcopy(binding)
    execution['requestBinding']['requestId'] = binding['requestId']
    execution['requestBinding']['attemptAuthority'] = copy.deepcopy(adoption)
    execution['github'].update(runId=adoption['adoptedRunId'], attempt=adoption['adoptedProviderAttempt'],
                               expectedWorkflowCommit=binding['workflowCommit'], trust=binding['trust'])
    ledger['githubObservation']['workflowCommit'] = binding['workflowCommit']
    execution['claimSha256'] = domain_hash('claim', acquired_claim)
    for receipt in result['checks']:
        proof = receipt['proof']
        proof['identity'].update(claimSha256=execution['claimSha256'], attempt=adoption['attemptNumber'])
        proof['collector'].update(runId=adoption['adoptedRunId'], attempt=adoption['adoptedProviderAttempt'])
    return tuple(bind_hashes(docs))


def acquired_version(workspace, claim_id):
    return next(record['payloadProjection'] for record in workspace.records()
                if record['recordType'] == 'claim-acquired' and record['payloadProjection']['claimId'] == claim_id)


def record_types(workspace):
    return [record['recordType'] for record in workspace.records()]


def module_fault(module, before, after=None, name='synthetic_claim_fault'):
    """Compile one changed copy of a production module in memory; never edit its file.

    ``before`` is one exact snippet (with ``after``) or a list of (before, after)
    pairs applied together, each of which must occur exactly once.
    """
    import inspect
    import types
    source = inspect.getsource(module)
    for old, new in ([(before, after)] if after is not None else before):
        if source.count(old) != 1:
            raise AssertionError('fault location changed')
        source = source.replace(old, new)
    fault = types.ModuleType('ci_contract.' + name)
    fault.__package__ = 'ci_contract'
    exec(compile(source, '<' + name + '>', 'exec'), fault.__dict__)
    if hasattr(module, 'AuthorityUnknown'):
        fault.AuthorityUnknown = module.AuthorityUnknown
    return fault


@contextmanager
def stub_reconstruction():
    """Isolate a journal decision from the separately tested M6 reconstruction."""
    from unittest.mock import patch
    from ci_contract.request_binding import validate_request_binding

    def reconstruct(inputs, binding, **_):
        request.restore_dispatch(inputs)
        validate_request_binding(binding)
    with patch.object(request, 'reconstruct_bound_dispatch', reconstruct):
        yield


START_TIMEOUT = 30
INTERLEAVE_TIMEOUT = 3
# Faults injected into child processes for the r17 negative controls.
FAULTS = {
    'digest-as-acquisition': ('claim', [("            if other['state'] == 'leased':\n                active = other",
                                         "            if False:\n                active = other")]),
    'unlocked-append': ('journal', [('                _lock(descriptor)\n', '                pass\n'),
                                    ('                _unlock(descriptor)\n', '                pass\n')]),
    'lock-file-existence': ('journal', [('                _lock(descriptor)\n', '                os.fstat(descriptor)\n'),
                                        ('                _unlock(descriptor)\n', '                pass\n')]),
}


def concurrent_client(index, journal_path, repository, binding, inputs, start, interleave, folder, fault):
    """One child process: acquire, and dispatch only when acquired, to a counting sender.

    The replaced clock first waits at a shared barrier. The production code
    reads the clock under the lock after re-reading the journal, so correct
    locking lets only one client reach it at a time (the barrier then times out
    and breaks), while a lock-free fault lets all clients reach it together.
    """
    import json
    import threading
    from ci_contract import claim as claim_module, journal as journal_module
    from synthetic_request import fixed_model
    if fault is not None:
        target, replacements = FAULTS[fault]
        if target == 'claim':
            claim_module = module_fault(claim_module, replacements)
        else:
            journal_module = module_fault(journal_module, replacements, name='synthetic_journal_fault')

    def clock():
        try:
            interleave.wait(timeout=INTERLEAVE_TIMEOUT)
        except threading.BrokenBarrierError:
            pass
        return T0

    def send(fields):
        with open(os.path.join(folder, 'sends.log'), 'ab') as handle:
            handle.write(b'sent\n')

    outcome = {}
    try:
        journal = journal_module.LocalJournal(journal_path, authority_id=AUTHORITY, repository_roots=[repository])
        start.wait(timeout=START_TIMEOUT)
        outcome['acquire'] = claim_module.acquire(journal, binding, owner_id='client-%d' % index, clock=clock)
        if outcome['acquire']['status'] == 'acquired':
            _, fixed = fixed_model()
            outcome['dispatch'] = claim_module.dispatch(journal, inputs, binding, send, clock=clock, **fixed)
    except Exception as error:
        outcome['error'] = type(error).__name__
    with open(os.path.join(folder, 'client-%d.json' % index), 'w', encoding='utf-8') as handle:
        json.dump(outcome, handle)


def run_clients(count, fault=None, limit_seconds=60):
    """Start 2-4 spawned clients at once against one journal; wait with an upper bound.

    Every child is joined (or terminated and joined) before the temporary
    folder is removed. A child still running at the limit fails the run.
    """
    import json
    import multiprocessing
    import time
    if not 2 <= count <= 4:
        raise ValueError('between two and four clients')
    plan, _ = shared_plan()
    context = multiprocessing.get_context('spawn')
    with Workspace() as space:
        space.journal()
        bindings = [binding_for(plan, 'synthetic-request-%d' % index) for index in range(count)]
        start, interleave = context.Barrier(count), context.Barrier(count)
        processes = [context.Process(target=concurrent_client,
                                     args=(index, space.path, str(space.repository), bindings[index],
                                           inputs_for(plan, bindings[index]), start, interleave,
                                           str(space.root), fault))
                     for index in range(count)]
        late = []
        try:
            for process in processes:
                process.start()
            deadline = time.monotonic() + limit_seconds
            for process in processes:
                process.join(max(0.0, deadline - time.monotonic()))
            late = [process for process in processes if process.is_alive()]
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
            for process in processes:
                process.join()
        if late:
            raise AssertionError('a client exceeded the time limit')
        outcomes = []
        for index in range(count):
            with open(os.path.join(space.root, 'client-%d.json' % index), encoding='utf-8') as handle:
                outcomes.append(json.load(handle))
        sends_log = space.root / 'sends.log'
        sends = sends_log.read_bytes().count(b'sent\n') if sends_log.exists() else 0
        return {'outcomes': outcomes, 'sends': sends, 'bindings': bindings}


def adopted_flow(space, plan, fixed, binding, clock, *, journal=None, run_id='123', stub=False):
    """acquire -> dispatch -> reconcile with one observed run; returns the observations."""
    from ci_contract import claim
    journal = space.journal() if journal is None else journal
    sender = Sender()
    acquired = claim.acquire(journal, binding, owner_id='synthetic-supervisor', clock=clock)
    if stub:
        with stub_reconstruction():
            submitted = claim.dispatch(journal, inputs_for(plan, binding), binding, sender, clock=clock, **fixed)
    else:
        submitted = claim.dispatch(journal, inputs_for(plan, binding), binding, sender, clock=clock, **fixed)
    adopted = claim.reconcile(journal, binding['requestId'], Query([candidate(binding, run_id=run_id)]), clock=clock)
    return journal, sender, acquired, submitted, adopted
