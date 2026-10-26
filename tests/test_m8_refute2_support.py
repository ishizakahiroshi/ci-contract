"""Synthetic repositories and adapter for the second M8 refutation (synthetic data only).

The adapter reads ``src/main.txt``: each line ``<action> <logical check ID or *> [argument]``.
It reads and writes only inside its own tree and its private home. ``app.generate``
writes ``build/payload.bin`` and lists it as ``synthetic-payload``; every check prints
the SHA-256 of ``build/payload.bin`` (or ``absent``) to its console log, so a test can
see which bytes a check actually read.
"""
import copy
import tempfile
from pathlib import Path
from ci_contract.execute import execute, host_platform
from ci_contract.plan import build_plan, variant_id
from synthetic_claim import Clock, Workspace
from synthetic_execute import execute_history, execute_manifest, host, quality_projection, target_files

IDENTITY = host_platform()

ADAPTER = rb'''# Synthetic second-refutation adapter (synthetic data only).
import hashlib
import json
import os
import subprocess
import sys
import time

CASES = ['synthetic-case']
PAYLOAD = os.path.join('build', 'payload.bin')


def actions(check):
    try:
        with open(os.path.join('src', 'main.txt'), encoding='utf-8') as handle:
            lines = handle.read().splitlines()
    except OSError:
        return {}
    found = {}
    for line in lines:
        parts = line.split(' ', 2)
        if len(parts) >= 2 and parts[1] in (check, '*'):
            found[parts[0]] = parts[2] if len(parts) == 3 else ''
    return found


def seen():
    try:
        with open(PAYLOAD, 'rb') as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return 'absent'


def main():
    check = sys.argv[2]
    todo = actions(check)
    print('seen-payload ' + seen(), flush=True)
    if 'overwrite' in todo:
        # An accident of a build step: this check writes the same output path as the generator.
        os.makedirs('build', exist_ok=True)
        with open(PAYLOAD, 'wb') as handle:
            handle.write(todo['overwrite'].encode('utf-8') + b'\n')
    if 'latewrite' in todo:
        # A descendant that changes the pinned adapter after its parent ended.
        code = ('import sys, time; time.sleep(1.5); data = open(sys.argv[1], "rb").read(); '
                'open(sys.argv[1], "wb").write(data + b"# changed late\\n")')
        subprocess.Popen([sys.executable, '-I', '-c', code, os.path.join('tools', 'adapter.py')],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if 'breakaway' in todo:
        try:
            subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)'],
                             creationflags=0x01000000, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            print('breakaway-started', flush=True)
        except OSError:
            print('breakaway-refused', flush=True)
    if 'junction' in todo:
        # A directory junction in the tree that points outside it (a build tool's cache link).
        import _winapi
        os.makedirs('build', exist_ok=True)
        _winapi.CreateJunction(todo['junction'], os.path.abspath(os.path.join('build', 'outside')))
    if 'pause' in todo:
        time.sleep(float(todo['pause']))
    failed = 'fail' in todo
    value = {'kind': 'ci-contract-adapter-report-v1', 'expectedCaseIds': [], 'executedCaseIds': [],
             'passedCaseIds': [], 'failedCaseIds': [], 'skippedCases': [], 'collectionComplete': True,
             'targetPaths': [], 'analysisCompleted': False, 'diagnosticCount': None, 'payloads': []}
    if check == 'app.test':
        value.update(expectedCaseIds=CASES, executedCaseIds=CASES, passedCaseIds=[] if failed else CASES,
                     failedCaseIds=CASES if failed else [])
    elif check == 'app.generate':
        os.makedirs('build', exist_ok=True)
        with open(PAYLOAD, 'wb') as handle:
            handle.write(b'synthetic payload\n')
        value['payloads'] = [{'artifactId': 'synthetic-payload', 'path': 'build/payload.bin'}]
    else:
        value.update(targetPaths=['src/main.txt'], analysisCompleted=True, diagnosticCount=1 if failed else 0)
    if 'samepayload' in todo:
        # Many artifact IDs naming one file: each is read whole and kept until the end.
        count = int(todo['samepayload'])
        os.makedirs('build', exist_ok=True)
        with open(os.path.join('build', 'big.bin'), 'wb') as handle:
            handle.write(b'x' * 1024)
        value['payloads'] = [{'artifactId': 'synthetic-copy-%d' % number, 'path': 'build/big.bin'}
                             for number in range(count)]
    if 'uniquepayloads' in todo:
        # Many small payloads with IDs unique in the execution (prefix from this check's report path).
        count = int(todo['uniquepayloads'])
        prefix = 'p' + hashlib.sha256(os.environ['CI_CONTRACT_REPORT'].encode('utf-8')).hexdigest()[:10]
        os.makedirs('build', exist_ok=True)
        with open(os.path.join('build', 'small.bin'), 'wb') as handle:
            handle.write(b'synthetic small payload\n')
        value['payloads'] = [{'artifactId': '%s-%d' % (prefix, number), 'path': 'build/small.bin'}
                             for number in range(count)]
    with open(os.environ['CI_CONTRACT_REPORT'], 'w', encoding='utf-8') as handle:
        json.dump(value, handle, sort_keys=True, separators=(',', ':'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
'''


def variant_manifest(manifest, features=(('synthetic-f1',), ('synthetic-f2',))):
    """Every check with two more variants on this host that differ only in their features."""
    for check in manifest['checks']:
        base = check['variants'][0]
        check['variants'] = [base] + [dict(copy.deepcopy(base), features=list(names)) for names in features]
    ids = sorted({variant_id(v) for check in manifest['checks'] for v in check['variants']})
    graph = manifest['selectionModel']
    for item in graph['inputRules'] + graph['impactEdges'] + graph['checkMappings']:
        item['condition']['variantIds'] = list(ids)
    return manifest


class Repository:
    """One synthetic repository whose pinned adapter is ADAPTER (optionally with app.generate)."""

    def __init__(self, root, name, timeout=10, generation=False, variants=False):
        manifest = execute_manifest(*IDENTITY, timeout=timeout, adapter=ADAPTER, generation=generation)
        if variants:
            manifest = variant_manifest(manifest)
        projection = quality_projection(generation=True) if generation else None
        self.git, self.base, self.files = execute_history(Path(root) / (name + '.git'), manifest, adapter=ADAPTER,
                                                          projection=projection)
        self.root, self.name, self.count = Path(root), name, 0

    def plan(self, text):
        target = self.git.commit(target_files(self.files, text), parents=(self.base,), message='synthetic target')
        return build_plan(self.git.path, 'synthetic', self.base, target)

    def out(self):
        self.count += 1
        return str(self.root / ('%s-out-%d' % (self.name, self.count)))


class Base:
    """Mixin for unittest cases: repositories per class, one anchored journal per call."""
    generation = False
    variants = False
    timeout = 10

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-refute2-')
        cls.root = Path(cls.temp.name)
        cls.repo = Repository(cls.root, 'refute2', timeout=cls.timeout, generation=cls.generation,
                              variants=cls.variants)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def space(self):
        space = Workspace()
        self.addCleanup(space.__exit__)
        (space.root / 'anchor').mkdir()
        space.anchored = space.journal(anchor_path=str(space.root / 'anchor' / 'journal.anchor'))
        return space

    def run_plan(self, plan, space=None, clock=None, out=None, journal=None, **options):
        space = self.space() if space is None else space
        out = self.repo.out() if out is None else out
        verdict = execute(plan, target='local', out=out, repo_path=str(self.repo.git.path), host=host(),
                          journal=space.anchored if journal is None else journal,
                          clock=Clock() if clock is None else clock, **options)
        return verdict, out, space

    @staticmethod
    def types(space):
        return [record['recordType'] for record in space.records()]
